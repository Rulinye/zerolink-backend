//! Background poller for the per-broker `broker_enabled` flag.
//!
//! Phase 4 Batch 4.7 supplement / B6 — closes the gap where admin
//! flips a broker's `broker_enabled` to false in the backend's `nodes`
//! table but the broker keeps accepting WS connections (and therefore
//! create_room / join_room) until next service restart. Operator-
//! reported symptom: clients with stale `/api/v1/nodes` cache pick the
//! disabled broker, the WS still upgrades, room create succeeds, and
//! then the user gets kicked out by the watchdog a moment later — no
//! explicit "broker not available" error.
//!
//! Architecture:
//!   - `BrokerStatusWatcher` owns an `Arc<AtomicBool>` representing
//!     the current "is this broker accepting work" view. WS handlers
//!     read it via `is_enabled()` early in their flow.
//!   - `run_poller` is a long-running task spawned by main.rs. It
//!     hits `GET /api/v1/broker-status?short_id=...` on the backend
//!     every `poll_interval` (default 15s) and updates the AtomicBool.
//!   - First poll latency is ~the broker's startup time — until the
//!     first poll completes, we fail OPEN (assume enabled). This
//!     matches the prior behaviour for clean restarts and avoids a
//!     chicken-and-egg ("backend is down so nothing works") at
//!     startup; falsely-permissive for at most one poll cycle.
//!   - Auth: Bearer service_token (same one used by VerifyClient).
//!     Wire-additive on the backend; existing token works.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use reqwest::Client;
use tokio::time::{interval, MissedTickBehavior};
use tracing::{info, warn};

#[derive(Clone)]
pub struct BrokerStatusWatcher {
    enabled: Arc<AtomicBool>,
}

impl BrokerStatusWatcher {
    pub fn new() -> Self {
        // Fail-open at startup: until the first poll lands, treat broker
        // as enabled so a transient backend outage at boot doesn't
        // brick room creation. Operator can audit-log via the
        // `broker_status` tracing target if anomalies appear.
        Self {
            enabled: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }
}

impl Default for BrokerStatusWatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Spawn this from main.rs once the verify client's HTTP stack is up.
/// Reuses the same `reqwest::Client` (pre-configured with
/// fingerprint-pinned TLS) so we get the same trust posture as
/// the JWT-verify path.
pub async fn run_poller(
    watcher: BrokerStatusWatcher,
    http: Client,
    backend_url: String,
    service_token: String,
    short_id: String,
    poll_interval: Duration,
) {
    let mut tick = interval(poll_interval);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    info!(
        target: "broker_status",
        "poller started (short_id={}, interval={:?})",
        short_id, poll_interval
    );
    loop {
        tick.tick().await;
        match poll_once(&http, &backend_url, &service_token, &short_id).await {
            Ok(enabled) => {
                let prev = watcher.enabled.swap(enabled, Ordering::Relaxed);
                if prev != enabled {
                    info!(
                        target: "broker_status",
                        "broker_enabled flipped: {} → {} (short_id={})",
                        prev, enabled, short_id
                    );
                }
            }
            Err(e) => {
                warn!(
                    target: "broker_status",
                    "poll failed: {} (keeping prior state: enabled={})",
                    e,
                    watcher.is_enabled()
                );
            }
        }
    }
}

async fn poll_once(
    http: &Client,
    backend_url: &str,
    service_token: &str,
    short_id: &str,
) -> Result<bool> {
    #[derive(serde::Deserialize)]
    struct Resp {
        broker_enabled: bool,
        is_enabled: bool,
    }
    let url = format!(
        "{}/api/v1/broker-status?short_id={}",
        backend_url, short_id
    );
    let resp = http
        .get(&url)
        .bearer_auth(service_token)
        .send()
        .await
        .map_err(|e| anyhow!("transport: {}", e))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow!("backend returned {}: {}", status, body));
    }
    let body: Resp = resp.json().await.map_err(|e| anyhow!("decode: {}", e))?;
    // Either flag false → broker should reject new sessions.
    Ok(body.broker_enabled && body.is_enabled)
}
