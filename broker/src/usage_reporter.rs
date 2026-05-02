//! Periodic broker→backend traffic reporter.
//!
//! Phase 4 Batch 4.7 supplement / B3 (room half) + B9 (admin audit
//! data feed).
//!
//! Every `REPORT_INTERVAL` (60s), the reporter scans every PathEntry
//! in PathMap, calls `snapshot_and_reset()` to drain the
//! per-(room, user) byte counters, aggregates by user_id (a user has
//! at most one session per the broker's by_user invariant, so the
//! aggregation is mostly a 1:1 map), and POSTs the deltas to backend's
//! `/api/v1/usage/report` (service-token authed).
//!
//! Robustness:
//!   - If the POST fails, we KEEP the deltas in a local pending map
//!     and retry on the next tick. Counters in PathMap are already
//!     zeroed — without local retention, transient backend outages
//!     would silently lose user quota credit.
//!   - We cap the local pending map at 10k entries (essentially
//!     "10k unique users with un-reported traffic"). If overflowing,
//!     we drop oldest — a last-resort guard against backend being
//!     down for hours.
//!
//! Auth: same Bearer service_token used by the verify client + the
//! broker_status poller.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{anyhow, Result};
use reqwest::Client;
use serde::Serialize;
use tokio::time::{interval, MissedTickBehavior};
use tracing::{debug, info, warn};

use crate::datapath::PathMap;

pub const REPORT_INTERVAL: Duration = Duration::from_secs(60);
const MAX_PENDING_USERS: usize = 10_000;

#[derive(Debug, Default, Clone, Copy)]
struct Delta {
    bytes_in: u64,
    bytes_out: u64,
}

#[derive(Serialize)]
struct ReportEntry {
    user_id: i64,
    source: &'static str,
    delta_bytes_in: u64,
    delta_bytes_out: u64,
}

#[derive(Serialize)]
struct ReportRequest {
    entries: Vec<ReportEntry>,
}

pub async fn run_reporter(
    paths: PathMap,
    http: Client,
    backend_url: String,
    service_token: String,
) {
    let mut tick = interval(REPORT_INTERVAL);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    info!(
        target: "usage_reporter",
        interval_secs = REPORT_INTERVAL.as_secs(),
        "broker traffic reporter started"
    );

    let mut pending: HashMap<i64, Delta> = HashMap::new();

    loop {
        tick.tick().await;

        // (1) Drain PathMap counters into pending.
        let entries = paths.snapshot_all().await;
        for (user_id, di, do_) in entries {
            if di == 0 && do_ == 0 {
                continue;
            }
            let slot = pending.entry(user_id).or_default();
            slot.bytes_in = slot.bytes_in.saturating_add(di);
            slot.bytes_out = slot.bytes_out.saturating_add(do_);
        }

        if pending.is_empty() {
            continue;
        }

        // Cap pending size to avoid unbounded memory if backend is
        // down for a long time. Drop oldest in iteration order
        // (HashMap iteration order is implementation-defined; this
        // is best-effort).
        if pending.len() > MAX_PENDING_USERS {
            let excess = pending.len() - MAX_PENDING_USERS;
            let drop_keys: Vec<i64> = pending.keys().copied().take(excess).collect();
            for k in drop_keys {
                pending.remove(&k);
            }
            warn!(
                target: "usage_reporter",
                "pending overflow: dropped {} entries (backend has been down too long?)",
                excess
            );
        }

        // (2) Build request.
        let entries: Vec<ReportEntry> = pending
            .iter()
            .map(|(uid, d)| ReportEntry {
                user_id: *uid,
                source: "room",
                delta_bytes_in: d.bytes_in,
                delta_bytes_out: d.bytes_out,
            })
            .collect();
        let req = ReportRequest { entries };

        // (3) POST. On success, clear pending; on failure, retain.
        match post_report(&http, &backend_url, &service_token, &req).await {
            Ok(applied) => {
                debug!(
                    target: "usage_reporter",
                    users = pending.len(),
                    applied,
                    "report POST ok"
                );
                pending.clear();
            }
            Err(e) => {
                warn!(
                    target: "usage_reporter",
                    err = %e,
                    pending_users = pending.len(),
                    "report POST failed; retaining deltas for next tick"
                );
            }
        }
    }
}

async fn post_report(
    http: &Client,
    backend_url: &str,
    service_token: &str,
    req: &ReportRequest,
) -> Result<i64> {
    #[derive(serde::Deserialize)]
    struct Resp {
        applied: i64,
    }
    let url = format!("{}/api/v1/usage/report", backend_url);
    let resp = http
        .post(&url)
        .bearer_auth(service_token)
        .json(req)
        .send()
        .await
        .map_err(|e| anyhow!("transport: {}", e))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow!("backend {}: {}", status, body));
    }
    let body: Resp = resp.json().await.map_err(|e| anyhow!("decode: {}", e))?;
    Ok(body.applied)
}
