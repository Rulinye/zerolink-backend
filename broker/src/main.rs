#![allow(dead_code)] // TODO 2c: remove when fields/methods are wired into RPC handlers
//! zerolink-broker — room signaling + L3 datapath relay daemon.
//!
//! 2a scope: bootstrap, env config, fingerprint-pinned reverse-verify
//! client, and an HTTP listener with `/ping` + `/version`. No room
//! model, no WebSocket signaling, no QUIC datapath — those land in
//! 2b/2c/2d respectively.
//!
//! Run with all required env vars set (see config.rs). systemd
//! EnvironmentFile is the production mechanism; for local development
//! use a `.env` file or inline `ENV=val cargo run`.

mod config;
mod http;
mod verify_client;

use anyhow::Context;
use std::sync::Arc;
use tokio::signal;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::http::AppState;
use crate::verify_client::VerifyClient;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // rustls 0.23 requires a crypto provider to be installed for the
    // process. We use ring (matches the feature flag in Cargo.toml).
    // This must happen BEFORE any rustls ClientConfig builder is called.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("install rustls crypto provider"))?;

    let cfg = Config::load().context("load config from env")?;

    init_logging(cfg.log_json);

    info!(
        target: "boot",
        version = VERSION,
        listen_http = %cfg.listen_http,
        listen_quic = %cfg.listen_quic,
        backend_url = %cfg.backend_url,
        short_id = %cfg.short_id,
        verify_cache_ttl_s = cfg.verify_cache_ttl.as_secs(),
        "starting zerolink-broker"
    );

    let verify = Arc::new(
        VerifyClient::new(
            cfg.backend_url.clone(),
            cfg.backend_fingerprint.clone(),
            cfg.service_token.clone(),
            cfg.request_timeout,
            cfg.verify_cache_ttl,
        )
        .context("build verify client")?,
    );

    let state = AppState {
        config: Arc::new(cfg.clone()),
        verify: verify.clone(),
        version: VERSION,
    };

    let router = http::router(state);

    let http_listen = cfg.listen_http.clone();

    // Spawn the signaling listener.
    let http_task = tokio::spawn(async move {
        if let Err(e) = http::serve(&http_listen, router).await {
            error!(target: "http", "signaling server exited: {e:#}");
        }
    });

    // Wait for SIGINT/SIGTERM. SIGTERM is what systemd sends on stop.
    shutdown_signal().await;
    info!(target: "boot", "shutdown signal received; stopping");

    http_task.abort();
    // Best-effort: give the listener a moment to finish in-flight reqs.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), http_task).await;

    info!(target: "boot", "stopped");
    Ok(())
}

fn init_logging(json: bool) {
    use tracing_subscriber::{fmt, EnvFilter};

    // RUST_LOG override stays active in dev; default to info,broker=debug
    // so per-module debug lines (verify cache, etc.) show up.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,zerolink_broker=debug"));

    if json {
        fmt()
            .json()
            .with_env_filter(filter)
            .with_target(true)
            .init();
    } else {
        fmt().with_env_filter(filter).with_target(true).init();
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.ok();
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => warn!(target: "boot", "received Ctrl-C"),
        _ = terminate => warn!(target: "boot", "received SIGTERM"),
    }
}
