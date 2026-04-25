#![allow(dead_code)] // TODO 2c: remove when fields/methods are wired into RPC handlers
//! zerolink-broker — room signaling + L3 datapath relay daemon.
//!
//! 2b scope: bootstrap now opens a SQLite pool and runs migrations.
//! Storage handles are wired into AppState but not yet consumed by any
//! handler — that lands in 2c.

mod config;
mod http;
mod storage;
mod verify_client;

use anyhow::Context;
use std::sync::Arc;
use tokio::signal;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::http::AppState;
use crate::storage::Storage;
use crate::verify_client::VerifyClient;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
        db_path = %cfg.db_path,
        "starting zerolink-broker"
    );

    // Storage open + migrations applied at boot. Failure at this stage
    // is fatal — there's no point starting an HTTP listener if we can't
    // persist room state.
    let storage = Storage::open(&cfg.db_path).await.context("open storage")?;

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
        storage: storage.clone(),
        version: VERSION,
    };

    let router = http::router(state);

    let http_listen = cfg.listen_http.clone();
    let http_task = tokio::spawn(async move {
        if let Err(e) = http::serve(&http_listen, router).await {
            error!(target: "http", "signaling server exited: {e:#}");
        }
    });

    shutdown_signal().await;
    info!(target: "boot", "shutdown signal received; stopping");

    http_task.abort();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), http_task).await;

    info!(target: "boot", "stopped");
    Ok(())
}

fn init_logging(json: bool) {
    use tracing_subscriber::{fmt, EnvFilter};

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
