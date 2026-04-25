//! HTTP signaling server (axum).
//!
//! 2a scope: skeleton router with `/ping` and `/version` only. WebSocket
//! signaling RPC + push events arrive in 2c. The room model + storage
//! arrive in 2b.
//!
//! The signaling listener and the QUIC datapath listener (2d) run as
//! independent Tokio tasks; nothing here cares about QUIC.

use axum::{routing::get, Json, Router};
use serde::Serialize;
use std::sync::Arc;
use tracing::info;

use crate::config::Config;
use crate::verify_client::VerifyClient;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub verify: Arc<VerifyClient>,
    pub version: &'static str,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/ping", get(handle_ping))
        .route("/version", get(handle_version))
        .with_state(state)
}

#[derive(Serialize)]
struct PingResponse {
    ok: bool,
    service: &'static str,
    short_id: String,
}

async fn handle_ping(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Json<PingResponse> {
    Json(PingResponse {
        ok: true,
        service: "zerolink-broker",
        short_id: state.config.short_id.clone(),
    })
}

#[derive(Serialize)]
struct VersionResponse {
    version: &'static str,
    service: &'static str,
    short_id: String,
}

async fn handle_version(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Json<VersionResponse> {
    Json(VersionResponse {
        version: state.version,
        service: "zerolink-broker",
        short_id: state.config.short_id.clone(),
    })
}

pub async fn serve(addr: &str, router: Router) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(target: "http", %addr, "signaling listening");
    axum::serve(listener, router).await?;
    Ok(())
}
