//! HTTP signaling server (axum).

use axum::{routing::get, Json, Router};
use serde::Serialize;
use std::sync::Arc;
use tracing::info;

use crate::broker_status::BrokerStatusWatcher;
use crate::config::Config;
use crate::datapath::{DatapathInfo, PathMap};
use crate::storage::Storage;
use crate::verify_client::VerifyClient;
use crate::ws::broadcast::BroadcastHub;
use crate::ws::session::SessionStore;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub verify: Arc<VerifyClient>,
    pub storage: Storage,
    pub sessions: SessionStore,
    pub broadcast: BroadcastHub,
    pub datapath: Arc<DatapathInfo>,
    pub datapath_paths: PathMap,
    /// B4.7-supp / B6: live view of `nodes.broker_enabled AND
    /// nodes.is_enabled` for THIS broker. Updated every 15s by the
    /// `broker_status` polling task spawned in main.rs. WS handlers
    /// read it before accepting create_room / join_room so admins
    /// can hard-disable a broker without service restart.
    pub broker_status: BrokerStatusWatcher,
    pub version: &'static str,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/ping", get(handle_ping))
        .route("/version", get(handle_version))
        .route("/rpc/ws", get(crate::ws::ws_upgrade))
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
