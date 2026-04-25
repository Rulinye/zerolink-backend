//! zerolink-broker — room signaling + L3 datapath relay daemon.

mod config;
mod http;
mod storage;
mod verify_client;
mod ws;

use anyhow::Context;
use chrono::Utc;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::http::AppState;
use crate::storage::members::MemberRepo;
use crate::storage::rooms::RoomRepo;
use crate::storage::Storage;
use crate::verify_client::VerifyClient;
use crate::ws::broadcast::BroadcastHub;
use crate::ws::protocol::{MemberLeftEvent, RoomDestroyedEvent, RoomEvent};
use crate::ws::session::SessionStore;

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

    let sessions = SessionStore::new();
    let broadcast = BroadcastHub::new();

    let state = AppState {
        config: Arc::new(cfg.clone()),
        verify: verify.clone(),
        storage: storage.clone(),
        sessions: sessions.clone(),
        broadcast: broadcast.clone(),
        version: VERSION,
    };

    let router = http::router(state);

    let http_listen = cfg.listen_http.clone();
    let http_task = tokio::spawn(async move {
        if let Err(e) = http::serve(&http_listen, router).await {
            error!(target: "http", "signaling server exited: {e:#}");
        }
    });

    // Grace watchdog: every 5s, finalize any session whose grace has
    // expired. This is the B2 mechanism — see ws/session.rs.
    let watchdog_storage = storage.clone();
    let watchdog_sessions = sessions.clone();
    let watchdog_broadcast = broadcast.clone();
    let watchdog_task = tokio::spawn(async move {
        grace_watchdog(watchdog_storage, watchdog_sessions, watchdog_broadcast).await
    });

    shutdown_signal().await;
    info!(target: "boot", "shutdown signal received; stopping");

    http_task.abort();
    watchdog_task.abort();
    let _ = tokio::time::timeout(Duration::from_secs(5), http_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), watchdog_task).await;

    info!(target: "boot", "stopped");
    Ok(())
}

/// Background GC task. Three responsibilities, all on the same 5s tick:
///
///   1. Session-grace expiry: a ws disconnect puts a session into
///      30s grace (B2 mechanism). When the deadline hits without a
///      resume_session, finalize the leave: delete member row,
///      broadcast member_left, transition the room to empty_grace
///      if the leaver was the last member.
///
///   2. Room-grace expiry: when a room has been in 'empty_grace' past
///      its grace_until (5 minutes by default), transition to
///      'destroyed' and broadcast room_destroyed (reason:
///      grace_expired). The broadcast hub's channel for that room
///      is dropped so the few remaining ws receivers (idle
///      connections that hadn't hit the room) get RecvError::Closed.
///
///   3. Hard-delete sweep: rooms in 'destroyed' state for more than
///      1 hour are physically removed. ON DELETE CASCADE drops
///      members + traffic in the same statement.
async fn grace_watchdog(storage: Storage, sessions: SessionStore, broadcast: BroadcastHub) {
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let room_repo = RoomRepo::new(storage.pool.clone());
    let member_repo = MemberRepo::new(storage.pool.clone());

    loop {
        tick.tick().await;
        let now = Utc::now().timestamp();

        // (1) session grace
        let expired_sessions = sessions.drain_expired().await;
        for rec in expired_sessions {
            if let Err(e) = member_repo.leave(rec.room_id, rec.user_id).await {
                warn!(target: "watchdog", err = %e, "leave failed during grace finalize");
                continue;
            }
            let _ = broadcast
                .send(
                    rec.room_id,
                    RoomEvent::MemberLeft(MemberLeftEvent {
                        room_id: rec.room_id,
                        user_id: rec.user_id,
                        username: rec.username.clone(),
                    }),
                )
                .await;
            let _ = room_repo.touch_activity(rec.room_id, now).await;
            match member_repo.count_in_room(rec.room_id).await {
                Ok(0) => {
                    let grace_secs = 5 * 60;
                    if let Err(e) = room_repo
                        .set_empty_grace(rec.room_id, now, grace_secs)
                        .await
                    {
                        warn!(target: "watchdog", err = %e, "set_empty_grace failed");
                    }
                }
                Ok(_) => {}
                Err(e) => warn!(target: "watchdog", err = %e, "count_in_room failed"),
            }
            info!(
                target: "watchdog",
                user_id = rec.user_id,
                room_id = rec.room_id,
                session_id = %rec.session_id,
                "grace expired; member left"
            );
        }

        // (2) room empty_grace expiry -> destroyed
        match room_repo.gc_expired_grace_ids(now).await {
            Ok(ids) => {
                for rid in ids {
                    let _ = broadcast
                        .send(
                            rid,
                            RoomEvent::RoomDestroyed(RoomDestroyedEvent {
                                room_id: rid,
                                reason: "grace_expired".to_string(),
                            }),
                        )
                        .await;
                    broadcast.drop_room(rid).await;
                    if let Err(e) = room_repo.destroy(rid, now).await {
                        warn!(
                            target: "watchdog",
                            err = %e,
                            room_id = rid,
                            "room grace destroy failed"
                        );
                    } else {
                        info!(
                            target: "watchdog",
                            room_id = rid,
                            "empty_grace expired; room destroyed"
                        );
                    }
                }
            }
            Err(e) => warn!(target: "watchdog", err = %e, "gc_expired_grace_ids failed"),
        }

        // (3) hard-delete destroyed rooms older than 1 hour. ON DELETE
        //     CASCADE wipes their members + traffic rows.
        let cutoff = now - 3600;
        match room_repo.hard_delete_old_destroyed(cutoff).await {
            Ok(0) => {}
            Ok(n) => info!(target: "watchdog", count = n, "hard-deleted old destroyed rooms"),
            Err(e) => warn!(target: "watchdog", err = %e, "hard-delete sweep failed"),
        }
    }
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
