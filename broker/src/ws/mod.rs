//! WebSocket signaling endpoint (`GET /rpc/ws`).
//!
//! Lifecycle:
//!   1. Upgrade — JWT comes in via `?jwt=...` query param. Verified
//!      against backend BEFORE accepting the upgrade (decision E1).
//!      Failure → HTTP 401 / 403, no WS established.
//!   2. Connection loop — alternates between reading client RPC
//!      requests (synchronously, decision D1) and pushing broadcast
//!      events from the room channel.
//!   3. Disconnect — if the connection was bound to a session, the
//!      session enters grace (decision B2). The grace_watchdog
//!      finalizes the leave 30s later if no resume happens.

pub mod broadcast;
pub mod handlers;
pub mod protocol;
pub mod session;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;
use tokio::sync::broadcast as tokio_broadcast;
use tracing::{debug, info, warn};

use crate::http::AppState;
use crate::verify_client::VerifyError;
use crate::ws::handlers::{HandlerOutput, SideEffect, WsAuth};
use crate::ws::protocol::{ClientMessage, RoomEvent, RpcResponse, ServerMessage};
use crate::ws::session::WsBinding;

#[derive(Debug, Deserialize)]
pub struct WsQuery {
    pub jwt: String,
}

/// axum handler for `GET /rpc/ws`.
pub async fn ws_upgrade(
    ws: WebSocketUpgrade,
    Query(q): Query<WsQuery>,
    State(state): State<AppState>,
) -> axum::response::Response {
    // Decision E1: verify JWT before accepting the upgrade. The
    // VerifyClient has its own 5min cache, so back-to-back
    // reconnects from the same client don't pile traffic on the
    // backend.
    let resp = match state.verify.verify(&q.jwt).await {
        Ok(r) => r,
        Err(VerifyError::ServiceTokenRejected) => {
            warn!(target: "ws", "backend rejected our service token");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "broker auth misconfigured",
            )
                .into_response();
        }
        Err(e) => {
            warn!(target: "ws", err = %e, "verify backend call failed");
            return (StatusCode::BAD_GATEWAY, "auth verify failed").into_response();
        }
    };
    if !resp.valid {
        let reason = resp.reason.unwrap_or_else(|| "invalid".to_string());
        debug!(target: "ws", %reason, "rejecting ws: invalid jwt");
        return (StatusCode::UNAUTHORIZED, format!("jwt {reason}")).into_response();
    }

    // verify response carries the user identity we need.
    let auth = WsAuth {
        user_id: resp.user_id.unwrap_or(0),
        username: resp.username.unwrap_or_default(),
        is_admin: resp.is_admin.unwrap_or(false),
    };
    if auth.user_id == 0 || auth.username.is_empty() {
        warn!(target: "ws", "verify response missing user_id/username");
        return (StatusCode::BAD_GATEWAY, "verify response malformed").into_response();
    }

    info!(
        target: "ws",
        user_id = auth.user_id,
        username = %auth.username,
        "ws upgrading"
    );

    ws.on_upgrade(move |socket| connection_loop(socket, state, auth))
}

/// State carried through the connection loop. None when not in any
/// room (idle); Some when a successful create_room/join_room/
/// resume_session has bound the connection to a session.
struct InRoom {
    room_id: i64,
    session_id: String,
    binding: WsBinding,
    /// Receiver from BroadcastHub for this room.
    event_rx: tokio_broadcast::Receiver<RoomEvent>,
}

async fn connection_loop(mut socket: WebSocket, state: AppState, auth: WsAuth) {
    let mut current: Option<InRoom> = None;

    loop {
        // Two-way select: read client frame OR push broadcast event.
        let next = {
            // We can't borrow current.event_rx mutably while still
            // wanting to drop `current` later inside the same scope,
            // so split the select into a small helper.
            select_next(&mut socket, current.as_mut()).await
        };

        match next {
            NextEvent::ClientMessage(Ok(msg)) => match msg {
                Message::Text(text) => {
                    if let Err(()) =
                        handle_client_text(&state, &auth, &mut socket, &mut current, &text).await
                    {
                        // Fatal protocol error → close.
                        break;
                    }
                }
                Message::Binary(_) => {
                    // 3.3 protocol is JSON only; binary frames are
                    // reserved for future use (datapath is on quinn,
                    // not WS).
                    debug!(target: "ws", "ignoring binary frame");
                }
                Message::Ping(p) => {
                    let _ = socket.send(Message::Pong(p)).await;
                }
                Message::Pong(_) => {}
                Message::Close(_) => break,
            },
            NextEvent::ClientMessage(Err(e)) => {
                debug!(target: "ws", err = %e, "ws read error; closing");
                break;
            }
            NextEvent::BroadcastEvent(Ok(evt)) => {
                // Suppress events whose user_id matches self — the
                // joiner already learned of itself via the
                // join_room response.
                if event_targets_self(&evt, auth.user_id) {
                    continue;
                }
                let env = evt.clone().into_envelope();
                let msg = ServerMessage::Event(env);
                let body = serde_json::to_string(&msg).unwrap_or_default();
                if socket.send(Message::Text(body)).await.is_err() {
                    break;
                }
                // If we just delivered a room_destroyed event, the
                // room is gone; gracefully close the connection. The
                // session was already removed by destroy_room or the
                // grace watchdog.
                if matches!(evt, RoomEvent::RoomDestroyed(_)) {
                    let _ = socket.send(Message::Close(None)).await;
                    current = None;
                    break;
                }
            }
            NextEvent::BroadcastEvent(Err(tokio_broadcast::error::RecvError::Lagged(n))) => {
                warn!(
                    target: "ws",
                    user_id = auth.user_id,
                    lagged = n,
                    "ws receiver lagged; closing connection"
                );
                let _ = socket.send(Message::Close(None)).await;
                break;
            }
            NextEvent::BroadcastEvent(Err(tokio_broadcast::error::RecvError::Closed)) => {
                debug!(target: "ws", "broadcast channel closed; closing ws");
                break;
            }
        }
    }

    // Disconnect path: if a session is bound, detach (start grace).
    // The grace_watchdog will finalize the leave 30s later.
    if let Some(in_room) = current {
        if let Some(_session_id) = state
            .sessions
            .detach(&in_room.session_id, in_room.binding)
            .await
        {
            info!(
                target: "ws",
                user_id = auth.user_id,
                session_id = %in_room.session_id,
                room_id = in_room.room_id,
                "ws disconnected; session in grace"
            );
        }
    }
}

enum NextEvent {
    ClientMessage(Result<Message, axum::Error>),
    BroadcastEvent(Result<RoomEvent, tokio_broadcast::error::RecvError>),
}

async fn select_next(socket: &mut WebSocket, in_room: Option<&mut InRoom>) -> NextEvent {
    use futures_util::stream::StreamExt;
    match in_room {
        Some(ir) => tokio::select! {
            // Biased so we strictly drain client requests when
            // both client and broadcast are ready (preserves the
            // intuition that a request placed BEFORE an event
            // gets a response BEFORE the event).
            biased;
            client = socket.next() => match client {
                Some(r) => NextEvent::ClientMessage(r),
                None    => NextEvent::ClientMessage(Err(axum::Error::new("stream closed"))),
            },
            evt = ir.event_rx.recv() => NextEvent::BroadcastEvent(evt),
        },
        None => match socket.next().await {
            Some(r) => NextEvent::ClientMessage(r),
            None => NextEvent::ClientMessage(Err(axum::Error::new("stream closed"))),
        },
    }
}

fn event_targets_self(evt: &RoomEvent, self_user_id: i64) -> bool {
    match evt {
        RoomEvent::MemberJoined(e) => e.user_id == self_user_id,
        RoomEvent::MemberLeft(e) => e.user_id == self_user_id,
        RoomEvent::RoomDestroyed(_) => false, // everyone needs this
        // D4.5: don't echo our own candidate publish back to ourselves.
        RoomEvent::PeerCandidatesUpdated(e) => e.user_id == self_user_id,
    }
}

async fn handle_client_text(
    state: &AppState,
    auth: &WsAuth,
    socket: &mut WebSocket,
    current: &mut Option<InRoom>,
    text: &str,
) -> Result<(), ()> {
    let msg: ClientMessage = match serde_json::from_str(text) {
        Ok(m) => m,
        Err(e) => {
            warn!(target: "ws", err = %e, "bad client frame; closing ws");
            // Try to extract an id field and reply with bad_params so
            // the client (e.g. websocat) doesn't hang waiting for a
            // response that never comes. Best-effort; if even the id
            // extraction fails, just close.
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
                if let Some(id) = v.get("id").and_then(|x| x.as_str()) {
                    let res = crate::ws::protocol::RpcResponse::err(
                        id.to_string(),
                        "bad_params",
                        format!("malformed frame: {e}"),
                    );
                    let body = serde_json::to_string(&crate::ws::protocol::ServerMessage::Res(res))
                        .unwrap_or_default();
                    let _ = socket.send(Message::Text(body)).await;
                }
            }
            // Force close — bad frames signal a misbehaving client.
            return Err(());
        }
    };

    match msg {
        ClientMessage::Req(req) => {
            let id = req.id.clone();
            let in_room_flag = current.is_some();
            let in_room_pair = current
                .as_ref()
                .map(|ir| (ir.room_id, ir.session_id.clone()));

            let out = match req.method.as_str() {
                "create_room" => {
                    handlers::handle_create_room(state, auth, req.params, in_room_flag).await
                }
                "join_room" => {
                    handlers::handle_join_room(state, auth, req.params, in_room_flag).await
                }
                "leave_room" => handlers::handle_leave_room(state, auth, in_room_pair).await,
                "destroy_room" => {
                    handlers::handle_destroy_room(state, auth, req.params, in_room_pair).await
                }
                "list_my_rooms" => handlers::handle_list_my_rooms(state, auth).await,
                "room_info" => handlers::handle_room_info(state, auth, req.params).await,
                "resume_session" => {
                    handlers::handle_resume_session(state, auth, req.params, in_room_flag).await
                }
                "admin_list_all_rooms" => handlers::handle_admin_list_all_rooms(state, auth).await,
                "admin_destroy_room" => {
                    handlers::handle_admin_destroy_room(state, auth, req.params).await
                }
                // D4.5 (Phase 4.4) — P2P signaling.
                "signal_publish_candidates" => {
                    handlers::handle_signal_publish_candidates(
                        state,
                        auth,
                        req.params,
                        in_room_pair.clone(),
                    )
                    .await
                }
                "signal_get_candidates" => {
                    handlers::handle_signal_get_candidates(
                        state,
                        auth,
                        req.params,
                        in_room_pair.clone(),
                    )
                    .await
                }
                other => HandlerOutput {
                    result: Err(crate::ws::protocol::RpcError {
                        code: "unknown_method".to_string(),
                        message: format!("unknown method {other:?}"),
                    }),
                    side_effect: SideEffect::None,
                },
            };

            apply_side_effect(current, out.side_effect);

            // Send response.
            let res = match out.result {
                Ok(value) => RpcResponse::ok(id, value),
                Err(e) => RpcResponse {
                    id,
                    result: None,
                    error: Some(e),
                },
            };
            let body = serde_json::to_string(&ServerMessage::Res(res)).unwrap_or_default();
            if socket.send(Message::Text(body)).await.is_err() {
                return Err(());
            }
        }
    }
    Ok(())
}

fn apply_side_effect(current: &mut Option<InRoom>, eff: SideEffect) {
    match eff {
        SideEffect::None => {}
        SideEffect::EnterRoom {
            room_id,
            session_id,
            binding,
            rx,
        } => {
            *current = Some(InRoom {
                room_id,
                session_id,
                binding,
                event_rx: rx,
            });
        }
        SideEffect::ExitRoom => {
            *current = None;
        }
    }
}
