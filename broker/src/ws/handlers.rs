//! RPC method implementations.
//!
//! Each handler:
//!   1. Parses params from `req.params` (JSON value).
//!   2. Performs storage and verify-cache calls.
//!   3. Updates session state.
//!   4. Optionally fires broadcast events.
//!   5. Returns a serializable result OR an RpcError.
//!
//! Handlers DO NOT touch the WS sink directly. They produce a pure
//! result; the surrounding `connection_loop` is responsible for
//! turning that into a frame on the wire and for any side-effect
//! dispatch (subscribe/unsubscribe broadcast, replace event_rx).

use chrono::Utc;
use serde_json::Value as Json;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use crate::http::AppState;
use crate::storage::rooms::{RoomError, RoomState};
use crate::ws::protocol::{
    AdminDestroyRoomParams, AdminListAllRoomsResult, AdminRoomEntry, CreateRoomParams,
    CreateRoomResult, DestroyRoomParams, JoinRoomParams, JoinRoomResult, ListMyRoomsResult,
    MemberInfo, MemberJoinedEvent, MemberLeftEvent, MyRoomEntry, OkResult, ResumeSessionParams,
    ResumeSessionResult, RoomDestroyedEvent, RoomEvent, RpcError,
};
use crate::ws::session::{SessionError, WsBinding};

/// Authenticated context for a connection. Filled in once at WS upgrade
/// time (after JWT verify) and never changes for the lifetime of the WS.
#[derive(Debug, Clone)]
pub struct WsAuth {
    pub user_id: i64,
    pub username: String,
    pub is_admin: bool,
}

/// Per-call result. The connection loop uses these to update its
/// own state: subscribe to a new room channel, swap event_rx,
/// drop the connection after destroy_room, etc.
#[derive(Debug)]
pub struct HandlerOutput {
    pub result: Result<Json, RpcError>,
    pub side_effect: SideEffect,
}

#[derive(Debug, Default)]
pub enum SideEffect {
    #[default]
    None,
    /// Subscribe to a room's broadcast channel and remember the
    /// session_id + binding for cleanup on disconnect.
    EnterRoom {
        room_id: i64,
        session_id: String,
        binding: WsBinding,
        rx: broadcast::Receiver<RoomEvent>,
    },
    /// User left the room (leave_room or destroy_room). Connection
    /// returns to idle state.
    ExitRoom,
}

// =====================================================================
// create_room
// =====================================================================

pub async fn handle_create_room(
    state: &AppState,
    auth: &WsAuth,
    params: Json,
    in_room: bool,
) -> HandlerOutput {
    if in_room {
        return err(
            "already_in_room",
            "leave the current room before creating a new one",
        );
    }
    // A3 cache+DB bottom: even if THIS ws is idle, the user may have a
    // session bound to a different ws or in grace. Reject early so we
    // don't hit the UNIQUE constraint at SQL layer.
    if let Some(s) = state.sessions.find_by_user(auth.user_id).await {
        return err(
            "already_in_room",
            format!("session already active in room {}", s.room_id),
        );
    }

    // DB authority: even if SessionStore says no session, the user
    // might still own a room that is in empty_grace (session expired
    // but the room itself is still in its 5-min reclaim window). The
    // partial unique index on rooms enforces this at SQL level but
    // we want a clean error code instead of "internal" + UNIQUE crash.
    let probe_room_repo = crate::storage::rooms::RoomRepo::new(state.storage.pool.clone());
    if let Ok(existing) = probe_room_repo.list_alive_owned_by(auth.user_id).await {
        if let Some(r) = existing.first() {
            return err(
                "room_limit",
                format!(
                    "you already own a room ({}); close it before creating a new one",
                    r.code
                ),
            );
        }
    }

    let p: CreateRoomParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => return err("bad_params", format!("create_room params: {e}")),
    };
    let strategy = p
        .path_strategy
        .as_deref()
        .filter(|s| matches!(*s, "auto" | "p2p_only" | "broker_only"))
        .unwrap_or("auto");

    let now = Utc::now().timestamp();

    let room_repo = crate::storage::rooms::RoomRepo::new(state.storage.pool.clone());
    let member_repo = crate::storage::members::MemberRepo::new(state.storage.pool.clone());

    let room = match room_repo
        .create(auth.user_id, &auth.username, strategy, now)
        .await
    {
        Ok(r) => r,
        Err(RoomError::RoomLimitExceeded) => {
            return err(
                "room_limit",
                "you already own a room; close it before creating a new one",
            );
        }
        Err(RoomError::CodeGenExhausted) => {
            return err("internal", "could not generate a room code; try again");
        }
        Err(e) => {
            warn!(target: "rpc", err = %e, "create_room storage error");
            return err("internal", "create_room failed");
        }
    };

    // Owner is also an automatic member of the room they just created.
    if let Err(e) = member_repo
        .join(room.id, auth.user_id, &auth.username, now)
        .await
    {
        warn!(target: "rpc", err = %e, "create_room: auto-add owner failed");
        // Best-effort cleanup so we don't leak a room with no members.
        let _ = room_repo.destroy(room.id, now).await;
        return err("internal", "create_room failed");
    }

    let (session_record, binding) = match state
        .sessions
        .create(auth.user_id, auth.username.clone(), room.id)
        .await
    {
        Ok(s) => s,
        Err(SessionError::AlreadyExists) => {
            // Should not happen — we checked in_room above and the
            // SessionStore cache should agree. Defensive: roll back
            // the room create.
            let _ = room_repo.destroy(room.id, now).await;
            let _ = member_repo.leave(room.id, auth.user_id).await;
            return err("already_in_room", "you already have an active session");
        }
        Err(e) => {
            warn!(target: "rpc", err = %e, "create_room: session create failed");
            let _ = room_repo.destroy(room.id, now).await;
            return err("internal", "create_room failed");
        }
    };

    let rx = state.broadcast.subscribe(room.id).await;

    info!(
        target: "rpc",
        user_id = auth.user_id,
        room_id = room.id,
        code = %room.code,
        "room created"
    );

    let code_display = format!("{}-{}", state.config.short_id, room.code);
    let result = serde_json::to_value(CreateRoomResult {
        session_id: session_record.session_id.clone(),
        room_id: room.id,
        code: room.code,
        code_display,
        quic_endpoint: state.datapath.endpoint.clone(),
        quic_fingerprint: state.datapath.fingerprint.clone(),
    })
    .expect("CreateRoomResult serializable");

    HandlerOutput {
        result: Ok(result),
        side_effect: SideEffect::EnterRoom {
            room_id: room.id,
            session_id: session_record.session_id,
            binding,
            rx,
        },
    }
}

// =====================================================================
// join_room
// =====================================================================

pub async fn handle_join_room(
    state: &AppState,
    auth: &WsAuth,
    params: Json,
    in_room: bool,
) -> HandlerOutput {
    if in_room {
        return err(
            "already_in_room",
            "leave the current room before joining another",
        );
    }
    let p: JoinRoomParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => return err("bad_params", format!("join_room params: {e}")),
    };

    // A3: cache check first (fast), DB fallback (authoritative).
    if let Some(s) = state.sessions.find_by_user(auth.user_id).await {
        return err(
            "already_in_room",
            format!("session already active in room {}", s.room_id),
        );
    }

    let member_repo = crate::storage::members::MemberRepo::new(state.storage.pool.clone());

    // DB authority check: even if the cache says no session, a stale
    // member row from a crashed broker run could still be there. We
    // don't have a get_membership_by_user method on MemberRepo (yet),
    // but the SessionStore is the only entry to creating member rows
    // post-2c, so cache is sufficient in practice. Reaching this code
    // path with a stale row would require: broker crashed mid-create
    // before SessionStore.create succeeded, AND we restarted without
    // grace expiring the row. The next member_repo.join below uses
    // ON CONFLICT to update last_seen_at, so we don't actually create
    // duplicates either way. This is acceptable for 3.3.

    let room_repo = crate::storage::rooms::RoomRepo::new(state.storage.pool.clone());

    let room = match room_repo.get_alive_by_code(&p.code).await {
        Ok(Some(r)) => r,
        Ok(None) => return err("not_found", "room not found or no longer active"),
        Err(e) => {
            warn!(target: "rpc", err = %e, code = %p.code, "join_room lookup failed");
            return err("internal", "join_room failed");
        }
    };

    // DB authority: if the user owns a DIFFERENT non-destroyed room, reject
    // (they must close it first). Joining their OWN room is allowed — this
    // is the rejoin path after their previous session was watchdog-cleaned
    // but the room itself is still in empty_grace. The clear_empty_grace
    // call below will restore it to active.
    if let Ok(owned) = room_repo.list_alive_owned_by(auth.user_id).await {
        if let Some(other) = owned.iter().find(|r| r.id != room.id) {
            return err(
                "already_in_room",
                format!(
                    "you own a different room ({}); close it before joining another",
                    other.code
                ),
            );
        }
    }

    let now = Utc::now().timestamp();

    // If the room was in empty_grace, restore it to active.
    if matches!(room.state, RoomState::EmptyGrace) {
        if let Err(e) = room_repo.clear_empty_grace(room.id, now).await {
            warn!(target: "rpc", err = %e, "clear_empty_grace failed");
            return err("internal", "join_room failed");
        }
    }

    if let Err(e) = member_repo
        .join(room.id, auth.user_id, &auth.username, now)
        .await
    {
        warn!(target: "rpc", err = %e, "members.join failed");
        return err("internal", "join_room failed");
    }
    let _ = room_repo.touch_activity(room.id, now).await;

    let (session_record, binding) = match state
        .sessions
        .create(auth.user_id, auth.username.clone(), room.id)
        .await
    {
        Ok(s) => s,
        Err(SessionError::AlreadyExists) => {
            // Rare race: session created between find_by_user above
            // and this point. Roll back the member row.
            let _ = member_repo.leave(room.id, auth.user_id).await;
            return err("already_in_room", "you already have an active session");
        }
        Err(e) => {
            warn!(target: "rpc", err = %e, "session create failed");
            let _ = member_repo.leave(room.id, auth.user_id).await;
            return err("internal", "join_room failed");
        }
    };

    let rx = state.broadcast.subscribe(room.id).await;

    // Snapshot member list AFTER our own join so client sees itself
    // in the list immediately.
    let members = match member_repo.list(room.id).await {
        Ok(rows) => rows
            .into_iter()
            .map(|m| MemberInfo {
                user_id: m.user_id,
                username: m.username,
                joined_at: m.joined_at,
                public_endpoint: m.public_endpoint,
            })
            .collect::<Vec<_>>(),
        Err(e) => {
            warn!(target: "rpc", err = %e, "members.list failed after join");
            Vec::new()
        }
    };

    // Broadcast member_joined to OTHER subscribers (the joiner just
    // got the full member list in the response, so the event would
    // be redundant for them — but tokio::broadcast delivers to ALL
    // active receivers including our own. The connection loop will
    // suppress events whose user_id == self.user_id at the wire
    // boundary; see ws/mod.rs).
    let evt = RoomEvent::MemberJoined(MemberJoinedEvent {
        room_id: room.id,
        user_id: auth.user_id,
        username: auth.username.clone(),
        joined_at: now,
        public_endpoint: None,
    });
    let _ = state.broadcast.send(room.id, evt).await;

    info!(
        target: "rpc",
        user_id = auth.user_id,
        room_id = room.id,
        code = %room.code,
        "user joined room"
    );

    let code_display = format!("{}-{}", state.config.short_id, room.code);
    let result = serde_json::to_value(JoinRoomResult {
        session_id: session_record.session_id.clone(),
        room_id: room.id,
        owner_user_id: room.owner_user_id,
        owner_username: room.owner_username,
        code: room.code,
        code_display,
        members,
        quic_endpoint: state.datapath.endpoint.clone(),
        quic_fingerprint: state.datapath.fingerprint.clone(),
    })
    .expect("JoinRoomResult serializable");

    HandlerOutput {
        result: Ok(result),
        side_effect: SideEffect::EnterRoom {
            room_id: room.id,
            session_id: session_record.session_id,
            binding,
            rx,
        },
    }
}

// =====================================================================
// leave_room
// =====================================================================

pub async fn handle_leave_room(
    state: &AppState,
    auth: &WsAuth,
    in_room: Option<(i64, String)>,
) -> HandlerOutput {
    let Some((room_id, session_id)) = in_room else {
        return err("not_in_room", "you are not in any room");
    };

    let now = Utc::now().timestamp();
    let member_repo = crate::storage::members::MemberRepo::new(state.storage.pool.clone());
    let room_repo = crate::storage::rooms::RoomRepo::new(state.storage.pool.clone());

    let _removed = member_repo
        .leave(room_id, auth.user_id)
        .await
        .unwrap_or(false);
    state.sessions.remove(&session_id).await;

    let _ = state
        .broadcast
        .send(
            room_id,
            RoomEvent::MemberLeft(MemberLeftEvent {
                room_id,
                user_id: auth.user_id,
                username: auth.username.clone(),
            }),
        )
        .await;

    let _ = room_repo.touch_activity(room_id, now).await;

    // If the room is now empty, transition to empty_grace. The owner
    // is just another member here — owner walking away from their
    // own room without destroying it leaves the room running for
    // others, and only triggers grace when the LAST member leaves.
    match member_repo.count_in_room(room_id).await {
        Ok(0) => {
            let grace_secs = 5 * 60;
            if let Err(e) = room_repo.set_empty_grace(room_id, now, grace_secs).await {
                warn!(target: "rpc", err = %e, "set_empty_grace failed");
            } else {
                debug!(target: "rpc", room_id, "room empty; entered grace");
            }
        }
        Ok(_) => {}
        Err(e) => warn!(target: "rpc", err = %e, "count_in_room failed"),
    }

    info!(
        target: "rpc",
        user_id = auth.user_id,
        room_id,
        "user left room"
    );

    HandlerOutput {
        result: Ok(serde_json::to_value(OkResult { ok: true }).unwrap()),
        side_effect: SideEffect::ExitRoom,
    }
}

// =====================================================================
// destroy_room (owner only)
// =====================================================================

pub async fn handle_destroy_room(
    state: &AppState,
    auth: &WsAuth,
    params: Json,
    in_room: Option<(i64, String)>,
) -> HandlerOutput {
    let p: DestroyRoomParams = serde_json::from_value(params).unwrap_or_default();

    // Resolve room_id + session_id from either the in-room state
    // (when the caller is still bound to a session) or from
    // params.room_id (owner closing an empty_grace room from the
    // search-rooms UI). The caller MUST have owner rights — admin
    // override goes through handle_admin_destroy_room.
    let was_in_room = in_room.is_some();
    let (room_id, session_id_for_cleanup) = match (in_room, p.room_id) {
        (Some((rid, sid)), _) => (rid, Some(sid)),
        (None, Some(rid)) => (rid, None),
        (None, None) => {
            return err(
                "bad_params",
                "destroy_room requires room_id when not currently in a room",
            );
        }
    };

    let room_repo = crate::storage::rooms::RoomRepo::new(state.storage.pool.clone());
    let room = match room_repo.get_by_id(room_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return err("not_found", "room not found"),
        Err(e) => {
            warn!(target: "rpc", err = %e, "destroy_room lookup failed");
            return err("internal", "destroy_room failed");
        }
    };
    if room.owner_user_id != auth.user_id {
        return err(
            "permission_denied",
            "only the room owner can destroy this room",
        );
    }
    if matches!(room.state, crate::storage::rooms::RoomState::Destroyed) {
        return err("not_found", "room already destroyed");
    }

    let now = Utc::now().timestamp();
    if let Err(e) = room_repo.destroy(room_id, now).await {
        warn!(target: "rpc", err = %e, "destroy failed");
        return err("internal", "destroy_room failed");
    }

    // Broadcast BEFORE dropping the channel so existing subscribers
    // see the event before they get RecvError::Closed.
    let _ = state
        .broadcast
        .send(
            room_id,
            RoomEvent::RoomDestroyed(RoomDestroyedEvent {
                room_id,
                reason: "owner_destroy".to_string(),
            }),
        )
        .await;

    state.broadcast.drop_room(room_id).await;
    state.datapath_paths.drop_room(room_id).await;
    if let Some(sid) = session_id_for_cleanup {
        // This WS was bound to the room — cleanup the session it knew.
        state.sessions.remove(&sid).await;
    } else if let Some(other_sess) = state.sessions.find_by_user(auth.user_id).await {
        // Owner closed the room remotely (params.room_id path) while
        // still holding a grace session bound to this room from a
        // prior ws. Clear it so the user can immediately create a
        // new room without waiting 30s for the watchdog.
        if other_sess.room_id == room_id {
            state.sessions.remove(&other_sess.session_id).await;
        }
    }

    info!(
        target: "rpc",
        user_id = auth.user_id,
        room_id,
        "owner destroyed room"
    );

    // ExitRoom only when the WS was actually bound to the room being
    // destroyed. When the owner is closing an empty_grace room from
    // the search-rooms UI (no session), the WS stays in idle state
    // and can issue further RPCs (e.g. create a new room).
    let side_effect = if was_in_room {
        SideEffect::ExitRoom
    } else {
        SideEffect::None
    };

    HandlerOutput {
        result: Ok(serde_json::to_value(OkResult { ok: true }).unwrap()),
        side_effect,
    }
}

// =====================================================================
// list_my_rooms
// =====================================================================

pub async fn handle_list_my_rooms(state: &AppState, auth: &WsAuth) -> HandlerOutput {
    let room_repo = crate::storage::rooms::RoomRepo::new(state.storage.pool.clone());
    let member_repo = crate::storage::members::MemberRepo::new(state.storage.pool.clone());

    let rooms = match room_repo.list_alive_owned_by(auth.user_id).await {
        Ok(r) => r,
        Err(e) => {
            warn!(target: "rpc", err = %e, "list_alive_owned_by failed");
            return err("internal", "list_my_rooms failed");
        }
    };

    let mut entries = Vec::with_capacity(rooms.len());
    for r in rooms {
        let count = member_repo.count_in_room(r.id).await.unwrap_or(0);
        entries.push(MyRoomEntry {
            room_id: r.id,
            code: r.code.clone(),
            code_display: format!("{}-{}", state.config.short_id, r.code),
            created_at: r.created_at,
            state: r.state.as_str().to_string(),
            member_count: count,
        });
    }

    HandlerOutput {
        result: Ok(serde_json::to_value(ListMyRoomsResult { rooms: entries }).unwrap()),
        side_effect: SideEffect::None,
    }
}

// =====================================================================
// resume_session (B2)
// =====================================================================

pub async fn handle_resume_session(
    state: &AppState,
    auth: &WsAuth,
    params: Json,
    in_room: bool,
) -> HandlerOutput {
    if in_room {
        return err("already_in_room", "this connection is already in a room");
    }
    let p: ResumeSessionParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => return err("bad_params", format!("resume_session params: {e}")),
    };

    let (session_record, binding) = match state.sessions.reattach(&p.session_id, auth.user_id).await
    {
        Ok(s) => s,
        Err(SessionError::NotFound) => return err("session_not_found", "no such session"),
        Err(SessionError::OwnerMismatch) => {
            return err(
                "session_owner_mismatch",
                "session belongs to a different user",
            );
        }
        Err(SessionError::Expired) => return err("session_expired", "session grace expired"),
        Err(SessionError::AlreadyBound) => {
            return err(
                "session_already_bound",
                "session is bound to another connection",
            );
        }
        Err(e) => {
            warn!(target: "rpc", err = %e, "reattach failed");
            return err("internal", "resume_session failed");
        }
    };

    let room_repo = crate::storage::rooms::RoomRepo::new(state.storage.pool.clone());
    let member_repo = crate::storage::members::MemberRepo::new(state.storage.pool.clone());
    let room = match room_repo.get_by_id(session_record.room_id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            // Room was hard-deleted while we were in grace.
            state.sessions.remove(&session_record.session_id).await;
            return err("session_not_found", "room no longer exists");
        }
        Err(e) => {
            warn!(target: "rpc", err = %e, "resume room lookup failed");
            return err("internal", "resume_session failed");
        }
    };

    let members = member_repo
        .list(room.id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|m| MemberInfo {
            user_id: m.user_id,
            username: m.username,
            joined_at: m.joined_at,
            public_endpoint: m.public_endpoint,
        })
        .collect();

    let rx = state.broadcast.subscribe(room.id).await;

    info!(
        target: "rpc",
        user_id = auth.user_id,
        room_id = room.id,
        session_id = %session_record.session_id,
        "session resumed"
    );

    let code_display = format!("{}-{}", state.config.short_id, room.code);
    let result = serde_json::to_value(ResumeSessionResult {
        room_id: room.id,
        code: room.code,
        code_display,
        members,
        quic_endpoint: state.datapath.endpoint.clone(),
        quic_fingerprint: state.datapath.fingerprint.clone(),
    })
    .expect("ResumeSessionResult serializable");

    HandlerOutput {
        result: Ok(result),
        side_effect: SideEffect::EnterRoom {
            room_id: room.id,
            session_id: session_record.session_id,
            binding,
            rx,
        },
    }
}

// =====================================================================
// admin_list_all_rooms (admin only)
// =====================================================================

pub async fn handle_admin_list_all_rooms(state: &AppState, auth: &WsAuth) -> HandlerOutput {
    if !auth.is_admin {
        return err("permission_denied", "admin privileges required");
    }
    let room_repo = crate::storage::rooms::RoomRepo::new(state.storage.pool.clone());
    let member_repo = crate::storage::members::MemberRepo::new(state.storage.pool.clone());

    let rooms = match room_repo.list_all_alive().await {
        Ok(r) => r,
        Err(e) => {
            warn!(target: "rpc", err = %e, "admin: list_all_alive failed");
            return err("internal", "admin_list_all_rooms failed");
        }
    };

    let mut entries = Vec::with_capacity(rooms.len());
    for r in rooms {
        let count = member_repo.count_in_room(r.id).await.unwrap_or(0);
        entries.push(AdminRoomEntry {
            room_id: r.id,
            code: r.code.clone(),
            code_display: format!("{}-{}", state.config.short_id, r.code),
            owner_user_id: r.owner_user_id,
            owner_username: r.owner_username,
            state: r.state.as_str().to_string(),
            created_at: r.created_at,
            last_active_at: r.last_active_at,
            grace_until: r.grace_until,
            member_count: count,
        });
    }

    info!(
        target: "rpc",
        admin_user_id = auth.user_id,
        room_count = entries.len(),
        "admin listed all rooms"
    );

    HandlerOutput {
        result: Ok(serde_json::to_value(AdminListAllRoomsResult { rooms: entries }).unwrap()),
        side_effect: SideEffect::None,
    }
}

// =====================================================================
// admin_destroy_room (admin only) — force destroy any room
// =====================================================================

pub async fn handle_admin_destroy_room(
    state: &AppState,
    auth: &WsAuth,
    params: Json,
) -> HandlerOutput {
    if !auth.is_admin {
        return err("permission_denied", "admin privileges required");
    }
    let p: AdminDestroyRoomParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => return err("bad_params", format!("admin_destroy_room params: {e}")),
    };

    let room_repo = crate::storage::rooms::RoomRepo::new(state.storage.pool.clone());
    let room = match room_repo.get_by_id(p.room_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return err("not_found", "room not found"),
        Err(e) => {
            warn!(target: "rpc", err = %e, "admin_destroy_room lookup failed");
            return err("internal", "admin_destroy_room failed");
        }
    };
    if matches!(room.state, crate::storage::rooms::RoomState::Destroyed) {
        return err("not_found", "room already destroyed");
    }

    let now = Utc::now().timestamp();
    if let Err(e) = room_repo.destroy(p.room_id, now).await {
        warn!(target: "rpc", err = %e, "admin destroy failed");
        return err("internal", "admin_destroy_room failed");
    }

    let _ = state
        .broadcast
        .send(
            p.room_id,
            RoomEvent::RoomDestroyed(RoomDestroyedEvent {
                room_id: p.room_id,
                reason: "admin_destroy".to_string(),
            }),
        )
        .await;
    state.broadcast.drop_room(p.room_id).await;
    state.datapath_paths.drop_room(p.room_id).await;

    // The owner of the destroyed room may currently have an active
    // session bound to it — find it via the by_user index and remove
    // so they can immediately create a new room without bumping into
    // the partial-unique constraint.
    if let Some(sess) = state.sessions.find_by_user(room.owner_user_id).await {
        if sess.room_id == p.room_id {
            state.sessions.remove(&sess.session_id).await;
        }
    }

    info!(
        target: "rpc",
        admin_user_id = auth.user_id,
        room_id = p.room_id,
        target_owner = room.owner_user_id,
        target_code = %room.code,
        "admin destroyed room"
    );

    HandlerOutput {
        result: Ok(serde_json::to_value(OkResult { ok: true }).unwrap()),
        side_effect: SideEffect::None,
    }
}

// =====================================================================
// helper
// =====================================================================

fn err(code: &str, msg: impl Into<String>) -> HandlerOutput {
    HandlerOutput {
        result: Err(RpcError {
            code: code.to_string(),
            message: msg.into(),
        }),
        side_effect: SideEffect::None,
    }
}
