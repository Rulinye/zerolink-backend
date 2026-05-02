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
    AdminDestroyRoomParams, AdminListAllRoomsResult, AdminRoomEntry, Candidate, CreateRoomParams,
    CreateRoomResult, DestroyRoomParams, JoinRoomParams, JoinRoomResult, ListMyRoomsResult,
    MemberInfo, MemberJoinedEvent, MemberLeftEvent, MyRoomEntry, OkResult,
    PeerCandidatesUpdatedEvent, ResumeSessionParams, ResumeSessionResult, RoomDestroyedEvent,
    RoomEvent, RoomInfoParams, RoomInfoResult, RpcError, SignalGetCandidatesParams,
    SignalGetCandidatesResult, SignalPublishCandidatesParams,
};
use crate::ws::session::{SessionError, WsBinding};

/// Authenticated context for a connection. Filled in once at WS upgrade
/// time (after JWT verify) and never changes for the lifetime of the WS.
#[derive(Debug, Clone)]
pub struct WsAuth {
    pub user_id: i64,
    pub username: String,
    pub is_admin: bool,
    /// B4.7-supp / B9: per-user broker datapath rate limit (bytes/sec)
    /// from backend verify response. 0 = unlimited. Captured at WS
    /// upgrade time and threaded into SessionStore.create so the
    /// datapath bind frame can copy onto the PathEntry's TokenBucket.
    pub rate_limit_bps: u64,
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
        /// Phase 4.7-K2 rc9: shared last_seen timestamp Arc.
        /// connection_loop holds this Arc and bumps it on every
        /// inbound frame; SessionStore.drain_expired uses it to
        /// detect zombie sessions whose ws task died abruptly.
        last_seen: crate::ws::session::LastSeenRef,
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
    // B4.7-supp / B6: defense-in-depth. Admin may have toggled this
    // broker's nodes.broker_enabled / is_enabled to false; the
    // background poller (broker_status::run_poller) reflects that
    // within ~15s. Reject create here so a stale client cache picking
    // a disabled broker gets a clean error instead of being kicked
    // out by the watchdog post-create.
    if !state.broker_status.is_enabled() {
        return err(
            "broker_disabled",
            "this broker is currently disabled by an administrator",
        );
    }
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
    // Phase 4.6 / D4.8 — clamp room_type to the allowed set; default
    // "l3" preserves pre-4.6 behaviour. Invalid values become "l3"
    // rather than erroring (older clients pre-4.6 may not send the
    // field at all; shape-tolerant default is the wire-additive
    // contract per the migration's commentary).
    let room_type = p
        .room_type
        .as_deref()
        .filter(|s| matches!(*s, "l2" | "l3"))
        .unwrap_or("l3");

    let now = Utc::now().timestamp();

    let room_repo = crate::storage::rooms::RoomRepo::new(state.storage.pool.clone());
    let member_repo = crate::storage::members::MemberRepo::new(state.storage.pool.clone());

    let room = match room_repo
        .create(auth.user_id, &auth.username, strategy, room_type, now)
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
        .create(auth.user_id, auth.username.clone(), room.id, auth.rate_limit_bps)
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
        room_type: room.room_type,
        path_strategy: room.path_strategy,
    })
    .expect("CreateRoomResult serializable");

    let last_seen = session_record.last_seen.clone();
    HandlerOutput {
        result: Ok(result),
        side_effect: SideEffect::EnterRoom {
            room_id: room.id,
            session_id: session_record.session_id,
            binding,
            rx,
            last_seen,
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
    // B4.7-supp / B6: same gate as create_room — disabled broker
    // rejects new joins. Existing rooms continue to run; only NEW
    // session admission is blocked.
    if !state.broker_status.is_enabled() {
        return err(
            "broker_disabled",
            "this broker is currently disabled by an administrator",
        );
    }
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
        .create(auth.user_id, auth.username.clone(), room.id, auth.rate_limit_bps)
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
        room_type: room.room_type,
        path_strategy: room.path_strategy,
    })
    .expect("JoinRoomResult serializable");

    let last_seen = session_record.last_seen.clone();
    HandlerOutput {
        result: Ok(result),
        side_effect: SideEffect::EnterRoom {
            room_id: room.id,
            session_id: session_record.session_id,
            binding,
            rx,
            last_seen,
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
    // Phase 4.7-K8 (rc9): sweep ALL sessions bound to this room.
    // Pre-K8 only cleared the owner's session (via session_id_for_cleanup
    // OR find_by_user fallback), leaving non-owner members with stale
    // SessionStore entries pointing at the now-dead room_id. Those
    // members would then hit `already_in_room` on their NEXT
    // create_room/join_room until a zombie cleanup eventually fired.
    // Explicit per-room sweep is the correct model — destroy_room
    // is the room's terminal event, every session bound to it is
    // unambiguously dead.
    let removed = state.sessions.remove_by_room(room_id).await;
    if !removed.is_empty() {
        let count = removed.len();
        let user_ids: Vec<i64> = removed.iter().map(|r| r.user_id).collect();
        info!(
            target: "rpc",
            room_id,
            session_count = count,
            ?user_ids,
            "destroy_room: cleared all bound sessions"
        );
    }
    // Defensive: if owner was in grace from a prior ws (no
    // session_id_for_cleanup, no removal above either because grace
    // session under different room_id?), keep the legacy fallback.
    if removed.is_empty() && session_id_for_cleanup.is_none() {
        if let Some(other_sess) = state.sessions.find_by_user(auth.user_id).await {
            if other_sess.room_id == room_id {
                state.sessions.remove(&other_sess.session_id).await;
            }
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

    // B4.4-K5 fix (batch 4.5): include rooms the user joined but
    // doesn't own, in addition to owned rooms. is_owner flag lets the
    // client UI label / sort. The other call sites of
    // list_alive_owned_by (room-creation 1-per-user check, etc.) keep
    // owned-only semantics — those want to enforce ownership limits.
    let rooms = match room_repo.list_alive_for_user(auth.user_id).await {
        Ok(r) => r,
        Err(e) => {
            warn!(target: "rpc", err = %e, "list_alive_for_user failed");
            return err("internal", "list_my_rooms failed");
        }
    };

    let mut entries = Vec::with_capacity(rooms.len());
    for r in rooms {
        let count = member_repo.count_in_room(r.id).await.unwrap_or(0);
        let is_owner = r.owner_user_id == auth.user_id;
        entries.push(MyRoomEntry {
            room_id: r.id,
            code: r.code.clone(),
            code_display: format!("{}-{}", state.config.short_id, r.code),
            created_at: r.created_at,
            state: r.state.as_str().to_string(),
            member_count: count,
            is_owner,
            room_type: r.room_type,
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
        room_type: room.room_type,
        path_strategy: room.path_strategy,
    })
    .expect("ResumeSessionResult serializable");

    let last_seen = session_record.last_seen.clone();
    HandlerOutput {
        result: Ok(result),
        side_effect: SideEffect::EnterRoom {
            room_id: room.id,
            session_id: session_record.session_id,
            binding,
            rx,
            last_seen,
        },
    }
}

// =====================================================================
// room_info — non-mutating lookup, any authenticated user
// =====================================================================

/// Returns public metadata for a single room by code. Used by the
/// client's "search before join" UX flow so the user can sanity-
/// check the destination before committing.
///
/// Anyone authenticated may call this — same trust assumption as
/// the rest of the broker (a JWT is a "logged-in user" capability).
/// Phase 4 may layer private-room ACLs on top.
pub async fn handle_room_info(state: &AppState, _auth: &WsAuth, params: Json) -> HandlerOutput {
    let p: RoomInfoParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => return err("bad_params", format!("room_info params: {e}")),
    };

    // Normalize to upper-case to match how codes are stored.
    let code = p.code.trim().to_uppercase();
    if code.len() != 6 {
        return err("bad_params", "code must be 6 chars (bare form)");
    }

    let room_repo = crate::storage::rooms::RoomRepo::new(state.storage.pool.clone());
    let member_repo = crate::storage::members::MemberRepo::new(state.storage.pool.clone());

    // get_alive_by_code returns None for destroyed rooms — clients
    // see "not_found" identically to "no such code", which is the
    // privacy-correct behavior.
    let room = match room_repo.get_alive_by_code(&code).await {
        Ok(Some(r)) => r,
        Ok(None) => return err("not_found", "no room with this code"),
        Err(e) => {
            warn!(target: "rpc", err = %e, "room_info lookup failed");
            return err("internal", "room_info failed");
        }
    };

    let count = member_repo.count_in_room(room.id).await.unwrap_or(0);

    // owner_username is captured at create_room time (snapshot)
    // and stored on the rooms row — see schema 0001 line 47.
    let result = RoomInfoResult {
        room_id: room.id,
        code: room.code.clone(),
        code_display: format!("{}-{}", state.config.short_id, room.code),
        state: room.state.as_str().to_string(),
        member_count: count,
        owner_username: room.owner_username.clone(),
        created_at: room.created_at,
        room_type: room.room_type.clone(),
    };

    HandlerOutput {
        result: Ok(serde_json::to_value(&result).expect("serialize")),
        side_effect: SideEffect::None,
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

    // Phase 4.7-K8 (rc9): sweep ALL sessions bound to this room
    // (mirror of handle_destroy_room — same gap if non-owner members
    // are bound). Same blast radius as the broadcast event,
    // semantically correct: the room is dead, every session bound to
    // it is dead.
    let removed = state.sessions.remove_by_room(p.room_id).await;
    if !removed.is_empty() {
        let count = removed.len();
        let user_ids: Vec<i64> = removed.iter().map(|r| r.user_id).collect();
        info!(
            target: "rpc",
            room_id = p.room_id,
            session_count = count,
            ?user_ids,
            "admin_destroy_room: cleared all bound sessions"
        );
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
// signal_publish_candidates (D4.5, Phase 4.4)
// =====================================================================

/// Persist the caller's candidate set into `members.public_endpoint`
/// (JSON of `Vec<Candidate>`), then broadcast `peer_candidates_updated`
/// to room peers. Fingerprint travels in the live event but is NOT
/// persisted (it's a per-process value; cf. D4.6).
pub async fn handle_signal_publish_candidates(
    state: &AppState,
    auth: &WsAuth,
    params: Json,
    in_room: Option<(i64, String)>,
) -> HandlerOutput {
    let Some((room_id, _session_id)) = in_room else {
        return err(
            "not_in_room",
            "join or create a room before publishing candidates",
        );
    };

    let p: SignalPublishCandidatesParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => {
            return err(
                "bad_params",
                format!("signal_publish_candidates params: {e}"),
            );
        }
    };

    if p.fingerprint_sha256.len() != 64
        || !p.fingerprint_sha256.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return err(
            "bad_params",
            "fingerprint_sha256 must be 64 lowercase hex chars (SHA-256)",
        );
    }

    let json = match serde_json::to_string(&p.candidates) {
        Ok(s) => s,
        Err(e) => {
            warn!(target: "rpc", err = %e, "candidate JSON encode failed");
            return err("internal", "signal_publish_candidates failed");
        }
    };

    let member_repo = crate::storage::members::MemberRepo::new(state.storage.pool.clone());
    let updated = match member_repo
        .update_public_endpoint(room_id, auth.user_id, Some(json.as_str()))
        .await
    {
        Ok(b) => b,
        Err(e) => {
            warn!(target: "rpc", err = %e, "members.update_public_endpoint failed");
            return err("internal", "signal_publish_candidates failed");
        }
    };
    if !updated {
        // Caller's session says they're in_room, but the row is gone.
        // This is the rare race where grace_watchdog finalized between
        // our last successful RPC and now. Surface as not_in_room so
        // the client knows to rejoin.
        return err(
            "not_in_room",
            "member row missing — session may have been finalized",
        );
    }

    let evt = RoomEvent::PeerCandidatesUpdated(PeerCandidatesUpdatedEvent {
        user_id: auth.user_id,
        candidates: p.candidates,
        fingerprint_sha256: p.fingerprint_sha256,
    });
    let _ = state.broadcast.send(room_id, evt).await;

    info!(
        target: "rpc",
        user_id = auth.user_id,
        room_id,
        "candidates published"
    );

    HandlerOutput {
        result: Ok(serde_json::to_value(OkResult { ok: true }).unwrap()),
        side_effect: SideEffect::None,
    }
}

// =====================================================================
// signal_get_candidates (D4.5, Phase 4.4)
// =====================================================================

/// Best-effort race-recovery pull: a peer who just joined can fetch
/// the last-published candidate set of any other peer in the SAME
/// room. Fingerprint is not persisted (always returns None); caller
/// either waits for the next live broadcast or proceeds without it.
pub async fn handle_signal_get_candidates(
    state: &AppState,
    auth: &WsAuth,
    params: Json,
    in_room: Option<(i64, String)>,
) -> HandlerOutput {
    let Some((room_id, _session_id)) = in_room else {
        return err(
            "not_in_room",
            "join or create a room before querying candidates",
        );
    };

    let p: SignalGetCandidatesParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => return err("bad_params", format!("signal_get_candidates params: {e}")),
    };

    let member_repo = crate::storage::members::MemberRepo::new(state.storage.pool.clone());
    let raw = match member_repo.get_public_endpoint(room_id, p.user_id).await {
        Ok(opt) => opt,
        Err(e) => {
            warn!(target: "rpc", err = %e, "members.get_public_endpoint failed");
            return err("internal", "signal_get_candidates failed");
        }
    };

    let candidates: Vec<Candidate> = match raw {
        Some(s) => match serde_json::from_str::<Vec<Candidate>>(&s) {
            Ok(v) => v,
            Err(e) => {
                // Stored value is corrupt; treat as "no candidates"
                // and log so we notice repeat occurrences.
                debug!(
                    target: "rpc",
                    err = %e,
                    target_user = p.user_id,
                    "stored public_endpoint is not Vec<Candidate>; returning empty"
                );
                Vec::new()
            }
        },
        None => Vec::new(),
    };

    let _ = auth; // same-room enforced by `in_room` capture; auth unused here.

    HandlerOutput {
        result: Ok(serde_json::to_value(SignalGetCandidatesResult {
            candidates,
            fingerprint_sha256: None,
        })
        .unwrap()),
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
