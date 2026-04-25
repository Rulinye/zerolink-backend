//! WebSocket signaling protocol types.
//!
//! Three message kinds, distinguished by the `type` discriminator:
//!
//!   - `req`   client → broker; carries an `id` for response correlation
//!   - `res`   broker → client; matches a prior `req.id`
//!   - `event` broker → client; unsolicited push (member_joined, etc.)
//!
//! `req` methods (5 in 3.3 + resume_session for B2 grace mechanism):
//!
//!   create_room      {path_strategy?}                    → {session_id, room_id, code, code_display}
//!   join_room        {code}                              → {session_id, room_id, owner_user_id, members: []}
//!   leave_room       {}                                  → {ok: true}
//!   destroy_room     {}                                  → {ok: true}        (owner only)
//!   list_my_rooms    {}                                  → {rooms: []}
//!   resume_session   {session_id}                        → {room_id, members: []}
//!
//! `event` names:
//!
//!   member_joined    {room_id, user_id, username, joined_at, public_endpoint:null}
//!   member_left      {room_id, user_id, username}
//!   room_destroyed   {room_id, reason: "owner_destroy"|"grace_expired"}
//!   p2p_candidate    Phase 4.1 placeholder; never emitted in 3.3.

use serde::{Deserialize, Serialize};

// ----- top-level wire envelope -----

/// Inbound wire frames from the client. The `type` discriminator splits
/// requests from any future client → broker message kind.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    Req(RpcRequest),
}

/// Outbound wire frames from the broker.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    Res(RpcResponse),
    Event(EventEnvelope),
}

// ----- RPC request envelope -----

#[derive(Debug, Deserialize)]
pub struct RpcRequest {
    pub id: String,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

// ----- RPC response envelope -----

#[derive(Debug, Serialize)]
pub struct RpcResponse {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

impl RpcResponse {
    pub fn ok(id: String, result: serde_json::Value) -> Self {
        Self {
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: String, code: &str, message: impl Into<String>) -> Self {
        Self {
            id,
            result: None,
            error: Some(RpcError {
                code: code.to_string(),
                message: message.into(),
            }),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct RpcError {
    /// Stable machine-readable code: `room_limit`, `not_found`,
    /// `permission_denied`, `already_in_room`, `session_not_found`,
    /// `session_owner_mismatch`, `bad_params`, `internal`, …
    pub code: String,
    /// Human-readable explanation. UI may show this to end users; do
    /// not include sensitive details.
    pub message: String,
}

// ----- per-method params (deserialized from `req.params`) -----

#[derive(Debug, Default, Deserialize)]
pub struct CreateRoomParams {
    /// One of "auto" | "p2p_only" | "broker_only". Defaults to "auto".
    /// Phase 3.3 always relays regardless of strategy.
    #[serde(default)]
    pub path_strategy: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct JoinRoomParams {
    /// 6-char Crockford base32 code. Bare form (no broker prefix).
    pub code: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct DestroyRoomParams {
    /// Optional room_id. When the caller is currently in a room
    /// (via this WS), broker uses the in-room id and ignores this
    /// field. When the caller is NOT in a room (e.g. owner closing
    /// their own empty_grace room from the search-rooms UI), this
    /// field is REQUIRED and must reference a room owned by the
    /// caller. Admins can target any room id (see is_admin check
    /// in handle_destroy_room).
    #[serde(default)]
    pub room_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct ResumeSessionParams {
    pub session_id: String,
}

/// Params for admin_destroy_room. room_id is required.
#[derive(Debug, Deserialize)]
pub struct AdminDestroyRoomParams {
    pub room_id: i64,
}

// ----- per-method result shapes -----

#[derive(Debug, Serialize)]
pub struct CreateRoomResult {
    pub session_id: String,
    pub room_id: i64,
    /// Bare code as stored in DB.
    pub code: String,
    /// Display form: `"<short_id>-<code>"` e.g. "KR-XK7P9R".
    pub code_display: String,
}

#[derive(Debug, Serialize)]
pub struct JoinRoomResult {
    pub session_id: String,
    pub room_id: i64,
    pub owner_user_id: i64,
    pub owner_username: String,
    pub code: String,
    pub code_display: String,
    pub members: Vec<MemberInfo>,
}

#[derive(Debug, Serialize, Clone)]
pub struct MemberInfo {
    pub user_id: i64,
    pub username: String,
    pub joined_at: i64,
    /// Phase 4.1 placeholder; always null in 3.3.
    pub public_endpoint: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ListMyRoomsResult {
    pub rooms: Vec<MyRoomEntry>,
}

#[derive(Debug, Serialize)]
pub struct MyRoomEntry {
    pub room_id: i64,
    pub code: String,
    pub code_display: String,
    pub created_at: i64,
    pub state: String,
    pub member_count: i64,
}

/// Per-room entry in the admin view. Includes owner identity and
/// state machine fields (last_active_at, grace_until) that the
/// owner-facing list_my_rooms response omits.
#[derive(Debug, Serialize)]
pub struct AdminRoomEntry {
    pub room_id: i64,
    pub code: String,
    pub code_display: String,
    pub owner_user_id: i64,
    pub owner_username: String,
    pub state: String,
    pub created_at: i64,
    pub last_active_at: i64,
    pub grace_until: Option<i64>,
    pub member_count: i64,
}

#[derive(Debug, Serialize)]
pub struct AdminListAllRoomsResult {
    pub rooms: Vec<AdminRoomEntry>,
}

#[derive(Debug, Serialize)]
pub struct ResumeSessionResult {
    pub room_id: i64,
    pub code: String,
    pub code_display: String,
    pub members: Vec<MemberInfo>,
}

#[derive(Debug, Serialize)]
pub struct OkResult {
    pub ok: bool,
}

// ----- event envelope -----

#[derive(Debug, Serialize, Clone)]
pub struct EventEnvelope {
    pub name: String,
    pub data: serde_json::Value,
}

#[derive(Debug, Serialize, Clone)]
pub struct MemberJoinedEvent {
    pub room_id: i64,
    pub user_id: i64,
    pub username: String,
    pub joined_at: i64,
    pub public_endpoint: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct MemberLeftEvent {
    pub room_id: i64,
    pub user_id: i64,
    pub username: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct RoomDestroyedEvent {
    pub room_id: i64,
    /// `"owner_destroy"` | `"grace_expired"`.
    pub reason: String,
}

// ----- internal RoomEvent that the broadcast hub shuttles -----
//
// This is the type passed through tokio::broadcast channels. It's
// NOT serialized as-is; the ws connection task converts it into an
// EventEnvelope before sending.

#[derive(Debug, Clone)]
pub enum RoomEvent {
    MemberJoined(MemberJoinedEvent),
    MemberLeft(MemberLeftEvent),
    RoomDestroyed(RoomDestroyedEvent),
}

impl RoomEvent {
    pub fn into_envelope(self) -> EventEnvelope {
        match self {
            RoomEvent::MemberJoined(e) => EventEnvelope {
                name: "member_joined".to_string(),
                data: serde_json::to_value(e).expect("MemberJoinedEvent serializable"),
            },
            RoomEvent::MemberLeft(e) => EventEnvelope {
                name: "member_left".to_string(),
                data: serde_json::to_value(e).expect("MemberLeftEvent serializable"),
            },
            RoomEvent::RoomDestroyed(e) => EventEnvelope {
                name: "room_destroyed".to_string(),
                data: serde_json::to_value(e).expect("RoomDestroyedEvent serializable"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_response_ok_skips_error() {
        let r = RpcResponse::ok("abc".into(), serde_json::json!({"foo": 1}));
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"result\""));
        assert!(!s.contains("\"error\""));
    }

    #[test]
    fn rpc_response_err_skips_result() {
        let r = RpcResponse::err("abc".into(), "bad_params", "missing code");
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"error\""));
        assert!(!s.contains("\"result\""));
    }

    #[test]
    fn client_message_req_roundtrip() {
        let raw = r#"{"type":"req","id":"q1","method":"join_room","params":{"code":"XK7P9R"}}"#;
        let m: ClientMessage = serde_json::from_str(raw).unwrap();
        match m {
            ClientMessage::Req(r) => {
                assert_eq!(r.id, "q1");
                assert_eq!(r.method, "join_room");
                let jp: JoinRoomParams = serde_json::from_value(r.params).unwrap();
                assert_eq!(jp.code, "XK7P9R");
            }
        }
    }

    #[test]
    fn server_message_event_serializes() {
        let evt = RoomEvent::MemberLeft(MemberLeftEvent {
            room_id: 1,
            user_id: 42,
            username: "alice".into(),
        });
        let env = evt.into_envelope();
        let msg = ServerMessage::Event(env);
        let s = serde_json::to_string(&msg).unwrap();
        assert!(s.contains("\"type\":\"event\""));
        assert!(s.contains("\"name\":\"member_left\""));
        assert!(s.contains("\"username\":\"alice\""));
    }
}
