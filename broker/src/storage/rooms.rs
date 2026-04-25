//! Room repository.
//!
//! This is the 2b skeleton: types + method signatures + doc comments.
//! Actual sqlx::query! invocations land in 2c when RPC handlers
//! consume them. Compiles cleanly today but every method body is
//! `unimplemented!()`.

use sqlx::SqlitePool;

/// Lifecycle states. Mirrors the CHECK constraint in 0001_initial.sql.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomState {
    Active,
    EmptyGrace,
    Destroyed,
}

impl RoomState {
    pub fn as_str(&self) -> &'static str {
        match self {
            RoomState::Active => "active",
            RoomState::EmptyGrace => "empty_grace",
            RoomState::Destroyed => "destroyed",
        }
    }
}

/// Hydrated room row.
#[derive(Debug, Clone)]
pub struct Room {
    pub id: i64,
    pub code: String,
    pub owner_user_id: i64,
    pub owner_username: String,
    pub created_at: i64,
    pub last_active_at: i64,
    pub path_strategy: String,
    pub supports_p2p: bool,
    pub state: RoomState,
    pub grace_until: Option<i64>,
    pub destroyed_at: Option<i64>,
}

#[derive(Clone)]
pub struct RoomRepo {
    #[allow(dead_code)]
    pool: SqlitePool,
}

impl RoomRepo {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    // -- Methods land in 2c. Sketched here to keep schema-level
    // -- design conversations grounded in callable shape.

    // Create a new active room owned by `owner_user_id`. Generates a
    // 6-char Crockford base32 code, retrying on UNIQUE collision.
    // Returns RoomLimitExceeded if the user already owns a non-
    // destroyed room (partial unique index on rooms).
    //
    // pub async fn create(...) -> Result<Room, RoomError>;

    // Look up an active or empty_grace room by its code. Used by
    // join_room. Returns None for destroyed or unknown codes (we do
    // NOT distinguish — destroyed codes look the same as never-
    // existed to callers).
    //
    // pub async fn get_alive_by_code(&self, code: &str) -> Result<Option<Room>>;

    // Transition active -> empty_grace, setting grace_until = now + 5min.
    // Called when the last member leaves.
    //
    // pub async fn set_empty_grace(&self, room_id: i64, now: i64) -> Result<()>;

    // Transition empty_grace -> active, clearing grace_until. Called
    // when someone joins a room that was in grace.
    //
    // pub async fn clear_empty_grace(&self, room_id: i64, now: i64) -> Result<()>;

    // Transition any state -> destroyed. Used by:
    //   - owner explicit destroy_room RPC
    //   - GC: empty_grace rooms past grace_until
    //
    // pub async fn destroy(&self, room_id: i64, now: i64) -> Result<()>;

    // GC: rooms in 'empty_grace' whose grace_until < now. Returns
    // the room ids transitioned, so the caller can broadcast
    // room_destroyed events to any lingering ws connections.
    //
    // pub async fn gc_expired_grace(&self, now: i64) -> Result<Vec<i64>>;

    // GC: hard delete 'destroyed' rooms older than `older_than` (e.g.
    // now - 1h) so the table doesn't grow unbounded. ON DELETE
    // CASCADE wipes members + traffic at the same time.
    //
    // pub async fn hard_delete_old_destroyed(&self, older_than: i64) -> Result<u64>;
}

#[derive(Debug, thiserror::Error)]
pub enum RoomError {
    #[error("user already owns a room (limit: 1 active room per user)")]
    RoomLimitExceeded,

    #[error("room code collision after retries; try again")]
    CodeGenExhausted,

    #[error("storage error: {0}")]
    Storage(#[from] sqlx::Error),
}
