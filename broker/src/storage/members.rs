//! Member repository — 2b skeleton.
//!
//! Same pattern as rooms.rs: types and signatures land now; sqlx
//! invocations move in during 2c when join_room / leave_room /
//! list_members RPCs need them.

use sqlx::SqlitePool;

#[derive(Debug, Clone)]
pub struct Member {
    pub id: i64,
    pub room_id: i64,
    pub user_id: i64,
    pub username: String,
    pub joined_at: i64,
    pub last_seen_at: i64,
    pub public_endpoint: Option<String>,
}

#[derive(Clone)]
pub struct MemberRepo {
    #[allow(dead_code)]
    pool: SqlitePool,
}

impl MemberRepo {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    // Methods (2c):
    //
    // pub async fn join(...) -> Result<Member, MemberError>;
    //   Inserts (room_id, user_id, username, joined_at, last_seen_at).
    //   On UNIQUE conflict (rejoin) returns existing row with
    //   last_seen_at refreshed.
    //
    // pub async fn leave(&self, room_id, user_id) -> Result<bool>;
    //   Removes the member. Returns true if a row was removed.
    //
    // pub async fn list(&self, room_id) -> Result<Vec<Member>>;
    //
    // pub async fn touch_heartbeat(&self, room_id, user_id, now) -> Result<()>;
    //   Bumps last_seen_at. Called on every ws frame from this member.
    //
    // pub async fn count_in_room(&self, room_id) -> Result<i64>;
    //   Used by leave handler to detect "last member left -> trigger
    //   empty_grace".
}

#[derive(Debug, thiserror::Error)]
pub enum MemberError {
    #[error("room not found or not joinable")]
    RoomNotFound,

    #[error("storage error: {0}")]
    Storage(#[from] sqlx::Error),
}
