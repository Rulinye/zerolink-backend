//! Room repository — real sqlx implementations.
//!
//! All sqlx::query! invocations live here. The `cargo sqlx prepare`
//! step generates a JSON file under `broker/.sqlx/` for each call
//! site, capturing the schema-derived column types so CI builds work
//! with `SQLX_OFFLINE=true` (no live DB needed).
//!
//! Method semantics follow the state machine documented in
//! `0001_initial.sql`:
//!
//!   active ─── (last member leaves) ──→ empty_grace
//!   active ─── (owner destroy_room) ──→ destroyed
//!   empty_grace ── (someone joins) ──→ active
//!   empty_grace ── (grace expires) ──→ destroyed
//!   destroyed ── (>1h old) ──→ hard-delete (FK cascade)

use rand::Rng;
use sqlx::SqlitePool;

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

    pub fn from_db(s: &str) -> Option<Self> {
        match s {
            "active" => Some(RoomState::Active),
            "empty_grace" => Some(RoomState::EmptyGrace),
            "destroyed" => Some(RoomState::Destroyed),
            _ => None,
        }
    }
}

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
    pool: SqlitePool,
}

#[derive(Debug, thiserror::Error)]
pub enum RoomError {
    #[error("user already owns a room (limit: 1 active room per user)")]
    RoomLimitExceeded,

    #[error("room code collision after retries; try again")]
    CodeGenExhausted,

    #[error("room not found")]
    NotFound,

    #[error("storage error: {0}")]
    Storage(#[from] sqlx::Error),
}

impl RoomRepo {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Create a new active room. Generates a 6-char Crockford base32
    /// code, retrying up to 8 times on UNIQUE collision (the second
    /// retry already has odds < 10^-7 against ~100 active rooms, so 8
    /// is paranoid).
    ///
    /// Errors:
    ///   - RoomLimitExceeded if the user already owns a non-destroyed
    ///     room (caught from sqlite's UNIQUE constraint via
    ///     `idx_rooms_owner_alive` partial index).
    ///   - CodeGenExhausted if 8 consecutive code generations all
    ///     collided (effectively impossible in practice).
    pub async fn create(
        &self,
        owner_user_id: i64,
        owner_username: &str,
        path_strategy: &str,
        now: i64,
    ) -> Result<Room, RoomError> {
        for _ in 0..8 {
            let code = generate_room_code();
            let supports_p2p_int: i64 = 0; // 3.3 stub

            let res = sqlx::query!(
                r#"
                INSERT INTO rooms (
                    code, owner_user_id, owner_username,
                    created_at, last_active_at,
                    path_strategy, supports_p2p, state
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, 'active')
                RETURNING id AS "id!"
                "#,
                code,
                owner_user_id,
                owner_username,
                now,
                now,
                path_strategy,
                supports_p2p_int,
            )
            .fetch_one(&self.pool)
            .await;

            match res {
                Ok(row) => {
                    return Ok(Room {
                        id: row.id,
                        code,
                        owner_user_id,
                        owner_username: owner_username.to_string(),
                        created_at: now,
                        last_active_at: now,
                        path_strategy: path_strategy.to_string(),
                        supports_p2p: false,
                        state: RoomState::Active,
                        grace_until: None,
                        destroyed_at: None,
                    });
                }
                Err(sqlx::Error::Database(db_err)) => {
                    let msg = db_err.message();
                    if msg.contains("idx_rooms_owner_alive") {
                        return Err(RoomError::RoomLimitExceeded);
                    }
                    if msg.contains("rooms.code") {
                        // Code collision: retry with a fresh code.
                        continue;
                    }
                    return Err(RoomError::Storage(sqlx::Error::Database(db_err)));
                }
                Err(e) => return Err(RoomError::Storage(e)),
            }
        }
        Err(RoomError::CodeGenExhausted)
    }

    /// Look up a room by its code if it's currently joinable
    /// (active or empty_grace). Destroyed rooms return None — we do
    /// not distinguish "destroyed" from "never existed" for join
    /// callers, so a leaked invite to a destroyed room cannot reveal
    /// that the room ever existed.
    pub async fn get_alive_by_code(&self, code: &str) -> Result<Option<Room>, sqlx::Error> {
        let row = sqlx::query!(
            r#"
            SELECT id AS "id!", code, owner_user_id, owner_username,
                   created_at, last_active_at,
                   path_strategy, supports_p2p,
                   state, grace_until, destroyed_at
              FROM rooms
             WHERE code = ?
               AND state != 'destroyed'
            "#,
            code
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| Room {
            id: r.id,
            code: r.code,
            owner_user_id: r.owner_user_id,
            owner_username: r.owner_username,
            created_at: r.created_at,
            last_active_at: r.last_active_at,
            path_strategy: r.path_strategy,
            supports_p2p: r.supports_p2p != 0,
            state: RoomState::from_db(&r.state).unwrap_or(RoomState::Active),
            grace_until: r.grace_until,
            destroyed_at: r.destroyed_at,
        }))
    }

    /// Get a room by id including destroyed rooms. Used by GC and
    /// admin paths that need to inspect terminal state.
    pub async fn get_by_id(&self, id: i64) -> Result<Option<Room>, sqlx::Error> {
        let row = sqlx::query!(
            r#"
            SELECT id AS "id!", code, owner_user_id, owner_username,
                   created_at, last_active_at,
                   path_strategy, supports_p2p,
                   state, grace_until, destroyed_at
              FROM rooms
             WHERE id = ?
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| Room {
            id: r.id,
            code: r.code,
            owner_user_id: r.owner_user_id,
            owner_username: r.owner_username,
            created_at: r.created_at,
            last_active_at: r.last_active_at,
            path_strategy: r.path_strategy,
            supports_p2p: r.supports_p2p != 0,
            state: RoomState::from_db(&r.state).unwrap_or(RoomState::Active),
            grace_until: r.grace_until,
            destroyed_at: r.destroyed_at,
        }))
    }

    /// List rooms owned by `user_id` that are still alive (any state
    /// except destroyed). Used by the `list_my_rooms` RPC so the
    /// "search rooms" UI can pin the user's own room at the top with
    /// a "close room" button.
    pub async fn list_alive_owned_by(&self, user_id: i64) -> Result<Vec<Room>, sqlx::Error> {
        let rows = sqlx::query!(
            r#"
            SELECT id AS "id!", code, owner_user_id, owner_username,
                   created_at, last_active_at,
                   path_strategy, supports_p2p,
                   state, grace_until, destroyed_at
              FROM rooms
             WHERE owner_user_id = ?
               AND state != 'destroyed'
             ORDER BY created_at DESC
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| Room {
                id: r.id,
                code: r.code,
                owner_user_id: r.owner_user_id,
                owner_username: r.owner_username,
                created_at: r.created_at,
                last_active_at: r.last_active_at,
                path_strategy: r.path_strategy,
                supports_p2p: r.supports_p2p != 0,
                state: RoomState::from_db(&r.state).unwrap_or(RoomState::Active),
                grace_until: r.grace_until,
                destroyed_at: r.destroyed_at,
            })
            .collect())
    }

    /// List rooms `user_id` is associated with — either as owner OR as
    /// a member — that are still alive (any state except destroyed).
    /// Used by the `list_my_rooms` RPC so non-owners can see rooms
    /// they've joined in the dashboard "我的房间" panel (B4.4-K5
    /// closeout in batch 4.5).
    ///
    /// Caller computes `is_owner` per row via `r.owner_user_id ==
    /// user_id` (the SQL is intentionally just the union — no
    /// per-row computed column needed).
    ///
    /// EXISTS predicate (rather than LEFT JOIN) keeps the result
    /// strictly one-row-per-room without dedup concerns; `members`
    /// has UNIQUE(room_id, user_id) per `0001_initial.sql:123` so
    /// LEFT JOIN would also yield one row, but EXISTS reads more
    /// clearly.
    pub async fn list_alive_for_user(&self, user_id: i64) -> Result<Vec<Room>, sqlx::Error> {
        let rows = sqlx::query!(
            r#"
            SELECT id AS "id!", code, owner_user_id, owner_username,
                   created_at, last_active_at,
                   path_strategy, supports_p2p,
                   state, grace_until, destroyed_at
              FROM rooms
             WHERE state != 'destroyed'
               AND (
                 owner_user_id = ?
                 OR EXISTS (
                   SELECT 1 FROM members
                    WHERE members.room_id = rooms.id
                      AND members.user_id = ?
                 )
               )
             ORDER BY created_at DESC
            "#,
            user_id,
            user_id
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| Room {
                id: r.id,
                code: r.code,
                owner_user_id: r.owner_user_id,
                owner_username: r.owner_username,
                created_at: r.created_at,
                last_active_at: r.last_active_at,
                path_strategy: r.path_strategy,
                supports_p2p: r.supports_p2p != 0,
                state: RoomState::from_db(&r.state).unwrap_or(RoomState::Active),
                grace_until: r.grace_until,
                destroyed_at: r.destroyed_at,
            })
            .collect())
    }

    /// List ALL alive rooms (active or empty_grace) across the broker.
    /// For the admin view: `admin_list_all_rooms` RPC. Ordered by
    /// last_active_at DESC so freshly-active rooms surface first.
    pub async fn list_all_alive(&self) -> Result<Vec<Room>, sqlx::Error> {
        let rows = sqlx::query!(
            r#"
            SELECT id AS "id!", code, owner_user_id, owner_username,
                   created_at, last_active_at,
                   path_strategy, supports_p2p,
                   state, grace_until, destroyed_at
              FROM rooms
             WHERE state != 'destroyed'
             ORDER BY last_active_at DESC
            "#
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| Room {
                id: r.id,
                code: r.code,
                owner_user_id: r.owner_user_id,
                owner_username: r.owner_username,
                created_at: r.created_at,
                last_active_at: r.last_active_at,
                path_strategy: r.path_strategy,
                supports_p2p: r.supports_p2p != 0,
                state: RoomState::from_db(&r.state).unwrap_or(RoomState::Active),
                grace_until: r.grace_until,
                destroyed_at: r.destroyed_at,
            })
            .collect())
    }

    /// Bump `last_active_at` to `now`. Called on every join/leave/
    /// heartbeat by the WS layer.
    pub async fn touch_activity(&self, room_id: i64, now: i64) -> Result<(), sqlx::Error> {
        sqlx::query!(
            "UPDATE rooms SET last_active_at = ? WHERE id = ?",
            now,
            room_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Transition active -> empty_grace, setting grace_until = now +
    /// grace_secs. Called when the last member leaves a room. No-op
    /// if the room is already destroyed or already in grace.
    pub async fn set_empty_grace(
        &self,
        room_id: i64,
        now: i64,
        grace_secs: i64,
    ) -> Result<(), sqlx::Error> {
        let grace_until = now + grace_secs;
        sqlx::query!(
            r#"
            UPDATE rooms
               SET state = 'empty_grace',
                   grace_until = ?,
                   last_active_at = ?
             WHERE id = ?
               AND state = 'active'
            "#,
            grace_until,
            now,
            room_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Transition empty_grace -> active, clearing grace_until. Called
    /// when someone joins a room that was in grace.
    pub async fn clear_empty_grace(&self, room_id: i64, now: i64) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            UPDATE rooms
               SET state = 'active',
                   grace_until = NULL,
                   last_active_at = ?
             WHERE id = ?
               AND state = 'empty_grace'
            "#,
            now,
            room_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Transition any non-destroyed state -> destroyed. Used by both
    /// the owner explicit destroy_room RPC and the GC sweep when a
    /// grace timer expires.
    pub async fn destroy(&self, room_id: i64, now: i64) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            UPDATE rooms
               SET state = 'destroyed',
                   destroyed_at = ?,
                   grace_until = NULL
             WHERE id = ?
               AND state != 'destroyed'
            "#,
            now,
            room_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// GC: find rooms whose grace_until has expired. Returns the room
    /// ids; the caller is expected to broadcast `room_destroyed`
    /// events to any WS connections still observing them, then call
    /// `destroy(...)` on each id.
    ///
    /// We split selection from mutation so the broadcast layer (which
    /// holds the per-room channel handles) can fire its events
    /// between the two.
    pub async fn gc_expired_grace_ids(&self, now: i64) -> Result<Vec<i64>, sqlx::Error> {
        let rows = sqlx::query!(
            r#"
            SELECT id AS "id!"
              FROM rooms
             WHERE state = 'empty_grace'
               AND grace_until IS NOT NULL
               AND grace_until < ?
            "#,
            now
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|r| r.id).collect())
    }

    /// GC: hard-delete destroyed rooms older than `cutoff`. ON DELETE
    /// CASCADE drops the corresponding members and traffic rows in
    /// the same transaction (single sqlite statement).
    pub async fn hard_delete_old_destroyed(&self, cutoff: i64) -> Result<u64, sqlx::Error> {
        let res = sqlx::query!(
            r#"
            DELETE FROM rooms
             WHERE state = 'destroyed'
               AND destroyed_at IS NOT NULL
               AND destroyed_at < ?
            "#,
            cutoff
        )
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }
}

/// Generate a 6-character Crockford base32 code (no I, L, O, U).
/// 32^6 ≈ 10^9 codes; collision rate on a 100-room broker is < 10^-7
/// per generation, but `RoomRepo::create` retries on collision anyway.
fn generate_room_code() -> String {
    // Crockford alphabet, RFC-style: 0-9 + A-Z minus I, L, O, U.
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    debug_assert_eq!(ALPHABET.len(), 32);

    let mut rng = rand::thread_rng();
    let mut s = String::with_capacity(6);
    for _ in 0..6 {
        let idx = rng.gen_range(0..ALPHABET.len());
        s.push(ALPHABET[idx] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn room_code_format() {
        let code = generate_room_code();
        assert_eq!(code.len(), 6);
        // Every char must be in the Crockford alphabet (no I/L/O/U).
        for c in code.chars() {
            assert!(c.is_ascii_uppercase() || c.is_ascii_digit());
            assert!(!matches!(c, 'I' | 'L' | 'O' | 'U'));
        }
    }

    #[test]
    fn room_state_roundtrip() {
        for s in [
            RoomState::Active,
            RoomState::EmptyGrace,
            RoomState::Destroyed,
        ] {
            assert_eq!(RoomState::from_db(s.as_str()), Some(s));
        }
        assert_eq!(RoomState::from_db("unknown"), None);
    }
}
