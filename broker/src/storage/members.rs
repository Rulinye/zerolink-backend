//! Member repository — real sqlx implementations.

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
    pool: SqlitePool,
}

#[derive(Debug, thiserror::Error)]
pub enum MemberError {
    #[error("storage error: {0}")]
    Storage(#[from] sqlx::Error),
}

impl MemberRepo {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Insert a (room_id, user_id) member, or refresh last_seen_at if
    /// the user is already a member of this room (rejoin path).
    /// Returns the resulting Member row.
    pub async fn join(
        &self,
        room_id: i64,
        user_id: i64,
        username: &str,
        now: i64,
    ) -> Result<Member, MemberError> {
        let row = sqlx::query!(
            r#"
            INSERT INTO members (room_id, user_id, username, joined_at, last_seen_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(room_id, user_id) DO UPDATE SET
                last_seen_at = excluded.last_seen_at,
                username     = excluded.username
            RETURNING id AS "id!", room_id, user_id, username,
                      joined_at, last_seen_at, public_endpoint
            "#,
            room_id,
            user_id,
            username,
            now,
            now
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(Member {
            id: row.id,
            room_id: row.room_id,
            user_id: row.user_id,
            username: row.username,
            joined_at: row.joined_at,
            last_seen_at: row.last_seen_at,
            public_endpoint: row.public_endpoint,
        })
    }

    /// Remove a member from a room. Returns true if a row was
    /// removed, false if the user wasn't a member to begin with.
    pub async fn leave(&self, room_id: i64, user_id: i64) -> Result<bool, sqlx::Error> {
        let res = sqlx::query!(
            "DELETE FROM members WHERE room_id = ? AND user_id = ?",
            room_id,
            user_id
        )
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// List all current members of a room, ordered by joined_at
    /// (so the owner / earliest joiner shows up first).
    pub async fn list(&self, room_id: i64) -> Result<Vec<Member>, sqlx::Error> {
        let rows = sqlx::query!(
            r#"
            SELECT id AS "id!", room_id, user_id, username,
                   joined_at, last_seen_at, public_endpoint
              FROM members
             WHERE room_id = ?
             ORDER BY joined_at
            "#,
            room_id
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| Member {
                id: r.id,
                room_id: r.room_id,
                user_id: r.user_id,
                username: r.username,
                joined_at: r.joined_at,
                last_seen_at: r.last_seen_at,
                public_endpoint: r.public_endpoint,
            })
            .collect())
    }

    /// Bump last_seen_at on a member's heartbeat.
    pub async fn touch_heartbeat(
        &self,
        room_id: i64,
        user_id: i64,
        now: i64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            "UPDATE members SET last_seen_at = ? WHERE room_id = ? AND user_id = ?",
            now,
            room_id,
            user_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Count current members of a room. Used by the leave handler to
    /// detect "the leaver was the last member -> trigger empty_grace
    /// transition on the room".
    pub async fn count_in_room(&self, room_id: i64) -> Result<i64, sqlx::Error> {
        let row = sqlx::query!(
            "SELECT COUNT(*) AS n FROM members WHERE room_id = ?",
            room_id
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(row.n)
    }
}
