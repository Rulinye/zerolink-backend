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

    /// D4.5 (P2P signaling): write a member's NAT-reflected /
    /// host-enumerated candidate set as a JSON blob into
    /// `members.public_endpoint`. The column is TEXT in the schema
    /// (broker/migrations/0001_initial.sql:119, "Phase 4.1 stub")
    /// and we serialize `Vec<Candidate>` to JSON at the call site.
    /// Returns true if a row was updated, false if the (room_id,
    /// user_id) pair has no member row (caller decides whether
    /// that's an error or a benign race).
    pub async fn update_public_endpoint(
        &self,
        room_id: i64,
        user_id: i64,
        value: Option<&str>,
    ) -> Result<bool, sqlx::Error> {
        let res = sqlx::query!(
            "UPDATE members SET public_endpoint = ? WHERE room_id = ? AND user_id = ?",
            value,
            room_id,
            user_id
        )
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// D4.5: fetch a single member's `public_endpoint` JSON blob.
    /// Returns `Ok(None)` when the member row exists but has never
    /// been published, AND when the member row doesn't exist —
    /// callers shouldn't distinguish (race recovery is best-effort).
    pub async fn get_public_endpoint(
        &self,
        room_id: i64,
        user_id: i64,
    ) -> Result<Option<String>, sqlx::Error> {
        let row = sqlx::query!(
            "SELECT public_endpoint FROM members WHERE room_id = ? AND user_id = ?",
            room_id,
            user_id
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.and_then(|r| r.public_endpoint))
    }
}
