//! Traffic accumulator — 2b skeleton.
//!
//! Implementation arrives in **G7** (traffic accounting / quota
//! reporting), not 2c. The 2d datapath relay will _record_ bytes via
//! a method we'll add here, but billing-side logic (upserts on
//! period_started_at, reporting to backend) is G7's scope.
//!
//! The schema is in 0001_initial.sql; this module is just so
//! `Storage::traffic` exists and can be passed around without
//! requiring G7 to land first.

use sqlx::SqlitePool;

#[derive(Debug, Clone)]
pub struct TrafficRow {
    pub id: i64,
    pub room_id: i64,
    pub user_id: i64,
    pub bytes_up: i64,
    pub bytes_down: i64,
    pub period_started_at: i64, // unix epoch seconds, KST month start
    pub last_updated_at: i64,
    pub reported_at: Option<i64>,
}

#[derive(Clone)]
pub struct TrafficRepo {
    #[allow(dead_code)]
    pool: SqlitePool,
}

impl TrafficRepo {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    // Methods (G7):
    //
    // pub async fn add_bytes(
    //     &self, room_id, user_id, bytes_up_delta, bytes_down_delta, now,
    // ) -> Result<()>;
    //   UPSERT on (room_id, user_id, period_started_at) where
    //   period_started_at = kst::current_period_start(). Bumps
    //   bytes_up / bytes_down by the deltas, sets last_updated_at = now.
    //
    // pub async fn list_unreported(&self) -> Result<Vec<TrafficRow>>;
    //   Rows with reported_at IS NULL OR reported_at < last_updated_at.
    //   Used by the report-to-backend job.
    //
    // pub async fn mark_reported(&self, id, reported_at) -> Result<()>;
}
