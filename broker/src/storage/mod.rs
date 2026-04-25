//! SQLite storage layer (sqlx + offline-mode query macros).
//!
//! Connection pool is opened by `Storage::open` at boot. Migrations
//! under `broker/migrations/` are applied automatically (via
//! `sqlx::migrate!` macro, which embeds the SQL files into the binary
//! at compile time — no migration files need to be present at runtime).
//!
//! Sub-modules:
//!   - rooms.rs — RoomRepo (Create / GetByCode / SetEmptyGrace /
//!     Destroy / GcEmptyGrace / GcDestroyed)
//!   - members.rs — MemberRepo (Join / Leave / List / TouchHeartbeat)
//!   - traffic.rs — TrafficRepo (per-(room, user, period) accumulator)
//!
//! 2b lands the schema + module skeleton; the actual sqlx::query!
//! invocations move in across 2c (RPC handlers consume them).
//! `cargo sqlx prepare` is run after each schema or query change and
//! commits `.sqlx/`.

pub mod members;
pub mod rooms;
pub mod traffic;

use anyhow::{Context, Result};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::str::FromStr;
use tracing::info;

/// Top-level storage handle. Cloned freely (it's `Arc` under the hood).
#[derive(Clone)]
pub struct Storage {
    pub pool: SqlitePool,
}

impl Storage {
    /// Open (or create) the DB at `path` and run any pending migrations.
    ///
    /// Connection-time pragmas:
    ///   - foreign_keys = ON   (enables ON DELETE CASCADE on members /
    ///     traffic when their parent room is hard-deleted by the GC sweep)
    ///   - journal_mode = WAL  (concurrent reads while a write is in
    ///     progress; matches backend's choice)
    ///   - busy_timeout = 5000 ms (forgiving under contention)
    pub async fn open(path: &str) -> Result<Self> {
        let opts = SqliteConnectOptions::from_str(&format!("sqlite://{path}"))
            .with_context(|| format!("parse sqlite path {path:?}"))?
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .busy_timeout(std::time::Duration::from_secs(5));

        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(opts)
            .await
            .with_context(|| format!("open sqlite at {path:?}"))?;

        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .context("run sqlx migrations")?;

        info!(target: "storage", %path, "sqlite open + migrations applied");

        Ok(Self { pool })
    }
}

/// KST month boundary helpers. All quota / billing periods are anchored
/// to Asia/Seoul (UTC+9) regardless of broker host timezone — see top
/// of file comment block in 0001_initial.sql.
pub mod kst {
    use chrono::{DateTime, Datelike, NaiveDate, TimeZone, Utc};
    use chrono_tz::Asia::Seoul;

    /// Unix epoch seconds for the 1st-of-month at 00:00 in KST that
    /// contains the given instant.
    pub fn period_start_for(instant: DateTime<Utc>) -> i64 {
        let local = instant.with_timezone(&Seoul);
        let first = NaiveDate::from_ymd_opt(local.year(), local.month(), 1)
            .expect("valid year/month")
            .and_hms_opt(0, 0, 0)
            .expect("valid hms");
        // Localize the naive first-of-month into KST. .single() is safe
        // here because no DST transition happens at midnight on the 1st
        // in Seoul (Korea has no DST).
        let kst_dt = Seoul
            .from_local_datetime(&first)
            .single()
            .expect("KST 00:00 on 1st of month is unambiguous");
        kst_dt.with_timezone(&Utc).timestamp()
    }

    /// Convenience: period_start for "right now".
    pub fn current_period_start() -> i64 {
        period_start_for(Utc::now())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn period_for_known_instant() {
            // 2026-04-25 12:00:00 UTC = 2026-04-25 21:00 KST. Period
            // start = 2026-04-01 00:00 KST = 2026-03-31 15:00 UTC.
            let t = Utc.with_ymd_and_hms(2026, 4, 25, 12, 0, 0).unwrap();
            let expected = Utc
                .with_ymd_and_hms(2026, 3, 31, 15, 0, 0)
                .unwrap()
                .timestamp();
            assert_eq!(period_start_for(t), expected);
        }

        #[test]
        fn period_at_kst_month_boundary() {
            // 2026-04-30 14:59 UTC = 2026-04-30 23:59 KST -> April period.
            // 2026-04-30 15:00 UTC = 2026-05-01 00:00 KST -> May period.
            let april_last_min = Utc.with_ymd_and_hms(2026, 4, 30, 14, 59, 0).unwrap();
            let may_first = Utc.with_ymd_and_hms(2026, 4, 30, 15, 0, 0).unwrap();
            assert_ne!(
                period_start_for(april_last_min),
                period_start_for(may_first)
            );
        }
    }
}
