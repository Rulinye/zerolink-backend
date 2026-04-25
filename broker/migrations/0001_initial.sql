-- 0001_initial.sql
-- broker SQLite schema, batch 3.3 group 2b.
--
-- All timestamps are unix epoch seconds (INTEGER, i64 in Rust). Month
-- boundary calculations done in-process using chrono-tz / Asia/Seoul to
-- match backend's quota period semantics (D2.25 + D3.25). Broker host
-- system TZ is irrelevant — internal computations always use KST.
--
-- Three tables:
--
--   rooms     — one row per active or recently-destroyed room. State
--               machine: 'active' -> 'empty_grace' -> 'destroyed'.
--               Also: 'active' -> 'destroyed' (owner explicit destroy).
--               Partial unique index on (owner_user_id) WHERE state !=
--               'destroyed' enforces "one active room per user" without
--               blocking ownership of a *destroyed* room (i.e. the
--               user can create a new one as soon as their old one
--               hits 'destroyed').
--
--   members   — current room members. (room_id, user_id) UNIQUE.
--               Removed on leave_room or owner-destroy or grace expiry.
--
--   traffic   — per-(room, user, period) accumulator for L3 relay
--               bytes. period_started_at is the unix timestamp of the
--               1st-of-month at 00:00 Asia/Seoul. Group 7 (G7) builds
--               the reporting path on top of this; 2b only creates
--               the schema.
--
-- All foreign keys cascade on delete. Sqlite's enforcement requires
-- PRAGMA foreign_keys = ON, set at connection open time by storage.rs.

-- --- rooms ----------------------------------------------------------

CREATE TABLE rooms (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,

    -- 6-char Crockford base32 (db column stores bare code, e.g.
    -- 'XK7P9R'; client-side display prefixes broker short_id like
    -- 'KR-XK7P9R' for human-friendly invitation strings.)
    code            TEXT    NOT NULL UNIQUE,

    -- backend's user_id of the user who created this room.
    owner_user_id   INTEGER NOT NULL,

    -- snapshot of owner's username at create time, for display in
    -- list_rooms responses without needing to reverse-resolve.
    owner_username  TEXT    NOT NULL,

    -- unix epoch seconds.
    created_at      INTEGER NOT NULL,

    -- bumped on any member ws heartbeat, member join/leave, or
    -- owner action. Used by GC to detect stuck rooms.
    last_active_at  INTEGER NOT NULL,

    -- 'auto' | 'p2p_only' | 'broker_only'. Phase 4.1 will use this
    -- to gate path selection; in 3.3 the broker always relays
    -- regardless of value.
    path_strategy   TEXT    NOT NULL DEFAULT 'auto'
                    CHECK (path_strategy IN ('auto', 'p2p_only', 'broker_only')),

    -- Phase 4.1 stub. Always 0 in 3.3.
    supports_p2p    INTEGER NOT NULL DEFAULT 0
                    CHECK (supports_p2p IN (0, 1)),

    -- 'active'      = has members or just-created
    -- 'empty_grace' = last member left, ~5min countdown to destroy
    -- 'destroyed'   = soft-deleted; rows reaped by GC after 1h
    state           TEXT    NOT NULL DEFAULT 'active'
                    CHECK (state IN ('active', 'empty_grace', 'destroyed')),

    -- Set when state transitions to 'empty_grace'; null otherwise.
    -- unix epoch seconds; GC destroys when now > grace_until.
    grace_until     INTEGER,

    -- Set when state transitions to 'destroyed'; null otherwise.
    -- Used for "destroy older than 1h" hard-delete sweep.
    destroyed_at    INTEGER
);

-- One room code is globally unique inside a single broker (even
-- across destroyed rows) so an old leaked invite can't suddenly
-- become valid again pointing at a new room.
CREATE INDEX idx_rooms_state ON rooms(state);
CREATE INDEX idx_rooms_grace_until ON rooms(grace_until)
    WHERE grace_until IS NOT NULL;
CREATE INDEX idx_rooms_destroyed_at ON rooms(destroyed_at)
    WHERE destroyed_at IS NOT NULL;

-- The "one active room per owner" constraint. Allows multiple
-- 'destroyed' rows for the same user (history), forbids more than
-- one 'active' or 'empty_grace' for the same user.
CREATE UNIQUE INDEX idx_rooms_owner_alive
    ON rooms(owner_user_id)
    WHERE state != 'destroyed';

-- --- members --------------------------------------------------------

CREATE TABLE members (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id         INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,

    -- backend's user_id.
    user_id         INTEGER NOT NULL,

    -- snapshot of username at join time. Used for list_members
    -- responses + owner display. We do NOT update this if the user
    -- renames in backend; rename mid-session is rare and confusing.
    username        TEXT    NOT NULL,

    joined_at       INTEGER NOT NULL,

    -- bumped on every ws frame from this member; used by ws-loop to
    -- detect stale connections (no heartbeat for >30s -> disconnect).
    last_seen_at    INTEGER NOT NULL,

    -- Phase 4.1 stub: NAT-reflected public endpoint of this member,
    -- e.g. "1.2.3.4:55678". 3.3 always NULL.
    public_endpoint TEXT,

    -- One row per (room, user). Re-joining the same room re-uses the
    -- existing row via UPSERT to preserve joined_at.
    UNIQUE(room_id, user_id)
);

CREATE INDEX idx_members_room ON members(room_id);
CREATE INDEX idx_members_user ON members(user_id);
CREATE INDEX idx_members_last_seen ON members(last_seen_at);

-- --- traffic --------------------------------------------------------

CREATE TABLE traffic (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id           INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    user_id           INTEGER NOT NULL,

    -- Accumulators. Updated incrementally by the L3 relay loop in 2d.
    bytes_up          INTEGER NOT NULL DEFAULT 0,
    bytes_down        INTEGER NOT NULL DEFAULT 0,

    -- unix epoch seconds of the start of the billing month for this
    -- accumulator, computed in-process at insert time using
    -- Asia/Seoul. Two rows for the same (room_id, user_id) but
    -- different period_started_at represent traffic in different
    -- billing months.
    period_started_at INTEGER NOT NULL,

    last_updated_at   INTEGER NOT NULL,

    -- Set by the report-to-backend job when this row's bytes_*
    -- counters were reported to backend. The reporter runs the
    -- equivalent of "for each row WHERE last_updated_at >
    -- COALESCE(reported_at, 0): post to /traffic/report; on success
    -- set reported_at = last_updated_at." Group 7 implements this.
    reported_at       INTEGER,

    UNIQUE(room_id, user_id, period_started_at)
);

CREATE INDEX idx_traffic_room_user ON traffic(room_id, user_id);

-- Partial index covering "rows with unreported updates", used by the
-- G7 reporter to find pending work cheaply.
CREATE INDEX idx_traffic_unreported ON traffic(last_updated_at)
    WHERE reported_at IS NULL OR reported_at < last_updated_at;
