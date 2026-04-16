-- 0001_init.up.sql
-- Phase 1 initial schema. SQLite dialect.

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_admin      INTEGER NOT NULL DEFAULT 0,
    is_disabled   INTEGER NOT NULL DEFAULT 0,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at DATETIME
);

CREATE TABLE invites (
    code         TEXT PRIMARY KEY,
    created_by   INTEGER NOT NULL REFERENCES users(id),
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at   DATETIME NOT NULL,
    used_by      INTEGER REFERENCES users(id),
    used_at      DATETIME,
    note         TEXT
);

CREATE INDEX idx_invites_unused ON invites(used_by) WHERE used_by IS NULL;

CREATE TABLE nodes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL UNIQUE,                -- 'chuncheon-01' from inventory hostname
    region       TEXT NOT NULL,                       -- 'kr-chuncheon'
    address      TEXT NOT NULL,                       -- 'gz.example.com' (the entry the client connects to)
    port         INTEGER NOT NULL,
    protocol     TEXT NOT NULL,                       -- 'vless+reality'
    config_json  TEXT NOT NULL,                       -- full client-side parameters as JSON blob
    is_enabled   INTEGER NOT NULL DEFAULT 1,
    sort_order   INTEGER NOT NULL DEFAULT 100,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE subscriptions (
    token        TEXT PRIMARY KEY,                    -- opaque random, 32 bytes base64url
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,                       -- user-given label e.g. "macbook"
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_fetched_at DATETIME,
    fetch_count  INTEGER NOT NULL DEFAULT 0,
    revoked      INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_subscriptions_user ON subscriptions(user_id);

CREATE TABLE traffic (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    node_id      INTEGER REFERENCES nodes(id) ON DELETE SET NULL,
    bytes_up     INTEGER NOT NULL DEFAULT 0,
    bytes_down   INTEGER NOT NULL DEFAULT 0,
    recorded_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_traffic_user_time ON traffic(user_id, recorded_at);

-- Token revocation list. Used by JWT middleware.
-- Phase 1 keeps it persistent (not in-memory), so process restart doesn't accidentally re-allow revoked tokens.
CREATE TABLE revoked_tokens (
    jti          TEXT PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    revoked_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at   DATETIME NOT NULL                  -- can be GC'd after exp
);

CREATE INDEX idx_revoked_tokens_expires ON revoked_tokens(expires_at);

-- Bookkeeping: what migration version is applied. Used by golang-migrate.
-- migrate creates schema_migrations itself; we don't define it here.
