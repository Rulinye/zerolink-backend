-- 0004_broker_and_service_tokens.up.sql
-- Phase 3 Batch 3.3 Group 1a — broker capability + service token table.
--
-- Three coordinated changes:
--
--   1. nodes table gains broker capability fields. Each node may run a
--      broker daemon alongside (or instead of) its sing-box outbound;
--      clients fetching /api/v1/nodes get the broker_endpoint and
--      broker_short_id so the room creation modal can offer a broker
--      picker.
--
--      broker_short_id is a 2-3 char human-readable label embedded in
--      room codes ("GZ-XK7P9R"). Globally unique among non-NULL values
--      via a partial unique index — multiple nodes with NULL short_id
--      are allowed (not every node runs a broker). Ansible has an
--      assert task that mirrors this constraint at deploy time.
--
--      has_broker is a denormalized convenience flag. Could be derived
--      from "broker_endpoint IS NOT NULL" but keeping it explicit lets
--      the client UI gate the room feature without parsing endpoints.
--
--   2. users.used_bytes splits into used_bytes_main (vless/sing-box
--      traffic, the existing counter) and used_bytes_room (broker L3
--      relay traffic, new in 3.3). Quota cap remains a single combined
--      ceiling (D3.25); these two columns are diagnostic counters so
--      users can see "why did I hit cap this month".
--
--      Existing used_bytes values migrate cleanly to used_bytes_main
--      via RENAME COLUMN — the existing counter has only ever been
--      counting main connection traffic anyway (rooms didn't exist
--      before 3.3). RENAME COLUMN requires SQLite >= 3.25.0 (2018);
--      Ubuntu 22.04+ ships 3.37+, so production is fine.
--
--   3. service_tokens table holds one entry per broker. Brokers
--      authenticate to backend's /api/v1/auth/verify endpoint with a
--      Bearer token issued at deploy time (Ansible vault per-broker).
--      Stored hashed (sha256, hex) — plaintext is shown once at gen
--      time via `cmd/gen-service-token` and then forgotten by backend.
--
-- SQLite ALTER TABLE ADD COLUMN: defaults required for NOT NULL columns
-- on existing rows, satisfied below.

-- (1) nodes: broker capability ----------------------------------------
ALTER TABLE nodes ADD COLUMN broker_endpoint TEXT;
ALTER TABLE nodes ADD COLUMN broker_short_id TEXT;
ALTER TABLE nodes ADD COLUMN has_broker      INTEGER NOT NULL DEFAULT 0;

-- broker_short_id must be globally unique among non-NULL values. Partial
-- index permits many NULLs (nodes without a broker) but rejects duplicate
-- "GZ" / "KR" labels.
CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_broker_short_id
    ON nodes(broker_short_id)
    WHERE broker_short_id IS NOT NULL;

-- (2) users: split used_bytes into main / room ------------------------
ALTER TABLE users RENAME COLUMN used_bytes TO used_bytes_main;
ALTER TABLE users ADD COLUMN used_bytes_room INTEGER NOT NULL DEFAULT 0;

-- (3) service_tokens table -------------------------------------------
CREATE TABLE service_tokens (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    label         TEXT     NOT NULL UNIQUE,         -- 'broker-gz', 'broker-kr', etc.
    token_hash    TEXT     NOT NULL,                -- sha256(plaintext) hex
    created_at    DATETIME NOT NULL,
    last_used_at  DATETIME DEFAULT NULL,
    disabled      INTEGER  NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_service_tokens_label
    ON service_tokens(label);
