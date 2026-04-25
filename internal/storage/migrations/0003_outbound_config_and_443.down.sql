-- 0003_outbound_config_and_443.down.sql
--
-- Best-effort rollback. SQLite cannot DROP COLUMN without rebuilding
-- the table (until 3.35; we're on the modernc driver which supports
-- modern SQLite, but the rebuild is fiddly). We do the table-rebuild
-- the long way to keep this clean.
--
-- The port 443 → 23456 reversal is harder to do correctly: we only
-- want to undo rows we touched, not arbitrary other ports. The safest
-- rollback is "do nothing"; the production data has been corrected
-- and is now consistent. If you really need to roll back, do it
-- manually.

-- Recreate nodes WITHOUT outbound_config.
CREATE TABLE nodes_new (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL UNIQUE,
    region       TEXT NOT NULL,
    address      TEXT NOT NULL,
    port         INTEGER NOT NULL,
    protocol     TEXT NOT NULL,
    config_json  TEXT NOT NULL,
    is_enabled   INTEGER NOT NULL DEFAULT 1,
    sort_order   INTEGER NOT NULL DEFAULT 100,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO nodes_new
    (id, name, region, address, port, protocol, config_json, is_enabled, sort_order, updated_at)
SELECT
    id, name, region, address, port, protocol, config_json, is_enabled, sort_order, updated_at
FROM nodes;

DROP TABLE nodes;
ALTER TABLE nodes_new RENAME TO nodes;

-- Port reversal intentionally NOT performed — see header note.
