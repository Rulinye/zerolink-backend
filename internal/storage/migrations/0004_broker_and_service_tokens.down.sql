-- 0004_broker_and_service_tokens.down.sql
-- Reverse 0004. Note: down migrations are best-effort here. We drop the
-- new table cleanly but leave the added columns on `nodes` intact
-- because SQLite < 3.35 had no DROP COLUMN, and rebuilding tables in a
-- down migration is fragile. The added columns are nullable / have safe
-- defaults, so 0003-era code doesn't break by their presence. If a real
-- rollback is needed in production, restore from backup.

DROP INDEX IF EXISTS idx_service_tokens_label;
DROP TABLE IF EXISTS service_tokens;

DROP INDEX IF EXISTS idx_nodes_broker_short_id;

-- Reverse the rename so the schema returns to a state the 0003-era code
-- can read. The added used_bytes_room column is left in place; harmless.
ALTER TABLE users RENAME COLUMN used_bytes_main TO used_bytes;

-- nodes broker_* columns left in place (see note above).
