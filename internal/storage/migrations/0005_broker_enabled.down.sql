-- 0005_broker_enabled.down.sql
-- SQLite < 3.35 does not support DROP COLUMN cleanly; rollback would
-- require recreating the nodes table without the column. Up-only is
-- acceptable here because the column is additive with a safe default.
SELECT 1;
