-- 0002_quota_and_disable.down.sql
--
-- Rollback. SQLite before 3.35 can't DROP COLUMN, so we recreate the users
-- table. modernc.org/sqlite ships 3.40+ so DROP COLUMN works, but we use the
-- recreate-table approach for broader compatibility with future backports.

DROP INDEX IF EXISTS idx_users_disabled_until;
DROP INDEX IF EXISTS idx_users_quota_reset;

-- For modern SQLite this works directly:
ALTER TABLE users DROP COLUMN password_changed_at;
ALTER TABLE users DROP COLUMN quota_reset_at;
ALTER TABLE users DROP COLUMN used_bytes;
ALTER TABLE users DROP COLUMN quota_bytes;
ALTER TABLE users DROP COLUMN disabled_until;
