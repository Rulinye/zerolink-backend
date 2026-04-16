-- 0001_init.down.sql
-- Rollback for the initial schema. Drops all tables in reverse FK order.

DROP INDEX IF EXISTS idx_revoked_tokens_expires;
DROP TABLE IF EXISTS revoked_tokens;

DROP INDEX IF EXISTS idx_traffic_user_time;
DROP TABLE IF EXISTS traffic;

DROP INDEX IF EXISTS idx_subscriptions_user;
DROP TABLE IF EXISTS subscriptions;

DROP TABLE IF EXISTS nodes;

DROP INDEX IF EXISTS idx_invites_unused;
DROP TABLE IF EXISTS invites;

DROP TABLE IF EXISTS users;
