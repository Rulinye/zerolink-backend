-- 0002_quota_and_disable.up.sql
-- Phase 2 followup (Batch 3a).
--
-- Adds:
--   1. users.disabled_until   — nullable timestamp; when NOT NULL and in the
--      future, user is considered disabled. Replaces/supplements is_disabled
--      semantics (is_disabled kept for backward compat: is_disabled=1 AND
--      disabled_until IS NULL means "permanent").
--   2. users.quota_bytes      — monthly traffic cap (NULL = unlimited; default
--      100 GB for new users).
--   3. users.used_bytes       — running counter for current billing period.
--   4. users.quota_reset_at   — next reset timestamp (start of next month
--      00:00 UTC+9). Computed by Go code at reset time.
--   5. users.password_changed_at — for auditing & "invalidate all tokens
--      issued before this" logic in F15/F17.
--   6. invites.note           — annotation (already present per phase-1 schema,
--      kept for reference; migration skips if column exists).
--
-- SQLite ALTER TABLE limitations: we can only ADD COLUMN. All added columns
-- either have DEFAULT or are nullable, so existing rows won't break NOT NULL
-- constraints.

ALTER TABLE users ADD COLUMN disabled_until DATETIME DEFAULT NULL;
ALTER TABLE users ADD COLUMN quota_bytes INTEGER DEFAULT NULL;
ALTER TABLE users ADD COLUMN used_bytes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN quota_reset_at DATETIME DEFAULT NULL;
ALTER TABLE users ADD COLUMN password_changed_at DATETIME DEFAULT NULL;

-- Populate quota_reset_at for existing users so the monthly-reset job has a
-- valid next-reset time for everyone. Set to the 1st of next month, 00:00
-- local time (server is UTC+9 via /etc/timezone = Asia/Seoul per Ansible).
UPDATE users
   SET quota_reset_at = datetime(
         strftime('%Y-%m-01 00:00:00', 'now', '+1 month')
       )
 WHERE quota_reset_at IS NULL;

-- Default 100 GB cap for existing users with no quota set (admins can unlimit
-- via the new admin endpoint).
UPDATE users
   SET quota_bytes = 107374182400  -- 100 * 1024^3
 WHERE quota_bytes IS NULL;

-- Index for the "find users to reset" batch job. Cheap on SQLite (B-tree on
-- DATETIME-as-text).
CREATE INDEX IF NOT EXISTS idx_users_quota_reset ON users(quota_reset_at);

-- Index for looking up active disables (expire job + middleware checks).
CREATE INDEX IF NOT EXISTS idx_users_disabled_until ON users(disabled_until)
    WHERE disabled_until IS NOT NULL;
