-- 0006_invites_fk_set_null.up.sql
--
-- Phase 4 Batch 4.7 supplement / B4 — fix FK deletion path that bricks
-- the admin "delete invite" button after the consuming user has been
-- removed.
--
-- Original schema: invites.created_by NOT NULL REFERENCES users(id),
-- invites.used_by REFERENCES users(id). NEITHER FK has an ON DELETE
-- clause → SQLite default = RESTRICT. Two bugs follow:
--
--   1. DELETE FROM users WHERE id = ? fails (RESTRICT) when the user
--      created or used any invite. handleAdminDeleteUser uses
--      ExecForCleanup which runs raw SQL through the connection
--      with foreign_keys=ON, so this delete blocks.
--
--   2. handleAdminDeleteInvite (cascade=true) calls DELETE FROM users
--      first, then DELETE FROM invites. If the user has OTHER invites
--      they CREATED, the cascade-DELETE blocks at step 1 with
--      "constraint failed: FOREIGN KEY constraint failed (787)".
--
-- Fix: change both FK references to ON DELETE SET NULL. Now:
--   * Deleting a user nulls out the FK columns in any invite they
--     created or used. Invite rows are preserved as historical record.
--   * The "已使用" badge migrates from `used_by IS NOT NULL` →
--     `used_at IS NOT NULL` (consume-marker timestamp). used_at is
--     set atomically with used_by in InviteRepo.Consume, so the new
--     predicate is identical for never-deleted-user paths and
--     correct for deleted-user paths.
--
-- Same fix makes invites.created_by nullable. UI display layer treats
-- NULL created_by as "creator removed" and shows "—".
--
-- modernc SQLite (< 3.35) cannot ALTER COLUMN to add ON DELETE; so
-- the standard table-recreate dance:

PRAGMA foreign_keys = OFF;

CREATE TABLE invites_new (
    code         TEXT PRIMARY KEY,
    created_by   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at   DATETIME NOT NULL,
    used_by      INTEGER REFERENCES users(id) ON DELETE SET NULL,
    used_at      DATETIME,
    note         TEXT
);

INSERT INTO invites_new (code, created_by, created_at, expires_at, used_by, used_at, note)
SELECT code, created_by, created_at, expires_at, used_by, used_at, note FROM invites;

DROP TABLE invites;
ALTER TABLE invites_new RENAME TO invites;

DROP INDEX IF EXISTS idx_invites_unused;
-- Predicate also migrates: "unused" was `used_by IS NULL`; now
-- `used_at IS NULL` is the authoritative consumed-marker since
-- used_by can be nulled by user deletion post-consume.
CREATE INDEX idx_invites_unused ON invites(used_at) WHERE used_at IS NULL;

PRAGMA foreign_keys = ON;
