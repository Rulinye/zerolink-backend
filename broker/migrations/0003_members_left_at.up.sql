-- 0003_members_left_at.up.sql
--
-- Phase 4 Batch 4.7 / B4.7-K3 closure.
--
-- Add a `left_at INTEGER` column to `members` and convert
-- `MemberRepo::leave` from hard-DELETE to soft-DELETE (UPDATE
-- `left_at = ?`). The change is required so the dashboard's
-- `list_my_rooms` (which qualifies "is in this room" via EXISTS
-- against `members`) keeps showing rooms the user has previously
-- joined and then left, until the room itself is destroyed. Operator
-- expectation surfaced during 4.7 smoke; the original 3.3 schema's
-- hard-delete removed the row and the room disappeared from the
-- joiner's dashboard once their grace expired.
--
-- New semantics:
--   * `left_at IS NULL` → user is currently a member of the room.
--   * `left_at IS NOT NULL` → user previously left; row preserved
--     for history. Rejoin via `MemberRepo::join` UPSERTs + clears
--     `left_at` back to NULL.
--   * Cascade delete on rooms still works (FK ON DELETE CASCADE) —
--     destroying the room takes the history with it.
--
-- Existing rows: NULL means "currently active"; that matches the
-- pre-migration state where every row in members IS a current
-- member. No backfill needed.

ALTER TABLE members ADD COLUMN left_at INTEGER NULL;

-- Optional index to speed up list_alive_for_user's EXISTS predicate
-- once history rows accumulate. The existing idx_members_user covers
-- the user_id lookup; this partial index narrows to current members
-- which most queries care about (list, count, heartbeat).
CREATE INDEX idx_members_user_alive
    ON members(user_id)
    WHERE left_at IS NULL;
