-- 0002_add_room_type.down.sql
-- No-op per backend CLAUDE.md §"Migrations" — modernc SQLite < 3.35
-- can't ALTER COLUMN / DROP COLUMN cleanly; schema convention treats
-- ADD-COLUMN reversal as not reversible. See the .up.sql for context.
SELECT 1;
