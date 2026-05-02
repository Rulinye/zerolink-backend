-- 0003_members_left_at.down.sql
--
-- Per backend/CLAUDE.md: down-migration is no-op for ALTER COLUMN
-- style schema changes (modernc SQLite < 3.35 cannot drop columns
-- without a full table rewrite, and accepting the irreversibility
-- is documented project policy). The index drop IS reversible, but
-- without the column drop the rest of the migration can't actually
-- be undone, so we leave both intact for forensic clarity.

-- Intentional no-op.
