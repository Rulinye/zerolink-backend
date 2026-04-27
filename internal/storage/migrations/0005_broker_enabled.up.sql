-- 0005_broker_enabled.up.sql
-- Phase 3 Batch 3.3 Group 4-1c-3g: per-node broker_enabled toggle.
--
-- A node with has_broker=1 may want its broker capability temporarily
-- disabled (maintenance, debugging) without removing the node row.
-- This column lets the admin UI surface a toggle that hides the
-- broker from clients without disturbing the node's outbound usage.
--
-- Default 1 so existing has_broker rows continue to advertise their
-- broker after the migration applies.
--
-- Filter rule (handleListNodes): a node only advertises its broker
-- fields when has_broker=1 AND broker_enabled=1. has_broker stays
-- as the physical capability flag (set by import-nodes);
-- broker_enabled is the operational flag (toggled via admin UI).

ALTER TABLE nodes ADD COLUMN broker_enabled INTEGER NOT NULL DEFAULT 1
    CHECK (broker_enabled IN (0, 1));
