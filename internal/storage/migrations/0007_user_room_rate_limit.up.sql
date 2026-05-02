-- 0007_user_room_rate_limit.up.sql
--
-- Phase 4 Batch 4.7 supplement / B9 (room half).
--
-- users.room_rate_limit_bps: per-user upper bound on the broker
-- datapath bytes/sec when the user is in a room. Default 20 Mbps
-- (2,500,000 bytes/sec; product decision per operator 2026-05-02).
--
-- Hard ceiling: room_rate_limit_bps must be < the main-connection
-- rate limit (50 Mbps = 6,250,000 bytes/sec, hardcoded in admin
-- handler validation until Phase 5 promotes that to a separate
-- column). Operator UI rejects edits violating this.
--
-- Enforcement: broker reads the flag via the existing
-- /api/v1/auth/verify response (extended in 4.7-supp/B9 to include
-- the field), parks it on each SessionRecord, and gates QUIC
-- datapath datagrams through a per-session token bucket. Server-
-- side ONLY — client cannot bypass.

ALTER TABLE users ADD COLUMN room_rate_limit_bps INTEGER NOT NULL DEFAULT 2500000;
