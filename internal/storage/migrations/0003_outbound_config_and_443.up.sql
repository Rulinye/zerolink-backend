-- 0003_outbound_config_and_443.up.sql
-- Phase 3 Batch 3.2 Group 9a (Round 4 — backend Go side).
--
-- Two changes coordinated together:
--
--   1. Add `nodes.outbound_config` TEXT column. SQLite has no native
--      JSON type; we store JSON as TEXT and the application layer
--      marshals/unmarshals. The column is opaque to SQL — never
--      queried by it, only forwarded to the client.
--
--      Today the client (vswitch/config.rs) understands one key:
--          packet_encoding: "xudp" | "packet_up" | "packetaddr"
--      Default `{}` means "use the protocol's default" (which for
--      vless+reality with udp:true is "xudp").
--
--      Future protocols (ss2022, hysteria2, ...) can ship per-node
--      tuning here without requiring a client release.
--
--   2. UPDATE the existing port 23456 → 443. Group 9a moves the
--      reality entry from the dev-time high port to 443, hiding
--      among regular HTTPS traffic. The actual sing-box server-side
--      listen port is changed manually (see
--      docs/batches/BATCH-3.2-GROUP-9-DEPLOY.md).
--
--      We intentionally only update rows where port = 23456 — any
--      future node already on a different port is left alone. Safe
--      to run more than once (idempotent).
--
-- SQLite ALTER TABLE ADD COLUMN restriction: the new column must have
-- a DEFAULT or be nullable. We use DEFAULT '{}' (a valid empty JSON
-- object) so existing rows produce well-formed JSON when read.

ALTER TABLE nodes ADD COLUMN outbound_config TEXT NOT NULL DEFAULT '{}';

UPDATE nodes SET port = 443 WHERE port = 23456;
