-- 0002_add_room_type.up.sql
-- Phase 4.6 / D4.8 — Windows L2 implementation. Adds the room-overlay
-- type column to `rooms` so create_room can record whether a room is
-- L3 (default, all platforms) or L2 (Win/Linux only). Joiners inherit
-- the type at join time; clients gate macOS join attempts on L2 rooms
-- per D3.17 ("L2 房间不允许 L3 加入" — no silent downgrade).
--
-- Wire-additive:
--   - Old client + new broker: client doesn't send room_type → broker
--     defaults to 'l3' (preserves 4.5 behaviour). list_my_rooms /
--     room_info / join_room responses include the new field; old
--     clients ignore extra fields.
--   - New client + old broker: room_type RPC param is sent but
--     ignored; created rooms behave as L3 (correct legacy behaviour).
--     Responses lack the field; client-side `#[serde(default = "...")]`
--     maps missing → "l3".
--
-- Down migration is a no-op per backend CLAUDE.md §"Migrations":
-- modernc SQLite < 3.35 can't ALTER COLUMN / DROP COLUMN cleanly,
-- and the schema convention treats ADD-COLUMN reversal as not
-- reversible. Production rollback is a forward-fix, not a down.

ALTER TABLE rooms
    ADD COLUMN room_type TEXT NOT NULL DEFAULT 'l3'
        CHECK (room_type IN ('l2', 'l3'));
