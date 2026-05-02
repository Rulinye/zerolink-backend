//! Routing table for the QUIC datapath.
//!
//! Each successfully-bound QUIC connection is registered as a path
//! entry keyed by `(room_id, user_id)`. Datagram forwarding looks
//! up the destination by `(room_id, dst_user_id)` and pushes the
//! packet onto the destination's connection.
//!
//! A connection's path entry also carries:
//!   - The control stream (bidi stream 0) used for `peer_added` /
//!     `peer_removed` notifications.
//!   - In-memory byte counters that G7 will sweep into the
//!     `traffic` table.
//!
//! The map is a `RwLock<HashMap>` rather than dashmap to keep the
//! dependency surface minimal. Datagram forwarding does a read-lock
//! lookup — the critical path is a hash + clone of an Arc — so
//! contention is fine for ≤ a few hundred concurrent paths.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use quinn::{Connection, SendStream};
use tokio::sync::{Mutex, RwLock};

use super::limiter::TokenBucket;

/// One entry per active QUIC datapath connection. Keyed externally
/// in PathMap by `(room_id, user_id)`.
pub struct PathEntry {
    pub room_id: i64,
    pub user_id: i64,
    pub username: String,
    pub conn: Connection,
    /// Bidi stream 0, kept open for control messages from the broker
    /// to the client. The send half lives behind a Mutex because
    /// peer_added / peer_removed broadcasts may arrive concurrently
    /// from different forwarding tasks.
    pub control_send: Mutex<SendStream>,
    /// Bytes received FROM this client (their uplink). Counted at
    /// datagram ingest before forwarding. G7 will reset + report.
    pub bytes_in: AtomicU64,
    /// Bytes sent TO this client (their downlink). Counted at
    /// datagram egress.
    pub bytes_out: AtomicU64,
    /// B4.7-supp / B9: per-session token bucket. Rate fed in from
    /// SessionRecord at bind-frame time, sourced from backend's
    /// verify response (users.room_rate_limit_bps). 0 = unlimited.
    /// Counts BOTH directions against the same budget.
    pub limiter: Mutex<TokenBucket>,
}

/// (room_id, user_id) -> path entry.
type PathMapInner = HashMap<(i64, i64), Arc<PathEntry>>;

#[derive(Clone, Default)]
pub struct PathMap {
    inner: Arc<RwLock<PathMapInner>>,
}

impl PathMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a new path. If an entry already exists for the same
    /// (room, user) — this happens when a client reconnects faster
    /// than the watchdog cleared the prior entry — the old
    /// connection is closed and replaced.
    pub async fn insert(&self, entry: Arc<PathEntry>) -> Option<Arc<PathEntry>> {
        let key = (entry.room_id, entry.user_id);
        let mut map = self.inner.write().await;
        let prior = map.insert(key, entry);
        if let Some(ref old) = prior {
            old.conn.close(quinn::VarInt::from_u32(0x10), b"replaced");
        }
        prior
    }

    /// Look up by (room, user). Cheap (read lock + hash + Arc clone).
    pub async fn get(&self, room_id: i64, user_id: i64) -> Option<Arc<PathEntry>> {
        let map = self.inner.read().await;
        map.get(&(room_id, user_id)).cloned()
    }

    /// Remove a single (room, user) entry. Caller is responsible
    /// for closing the underlying QUIC connection if appropriate.
    pub async fn remove(&self, room_id: i64, user_id: i64) -> Option<Arc<PathEntry>> {
        let mut map = self.inner.write().await;
        map.remove(&(room_id, user_id))
    }

    /// All entries for a given room. Used to:
    ///   - announce a newcomer to existing peers
    ///   - send the initial peer-list to a newcomer
    ///   - tear down all paths when a room is destroyed
    pub async fn list_room(&self, room_id: i64) -> Vec<Arc<PathEntry>> {
        let map = self.inner.read().await;
        map.iter()
            .filter(|((rid, _), _)| *rid == room_id)
            .map(|(_, v)| v.clone())
            .collect()
    }

    /// All room entries EXCEPT the one with `exclude_user_id`. Used by
    /// the D4.4 broadcast fan-out path: when a sender targets
    /// `dst_user_id = BROADCAST_USER_ID` we forward to every other
    /// member, skipping the sender (loop prevention).
    ///
    /// Same shape as `list_room` — read-lock + filter + Arc-clone. Cost
    /// is one extra equality check per entry over `list_room`.
    pub async fn list_room_excluding(
        &self,
        room_id: i64,
        exclude_user_id: i64,
    ) -> Vec<Arc<PathEntry>> {
        let map = self.inner.read().await;
        map.iter()
            .filter(|((rid, uid), _)| *rid == room_id && *uid != exclude_user_id)
            .map(|(_, v)| v.clone())
            .collect()
    }

    /// Drop all paths for a room. Called from admin_destroy_room and
    /// the room-grace watchdog. Each entry has its connection
    /// closed; caller does not need to send room_destroyed over QUIC
    /// because that notification rides the WS broadcast already.
    pub async fn drop_room(&self, room_id: i64) -> usize {
        let mut map = self.inner.write().await;
        let keys: Vec<(i64, i64)> = map
            .keys()
            .filter(|(rid, _)| *rid == room_id)
            .cloned()
            .collect();
        for k in &keys {
            if let Some(entry) = map.remove(k) {
                entry
                    .conn
                    .close(quinn::VarInt::from_u32(0x11), b"room_destroyed");
            }
        }
        keys.len()
    }

    #[allow(dead_code)] // diagnostics / future metrics
    pub async fn total(&self) -> usize {
        self.inner.read().await.len()
    }

    /// B4.7-supp / B3 (room half): drain bytes_in / bytes_out
    /// counters across every active path. Returns
    /// (user_id, bytes_in, bytes_out) tuples for the usage_reporter to
    /// aggregate by user_id and POST to backend.
    pub async fn snapshot_all(&self) -> Vec<(i64, u64, u64)> {
        let map = self.inner.read().await;
        map.values()
            .map(|e| {
                let (i, o) = e.snapshot_and_reset();
                (e.user_id, i, o)
            })
            .collect()
    }
}

impl PathEntry {
    pub fn add_in(&self, n: u64) {
        self.bytes_in.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_out(&self, n: u64) {
        self.bytes_out.fetch_add(n, Ordering::Relaxed);
    }

    #[allow(dead_code)] // G7 traffic reporter will read+reset
    pub fn snapshot_and_reset(&self) -> (u64, u64) {
        let i = self.bytes_in.swap(0, Ordering::Relaxed);
        let o = self.bytes_out.swap(0, Ordering::Relaxed);
        (i, o)
    }
}

#[cfg(test)]
mod tests {
    // Note: PathEntry holds a real quinn::Connection; full unit testing
    // requires spinning up a quinn server which is overkill here.
    // The end-to-end test for routing happens via the integration
    // test in main once datapath is wired.
    #[test]
    fn placeholder() {}
}
