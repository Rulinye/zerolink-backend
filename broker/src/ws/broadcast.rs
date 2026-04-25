//! Per-room broadcast hub.
//!
//! For each active room there is one `tokio::broadcast::Sender<RoomEvent>`
//! held by the hub. WS connections that have joined a room call
//! `subscribe(room_id)` to receive events; the hub creates the channel
//! lazily on first subscriber.
//!
//! Capacity is 128 events buffered per room (decision C2). When a slow
//! receiver lags more than 128 events behind, `broadcast::Receiver::recv`
//! returns `RecvError::Lagged` and the WS connection is forcibly closed
//! on this side — client is expected to reconnect and re-fetch state
//! via list_members/resume_session. This trades a rare hard reconnect
//! for guaranteed event consistency.
//!
//! After a room is destroyed, the hub's entry is removed. Existing
//! subscribers still receive any event sent before the entry was
//! dropped (per tokio::broadcast semantics). New subscribers cannot
//! be created.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

use super::protocol::RoomEvent;

const CHANNEL_CAPACITY: usize = 128;

#[derive(Clone, Default)]
pub struct BroadcastHub {
    /// room_id → broadcast sender. Wrapped in Arc so we can hand out
    /// Sender clones without holding the outer lock.
    inner: Arc<RwLock<HashMap<i64, broadcast::Sender<RoomEvent>>>>,
}

impl BroadcastHub {
    pub fn new() -> Self {
        Self::default()
    }

    /// Subscribe to a room. Creates the channel if no subscribers
    /// exist yet.
    pub async fn subscribe(&self, room_id: i64) -> broadcast::Receiver<RoomEvent> {
        let mut map = self.inner.write().await;
        let sender = map
            .entry(room_id)
            .or_insert_with(|| broadcast::channel(CHANNEL_CAPACITY).0);
        sender.subscribe()
    }

    /// Send an event to all subscribers of `room_id`. Returns the
    /// number of receivers it was delivered to (0 if no one is
    /// subscribed; that's not an error — it just means no ws
    /// connections are observing the room right now).
    pub async fn send(&self, room_id: i64, event: RoomEvent) -> usize {
        let map = self.inner.read().await;
        if let Some(sender) = map.get(&room_id) {
            sender.send(event).unwrap_or(0)
        } else {
            0
        }
    }

    /// Drop the broadcast channel for a room. Existing receivers
    /// will get `RecvError::Closed` once they drain any buffered
    /// events. Idempotent; called when a room transitions to
    /// `destroyed`.
    pub async fn drop_room(&self, room_id: i64) {
        let mut map = self.inner.write().await;
        map.remove(&room_id);
    }

    /// For diagnostics / metrics.
    #[allow(dead_code)]
    pub async fn active_room_count(&self) -> usize {
        self.inner.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ws::protocol::{MemberLeftEvent, RoomEvent};

    #[tokio::test]
    async fn subscribe_then_receive() {
        let hub = BroadcastHub::new();
        let mut rx = hub.subscribe(7).await;
        let n = hub
            .send(
                7,
                RoomEvent::MemberLeft(MemberLeftEvent {
                    room_id: 7,
                    user_id: 1,
                    username: "x".into(),
                }),
            )
            .await;
        assert_eq!(n, 1);
        let evt = rx.recv().await.unwrap();
        match evt {
            RoomEvent::MemberLeft(e) => assert_eq!(e.user_id, 1),
            _ => panic!("wrong event variant"),
        }
    }

    #[tokio::test]
    async fn send_to_no_subscribers_is_zero() {
        let hub = BroadcastHub::new();
        let n = hub
            .send(
                42,
                RoomEvent::MemberLeft(MemberLeftEvent {
                    room_id: 42,
                    user_id: 1,
                    username: "x".into(),
                }),
            )
            .await;
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn drop_room_closes_channel() {
        let hub = BroadcastHub::new();
        let mut rx = hub.subscribe(99).await;
        hub.drop_room(99).await;
        // Channel sender dropped → receiver eventually returns Closed.
        let res = rx.recv().await;
        assert!(matches!(
            res,
            Err(tokio::sync::broadcast::error::RecvError::Closed)
        ));
    }
}
