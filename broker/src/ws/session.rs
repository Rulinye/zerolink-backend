//! Session store — the source of truth for "user X is in room Y".
//!
//! Decisions in play:
//!   - B2: WS disconnect does NOT immediately leave the room. Instead,
//!     the session enters a 30-second grace window during which a
//!     reconnect via resume_session restores it.
//!   - A: During the grace window, OTHER members see no event — to
//!     them the user is still in the room with their original
//!     joined_at. Only after the grace expires does a member_left
//!     event fire (issued by the GraceWatchdog).
//!
//! Lifecycle:
//!
//!   created via SessionStore::create()
//!     ↓ (ws bound, grace_until = None)
//!   ws closes → SessionStore::detach()
//!     ↓ (ws unbound, grace_until = now + 30s)
//!   resume_session → SessionStore::reattach()
//!     ↓ (ws rebound, grace_until = None)
//!   grace_until < now → grace_watchdog finalizes
//!     ↓ (member row deleted, member_left broadcast, session removed)
//!
//! There is at most one active session per (user_id) in this broker.
//! Attempting to create a second one is rejected by the caller (ws
//! handler) after consulting `SessionStore::find_by_user`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::RngCore;
use tokio::sync::Mutex;

pub const GRACE_DURATION: Duration = Duration::from_secs(30);

/// Logical handle a WS connection holds while bound to a session. A
/// fresh handle is allocated on every (re)attach, so that an old
/// handle held by a prior ws task can no longer modify session state
/// after the session was reattached to a new ws.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WsBinding(u64);

impl WsBinding {
    fn next() -> Self {
        // Monotonic counter is enough; we only need to compare equal/
        // not-equal for "is this still the bound ws?".
        use std::sync::atomic::{AtomicU64, Ordering};
        static C: AtomicU64 = AtomicU64::new(1);
        WsBinding(C.fetch_add(1, Ordering::Relaxed))
    }
}

#[derive(Debug)]
pub struct SessionRecord {
    pub session_id: String,
    pub user_id: i64,
    pub username: String,
    pub room_id: i64,
    /// Some(handle) when a ws is currently bound; None during grace
    /// (after detach, before reattach or expiry).
    pub bound_ws: Option<WsBinding>,
    /// Some(deadline) when in grace; None when bound.
    pub grace_until: Option<Instant>,
}

#[derive(Clone, Default)]
pub struct SessionStore {
    inner: Arc<Mutex<Inner>>,
}

#[derive(Default)]
struct Inner {
    /// Primary index: session_id → record.
    sessions: HashMap<String, SessionRecord>,
    /// Secondary index: user_id → session_id. Used to enforce "one
    /// active session per user" cheaply on join.
    by_user: HashMap<i64, String>,
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("user already has an active session")]
    AlreadyExists,

    #[error("session not found")]
    NotFound,

    #[error("session belongs to a different user")]
    OwnerMismatch,

    #[error("session grace expired")]
    Expired,

    #[error("session is currently bound to another ws")]
    AlreadyBound,
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new session bound to a fresh WS. Caller is expected
    /// to have verified that the user has no existing session via
    /// `find_by_user` (cache+DB), but this method also rejects
    /// duplicates as a final guard.
    pub async fn create(
        &self,
        user_id: i64,
        username: String,
        room_id: i64,
    ) -> Result<(SessionRecord, WsBinding), SessionError> {
        let mut inner = self.inner.lock().await;
        if inner.by_user.contains_key(&user_id) {
            return Err(SessionError::AlreadyExists);
        }
        let session_id = generate_session_id();
        let binding = WsBinding::next();
        let rec = SessionRecord {
            session_id: session_id.clone(),
            user_id,
            username,
            room_id,
            bound_ws: Some(binding),
            grace_until: None,
        };
        inner.by_user.insert(user_id, session_id.clone());
        let snapshot = clone_record(&rec);
        inner.sessions.insert(session_id, rec);
        Ok((snapshot, binding))
    }

    /// Find a user's existing session if any. None means the user has
    /// no session in this broker at all.
    pub async fn find_by_user(&self, user_id: i64) -> Option<SessionRecord> {
        let inner = self.inner.lock().await;
        inner
            .by_user
            .get(&user_id)
            .and_then(|sid| inner.sessions.get(sid))
            .map(clone_record)
    }

    /// Detach a ws from its session. If `binding` matches the
    /// session's current bound_ws, the session enters grace.
    /// Otherwise (the session has already been re-bound to a newer
    /// ws) this is a no-op — the old ws is just disposed.
    ///
    /// Returns `Some(session_id)` if this call actually moved the
    /// session into grace, `None` otherwise.
    pub async fn detach(&self, session_id: &str, binding: WsBinding) -> Option<String> {
        let mut inner = self.inner.lock().await;
        let rec = inner.sessions.get_mut(session_id)?;
        if rec.bound_ws != Some(binding) {
            // Session moved on; old ws closing is irrelevant.
            return None;
        }
        rec.bound_ws = None;
        rec.grace_until = Some(Instant::now() + GRACE_DURATION);
        Some(session_id.to_string())
    }

    /// Re-bind a session that was in grace to a fresh ws. Caller
    /// already verified that user_id matches via JWT.
    pub async fn reattach(
        &self,
        session_id: &str,
        user_id: i64,
    ) -> Result<(SessionRecord, WsBinding), SessionError> {
        let mut inner = self.inner.lock().await;
        let Some(rec) = inner.sessions.get_mut(session_id) else {
            return Err(SessionError::NotFound);
        };
        if rec.user_id != user_id {
            return Err(SessionError::OwnerMismatch);
        }
        if rec.bound_ws.is_some() {
            return Err(SessionError::AlreadyBound);
        }
        if let Some(deadline) = rec.grace_until {
            if Instant::now() >= deadline {
                return Err(SessionError::Expired);
            }
        }
        let binding = WsBinding::next();
        rec.bound_ws = Some(binding);
        rec.grace_until = None;
        Ok((clone_record(rec), binding))
    }

    /// Forcibly remove a session (used by leave_room, destroy_room,
    /// and the grace watchdog when the deadline is hit). Returns
    /// the removed record so the caller can dispatch the necessary
    /// downstream effects (member_left broadcast, member row delete).
    pub async fn remove(&self, session_id: &str) -> Option<SessionRecord> {
        let mut inner = self.inner.lock().await;
        let rec = inner.sessions.remove(session_id)?;
        // Maintain the by_user index. Skip if it's been overwritten
        // by a fresher session under the same user (shouldn't
        // happen because we enforce one-per-user, but defensive).
        if let Some(ref_sid) = inner.by_user.get(&rec.user_id) {
            if ref_sid == &rec.session_id {
                inner.by_user.remove(&rec.user_id);
            }
        }
        Some(rec)
    }

    /// Snapshot of all sessions currently in grace whose deadline has
    /// expired. Returned records have already been removed from the
    /// store. The grace watchdog uses this to fan out the
    /// member_left broadcast + member-row delete.
    pub async fn drain_expired(&self) -> Vec<SessionRecord> {
        let mut inner = self.inner.lock().await;
        let now = Instant::now();
        let expired_ids: Vec<String> = inner
            .sessions
            .iter()
            .filter(|(_, rec)| rec.bound_ws.is_none() && rec.grace_until.is_some_and(|d| d <= now))
            .map(|(sid, _)| sid.clone())
            .collect();

        let mut out = Vec::with_capacity(expired_ids.len());
        for sid in expired_ids {
            if let Some(rec) = inner.sessions.remove(&sid) {
                if let Some(ref_sid) = inner.by_user.get(&rec.user_id) {
                    if ref_sid == &rec.session_id {
                        inner.by_user.remove(&rec.user_id);
                    }
                }
                out.push(rec);
            }
        }
        out
    }
}

fn clone_record(r: &SessionRecord) -> SessionRecord {
    SessionRecord {
        session_id: r.session_id.clone(),
        user_id: r.user_id,
        username: r.username.clone(),
        room_id: r.room_id,
        bound_ws: r.bound_ws,
        grace_until: r.grace_until,
    }
}

fn generate_session_id() -> String {
    // 16 bytes random → 32 hex chars. Prefixed with "s_" so logs are
    // greppable.
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("s_{}", hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn create_then_find_then_remove() {
        let store = SessionStore::new();
        let (rec, _b) = store.create(42, "alice".into(), 7).await.unwrap();
        let found = store.find_by_user(42).await.unwrap();
        assert_eq!(found.session_id, rec.session_id);
        let removed = store.remove(&rec.session_id).await.unwrap();
        assert_eq!(removed.session_id, rec.session_id);
        assert!(store.find_by_user(42).await.is_none());
    }

    #[tokio::test]
    async fn duplicate_create_rejected() {
        let store = SessionStore::new();
        store.create(42, "a".into(), 7).await.unwrap();
        let r = store.create(42, "a".into(), 7).await;
        assert!(matches!(r, Err(SessionError::AlreadyExists)));
    }

    #[tokio::test]
    async fn detach_starts_grace() {
        let store = SessionStore::new();
        let (rec, binding) = store.create(42, "alice".into(), 7).await.unwrap();
        let detached = store.detach(&rec.session_id, binding).await;
        assert_eq!(detached, Some(rec.session_id.clone()));
        let after = store.find_by_user(42).await.unwrap();
        assert!(after.bound_ws.is_none());
        assert!(after.grace_until.is_some());
    }

    #[tokio::test]
    async fn detach_with_stale_binding_is_noop() {
        let store = SessionStore::new();
        let (rec, _binding_a) = store.create(42, "alice".into(), 7).await.unwrap();
        // Pretend we already reattached with a new binding.
        let stale = WsBinding(99999);
        let result = store.detach(&rec.session_id, stale).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn reattach_after_detach() {
        let store = SessionStore::new();
        let (rec, b1) = store.create(42, "alice".into(), 7).await.unwrap();
        store.detach(&rec.session_id, b1).await.unwrap();
        let (rec2, b2) = store.reattach(&rec.session_id, 42).await.unwrap();
        assert_eq!(rec2.session_id, rec.session_id);
        assert!(rec2.bound_ws.is_some());
        assert!(rec2.grace_until.is_none());
        assert_ne!(b1, b2);
    }

    #[tokio::test]
    async fn reattach_owner_mismatch() {
        let store = SessionStore::new();
        let (rec, b1) = store.create(42, "alice".into(), 7).await.unwrap();
        store.detach(&rec.session_id, b1).await;
        let r = store.reattach(&rec.session_id, 999).await;
        assert!(matches!(r, Err(SessionError::OwnerMismatch)));
    }

    #[tokio::test]
    async fn reattach_when_bound_rejected() {
        let store = SessionStore::new();
        let (rec, _b1) = store.create(42, "alice".into(), 7).await.unwrap();
        let r = store.reattach(&rec.session_id, 42).await;
        assert!(matches!(r, Err(SessionError::AlreadyBound)));
    }
}
