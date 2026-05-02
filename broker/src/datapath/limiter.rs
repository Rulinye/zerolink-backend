//! Per-session token bucket rate limiter.
//!
//! Phase 4 Batch 4.7 supplement / B9 (room half).
//!
//! Each `PathEntry` carries a TokenBucket sized at `rate_limit_bps`.
//! `forward_loop` calls `try_consume(datagram_len)` before forwarding;
//! if not enough tokens, the datagram is DROPPED (not queued —
//! datagram channel doesn't carry retry semantics, real-time games
//! prefer drop-now to delay-later).
//!
//! Rate enforcement is on TOTAL (in + out) bytes — operator's intent
//! "联机限速 20 Mbps" is throughput regardless of direction. The
//! bucket counts both directions against the same budget.
//!
//! Burst capacity = 1 second worth of bytes at the configured rate.
//! Lets short bursts (game tick spikes, voice keyframes) through
//! while still bounding the steady-state.

use std::time::Instant;

#[derive(Debug)]
pub struct TokenBucket {
    /// Maximum tokens that can accumulate. = rate_bps (1 second of
    /// burst). Capped to prevent burst > 1 second of bandwidth.
    capacity: u64,
    /// Current available tokens (bytes).
    tokens: u64,
    /// Refill rate in bytes per second.
    rate_bps: u64,
    /// Last time we recomputed `tokens`.
    last_refill: Instant,
}

impl TokenBucket {
    /// Build a new bucket pre-filled to capacity. `rate_bps = 0`
    /// means "unlimited" — try_consume always returns true.
    pub fn new(rate_bps: u64) -> Self {
        Self {
            capacity: rate_bps,
            tokens: rate_bps,
            rate_bps,
            last_refill: Instant::now(),
        }
    }

    /// Update rate (admin live-update path; not currently used by the
    /// 4.7-supp commit but exposed so a future admin-push reconfigure
    /// can lift the new value into running sessions). Resets last_refill
    /// so old elapsed time doesn't suddenly fill a smaller bucket.
    #[allow(dead_code)]
    pub fn set_rate(&mut self, rate_bps: u64) {
        self.refill_now();
        self.capacity = rate_bps;
        self.rate_bps = rate_bps;
        if self.tokens > rate_bps {
            self.tokens = rate_bps;
        }
    }

    /// Attempt to consume `n` tokens. Returns true if granted (n
    /// tokens deducted), false if the bucket lacks them (no
    /// deduction, datagram should be dropped). `rate_bps == 0` means
    /// unlimited and always returns true without touching `tokens`.
    pub fn try_consume(&mut self, n: u64) -> bool {
        if self.rate_bps == 0 {
            return true;
        }
        self.refill_now();
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }

    fn refill_now(&mut self) {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.last_refill);
        // f64 is fine; we don't need sub-byte precision.
        let new_tokens = (self.rate_bps as f64 * elapsed.as_secs_f64()) as u64;
        if new_tokens > 0 {
            self.tokens = self.tokens.saturating_add(new_tokens).min(self.capacity);
            self.last_refill = now;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn unlimited_passes_all() {
        let mut b = TokenBucket::new(0);
        assert!(b.try_consume(1_000_000_000));
    }

    #[test]
    fn under_capacity_consumes() {
        let mut b = TokenBucket::new(1000);
        assert!(b.try_consume(500));
        assert!(b.try_consume(400));
        assert!(!b.try_consume(200)); // only 100 left
    }

    #[test]
    fn refills_over_time() {
        let mut b = TokenBucket::new(1000);
        assert!(b.try_consume(1000)); // drains
        assert!(!b.try_consume(1)); // empty
        sleep(Duration::from_millis(120));
        assert!(b.try_consume(100)); // refilled by ~120 tokens
    }

    #[test]
    fn capped_at_capacity() {
        let mut b = TokenBucket::new(100);
        sleep(Duration::from_millis(500)); // would refill 50 tokens; capacity is 100 so already full
        assert!(b.try_consume(100));
        assert!(!b.try_consume(1));
    }
}
