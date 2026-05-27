//! Pure idle tracker for the auto-lock timer. The actual timer thread and
//! the lock action live in `session.rs` / `main.rs`; this module is pure
//! data + truth-table functions, unit-testable without spinning up Tauri
//! or threads.
//!
//! See spec §6 (vault session lifecycle, auto-lock subsection).

use std::time::{SystemTime, UNIX_EPOCH};

/// Wall-clock milliseconds since the UNIX epoch. Used by both `IdleTracker`
/// and the timer thread to compute "now". Pulled out as a free function so
/// tests can inject a fixed value via the `is_expired` argument rather than
/// monkey-patching the clock.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_millis() as u64
}

/// Records the wall-clock time of the most recent UI activity. The auto-lock
/// timer thread checks `is_expired(threshold_ms, now_ms())` each tick.
#[derive(Debug, Clone, Copy)]
pub struct IdleTracker {
    pub last_activity_ms: u64,
}

impl IdleTracker {
    /// Construct fresh — `last_activity_ms` initialized to "now".
    pub fn new(now_ms: u64) -> Self {
        Self {
            last_activity_ms: now_ms,
        }
    }

    /// Mark activity at the given wall-clock time.
    ///
    /// Only advances forward — protects against clock skew that could
    /// make `last_activity_ms` jump into the past, which would cause a
    /// spurious auto-lock on the next tick.
    pub fn notify(&mut self, now_ms: u64) {
        if now_ms > self.last_activity_ms {
            self.last_activity_ms = now_ms;
        }
    }

    /// Returns true if `now_ms - last_activity_ms >= threshold_ms`.
    ///
    /// Underflow-safe: if the clock has gone backwards (rare; resume from
    /// suspend on some systems), returns false rather than panicking.
    pub fn is_expired(&self, threshold_ms: u64, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.last_activity_ms) >= threshold_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{AUTO_LOCK_DEFAULT_MS, AUTO_LOCK_TICK_MS};

    #[test]
    fn fresh_tracker_is_not_expired() {
        let t = IdleTracker::new(1_000);
        assert!(!t.is_expired(AUTO_LOCK_DEFAULT_MS, 1_000));
    }

    #[test]
    fn expired_after_threshold() {
        let t = IdleTracker::new(0);
        // Exactly at the threshold counts as expired (>= comparison).
        assert!(t.is_expired(AUTO_LOCK_DEFAULT_MS, AUTO_LOCK_DEFAULT_MS));
    }

    #[test]
    fn not_expired_just_before_threshold() {
        let t = IdleTracker::new(0);
        assert!(!t.is_expired(AUTO_LOCK_DEFAULT_MS, AUTO_LOCK_DEFAULT_MS - 1));
    }

    #[test]
    fn notify_advances_forward() {
        let mut t = IdleTracker::new(1_000);
        t.notify(5_000);
        assert_eq!(t.last_activity_ms, 5_000);
    }

    #[test]
    fn notify_ignores_backward_clock() {
        let mut t = IdleTracker::new(5_000);
        t.notify(1_000); // backward — clock skew or test fixture mistake
        assert_eq!(t.last_activity_ms, 5_000, "must not advance backward");
    }

    #[test]
    fn underflow_safe_on_backward_clock() {
        let t = IdleTracker::new(10_000);
        // "now" before "last_activity" — saturating_sub returns 0,
        // 0 < threshold, so not expired.
        assert!(!t.is_expired(AUTO_LOCK_DEFAULT_MS, 5_000));
    }

    #[test]
    fn tick_interval_constant_is_usable() {
        // Smoke: ensure tick interval is strictly positive. Compile-time
        // known, so use a const block — clippy correctly flags `assert!`
        // on compile-time constants as not a runtime test.
        const _: () = assert!(AUTO_LOCK_TICK_MS > 0);
    }

    #[test]
    fn now_ms_is_after_2020() {
        // Sanity: this code is being written in 2026; if `now_ms` returns
        // something before 2020 the system clock is broken (or we accidentally
        // started returning seconds instead of milliseconds).
        const JAN_1_2020_MS: u64 = 1_577_836_800_000;
        assert!(now_ms() > JAN_1_2020_MS);
    }
}
