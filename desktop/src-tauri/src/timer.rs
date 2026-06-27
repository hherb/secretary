//! Auto-lock timer logic.
//!
//! The actual OS-thread spawn + Tauri event emission live in `main`;
//! this module is the pure tick body — testable without spinning up a
//! Tauri runtime.
//!
//! See spec §6 (vault session lifecycle, auto-lock subsection).
//!
//! # Design: one mutex acquisition per tick
//!
//! The plan's original sketch took the auto-lock threshold as a parameter to
//! `tick`. That forced the thread loop in `main.rs` to either (a) acquire
//! the mutex twice per tick (once to read `auto_lock_timeout_ms`, once to
//! check expiry — racing if the user changed settings between the two), or
//! (b) inline the entire tick body in `main.rs` and bypass this module.
//!
//! The Task 5 implementation chooses a third option: `tick` reads the
//! threshold from `session.current_settings()` inside the same lock
//! acquisition that checks `should_auto_lock`. The pure-function surface
//! stays testable, and there is no race window where the threshold and the
//! expiry check could observe different versions of settings.

use std::sync::Mutex;

use crate::session::VaultSession;

/// Outcome of a single timer tick. The thread loop in `main` uses this
/// to decide whether to emit the `vault-locked` event.
#[derive(Debug, PartialEq, Eq)]
pub enum TickOutcome {
    /// Session is locked, or unlocked but not yet expired. The thread
    /// loop does nothing; the next tick will retry.
    NoAction,
    /// Session was unlocked, exceeded its auto-lock threshold, and was
    /// locked by this tick. The thread loop must emit `vault-locked`
    /// with `{ "reason": "auto" }`.
    AutoLocked,
    /// Session mutex was held by another caller (in-flight IPC command).
    /// The tick is dropped — the next tick will retry. Distinct from
    /// `NoAction` so the thread loop can record metrics if useful later.
    Skipped,
    /// Session mutex is **poisoned**: a prior holder panicked while owning
    /// the guard, so the auto-lock timer can never make progress again until
    /// the process restarts. Distinct from [`TickOutcome::Skipped`] (benign,
    /// self-healing contention) so the thread loop can surface a one-shot
    /// `tracing::error!` rather than stalling silently forever (#147). `tick`
    /// stays pure — it reports the condition; the loop edge does the logging.
    Poisoned,
}

/// Single timer-tick body. Non-blocking: acquires the session mutex via
/// `try_lock` so a long-running IPC command never stalls the timer thread.
///
/// Inside the single critical section, reads the current threshold from
/// `session.current_settings().auto_lock_timeout_ms` and checks
/// [`VaultSession::should_auto_lock`]. If the session is unlocked and
/// expired, calls [`VaultSession::lock`] and returns
/// [`TickOutcome::AutoLocked`] so the caller can emit the
/// `vault-locked` event.
///
/// Pure function — no Tauri dependency, no thread::sleep, no I/O (a poisoned
/// mutex is reported as [`TickOutcome::Poisoned`], not logged here; the loop
/// edge owns the I/O). The thread spawn + sleep + event emission live in
/// `main.rs`.
pub fn tick(session_mutex: &Mutex<VaultSession>) -> TickOutcome {
    let mut session = match session_mutex.try_lock() {
        Ok(guard) => guard,
        // Another caller holds the mutex; benign — the next tick retries.
        Err(std::sync::TryLockError::WouldBlock) => return TickOutcome::Skipped,
        // A prior holder panicked while locked: the timer is dead until the
        // process restarts. Report it distinctly so the loop edge logs once.
        Err(std::sync::TryLockError::Poisoned(_)) => return TickOutcome::Poisoned,
    };

    let threshold_ms = session.current_settings().auto_lock_timeout_ms;
    if session.should_auto_lock(threshold_ms) {
        session.lock();
        TickOutcome::AutoLocked
    } else {
        TickOutcome::NoAction
    }
}

/// One-shot latch for the poisoned-mutex error log. A poisoned session mutex
/// stays poisoned for the life of the process, so the timer loop emits
/// [`TickOutcome::Poisoned`] on every tick — logging each one would spam
/// `error!` once per interval forever. This returns `true` exactly once (the
/// first call), flipping `already_logged`, so the caller logs a single
/// operator-visible signal and stays quiet thereafter (#147).
///
/// Pure decision — the actual `tracing::error!` lives at the call site in
/// `main.rs`; keeping the anti-spam logic here makes it unit-testable without
/// driving the binary's infinite timer loop.
pub fn poison_should_log(already_logged: &mut bool) -> bool {
    if *already_logged {
        false
    } else {
        *already_logged = true;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// Build a fresh (locked) session in a TempDir. The TempDir owns the
    /// per-vault device-UUID storage and must outlive the session — every
    /// caller binds it to a local variable.
    fn locked_session() -> (Mutex<VaultSession>, TempDir) {
        let tmp = TempDir::new().expect("device-uuid tempdir");
        let dir: PathBuf = tmp.path().to_path_buf();
        (Mutex::new(VaultSession::new(dir)), tmp)
    }

    #[test]
    fn tick_returns_no_action_on_locked_session() {
        let (mutex, _tmp) = locked_session();
        assert_eq!(tick(&mutex), TickOutcome::NoAction);
    }

    #[test]
    fn locked_session_unchanged_by_tick() {
        let (mutex, _tmp) = locked_session();
        assert!(!mutex.lock().expect("lock").is_unlocked());
        let _ = tick(&mutex);
        assert!(
            !mutex.lock().expect("lock").is_unlocked(),
            "ticking a locked session must be a no-op"
        );
    }

    #[test]
    fn tick_returns_skipped_when_mutex_contended() {
        let (mutex, _tmp) = locked_session();
        // Hold the lock externally to simulate a mid-flight IPC command.
        let _guard = mutex.lock().expect("hold lock externally");
        assert_eq!(tick(&mutex), TickOutcome::Skipped);
    }

    #[test]
    fn contended_tick_does_not_block() {
        // Belt-and-braces companion to the "Skipped" check: ensure the
        // contended path returns promptly (try_lock semantics) rather
        // than blocking the timer thread. If `tick` ever regresses to
        // `lock()` (blocking) this test would hang the suite.
        let (mutex, _tmp) = locked_session();
        let _guard = mutex.lock().expect("hold lock externally");
        let start = std::time::Instant::now();
        let _ = tick(&mutex);
        assert!(
            start.elapsed() < std::time::Duration::from_millis(50),
            "tick must use try_lock; took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn tick_returns_poisoned_when_mutex_poisoned() {
        // A panic while a prior holder owned the session mutex poisons it.
        // Unlike a command `*_impl` (which surfaces poison → `AppError::Internal`
        // to its caller), the timer thread has no caller — so `tick` must report
        // `Poisoned` distinctly from the benign contended `Skipped` path, letting
        // the loop edge log once instead of silently stalling forever (#147).
        //
        // Poison by panicking a thread while it holds the guard — the established
        // pattern in `commands::shared`. `thread::scope` lets the child borrow the
        // local mutex without an `Arc`; the explicit `.join()` swallows the
        // expected `Err(panicked)`.
        let (mutex, _tmp) = locked_session();
        std::thread::scope(|s| {
            let _ = s
                .spawn(|| {
                    let _guard = mutex.lock().expect("acquire to poison");
                    panic!("deliberate poison");
                })
                .join(); // Err(panicked)
        });
        assert!(mutex.is_poisoned(), "thread panic must poison the mutex");
        assert_eq!(tick(&mutex), TickOutcome::Poisoned);
    }

    #[test]
    fn poison_should_log_fires_exactly_once() {
        // The anti-spam guarantee (#147): the loop sees `Poisoned` on every
        // tick once the mutex is poisoned, but the operator must get a single
        // error log, not one per interval forever. The latch returns `true`
        // only on the first call and `false` for every call after.
        let mut latch = false;
        assert!(
            poison_should_log(&mut latch),
            "first poisoned tick must log"
        );
        assert!(latch, "latch must flip on the first log");
        for _ in 0..5 {
            assert!(
                !poison_should_log(&mut latch),
                "subsequent poisoned ticks must stay quiet"
            );
        }
    }

    #[test]
    fn tick_outcome_distinct_variants() {
        // Sanity for the enum — keep the variants distinct so a future
        // "AutoLocked → NoAction" merge can't slip through a refactor.
        assert_ne!(TickOutcome::NoAction, TickOutcome::AutoLocked);
        assert_ne!(TickOutcome::NoAction, TickOutcome::Skipped);
        assert_ne!(TickOutcome::AutoLocked, TickOutcome::Skipped);
        assert_ne!(TickOutcome::Skipped, TickOutcome::Poisoned);
        assert_ne!(TickOutcome::NoAction, TickOutcome::Poisoned);
    }

    // The `AutoLocked` happy path requires an `UnlockedSession`, which
    // needs the golden vault to construct. That test lives in
    // `tests/session_integration.rs` — see
    // `timer_tick_auto_locks_expired_unlocked_session`.
}
