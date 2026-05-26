//! Signal handling for `secretary-sync` — SIGINT / SIGTERM flip a
//! shared shutdown flag the daemon already polls.
//!
//! Spec: [`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`](../../../docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md)
//! §"Public surface" — Signal handling.
//!
//! The daemon ([`crate::daemon`]) checks `DaemonConfig::shutdown_flag`
//! every loop iteration (worst-case cancellation latency =
//! `DEFAULT_SHUTDOWN_POLL_INTERVAL`, default 1 s). Installing the
//! handlers returned by [`install_shutdown_handlers`] wires SIGINT
//! (operator Ctrl-C) and SIGTERM (orchestrator stop) to that flag.
//!
//! **Unix-only:** per spec §D10 Windows is best-effort and not a
//! primary target; `signal-hook` is gated to `cfg(unix)` in
//! `cli/Cargo.toml`. The non-Unix surface of this module returns a
//! permanently-false flag with no handlers installed; operators on
//! non-Unix targets terminate the binary via the OS's task manager.

use std::io;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

/// Signals the `secretary-sync` daemon installs as default shutdown
/// triggers on Unix. SIGINT (operator Ctrl-C) and SIGTERM (orchestrator
/// stop) both flip the shared flag; SIGTERM-without-SIGINT covers
/// `systemd stop` / `kubectl delete pod` style termination paths where
/// the operator never opens an interactive shell.
#[cfg(unix)]
pub const DEFAULT_SHUTDOWN_SIGNALS: &[i32] =
    &[signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM];

/// On non-Unix the default-signal list is empty — no handlers are
/// installed. Kept as a `&'static [i32]` so call-sites can iterate
/// without `cfg`-gating their own code.
#[cfg(not(unix))]
pub const DEFAULT_SHUTDOWN_SIGNALS: &[i32] = &[];

/// RAII guard for installed shutdown handlers. Holds the shared
/// `Arc<AtomicBool>` flag that the daemon polls, plus the
/// `signal-hook` registration IDs for the signals it installed.
/// Dropping the guard unregisters every handler it installed, restoring
/// any prior chained handler (`signal-hook::flag::register` chains
/// rather than replaces, so the pre-existing handler keeps running
/// after we unregister).
///
/// Production code holds the guard for the lifetime of the daemon;
/// tests drop it to verify clean teardown and to allow re-installation
/// in subsequent assertions.
pub struct ShutdownGuard {
    flag: Arc<AtomicBool>,
    #[cfg(unix)]
    sig_ids: Vec<signal_hook::SigId>,
}

impl ShutdownGuard {
    /// Borrow the shutdown flag. The daemon clones this into
    /// [`crate::daemon::DaemonConfig::shutdown_flag`].
    pub fn flag(&self) -> &Arc<AtomicBool> {
        &self.flag
    }

    /// Number of signal handlers this guard currently owns. Always `0`
    /// on non-Unix. Useful for tests that want to assert the install
    /// hooked every requested signal without exposing the internal
    /// `SigId` collection.
    pub fn registered_count(&self) -> usize {
        #[cfg(unix)]
        {
            self.sig_ids.len()
        }
        #[cfg(not(unix))]
        {
            0
        }
    }
}

impl Drop for ShutdownGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        for id in self.sig_ids.drain(..) {
            signal_hook::low_level::unregister(id);
        }
    }
}

/// Install handlers for the platform-default shutdown signals (SIGINT
/// + SIGTERM on Unix; none on non-Unix).
///
/// Returns a [`ShutdownGuard`] whose [`ShutdownGuard::flag`] starts
/// `false` and is flipped to `true` by either signal.
pub fn install_shutdown_handlers() -> io::Result<ShutdownGuard> {
    install_shutdown_handlers_for(DEFAULT_SHUTDOWN_SIGNALS)
}

/// Install shutdown-flag handlers for an arbitrary signal set.
///
/// Test-facing surface: unit tests register on `SIGUSR1` (which is
/// rarely used elsewhere and won't interfere with the Rust test
/// harness's own SIGINT handling) and raise it via
/// `signal_hook::low_level::raise` to verify the flag-flip behavior.
///
/// On non-Unix the `signals` slice is ignored and a no-op guard is
/// returned. A `tracing::warn!` is emitted at install time so the
/// operator knows the binary will not respond to signals on this
/// platform (per spec §D10).
pub fn install_shutdown_handlers_for(signals: &[i32]) -> io::Result<ShutdownGuard> {
    let flag = Arc::new(AtomicBool::new(false));
    #[cfg(unix)]
    {
        let mut sig_ids = Vec::with_capacity(signals.len());
        for sig in signals {
            let id = signal_hook::flag::register(*sig, Arc::clone(&flag))?;
            sig_ids.push(id);
        }
        Ok(ShutdownGuard { flag, sig_ids })
    }
    #[cfg(not(unix))]
    {
        let _ = signals;
        tracing::warn!(
            target: "secretary_sync::signal",
            "non-Unix build: shutdown signal handlers unavailable (per spec D10); \
             use the OS task manager to terminate"
        );
        Ok(ShutdownGuard { flag })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    /// All signal-handling tests share process-global state (the kernel
    /// signal-disposition table). Serialise them with this mutex to
    /// keep parallel `cargo test` runs deterministic — without it the
    /// `raise → flag-flip` test can race with a concurrent
    /// `install → drop` test and observe a partially-installed state.
    static SIGNAL_TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Maximum time the flag-flip test waits for the signal handler to
    /// run. `signal_hook::low_level::raise` is synchronous on Unix and
    /// the handler runs before `raise` returns, but on a heavily-loaded
    /// CI runner there can still be a brief delay before the
    /// `AtomicBool` write becomes visible to the polling thread.
    const FLAG_FLIP_TIMEOUT: Duration = Duration::from_millis(500);

    /// Interval between flag-flip polls while waiting for the handler
    /// to run. Short enough that the test completes well under
    /// [`FLAG_FLIP_TIMEOUT`] on a normal run.
    const FLAG_FLIP_POLL_INTERVAL: Duration = Duration::from_millis(5);

    /// A freshly installed guard with an empty signal set holds a
    /// false flag and zero registered handlers. Pins the constructor
    /// contract — the flag must NOT start at the "shutdown requested"
    /// state, or every daemon run would exit on first iteration.
    #[test]
    fn empty_signal_set_returns_clean_guard() {
        let _lock = SIGNAL_TEST_LOCK.lock().unwrap();
        let guard = install_shutdown_handlers_for(&[]).expect("install must succeed");
        assert!(
            !guard.flag().load(Ordering::SeqCst),
            "flag must start false"
        );
        assert_eq!(guard.registered_count(), 0);
    }

    /// `install_shutdown_handlers` registers exactly the
    /// `DEFAULT_SHUTDOWN_SIGNALS` set. Catches the regression where a
    /// future edit removes one signal silently — a SIGTERM-only-aware
    /// orchestrator would not be able to stop the daemon.
    #[test]
    fn default_install_registers_default_signals() {
        let _lock = SIGNAL_TEST_LOCK.lock().unwrap();
        let guard = install_shutdown_handlers().expect("default install must succeed");
        assert_eq!(guard.registered_count(), DEFAULT_SHUTDOWN_SIGNALS.len());
        assert!(!guard.flag().load(Ordering::SeqCst));
    }

    /// Dropping a guard unregisters its handlers, so a signal raised
    /// afterwards does NOT flip its (still-held) flag. Done end-to-end
    /// on `SIGUSR1`: install guard A, keep a clone of its flag, drop
    /// guard A, install guard B for the same signal, raise the signal,
    /// then assert only guard B's flag flipped.
    ///
    /// Guard B's `SIGUSR1` registration is the critical safety net —
    /// without an active handler, the default disposition for
    /// `SIGUSR1` is "terminate the process" and the test runner dies.
    /// (Confirmed empirically: an earlier version of this test raised
    /// `SIGUSR1` with no handler installed and the test binary exited
    /// on signal 30 = `SIGUSR1` on macOS.)
    ///
    /// Catches the regression where the `Drop` impl forgets to call
    /// `signal_hook::low_level::unregister` and leaks `SigId`s —
    /// guard A's flag would also flip and the assertion would fail.
    #[test]
    fn drop_unregisters_handlers() {
        let _lock = SIGNAL_TEST_LOCK.lock().unwrap();
        let flag_a = {
            let guard_a = install_shutdown_handlers_for(&[signal_hook::consts::SIGUSR1])
                .expect("install A must succeed");
            Arc::clone(guard_a.flag())
        };
        let guard_b = install_shutdown_handlers_for(&[signal_hook::consts::SIGUSR1])
            .expect("install B must succeed");
        signal_hook::low_level::raise(signal_hook::consts::SIGUSR1)
            .expect("raising our own SIGUSR1 must not fail");
        let deadline = Instant::now() + FLAG_FLIP_TIMEOUT;
        while Instant::now() < deadline && !guard_b.flag().load(Ordering::SeqCst) {
            std::thread::sleep(FLAG_FLIP_POLL_INTERVAL);
        }
        assert!(
            guard_b.flag().load(Ordering::SeqCst),
            "guard B's flag must flip — its handler is active"
        );
        assert!(
            !flag_a.load(Ordering::SeqCst),
            "guard A's flag must NOT flip after guard A was dropped"
        );
    }

    /// Raising a registered signal flips the flag. Uses `SIGUSR1`
    /// (instead of SIGINT / SIGTERM) so the test does not race with
    /// the Rust test harness's own signal handlers. End-to-end pin of
    /// "signal arrives → daemon sees flag = true".
    #[test]
    fn raising_registered_signal_flips_flag() {
        let _lock = SIGNAL_TEST_LOCK.lock().unwrap();
        let guard = install_shutdown_handlers_for(&[signal_hook::consts::SIGUSR1])
            .expect("install SIGUSR1 handler");
        assert!(!guard.flag().load(Ordering::SeqCst));
        signal_hook::low_level::raise(signal_hook::consts::SIGUSR1)
            .expect("raising our own SIGUSR1 must not fail");
        let deadline = Instant::now() + FLAG_FLIP_TIMEOUT;
        while Instant::now() < deadline {
            if guard.flag().load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(FLAG_FLIP_POLL_INTERVAL);
        }
        assert!(
            guard.flag().load(Ordering::SeqCst),
            "flag must flip to true after the signal is raised"
        );
    }

    /// After the flag flips it stays flipped — handlers do not
    /// auto-reset. The daemon polls until shutdown completes and would
    /// loop forever if the flag self-cleared. Pins the
    /// `Ordering::SeqCst`-store-without-clear contract.
    #[test]
    fn flag_stays_set_after_flip() {
        let _lock = SIGNAL_TEST_LOCK.lock().unwrap();
        let guard = install_shutdown_handlers_for(&[signal_hook::consts::SIGUSR1])
            .expect("install SIGUSR1 handler");
        signal_hook::low_level::raise(signal_hook::consts::SIGUSR1).expect("raise");
        let deadline = Instant::now() + FLAG_FLIP_TIMEOUT;
        while Instant::now() < deadline && !guard.flag().load(Ordering::SeqCst) {
            std::thread::sleep(FLAG_FLIP_POLL_INTERVAL);
        }
        assert!(guard.flag().load(Ordering::SeqCst));
        std::thread::sleep(Duration::from_millis(20));
        assert!(
            guard.flag().load(Ordering::SeqCst),
            "flag must remain true — no self-reset path is acceptable"
        );
    }

    /// `DEFAULT_SHUTDOWN_SIGNALS` contains SIGINT and SIGTERM (in that
    /// order) on Unix. Pinning the order keeps a future
    /// `[SIGTERM, SIGINT]` edit from silently inverting the table —
    /// not a correctness issue, but the spec D10 surface says SIGINT
    /// is documented first.
    #[test]
    fn default_signals_are_sigint_then_sigterm() {
        assert_eq!(DEFAULT_SHUTDOWN_SIGNALS.len(), 2);
        assert_eq!(DEFAULT_SHUTDOWN_SIGNALS[0], signal_hook::consts::SIGINT);
        assert_eq!(DEFAULT_SHUTDOWN_SIGNALS[1], signal_hook::consts::SIGTERM);
    }
}

#[cfg(all(test, not(unix)))]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    /// Non-Unix smoke test: install must return a guard whose flag is
    /// false and whose registered count is zero. The function emits a
    /// `tracing::warn!` but does not error.
    #[test]
    fn non_unix_install_returns_no_op_guard() {
        let guard = install_shutdown_handlers().expect("install must succeed on non-Unix");
        assert!(!guard.flag().load(Ordering::SeqCst));
        assert_eq!(guard.registered_count(), 0);
    }
}
