//! `run` subcommand event loop. Composes the watcher submodule's pure
//! pieces ([`watcher::debounce::step`], [`watcher::notify_driver`]) +
//! the existing [`pipeline::run_one`] into a single-threaded blocking
//! daemon.
//!
//! Spec: [`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`](../../docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md)
//! §"Daemon loop sketch".
//!
//! The loop is **pure orchestration** — it takes a `poll` closure as
//! the event source and an `on_sync` closure as the sync action. This
//! lets the unit tests drive the loop with a scripted event source +
//! a counter, while the production wire-up (see
//! [`run_against_vault`]) plugs in [`watcher::notify_driver::NotifyWatcher`]
//! and a [`pipeline::run_one`] call.
//!
//! ## Trailing-edge debounce
//!
//! The loop honours the trailing-edge debounce semantic that
//! [`watcher::debounce`] documents: every fresh
//! [`watcher::WatcherEvent::SyncCandidate`] *resets* the deadline. The
//! sync only fires once an entire debounce window has elapsed without
//! a new event. The previous design (see C.2 Task 7 plan §"Plan
//! deviation" in the handoff) used a blocking `std::thread::sleep` in
//! the match arm and effectively degraded to *leading-edge with burst
//! coalescing* — that contradicted the semantic Task 6's debounce
//! module + its 5 unit tests pin. The closure-shaped loop here uses
//! the `poll` timeout itself as the debounce timer, which is the
//! straightforward implementation of trailing-edge semantics.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use secretary_core::crypto::secret::SecretBytes;
use secretary_core::sync::{SyncError, SyncState};
use secretary_core::unlock::UnlockedIdentity;
use secretary_core::vault::block::VectorClockEntry;

use crate::pipeline::{run_one, RunOutcome};
use crate::state::{self, StateError};
use crate::veto::VetoUx;
use crate::watcher::debounce::step as debounce_step;
use crate::watcher::notify_driver::NotifyWatcher;
use crate::watcher::ready::{wait_for_ready, RealClock};
use crate::watcher::WatcherEvent;

/// Default upper bound on how long the loop blocks on `poll` without
/// checking the shutdown flag.
///
/// Production daemons leave this at the default. Tests override
/// [`DaemonConfig::shutdown_poll_interval`] with a shorter value so
/// flag-flip assertions don't add a full second to the test suite.
///
/// Picked at 1 s as a balance between operator-visible shutdown
/// latency (Ctrl-C should feel snappy) and per-iteration overhead
/// (no point spinning the loop every 10 ms in an idle daemon).
pub const DEFAULT_SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(1000);

/// Configuration knobs for the daemon loop.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// Trailing-edge debounce window (typically `--debounce-ms`). A
    /// burst of [`WatcherEvent::SyncCandidate`] within `debounce` of
    /// the previous one extends the deadline; the sync fires once
    /// `debounce` has elapsed uninterrupted.
    pub debounce: Duration,
    /// Optional periodic safety-net poll. `None` disables it.
    ///
    /// When `Some(d)`, the loop runs an unconditional sync every `d`
    /// regardless of whether `notify` has surfaced events — defends
    /// against backend gaps (FSEvents coalescing, inotify queue
    /// overflow) at a small cost in wasted attempts.
    pub poll_interval: Option<Duration>,
    /// Upper bound on how long the loop blocks on `poll` without
    /// re-checking [`Self::shutdown_flag`]. Production wires this to
    /// [`DEFAULT_SHUTDOWN_POLL_INTERVAL`]; tests use a smaller value to
    /// keep flag-flip assertions fast.
    pub shutdown_poll_interval: Duration,
    /// Cancellation flag set by the signal handler (SIGINT/SIGTERM,
    /// landing in Task 8). The loop polls this flag at most every
    /// [`Self::shutdown_poll_interval`].
    pub shutdown_flag: Arc<AtomicBool>,
}

/// Run the daemon loop.
///
/// `poll` is the event source — typically `|t| watcher.poll(t)` for
/// a [`NotifyWatcher`]. It MUST block up to its `Duration` argument
/// then return either a `WatcherEvent` or `None` (timeout).
///
/// `on_sync` is invoked exactly once per fired sync (post-debounce or
/// post-periodic-poll). The production callsite passes a closure that
/// calls [`run_one`] + handles its result; tests pass a counter-bump.
///
/// The function returns when:
/// - `config.shutdown_flag` becomes `true`, or
/// - `poll` returns `Some(WatcherEvent::ShutdownRequested)`.
///
/// Pipeline-level errors are the caller's responsibility (the
/// closure logs + continues per spec; this function never sees a
/// [`SyncError`] directly).
pub fn run<P, S>(config: DaemonConfig, mut poll: P, mut on_sync: S)
where
    P: FnMut(Duration) -> Option<WatcherEvent>,
    S: FnMut(),
{
    let mut debounce_pending: Option<Instant> = None;
    let mut last_poll_at = Instant::now();

    loop {
        if config.shutdown_flag.load(Ordering::SeqCst) {
            tracing::debug!("daemon shutdown_flag set; exiting loop");
            return;
        }

        let now = Instant::now();

        // (1) Trailing-edge debounce: window has elapsed uninterrupted
        //     since the last event → fire sync.
        if let Some(pending_since) = debounce_pending {
            if now.duration_since(pending_since) >= config.debounce {
                debounce_pending = None;
                on_sync();
                continue;
            }
        }

        // (2) Periodic safety-net poll due → fire sync regardless of
        //     event activity.
        if let Some(poll_interval) = config.poll_interval {
            if now.duration_since(last_poll_at) >= poll_interval {
                last_poll_at = now;
                on_sync();
                continue;
            }
        }

        // (3) Block on the next event up to whichever deadline comes
        //     first (debounce expiry, next periodic poll, or the
        //     shutdown polling interval).
        let wait = compute_wait(
            now,
            debounce_pending,
            config.debounce,
            config.poll_interval.map(|pi| (pi, last_poll_at)),
            config.shutdown_poll_interval,
        );

        match poll(wait) {
            Some(WatcherEvent::SyncCandidate) => {
                // `_decision` distinguishes Schedule vs Reschedule
                // for telemetry; here the only thing we need is the
                // updated `pending_since`.
                let (_decision, new_pending) =
                    debounce_step(Instant::now(), debounce_pending, config.debounce);
                debounce_pending = new_pending;
            }
            Some(WatcherEvent::ShutdownRequested) => {
                tracing::debug!("daemon received ShutdownRequested; exiting loop");
                return;
            }
            Some(WatcherEvent::PollTick) | None => {
                // PollTick is delivered by the synthetic test source
                // only — production never emits it (the periodic-poll
                // check at the top of the loop handles real
                // backups). None = timeout; loop back.
            }
        }
    }
}

/// Pure helper: smallest of (remaining debounce window, remaining
/// poll interval, shutdown poll interval).
///
/// Pulled out as a free function for the unit tests + for clarity.
/// Saturating arithmetic everywhere so an "already elapsed" deadline
/// yields `Duration::ZERO`, which makes `poll` return immediately on
/// the next call — the top-of-loop checks then fire the appropriate
/// sync.
#[must_use]
fn compute_wait(
    now: Instant,
    debounce_pending: Option<Instant>,
    debounce_window: Duration,
    poll_state: Option<(Duration, Instant)>,
    shutdown_interval: Duration,
) -> Duration {
    let mut wait = shutdown_interval;
    if let Some(pending) = debounce_pending {
        let remaining = debounce_window.saturating_sub(now.duration_since(pending));
        if remaining < wait {
            wait = remaining;
        }
    }
    if let Some((interval, last)) = poll_state {
        let remaining = interval.saturating_sub(now.duration_since(last));
        if remaining < wait {
            wait = remaining;
        }
    }
    wait
}

/// What (if anything) a successful [`RunOutcome`] should announce to the
/// operator. Pure classification — the caller maps it to a `tracing`
/// call. Kept separate from the emission so the decision is unit-testable
/// without a subscriber, and so `pipeline.rs` stays free of logging.
#[derive(Debug, Clone, PartialEq, Eq)]
enum OutcomeLog {
    /// Manifest-rollback attack indicator (threat-model §3.1). Carries
    /// the two clocks an operator needs for forensics.
    RollbackRejected {
        disk: Vec<VectorClockEntry>,
        local: Vec<VectorClockEntry>,
    },
    /// `n > 0` tombstone vetoes were auto-resolved — a peer record
    /// deletion was overridden this pass.
    VetoesResolved(usize),
}

/// Classify an `Ok(RunOutcome)` into the operator-visible log event, if
/// any. The silent arms (`NothingToDo`, `AppliedAutomatically`,
/// `SilentMerge`, and `MergedAndCommitted { vetoes_resolved: 0 }`) return
/// `None`.
fn outcome_log(outcome: &RunOutcome) -> Option<OutcomeLog> {
    match outcome {
        RunOutcome::RollbackRejected(ev) => Some(OutcomeLog::RollbackRejected {
            disk: ev.disk_vector_clock.clone(),
            local: ev.local_highest_seen.clone(),
        }),
        RunOutcome::MergedAndCommitted { vetoes_resolved } if *vetoes_resolved > 0 => {
            Some(OutcomeLog::VetoesResolved(*vetoes_resolved))
        }
        RunOutcome::NothingToDo
        | RunOutcome::AppliedAutomatically
        | RunOutcome::SilentMerge
        | RunOutcome::MergedAndCommitted { .. } => None,
    }
}

/// Emit the operator-visible log line (if any) for a successful sync
/// outcome. The side-effecting edge over the pure [`outcome_log`].
///
/// `pub` because both the daemon loop ([`after_sync`]) and the single-shot
/// `once` dispatch (`main::once_ok_exit_code`, #295) route their `Ok`
/// outcomes through it, so a `once` rollback/veto gets the same forensic
/// log line — disk-vs-local vector clocks, auto-resolved veto counts — the
/// daemon path emits, not just a bare exit code.
pub fn log_outcome(outcome: &RunOutcome) {
    match outcome_log(outcome) {
        Some(OutcomeLog::RollbackRejected { disk, local }) => tracing::warn!(
            disk_clock = ?disk,
            local_clock = ?local,
            "manifest rollback rejected (threat-model §3.1 attack indicator); daemon continues",
        ),
        Some(OutcomeLog::VetoesResolved(n)) => tracing::warn!(
            vetoes_resolved = n,
            "auto-resolved {n} tombstone veto(es): a peer record deletion was overridden",
        ),
        None => {}
    }
}

/// Handle the result of one `run_one` pass: log the operator-visible
/// outcome (#207) and persist `state` (#208) whenever it advanced. `save`
/// is injected (not a direct `state::save` call) so the loop body is
/// unit-testable without a real watcher or filesystem. A save failure is
/// logged and swallowed — the in-memory clock has still advanced, and a
/// transient FS error must not kill a daemon that may run for weeks; the
/// next advancing pass retries the persist.
fn after_sync(
    result: Result<RunOutcome, SyncError>,
    state: &SyncState,
    save: &mut dyn FnMut(&SyncState) -> Result<(), StateError>,
) {
    match result {
        Ok(outcome) => {
            log_outcome(&outcome);
            if outcome.advanced_state() {
                if let Err(e) = save(state) {
                    tracing::warn!("state persist after sync failed (continuing): {e}");
                }
            }
        }
        Err(e) => tracing::warn!("pipeline error (continuing): {e}"),
    }
}

/// Threshold of consecutive `wait_for_ready` → `Ok(false)` returns that
/// triggers a single operator-visible warn log. After this many
/// debounce-fired or periodic-fired cycles in a row where the folder
/// was still being modified, something external (another process,
/// stuck cloud sync agent) is likely the cause and the operator
/// should know — debug-level "skipping sync" lines would otherwise
/// stay invisible at default verbosity.
///
/// Pinned by the [`note_not_ready_and_should_warn`] unit test so the
/// fire-exactly-once-at-threshold semantic is durable.
pub const READY_NOT_READY_WARN_THRESHOLD: u32 = 5;

/// Production composition: start a [`NotifyWatcher`] against
/// `vault_folder`, then run the daemon loop with closures that bridge
/// to [`wait_for_ready`] + [`run_one`].
///
/// The loop's `on_sync` closure:
///
/// 1. Calls [`wait_for_ready`] against `vault_folder` to confirm the
///    folder's metadata has stopped changing across a `ready_window`
///    probe. The check is best-effort — a stat failure or partial
///    marker on the folder itself (impossible in practice) is logged
///    at debug and skipped, not fatal. After
///    [`READY_NOT_READY_WARN_THRESHOLD`] consecutive `Ok(false)`
///    returns a warn-level log fires once so operators notice when
///    something external is continuously modifying the folder and
///    starving the sync; the counter resets on the next `Ok(true)`.
/// 2. Calls [`run_one`] for one sync attempt, then calls
///    [`after_sync`] to log the outcome and persist state if it
///    advanced (#208). A save failure is logged and swallowed;
///    any pipeline [`SyncError`] is logged at warn level and the loop
///    continues per spec §"Daemon loop sketch".
///
/// # Errors
///
/// Returns [`SyncError`] only if [`NotifyWatcher::start`] fails (i.e.
/// the OS refused to set up the file-watch). All in-loop pipeline
/// errors are caught + logged + continued, never propagated.
///
/// This helper is the production seam; it is **not** independently
/// unit-tested because its only logic is the closure composition —
/// the integration test suite (Task 10) will exercise it end-to-end
/// against `golden_vault_001`. Each individual piece (`NotifyWatcher`,
/// `debounce_step`, `wait_for_ready`, `run_one`, `after_sync`) is
/// unit-tested in place.
#[allow(clippy::too_many_arguments)] // production seam — all params are distinct, non-groupable
pub fn run_against_vault(
    vault_folder: &Path,
    identity: &UnlockedIdentity,
    password: &SecretBytes,
    state: &mut SyncState,
    veto_ux: &mut dyn VetoUx,
    state_dir: &Path,
    config: DaemonConfig,
    ready_window: Duration,
) -> Result<(), SyncError> {
    // Production should always use the default; flag accidental zeros
    // (would cause the loop to spin without ever blocking) at startup
    // rather than silently busy-loop in the watcher poll.
    debug_assert!(
        !config.shutdown_poll_interval.is_zero(),
        "DaemonConfig::shutdown_poll_interval must be > 0; use DEFAULT_SHUTDOWN_POLL_INTERVAL in production"
    );
    let watcher = NotifyWatcher::start(vault_folder).map_err(notify_start_to_sync_error)?;
    let clock = RealClock;
    let mut consecutive_not_ready: u32 = 0;
    run(
        config,
        |timeout| watcher.poll(timeout),
        || {
            match wait_for_ready(vault_folder, &clock, ready_window) {
                Ok(true) => {
                    consecutive_not_ready = 0;
                }
                Ok(false) => {
                    if note_not_ready_and_should_warn(
                        &mut consecutive_not_ready,
                        READY_NOT_READY_WARN_THRESHOLD,
                    ) {
                        tracing::warn!(
                            folder = %vault_folder.display(),
                            consecutive_skips = consecutive_not_ready,
                            "vault folder has not become size-stable across {} consecutive sync attempts; another process may be continuously modifying it",
                            READY_NOT_READY_WARN_THRESHOLD,
                        );
                    }
                    tracing::debug!("vault folder not size-stable; skipping sync");
                    return;
                }
                Err(e) => {
                    tracing::debug!("ready probe failed: {e}; skipping sync");
                    return;
                }
            }
            let result = run_one(vault_folder, identity, password, state, veto_ux, now_ms());
            let mut save = |s: &SyncState| state::save(state_dir, s);
            after_sync(result, state, &mut save);
        },
    );
    Ok(())
}

/// Increments `consecutive` (saturating) and returns `true` exactly
/// when the new value equals `threshold` — i.e. on the
/// `threshold`-th consecutive `wait_for_ready → Ok(false)`. Subsequent
/// returns over the threshold do NOT re-fire (the warn was already
/// emitted; further iterations stay at debug level until the counter
/// resets).
///
/// Pure helper extracted from [`run_against_vault`]'s `on_sync`
/// closure so the fire-once-at-threshold semantic is unit-testable
/// without spinning up a real watcher + vault fixture.
#[must_use]
fn note_not_ready_and_should_warn(consecutive: &mut u32, threshold: u32) -> bool {
    *consecutive = consecutive.saturating_add(1);
    *consecutive == threshold
}

/// Wall-clock milliseconds since the UNIX epoch, saturating on
/// overflow (the year 584,556,000 is not our problem).
fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Map a [`notify::Error`] from [`NotifyWatcher::start`] into a
/// [`SyncError`] the daemon caller can surface through its existing
/// exit-code mapping.
fn notify_start_to_sync_error(err: notify::Error) -> SyncError {
    SyncError::Vault(secretary_core::vault::VaultError::Io {
        context: "notify watcher start failed",
        source: std::io::Error::other(err.to_string()),
    })
}

#[cfg(test)]
mod tests {
    //! Daemon-loop unit tests.
    //!
    //! Each test composes:
    //! - a [`ScriptedPoller`] (drives the loop with a fixed sequence
    //!   of `Option<WatcherEvent>` values; sleeps the timeout when the
    //!   scripted slot is `None`, so the daemon's debounce / periodic
    //!   poll deadlines elapse against real wall-clock time);
    //! - a [`SyncCounter`] (records how many times the loop fired
    //!   `on_sync`).
    //!
    //! Debounce windows are kept short (~50 ms) so the suite stays
    //! under a second of real time.

    use std::collections::VecDeque;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    use super::*;
    use crate::pipeline::RunOutcome;
    use secretary_core::sync::{RollbackEvidence, SyncError, SyncState};

    #[test]
    fn outcome_log_rollback_carries_clocks() {
        let ev = RollbackEvidence {
            disk_vector_clock: Vec::new(),
            local_highest_seen: Vec::new(),
        };
        let log = outcome_log(&RunOutcome::RollbackRejected(ev));
        assert!(matches!(log, Some(OutcomeLog::RollbackRejected { .. })));
    }

    #[test]
    fn outcome_log_vetoes_only_when_nonzero() {
        assert_eq!(
            outcome_log(&RunOutcome::MergedAndCommitted { vetoes_resolved: 3 }),
            Some(OutcomeLog::VetoesResolved(3))
        );
        assert_eq!(
            outcome_log(&RunOutcome::MergedAndCommitted { vetoes_resolved: 0 }),
            None
        );
    }

    #[test]
    fn outcome_log_silent_arms_are_none() {
        assert_eq!(outcome_log(&RunOutcome::NothingToDo), None);
        assert_eq!(outcome_log(&RunOutcome::AppliedAutomatically), None);
        assert_eq!(outcome_log(&RunOutcome::SilentMerge), None);
    }

    #[test]
    fn after_sync_saves_on_advancing_arms() {
        let state = SyncState::empty([1; 16]);
        for outcome in [
            RunOutcome::AppliedAutomatically,
            RunOutcome::SilentMerge,
            RunOutcome::MergedAndCommitted { vetoes_resolved: 0 },
        ] {
            let mut saves = 0u32;
            let mut sink = |_: &SyncState| {
                saves += 1;
                Ok(())
            };
            after_sync(Ok(outcome), &state, &mut sink);
            assert_eq!(saves, 1);
        }
    }

    #[test]
    fn after_sync_skips_save_on_non_advancing_arms() {
        let state = SyncState::empty([2; 16]);
        let ev = RollbackEvidence {
            disk_vector_clock: Vec::new(),
            local_highest_seen: Vec::new(),
        };
        for outcome in [RunOutcome::NothingToDo, RunOutcome::RollbackRejected(ev)] {
            let mut saves = 0u32;
            let mut sink = |_: &SyncState| {
                saves += 1;
                Ok(())
            };
            after_sync(Ok(outcome), &state, &mut sink);
            assert_eq!(saves, 0);
        }
    }

    /// `after_sync` swallows a save-sink failure on an advancing arm.
    /// The in-memory clock still advanced; a transient FS error must not
    /// propagate — the next advancing pass will retry the persist.
    #[test]
    fn after_sync_swallows_save_error() {
        let state = SyncState::empty([4; 16]);
        let mut sink_called = false;
        let mut sink = |_: &SyncState| {
            sink_called = true;
            Err(StateError::Io(std::io::Error::other("disk full")))
        };
        // AppliedAutomatically is an advancing arm — the sink is invoked
        // but its Err must be swallowed (after_sync returns (), not a panic).
        after_sync(Ok(RunOutcome::AppliedAutomatically), &state, &mut sink);
        assert!(sink_called, "sink must be invoked on an advancing arm");
        // No assertion needed for the return value: if after_sync propagated
        // the error it would not compile (returns ()), and if it panicked
        // the test would fail.
    }

    #[test]
    fn after_sync_does_not_save_on_err() {
        let state = SyncState::empty([3; 16]);
        let mut saves = 0u32;
        let mut sink = |_: &SyncState| {
            saves += 1;
            Ok(())
        };
        let err = SyncError::Vault(secretary_core::vault::VaultError::Io {
            context: "test",
            source: std::io::Error::other("boom"),
        });
        after_sync(Err(err), &state, &mut sink);
        assert_eq!(saves, 0);
    }

    /// Short debounce window used across daemon tests. Tuned to be
    /// comfortably larger than typical iteration overhead (sub-ms)
    /// while keeping the whole suite well under a second.
    const TEST_DEBOUNCE: Duration = Duration::from_millis(50);

    /// Short periodic-poll interval for the periodic-poll test.
    /// Picked at 2× `TEST_DEBOUNCE` so the test scenario reads
    /// cleanly: one debounce window of "did nothing" then one poll
    /// fire.
    const TEST_POLL_INTERVAL: Duration = Duration::from_millis(100);

    /// Short shutdown-poll interval for tests. Keeps
    /// [`run_exits_when_shutdown_flag_flips_mid_loop`] under ~400 ms
    /// instead of paying [`DEFAULT_SHUTDOWN_POLL_INTERVAL`] (1 s) per
    /// iteration. Deliberately set ≥ [`TEST_POLL_INTERVAL`] so the
    /// shutdown interval never fragments a scripted `None` slot that
    /// is meant to elapse the full periodic-poll interval — see the
    /// scripting model in [`ScriptedPoller`].
    const TEST_SHUTDOWN_INTERVAL: Duration = Duration::from_millis(200);

    /// Sentinel that ends scripts in tests. The poller exhausting
    /// its script returns this so the loop exits deterministically.
    const SCRIPT_END: WatcherEvent = WatcherEvent::ShutdownRequested;

    /// Scripted event source. Each call to [`Self::poll`] pops the
    /// next slot from `script`:
    ///
    /// - `Some(event)` → return immediately (no sleep).
    /// - `None` → sleep the supplied `timeout` then return `None`,
    ///   which is how the daemon's deadline-based debounce / periodic
    ///   poll actually fire (the next loop iteration sees the
    ///   wall-clock has advanced past the deadline).
    ///
    /// Once exhausted, the poller emits [`SCRIPT_END`] forever so the
    /// daemon loop exits cleanly without the test needing to set the
    /// shutdown flag.
    struct ScriptedPoller {
        script: VecDeque<Option<WatcherEvent>>,
    }

    impl ScriptedPoller {
        fn new(script: impl IntoIterator<Item = Option<WatcherEvent>>) -> Self {
            Self {
                script: script.into_iter().collect(),
            }
        }

        fn poll(&mut self, timeout: Duration) -> Option<WatcherEvent> {
            match self.script.pop_front() {
                Some(Some(event)) => Some(event),
                Some(None) => {
                    std::thread::sleep(timeout);
                    None
                }
                None => Some(SCRIPT_END),
            }
        }
    }

    /// Records each `on_sync` invocation; the tests assert on its
    /// final `count`.
    struct SyncCounter {
        count: u32,
    }

    impl SyncCounter {
        fn new() -> Self {
            Self { count: 0 }
        }

        fn record(&mut self) {
            self.count += 1;
        }
    }

    /// Build a default test config with the given debounce window,
    /// no periodic poll, a fresh shutdown_flag, and the short
    /// [`TEST_SHUTDOWN_INTERVAL`].
    fn test_config(debounce: Duration) -> DaemonConfig {
        DaemonConfig {
            debounce,
            poll_interval: None,
            shutdown_poll_interval: TEST_SHUTDOWN_INTERVAL,
            shutdown_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// `compute_wait` with no debounce + no poll returns the shutdown
    /// interval verbatim — the loop should fall back to the slowest
    /// safe deadline when nothing tighter applies.
    #[test]
    fn compute_wait_returns_shutdown_interval_with_no_constraints() {
        let now = Instant::now();
        let wait = compute_wait(
            now,
            None,
            TEST_DEBOUNCE,
            None,
            DEFAULT_SHUTDOWN_POLL_INTERVAL,
        );
        assert_eq!(wait, DEFAULT_SHUTDOWN_POLL_INTERVAL);
    }

    /// `compute_wait` caps at the remaining debounce window when a
    /// debounce timer is pending and its deadline is closer than the
    /// shutdown interval.
    #[test]
    fn compute_wait_caps_at_remaining_debounce_window() {
        let now = Instant::now();
        // pending started 20ms ago, window is 50ms → 30ms remaining.
        let pending = now - Duration::from_millis(20);
        let wait = compute_wait(
            now,
            Some(pending),
            TEST_DEBOUNCE,
            None,
            DEFAULT_SHUTDOWN_POLL_INTERVAL,
        );
        // Allow a small tolerance for clock granularity.
        assert!(
            wait <= Duration::from_millis(30) && wait >= Duration::from_millis(29),
            "expected ~30ms remaining, got {wait:?}"
        );
    }

    /// `compute_wait` returns `Duration::ZERO` when the debounce
    /// window has already elapsed. The top-of-loop check will then
    /// fire `on_sync` on the next iteration, but we want `poll` not
    /// to block in the meantime.
    #[test]
    fn compute_wait_returns_zero_when_debounce_elapsed() {
        let now = Instant::now();
        // pending started 100ms ago, window is 50ms → elapsed.
        let pending = now - Duration::from_millis(100);
        let wait = compute_wait(
            now,
            Some(pending),
            TEST_DEBOUNCE,
            None,
            DEFAULT_SHUTDOWN_POLL_INTERVAL,
        );
        assert_eq!(wait, Duration::ZERO);
    }

    /// `compute_wait` caps at the remaining poll interval when a
    /// periodic poll is configured and closer than the shutdown
    /// interval.
    #[test]
    fn compute_wait_caps_at_remaining_poll_interval() {
        let now = Instant::now();
        // last poll 40ms ago, interval is 100ms → 60ms remaining.
        let last_poll = now - Duration::from_millis(40);
        let wait = compute_wait(
            now,
            None,
            TEST_DEBOUNCE,
            Some((TEST_POLL_INTERVAL, last_poll)),
            DEFAULT_SHUTDOWN_POLL_INTERVAL,
        );
        assert!(
            wait <= Duration::from_millis(60) && wait >= Duration::from_millis(59),
            "expected ~60ms remaining, got {wait:?}"
        );
    }

    /// `compute_wait` picks the smallest deadline among all sources —
    /// here debounce remaining (10ms) beats poll remaining (50ms) and
    /// shutdown_interval (1000ms).
    #[test]
    fn compute_wait_picks_smallest_constraint() {
        let now = Instant::now();
        let pending = now - Duration::from_millis(40); // 10ms remaining
        let last_poll = now - Duration::from_millis(50); // 50ms remaining
        let wait = compute_wait(
            now,
            Some(pending),
            TEST_DEBOUNCE,
            Some((TEST_POLL_INTERVAL, last_poll)),
            DEFAULT_SHUTDOWN_POLL_INTERVAL,
        );
        assert!(
            wait <= Duration::from_millis(10) && wait >= Duration::from_millis(9),
            "expected ~10ms (debounce remaining), got {wait:?}"
        );
    }

    /// A pre-set shutdown_flag causes [`run`] to exit on the very
    /// first iteration without ever calling `poll` or `on_sync`.
    #[test]
    fn run_exits_immediately_when_shutdown_flag_already_set() {
        let flag = Arc::new(AtomicBool::new(true));
        let mut counter = SyncCounter::new();
        let mut poller = ScriptedPoller::new([Some(WatcherEvent::SyncCandidate)]);
        let config = DaemonConfig {
            debounce: TEST_DEBOUNCE,
            poll_interval: None,
            shutdown_poll_interval: TEST_SHUTDOWN_INTERVAL,
            shutdown_flag: flag,
        };
        run(config, |t| poller.poll(t), || counter.record());
        assert_eq!(counter.count, 0);
    }

    /// Mid-loop: a `ShutdownRequested` event causes [`run`] to exit
    /// without firing the sync that the SyncCandidate before it had
    /// queued. (Test models the case where shutdown beats the
    /// debounce window.)
    #[test]
    fn run_exits_on_shutdown_event_before_window_expires() {
        let mut counter = SyncCounter::new();
        let mut poller = ScriptedPoller::new([
            Some(WatcherEvent::SyncCandidate),
            Some(WatcherEvent::ShutdownRequested),
        ]);
        let config = test_config(TEST_DEBOUNCE);
        run(config, |t| poller.poll(t), || counter.record());
        assert_eq!(counter.count, 0, "shutdown beat the debounce window");
    }

    /// A single SyncCandidate followed by a None (which makes the
    /// poller sleep the debounce window) → exactly one sync fires
    /// once the window elapses uninterrupted.
    #[test]
    fn run_fires_one_sync_after_single_event_when_window_elapses() {
        let mut counter = SyncCounter::new();
        let mut poller = ScriptedPoller::new([
            Some(WatcherEvent::SyncCandidate),
            None, // sleeps `wait` (~ debounce window) — daemon then fires
        ]);
        let config = test_config(TEST_DEBOUNCE);
        run(config, |t| poller.poll(t), || counter.record());
        assert_eq!(counter.count, 1);
    }

    /// A burst of three SyncCandidates (delivered back-to-back, all
    /// within one debounce window) followed by a None must collapse
    /// into a single sync. Trailing-edge semantic: each event extends
    /// the window; the window only fires after a full uninterrupted
    /// quiet stretch.
    #[test]
    fn run_collapses_burst_into_single_sync() {
        let mut counter = SyncCounter::new();
        let mut poller = ScriptedPoller::new([
            Some(WatcherEvent::SyncCandidate),
            Some(WatcherEvent::SyncCandidate),
            Some(WatcherEvent::SyncCandidate),
            None,
        ]);
        let config = test_config(TEST_DEBOUNCE);
        run(config, |t| poller.poll(t), || counter.record());
        assert_eq!(counter.count, 1, "burst must collapse into one sync");
    }

    /// Two bursts separated by a None (which makes the poller sleep
    /// the full debounce window between them, so the first burst
    /// fires before the second starts) → exactly two syncs.
    #[test]
    fn run_separate_bursts_fire_separate_syncs() {
        let mut counter = SyncCounter::new();
        let mut poller = ScriptedPoller::new([
            Some(WatcherEvent::SyncCandidate),
            None, // sleep debounce, fire sync #1
            Some(WatcherEvent::SyncCandidate),
            None, // sleep debounce, fire sync #2
        ]);
        let config = test_config(TEST_DEBOUNCE);
        run(config, |t| poller.poll(t), || counter.record());
        assert_eq!(counter.count, 2);
    }

    /// Periodic-poll-only: no events ever delivered, but a periodic
    /// poll interval is configured. After the interval elapses the
    /// safety-net poll fires `on_sync`. Pins the periodic-poll path
    /// independent of the debounce path.
    #[test]
    fn run_fires_periodic_poll_when_interval_elapses_without_events() {
        let mut counter = SyncCounter::new();
        // One None to advance wall-clock past the poll interval, then
        // SCRIPT_END terminates the loop. The None's sleep is bounded
        // by `compute_wait`, which here returns at most
        // TEST_POLL_INTERVAL (since shutdown_interval is much larger).
        let mut poller = ScriptedPoller::new([None]);
        let config = DaemonConfig {
            debounce: TEST_DEBOUNCE,
            poll_interval: Some(TEST_POLL_INTERVAL),
            shutdown_poll_interval: TEST_SHUTDOWN_INTERVAL,
            shutdown_flag: Arc::new(AtomicBool::new(false)),
        };
        run(config, |t| poller.poll(t), || counter.record());
        assert_eq!(counter.count, 1, "periodic poll must fire once");
    }

    /// Setting the shutdown flag from a side-thread mid-loop causes
    /// [`run`] to exit on its next iteration. Models the SIGINT path
    /// (Task 8) without depending on signal-hook.
    #[test]
    fn run_exits_when_shutdown_flag_flips_mid_loop() {
        let flag = Arc::new(AtomicBool::new(false));
        let flag_clone = flag.clone();
        let mut counter = SyncCounter::new();
        // Script is two Nones so the poller sleeps for two
        // TEST_SHUTDOWN_INTERVAL-bounded waits; the side thread flips
        // the flag during the first sleep. The loop catches it at the
        // top of the next iteration. Total wall-clock is bounded by
        // 2× TEST_SHUTDOWN_INTERVAL (≈400 ms) — without the test
        // override this would be 2 s.
        let mut poller = ScriptedPoller::new([None, None]);
        let config = DaemonConfig {
            debounce: TEST_DEBOUNCE,
            poll_interval: None,
            shutdown_poll_interval: TEST_SHUTDOWN_INTERVAL,
            shutdown_flag: flag,
        };
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            flag_clone.store(true, Ordering::SeqCst);
        });
        run(config, |t| poller.poll(t), || counter.record());
        handle.join().expect("flag-setter joined");
        assert_eq!(counter.count, 0);
    }

    /// A bare `PollTick` event is delivered (some test sources might
    /// inject it) — the loop ignores it (handled via the periodic
    /// poll check, not via the `poll` return). Pins that the variant
    /// match doesn't accidentally trigger a sync.
    #[test]
    fn run_ignores_polltick_event_from_poll() {
        let mut counter = SyncCounter::new();
        let mut poller = ScriptedPoller::new([Some(WatcherEvent::PollTick)]);
        let config = test_config(TEST_DEBOUNCE);
        run(config, |t| poller.poll(t), || counter.record());
        assert_eq!(counter.count, 0);
    }

    /// `now_ms` returns a plausible UNIX-epoch millisecond value —
    /// must be ≥ 2024-01-01 in ms (1_700_000_000_000) and ≤ year-3000
    /// upper bound. Sanity check that the helper isn't off by orders
    /// of magnitude.
    #[test]
    fn now_ms_returns_plausible_unix_timestamp() {
        let ms = now_ms();
        // 2024-01-01 UTC in ms.
        const FLOOR_MS: u64 = 1_700_000_000_000;
        // Year 3000 in ms — wildly future, but rules out u64::MAX
        // saturation or seconds-vs-ms unit confusion.
        const CEILING_MS: u64 = 32_503_680_000_000;
        assert!(ms >= FLOOR_MS, "now_ms below floor: {ms}");
        assert!(ms <= CEILING_MS, "now_ms above ceiling: {ms}");
    }

    /// `note_not_ready_and_should_warn` fires `true` exactly once on
    /// the threshold-th consecutive call and stays `false` afterwards
    /// until the caller resets the counter. Pins the
    /// fire-once-at-threshold semantic for the
    /// [`READY_NOT_READY_WARN_THRESHOLD`] policy.
    #[test]
    fn note_not_ready_fires_warn_exactly_once_at_threshold() {
        let mut counter: u32 = 0;
        let threshold: u32 = 3;
        assert!(!note_not_ready_and_should_warn(&mut counter, threshold));
        assert_eq!(counter, 1);
        assert!(!note_not_ready_and_should_warn(&mut counter, threshold));
        assert_eq!(counter, 2);
        assert!(
            note_not_ready_and_should_warn(&mut counter, threshold),
            "third call hits the threshold"
        );
        assert_eq!(counter, 3);
        assert!(
            !note_not_ready_and_should_warn(&mut counter, threshold),
            "fourth call is past the threshold and must NOT re-fire"
        );
        assert_eq!(counter, 4);
    }

    /// Resetting `counter` to 0 (as `run_against_vault` does on
    /// `wait_for_ready → Ok(true)`) restores fire-at-threshold
    /// behavior for the next streak. Pins that the warn would re-fire
    /// after a transient stable period followed by another stuck
    /// stretch — the operator should hear about each streak.
    #[test]
    fn note_not_ready_refires_after_counter_reset() {
        let mut counter: u32 = 0;
        let threshold: u32 = 2;
        let _ = note_not_ready_and_should_warn(&mut counter, threshold);
        assert!(note_not_ready_and_should_warn(&mut counter, threshold));
        // Folder became stable for one cycle.
        counter = 0;
        // Second streak — must fire again on its own threshold-th hit.
        assert!(!note_not_ready_and_should_warn(&mut counter, threshold));
        assert!(note_not_ready_and_should_warn(&mut counter, threshold));
    }

    /// `note_not_ready_and_should_warn` uses saturating arithmetic so
    /// a pathological never-ending stuck stretch can't panic on
    /// counter overflow. Caller can rely on counter staying at
    /// `u32::MAX` indefinitely after reaching it.
    #[test]
    fn note_not_ready_saturates_at_u32_max() {
        let mut counter: u32 = u32::MAX;
        let _ = note_not_ready_and_should_warn(&mut counter, 1);
        assert_eq!(counter, u32::MAX);
    }

    /// `notify_start_to_sync_error` wraps a notify error in
    /// `SyncError::Vault(VaultError::Io)` with the documented
    /// context string. Pins the mapping so callers can rely on the
    /// `context` value for log-grepping.
    #[test]
    fn notify_start_to_sync_error_maps_to_vault_io_with_context() {
        let notify_err = notify::Error::path_not_found();
        let err = notify_start_to_sync_error(notify_err);
        match err {
            SyncError::Vault(secretary_core::vault::VaultError::Io { context, .. }) => {
                assert_eq!(context, "notify watcher start failed");
            }
            other => panic!("expected SyncError::Vault(VaultError::Io {{..}}), got {other:?}"),
        }
    }
}
