//! File-watcher abstractions for the `run` subcommand.
//!
//! Spec: [`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`](../../../docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md)
//! §D3 (events + debounce + optional poll) + §D6 (partial-download).
//!
//! This task ships the **pure-function pieces only**:
//!
//! - [`ready`] — partial-download filename filter + size-stability
//!   probe + a [`ready::Clock`]-parameterised orchestrator. No `notify`
//!   integration; pattern matching and metadata comparison run
//!   identically on Linux / macOS / Windows.
//! - [`debounce`] — pure state machine that collapses an event burst
//!   into one scheduled `SyncCandidate` per `--debounce-ms` window.
//!
//! The [`notify::RecommendedWatcher`](https://docs.rs/notify) integration
//! that produces the actual event stream lives in [`notify_driver`]
//! (Task 7) and consumes both pure pieces through a
//! [`WatcherEvent`]-emitting driver.

pub mod debounce;
pub mod notify_driver;
pub mod ready;

/// What the watcher dispatcher tells the [`crate::pipeline::run_one`]
/// caller (the daemon loop) to do next.
///
/// Variants are mutually exclusive — exactly one is delivered per
/// driver tick. The driver is responsible for collapsing
/// `notify::Event` bursts into at most one [`Self::SyncCandidate`] per
/// debounce window (see [`debounce::step`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatcherEvent {
    /// One or more files in the vault folder changed; the daemon
    /// should attempt a sync after the debounce window expires.
    SyncCandidate,
    /// Periodic poll-tick fired. Used when the operator passes
    /// `--poll-ms` (off by default) to defend against notify backends
    /// that miss events under load (e.g. macOS FSEvents coalescing,
    /// Linux inotify queue overflow).
    PollTick,
    /// Operator requested shutdown (SIGINT or SIGTERM). The daemon
    /// loop should finish any in-flight sync attempt cleanly, then
    /// exit.
    ShutdownRequested,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watcher_event_variants_are_distinct() {
        assert_ne!(WatcherEvent::SyncCandidate, WatcherEvent::PollTick);
        assert_ne!(WatcherEvent::SyncCandidate, WatcherEvent::ShutdownRequested);
        assert_ne!(WatcherEvent::PollTick, WatcherEvent::ShutdownRequested);
    }

    #[test]
    fn watcher_event_copy_round_trip() {
        // Pin the `Copy` derive — Task 7's daemon loop passes these by
        // value across debounce/poll/shutdown branches; losing `Copy`
        // would force `.clone()` calls at every match arm.
        let original = WatcherEvent::SyncCandidate;
        let copied = original;
        assert_eq!(original, copied);
    }

    #[test]
    fn watcher_event_debug_is_non_empty() {
        // Pin a Debug shape so operators see informative log lines (the
        // daemon loop in Task 7 will log `?event` on every tick).
        assert!(!format!("{:?}", WatcherEvent::SyncCandidate).is_empty());
        assert!(!format!("{:?}", WatcherEvent::PollTick).is_empty());
        assert!(!format!("{:?}", WatcherEvent::ShutdownRequested).is_empty());
    }
}
