//! [`notify::RecommendedWatcher`] wrapper that surfaces filesystem
//! activity to the daemon loop as [`super::WatcherEvent`] values.
//!
//! Spec: [`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`](../../../docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md)
//! §D3 (events + debounce + optional poll).
//!
//! The driver is intentionally thin:
//!
//! - It owns the underlying `notify` watcher (so its OS resources stay
//!   alive for the daemon's lifetime).
//! - [`NotifyWatcher::poll`] blocks the calling thread for at most
//!   `timeout`. On a sync-relevant filesystem event it returns
//!   [`WatcherEvent::SyncCandidate`]; on timeout (or an event we filter
//!   out) it returns `None`.
//! - Burst coalescing is a single drain pass on the channel after the
//!   first relevant event — the daemon loop's trailing-edge debounce
//!   (see [`super::debounce::step`]) does the heavy lifting of
//!   collapsing repeated events into a single sync attempt.
//!
//! [`super::WatcherEvent::PollTick`] and
//! [`super::WatcherEvent::ShutdownRequested`] are **not** produced by
//! this driver — both are state-driven concerns handled by the daemon
//! loop directly (a periodic-poll timer and an [`std::sync::atomic`]
//! shutdown flag, respectively). The daemon's tests inject synthetic
//! `ShutdownRequested` events through a closure-shaped poller; the
//! production driver never emits them.

use std::path::Path;
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, TryRecvError};
use std::time::Duration;

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use super::ready::matches_partial_pattern;
use super::WatcherEvent;

/// Owns the [`RecommendedWatcher`] and its event receiver. Dropping a
/// [`NotifyWatcher`] tears down the OS-level subscription via
/// `notify`'s `Drop` impl.
pub struct NotifyWatcher {
    /// Held to keep the OS subscription alive; never read after
    /// construction. The leading underscore silences the unused-field
    /// lint while documenting intent.
    _watcher: RecommendedWatcher,
    rx: Receiver<notify::Result<Event>>,
}

impl NotifyWatcher {
    /// Begin watching `folder` recursively. Subsequent calls to
    /// [`Self::poll`] surface any filesystem activity that
    /// [`is_sync_relevant`] accepts.
    ///
    /// # Errors
    ///
    /// Bubbles up [`notify::Error`] from the underlying
    /// [`notify::recommended_watcher`] / [`Watcher::watch`] calls.
    /// Typical causes: missing directory, permission denied, inotify
    /// limits exhausted on Linux.
    pub fn start(folder: &Path) -> notify::Result<Self> {
        let (tx, rx) = channel();
        let mut watcher = notify::recommended_watcher(move |res| {
            // `mpsc::Sender::send` errors only when the receiver has
            // been dropped — which only happens after the daemon loop
            // exits and `NotifyWatcher` is being dropped. At that point
            // event delivery is irrelevant; silently discard.
            let _ = tx.send(res);
        })?;
        watcher.watch(folder, RecursiveMode::Recursive)?;
        Ok(Self {
            _watcher: watcher,
            rx,
        })
    }

    /// Block up to `timeout`, then return:
    ///
    /// - `Some(WatcherEvent::SyncCandidate)` if at least one
    ///   sync-relevant event arrived before the deadline.
    /// - `None` on timeout, channel disconnect, a `notify`-level error,
    ///   or a stream of exclusively non-relevant events (e.g. file
    ///   accesses).
    ///
    /// On a relevant first event, the method drains any
    /// immediately-pending events from the channel before returning,
    /// collapsing a burst into a single signal. This is **not** a
    /// debounce — that lives in [`super::debounce::step`], driven by
    /// the daemon loop. The drain just spares the daemon the cost of
    /// looping once per queued event for a burst that the platform
    /// has already coalesced into the channel.
    pub fn poll(&self, timeout: Duration) -> Option<WatcherEvent> {
        // Wait up to `timeout` for the FIRST event. Treat any of
        // timeout / disconnect / notify-level error as "no event".
        let first = match self.rx.recv_timeout(timeout) {
            Ok(Ok(event)) => event,
            Ok(Err(_notify_err)) => return None,
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => return None,
        };

        let mut any_relevant = is_sync_relevant(&first);

        // Drain whatever else is already queued. Each one updates
        // `any_relevant` so a relevant event later in the burst still
        // surfaces even if the first one was filtered out.
        loop {
            match self.rx.try_recv() {
                Ok(Ok(event)) => {
                    if is_sync_relevant(&event) {
                        any_relevant = true;
                    }
                }
                Ok(Err(_notify_err)) => continue,
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }

        if any_relevant {
            Some(WatcherEvent::SyncCandidate)
        } else {
            None
        }
    }
}

/// Pure predicate: does this `notify` event represent a content change
/// that might warrant a sync attempt?
///
/// Returns `false` when:
///
/// - The event kind is [`EventKind::Access`] (file read — not a change).
/// - Every path in the event matches the canonical partial-download
///   filename table (see [`matches_partial_pattern`]). This is the
///   spec §D6 partial-download gate at the watcher layer — a
///   `*.icloud` write should never trigger a debounce window.
///
/// Returns `true` otherwise. [`EventKind::Any`] and
/// [`EventKind::Other`] are conservatively treated as relevant — Any
/// is notify's catch-all when it couldn't classify the underlying OS
/// event, and Other is a platform-specific signal we don't model in
/// detail. False positives here cost a wasted sync attempt; false
/// negatives risk silently missing a real change.
///
/// Events with no paths attached are also conservatively relevant —
/// some platforms surface change notifications without specific paths.
fn is_sync_relevant(event: &Event) -> bool {
    if matches!(event.kind, EventKind::Access(_)) {
        return false;
    }
    if event.paths.is_empty() {
        return true;
    }
    !event.paths.iter().all(|p| matches_partial_pattern(p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::Duration;
    use tempfile::TempDir;

    /// Maximum time we wait for `notify` to surface an event in tests.
    /// 2 s comfortably covers macOS FSEvents' typical ~1 s coalescing
    /// window plus inotify queue drains on Linux under load.
    const TEST_POLL_TIMEOUT: Duration = Duration::from_secs(2);

    /// Brief settle before writing into a freshly-started watcher.
    /// Without this delay, the OS watch registration races the first
    /// write and notify may not surface that initial event on macOS.
    const WATCHER_SETTLE: Duration = Duration::from_millis(100);

    /// Smoke test: a write into a freshly-watched folder produces a
    /// [`WatcherEvent::SyncCandidate`] on the next poll.
    ///
    /// This is the cross-platform sanity check that the
    /// `notify`-backed driver is wired correctly. A more elaborate
    /// per-OS quirk suite (FSEvents coalescing, inotify queue
    /// overflow) lives in `cli/tests/notify_quirk.rs` (Task 10).
    #[test]
    fn writing_a_file_surfaces_a_sync_candidate() {
        let dir = TempDir::new().expect("tempdir");
        let watcher = NotifyWatcher::start(dir.path()).expect("watcher start");
        std::thread::sleep(WATCHER_SETTLE);
        fs::write(dir.path().join("vault.cbor.enc"), b"hello").expect("write");
        assert_eq!(
            watcher.poll(TEST_POLL_TIMEOUT),
            Some(WatcherEvent::SyncCandidate)
        );
    }

    /// `poll` with no events queued returns `None` after the timeout.
    /// Pinning this guarantees the daemon loop's "did the debounce
    /// window expire?" check fires reliably — if `poll` ever blocked
    /// past its timeout under no-event load, the trailing-edge
    /// debounce semantic would break.
    #[test]
    fn poll_returns_none_on_timeout() {
        let dir = TempDir::new().expect("tempdir");
        let watcher = NotifyWatcher::start(dir.path()).expect("watcher start");
        // Some platforms (macOS FSEvents) emit setup events as the
        // watch is registered against the freshly-created tempdir.
        // Drain everything that arrives in the first settle window so
        // the assertion exercises the timeout path, not the
        // startup-noise path.
        std::thread::sleep(WATCHER_SETTLE);
        let _ = watcher.poll(Duration::from_millis(10));
        // Quiet folder + short timeout — must come back as None.
        assert_eq!(watcher.poll(Duration::from_millis(50)), None);
    }

    /// Access-only events (file reads) are filtered out — only
    /// changes surface as sync candidates.
    ///
    /// We construct a synthetic [`Event`] with [`EventKind::Access`]
    /// and check the predicate directly; building a real Access event
    /// through notify is platform-dependent and noisy.
    #[test]
    fn access_events_are_filtered_by_relevance_predicate() {
        use notify::event::{AccessKind, Event, EventKind};
        let access = Event {
            kind: EventKind::Access(AccessKind::Read),
            paths: Vec::new(),
            attrs: Default::default(),
        };
        assert!(!is_sync_relevant(&access));
    }

    /// `Modify` events are treated as sync-relevant — the most
    /// common kind from text-editor saves. Companion test to
    /// `access_events_are_filtered_by_relevance_predicate`: pins
    /// the inverse direction of the predicate.
    #[test]
    fn modify_events_are_relevant() {
        use notify::event::{Event, EventKind, ModifyKind};
        let modify = Event {
            kind: EventKind::Modify(ModifyKind::Any),
            paths: Vec::new(),
            attrs: Default::default(),
        };
        assert!(is_sync_relevant(&modify));
    }

    /// An event whose paths all match the partial-download pattern
    /// table (`.icloud`, `.tmp`, etc.) is filtered as not-sync-relevant.
    /// This is the spec §D6 partial-download gate at the watcher
    /// layer — touching a partial file should not trip the debounce
    /// window.
    #[test]
    fn partial_marker_paths_are_filtered() {
        use notify::event::{Event, EventKind, ModifyKind};
        use std::path::PathBuf;
        let partial = Event {
            kind: EventKind::Modify(ModifyKind::Any),
            paths: vec![PathBuf::from("/vault/.foo.icloud")],
            attrs: Default::default(),
        };
        assert!(!is_sync_relevant(&partial));
    }

    /// An event with a mix of partial + real paths is still relevant —
    /// the real path warrants a sync attempt. Pins the "all paths
    /// must match" semantic of the filter.
    #[test]
    fn mixed_partial_and_real_paths_are_relevant() {
        use notify::event::{Event, EventKind, ModifyKind};
        use std::path::PathBuf;
        let mixed = Event {
            kind: EventKind::Modify(ModifyKind::Any),
            paths: vec![
                PathBuf::from("/vault/.foo.icloud"),
                PathBuf::from("/vault/manifest.toml"),
            ],
            attrs: Default::default(),
        };
        assert!(is_sync_relevant(&mixed));
    }

    /// An event with no paths attached is conservatively relevant —
    /// some platforms surface change notifications without specific
    /// paths and we'd rather sync on a false positive than miss a
    /// real change.
    #[test]
    fn pathless_events_are_relevant() {
        use notify::event::{Event, EventKind, ModifyKind};
        let pathless = Event {
            kind: EventKind::Modify(ModifyKind::Any),
            paths: Vec::new(),
            attrs: Default::default(),
        };
        assert!(is_sync_relevant(&pathless));
    }
}
