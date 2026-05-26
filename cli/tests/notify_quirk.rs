//! Cross-platform `notify` quirk pin. Drives [`notify::recommended_watcher`]
//! against a fresh tempdir on each supported OS and asserts the
//! `EventKind` shape the C.2 `NotifyWatcher` and its predicate
//! ([`secretary_cli::watcher`] internals) rely on.
//!
//! Spec: [`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`](../../docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md)
//! §D3 (notify event source) + the spec's reminder that we don't model
//! per-platform event taxonomies in detail.
//!
//! ## Purpose
//!
//! `cli/src/watcher/notify_driver.rs::tests` already exercises the
//! `NotifyWatcher` wrapper end-to-end (write → poll → SyncCandidate).
//! This file goes one layer lower — it drives the raw
//! [`notify::recommended_watcher`] API the wrapper is built on, so a
//! `notify` major version bump that changes either:
//!
//! - the channel callback shape (currently `Fn(notify::Result<Event>)`),
//! - the `EventKind` taxonomy our [`is_sync_relevant`] predicate
//!   pattern-matches on,
//! - the `RecursiveMode::Recursive` semantics we depend on,
//!
//! ...surfaces in CI as a clean compile-or-test failure here rather
//! than as a subtle daemon misbehaviour at runtime.
//!
//! ## Per-OS expectations
//!
//! - **Linux (inotify):** writes emit at least one of `EventKind::Create`
//!   or `EventKind::Modify`. The exact sequence depends on the kernel
//!   and the libc write-syscall path; we assert "at least one
//!   sync-relevant event arrives" rather than pinning a specific kind.
//! - **macOS (FSEvents):** writes emit `EventKind::Modify(_)` and/or
//!   `EventKind::Create(_)` coalesced into one event after FSEvents'
//!   ~1 s native debounce. Same "at least one sync-relevant event"
//!   assertion — FSEvents' coalescing is **the** quirk we tolerate at
//!   the daemon level via `cli/src/watcher/debounce.rs`.
//!
//! ## Why a separate file from `notify_driver.rs::tests`
//!
//! The `tests/` directory runs as a separate integration test binary,
//! invoked by `cargo test --workspace`. That gives the assertions here
//! a CI-visible "notify quirk regressions caught at the integration
//! layer" identity, distinct from the unit-test-level smoke covered by
//! the in-module `cli/src/watcher/notify_driver.rs::tests`. The unit
//! tests can still pass when the integration file fails (or vice
//! versa) if a regression is layer-specific — that diagnostic split is
//! the value-add.

use std::fs;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::time::Duration;

use notify::{event::EventKind, Event, RecommendedWatcher, RecursiveMode, Watcher};
use tempfile::TempDir;

/// Maximum time we wait for `notify` to surface an event. 2 s
/// comfortably covers macOS FSEvents' typical ~1 s coalescing window
/// plus inotify queue drains on Linux under CI load. Mirrors the
/// constant in `cli/src/watcher/notify_driver.rs::tests`.
const POLL_TIMEOUT: Duration = Duration::from_secs(2);

/// Brief settle window after registering the watcher and before
/// writing into the watched folder. macOS in particular can race the
/// watch registration against the first write and miss the initial
/// event. 100 ms matches the wrapper's tests + the `WATCHER_SETTLE`
/// constant pattern there.
const WATCHER_SETTLE: Duration = Duration::from_millis(100);

/// Filename used as the synthetic "vault content changed" trigger.
/// Picked to NOT match any partial-download pattern (`.icloud`,
/// `.tmp`, `.crdownload`, etc. — see `cli/src/watcher/ready.rs`) so
/// the event would surface as sync-relevant when fed through the
/// production predicate.
const TRIGGER_FILENAME: &str = "vault.cbor.enc";

/// Filename matching a partial-download pattern (`.tmp` suffix). Used
/// to verify `notify` itself emits an event for these filenames — the
/// production layer filters them via the predicate, but the watcher
/// MUST see the underlying syscall or our predicate has nothing to
/// filter against.
const PARTIAL_TRIGGER_FILENAME: &str = "in-progress.tmp";

/// Set up a `notify::recommended_watcher` against `folder` and return
/// the receiver end of its event channel. The `RecommendedWatcher` is
/// returned alongside the receiver so the caller can keep it alive
/// for the lifetime of the assertion — dropping the watcher tears
/// down the OS subscription.
fn start_watcher(
    folder: &std::path::Path,
) -> (RecommendedWatcher, Receiver<notify::Result<Event>>) {
    let (tx, rx) = channel();
    let mut watcher = notify::recommended_watcher(move |res| {
        let _ = tx.send(res);
    })
    .expect("recommended_watcher must construct");
    watcher
        .watch(folder, RecursiveMode::Recursive)
        .expect("watch folder");
    (watcher, rx)
}

/// Drain the channel for up to [`POLL_TIMEOUT`] and return every
/// successful `notify::Event` observed. Errors and disconnections are
/// silently dropped — the assertions check the positive shape, not
/// the failure modes (which are the wrapper's concern).
///
/// We drain rather than `recv_timeout` once because real `notify`
/// backends emit multiple events per write (e.g. Linux inotify: a
/// `Create` then a `Modify`); the per-platform assertion below only
/// needs one of them, but the drain shape helps if a future debug
/// build wants to inspect the full sequence.
fn collect_events(rx: &Receiver<notify::Result<Event>>, budget: Duration) -> Vec<Event> {
    let mut events = Vec::new();
    let deadline = std::time::Instant::now() + budget;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match rx.recv_timeout(remaining) {
            Ok(Ok(event)) => events.push(event),
            Ok(Err(_)) => continue,
            Err(RecvTimeoutError::Timeout) | Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    events
}

/// Returns `true` if `kind` is one of the `EventKind` variants the
/// production [`secretary_cli::watcher::notify_driver`] predicate treats
/// as sync-relevant — i.e. anything except `Access`. Filters out
/// FSEvents' read-only `Access` ticks while accepting the catch-all
/// `Any` / `Other` so this test stays robust against minor `notify`
/// taxonomy reshuffles.
///
/// **Intentional duplication.** This is a hand-rolled copy of the
/// wrapper's predicate, not an import — the file's purpose is to pin
/// `notify`'s **own** behaviour one layer below the wrapper, so the
/// two predicates SHOULD drift independently. A future "DRY" refactor
/// that imports the wrapper's predicate here would couple this
/// "naked notify" pin to the wrapper's filtering policy and erase the
/// diagnostic-split that motivates this file (see the module-level
/// "Why a separate file" docstring above).
#[must_use]
fn is_sync_relevant_kind(kind: &EventKind) -> bool {
    !matches!(kind, EventKind::Access(_))
}

/// Smoke: `notify::recommended_watcher` is wired correctly and a
/// single non-partial write surfaces at least one sync-relevant
/// event within [`POLL_TIMEOUT`].
///
/// This is the cross-platform smoke the daemon's `notify_driver`
/// builds on. A regression in `notify`'s callback shape, watch
/// registration, or event delivery surfaces here. The wrapper's
/// `writing_a_file_surfaces_a_sync_candidate` test catches the same
/// regression at one layer up; this file is the "naked notify" pin.
#[test]
fn raw_notify_surfaces_at_least_one_sync_relevant_event() {
    let dir = TempDir::new().expect("tempdir");
    let (_watcher, rx) = start_watcher(dir.path());
    std::thread::sleep(WATCHER_SETTLE);

    let target: PathBuf = dir.path().join(TRIGGER_FILENAME);
    fs::write(&target, b"convergence trigger").expect("write trigger file");

    let events = collect_events(&rx, POLL_TIMEOUT);
    assert!(
        events.iter().any(|e| is_sync_relevant_kind(&e.kind)),
        "expected at least one non-Access EventKind from notify; got {:?}",
        events.iter().map(|e| &e.kind).collect::<Vec<_>>()
    );
}

/// `notify` surfaces a write to a partial-marker filename too — the
/// filter that suppresses partial-download events lives in our
/// predicate (`cli/src/watcher/ready.rs::matches_partial_pattern`),
/// not in `notify` itself. Pinning this means a future `notify`
/// version that silently drops partial-marker files would surface as
/// a missed `Create` here, distinct from a production-layer behaviour
/// change.
#[test]
fn raw_notify_surfaces_partial_marker_writes() {
    let dir = TempDir::new().expect("tempdir");
    let (_watcher, rx) = start_watcher(dir.path());
    std::thread::sleep(WATCHER_SETTLE);

    let target: PathBuf = dir.path().join(PARTIAL_TRIGGER_FILENAME);
    fs::write(&target, b"partial marker payload").expect("write partial-marker file");

    let events = collect_events(&rx, POLL_TIMEOUT);
    assert!(
        !events.is_empty(),
        "notify must emit at least one event for a partial-marker write; got nothing in {POLL_TIMEOUT:?}"
    );
}

/// `RecursiveMode::Recursive` reaches into a subdirectory: a write
/// into `<tempdir>/sub/foo.cbor.enc` produces an event when the
/// watcher was registered against `<tempdir>`. Pins the recursive
/// watch semantic the daemon relies on for vault folders that nest
/// blocks under a `blocks/` subdir.
#[test]
fn raw_notify_recursive_mode_reaches_subdir() {
    let dir = TempDir::new().expect("tempdir");
    let sub = dir.path().join("sub");
    fs::create_dir(&sub).expect("create subdir");
    let (_watcher, rx) = start_watcher(dir.path());
    std::thread::sleep(WATCHER_SETTLE);

    let target = sub.join(TRIGGER_FILENAME);
    fs::write(&target, b"nested trigger").expect("write nested trigger");

    let events = collect_events(&rx, POLL_TIMEOUT);
    assert!(
        events.iter().any(|e| is_sync_relevant_kind(&e.kind)),
        "RecursiveMode::Recursive must surface subdir writes; got {:?}",
        events.iter().map(|e| &e.kind).collect::<Vec<_>>()
    );
}

/// Per-platform expectation: on Linux (inotify), at least one of
/// `Create` or `Modify` must appear in the event stream for a write.
/// Pins the `EventKind` variants the daemon's predicate
/// pattern-matches on against a future notify taxonomy change.
#[cfg(target_os = "linux")]
#[test]
fn raw_notify_linux_emits_create_or_modify() {
    let dir = TempDir::new().expect("tempdir");
    let (_watcher, rx) = start_watcher(dir.path());
    std::thread::sleep(WATCHER_SETTLE);

    fs::write(dir.path().join(TRIGGER_FILENAME), b"linux trigger").expect("write");

    let events = collect_events(&rx, POLL_TIMEOUT);
    let has_create_or_modify = events
        .iter()
        .any(|e| matches!(e.kind, EventKind::Create(_)) || matches!(e.kind, EventKind::Modify(_)));
    assert!(
        has_create_or_modify,
        "Linux inotify must emit Create or Modify for a fresh write; got {:?}",
        events.iter().map(|e| &e.kind).collect::<Vec<_>>()
    );
}

/// Per-platform expectation: on macOS (FSEvents), at least one of
/// `Create` or `Modify` must appear in the event stream for a write.
/// FSEvents coalesces multiple writes into a single event after a
/// short native debounce — we accept either kind to stay robust
/// against that coalescing behaviour.
#[cfg(target_os = "macos")]
#[test]
fn raw_notify_macos_emits_create_or_modify() {
    let dir = TempDir::new().expect("tempdir");
    let (_watcher, rx) = start_watcher(dir.path());
    std::thread::sleep(WATCHER_SETTLE);

    fs::write(dir.path().join(TRIGGER_FILENAME), b"macos trigger").expect("write");

    let events = collect_events(&rx, POLL_TIMEOUT);
    let has_create_or_modify = events
        .iter()
        .any(|e| matches!(e.kind, EventKind::Create(_)) || matches!(e.kind, EventKind::Modify(_)));
    assert!(
        has_create_or_modify,
        "macOS FSEvents must emit Create or Modify for a fresh write; got {:?}",
        events.iter().map(|e| &e.kind).collect::<Vec<_>>()
    );
}
