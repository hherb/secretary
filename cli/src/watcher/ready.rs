//! Partial-download readiness — ADR-0003 §"Cloud-folder integration".
//!
//! Spec: [`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`](../../../docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md)
//! §D6 — the canonical pattern table lives in the spec; this module
//! implements that table plus the size-stability probe.
//!
//! Design split:
//!
//! - [`matches_partial_pattern`] — pure string matcher over the
//!   path's basename. Table-tested.
//! - [`is_size_stable`] — pure `(Metadata, Metadata)` comparison.
//!   Table-tested via real `tempfile` reads.
//! - [`wait_for_ready`] — the thin I/O orchestrator that does two
//!   `stat()` reads with a [`Clock::sleep`] in between, then composes
//!   the two pure predicates above.
//!
//! Only [`wait_for_ready`] performs I/O; the inner predicates are
//! invariant under platform.

use std::fs::Metadata;
use std::path::Path;
use std::time::Duration;

/// Suffix patterns that mark a file as not-yet-fully-downloaded.
///
/// Sourced from spec §D6 (canonical pattern table). Comparison is
/// case-insensitive via [`str::to_ascii_lowercase`] in
/// [`matches_partial_pattern`]; the entries here are pre-lowercased.
/// Order is recognition-priority only and not semantically significant
/// — any match wins.
const PARTIAL_SUFFIXES: &[&str] = &[
    ".icloud",     // iCloud Drive placeholder for not-yet-downloaded
    ".tmp",        // generic temp suffix (rsync, rclone, many editors)
    ".partial",    // generic partial-download suffix
    ".crdownload", // Chromium-family in-progress download
    ".download",   // Safari / Firefox-family in-progress download
    ".swp",        // vim swap file (primary)
    ".swo",        // vim swap file (secondary)
];

/// Basename prefixes that mark lock or transient files.
///
/// `.~` catches LibreOffice / OpenOffice lockfiles (e.g.
/// `.~lock.foo.odt#`) and Dropbox dot-prefixed temp files (e.g.
/// `.~dropbox-abc.tmp`). `~$` catches Microsoft Office lockfiles
/// (e.g. `~$report.docx`). Both come from spec §D6.
const PARTIAL_PREFIXES: &[&str] = &[".~", "~$"];

/// Whole-basename markers for OS filesystem-metadata droppings that
/// must never be treated as vault content.
///
/// Comparison is case-insensitive — Windows is case-preserving but
/// case-insensitive at lookup time, and macOS volumes can be either.
const PARTIAL_BASENAMES: &[&str] = &["desktop.ini", ".DS_Store"];

/// True if the path's basename matches any known partial-download or
/// lock-file pattern per spec §D6.
///
/// Pure function — table-tested via the in-module `tests` mod.
///
/// Returns `false` if the path has no basename (e.g. `/` or `..`),
/// has a non-UTF-8 basename (extremely unusual on macOS/Linux; the
/// daemon's path stream is already `String`-typed by `notify`), or
/// does not match any of the three pattern axes.
#[must_use]
pub fn matches_partial_pattern(path: &Path) -> bool {
    let Some(basename) = path.file_name().and_then(|os| os.to_str()) else {
        return false;
    };
    if PARTIAL_BASENAMES
        .iter()
        .any(|b| basename.eq_ignore_ascii_case(b))
    {
        return true;
    }
    if PARTIAL_PREFIXES.iter().any(|p| basename.starts_with(p)) {
        return true;
    }
    let lowered = basename.to_ascii_lowercase();
    PARTIAL_SUFFIXES.iter().any(|s| lowered.ends_with(s))
}

/// True iff two [`Metadata`] snapshots indicate the file is the same
/// size AND has the same modification timestamp.
///
/// Pure comparison. If either snapshot's `modified()` fails (very
/// unusual on Linux / macOS / Windows where the platform always
/// reports mtime), conservatively returns `false` — the caller's next
/// retry will probe again.
#[must_use]
pub fn is_size_stable(a: &Metadata, b: &Metadata) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let (Ok(ma), Ok(mb)) = (a.modified(), b.modified()) else {
        return false;
    };
    ma == mb
}

/// Sleep abstraction used by [`wait_for_ready`].
///
/// Production wires [`RealClock`] (delegating to
/// [`std::thread::sleep`]); tests wire an instant impl to avoid
/// adding real wall-clock latency to the test suite.
pub trait Clock {
    /// Block the current thread for `dur`.
    fn sleep(&self, dur: Duration);
}

/// Real-time clock used by the production daemon loop. Delegates to
/// [`std::thread::sleep`].
pub struct RealClock;

impl Clock for RealClock {
    fn sleep(&self, dur: Duration) {
        std::thread::sleep(dur);
    }
}

/// Wait up to `window` for `path` to become size-stable.
///
/// Returns:
/// - `Ok(true)` if the path does NOT match a partial-marker pattern
///   AND the two metadata reads (`window` apart) report identical
///   size + mtime AND the size is non-zero.
/// - `Ok(false)` if the path matches a partial-marker pattern OR the
///   file is zero-bytes OR the size/mtime changed during the probe.
/// - `Err(io::Error)` if either `stat()` call fails (missing file,
///   permission denied, etc.). Caller (daemon loop) logs + skips.
///
/// Pure-function-decomposable per spec §D6: the inner predicates
/// ([`matches_partial_pattern`] + [`is_size_stable`]) are pure and
/// table-tested; only this orchestrator does I/O.
pub fn wait_for_ready<C: Clock>(path: &Path, clock: &C, window: Duration) -> std::io::Result<bool> {
    if matches_partial_pattern(path) {
        return Ok(false);
    }
    let first = std::fs::metadata(path)?;
    if first.len() == 0 {
        return Ok(false);
    }
    clock.sleep(window);
    let second = std::fs::metadata(path)?;
    Ok(is_size_stable(&first, &second))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    /// Smallest sleep granularity reliably observable across mtime
    /// resolutions on macOS APFS / Linux ext4 (both nanosecond), and
    /// FAT/exFAT (~1–2 s). The `size_unstable_after_write` test must
    /// straddle whichever resolution is in play; 50 ms is well below
    /// 1 s but above the high-res floor.
    const MTIME_GAP: Duration = Duration::from_millis(50);

    /// `Clock` impl used in tests — never actually sleeps. Avoids
    /// adding real wall-clock latency to the suite (the predicate
    /// behaviour, not the sleep duration, is under test).
    struct InstantClock;
    impl Clock for InstantClock {
        fn sleep(&self, _: Duration) {}
    }

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    // ---------- matches_partial_pattern: positive cases (one per spec §D6 row) ----------

    #[test]
    fn icloud_partial_marker_caught() {
        assert!(matches_partial_pattern(&p("foo.icloud")));
        assert!(matches_partial_pattern(&p("dir/sub/bar.icloud")));
    }

    #[test]
    fn tmp_partial_marker_caught() {
        assert!(matches_partial_pattern(&p("write.tmp")));
        assert!(matches_partial_pattern(&p("a.b.tmp")));
    }

    #[test]
    fn partial_suffix_caught() {
        assert!(matches_partial_pattern(&p("download.partial")));
    }

    #[test]
    fn crdownload_suffix_caught() {
        assert!(matches_partial_pattern(&p("foo.crdownload")));
    }

    #[test]
    fn download_suffix_caught() {
        // Safari / Firefox in-progress download — spec §D6.
        assert!(matches_partial_pattern(&p("install.download")));
    }

    #[test]
    fn dropbox_transient_caught() {
        // Dropbox `.~foo.tmp` matches BOTH the `.~` prefix branch
        // AND the `.tmp` suffix branch — pin both routes.
        assert!(matches_partial_pattern(&p(".~dropbox-abc.tmp")));
    }

    #[test]
    fn libreoffice_lockfile_caught() {
        assert!(matches_partial_pattern(&p(".~lock.foo.odt#")));
    }

    #[test]
    fn ms_office_lockfile_caught() {
        assert!(matches_partial_pattern(&p("~$report.docx")));
    }

    #[test]
    fn vim_swap_caught() {
        assert!(matches_partial_pattern(&p("foo.swp")));
        assert!(matches_partial_pattern(&p("foo.swo")));
    }

    #[test]
    fn dotted_metadata_caught() {
        assert!(matches_partial_pattern(&p(".DS_Store")));
        assert!(matches_partial_pattern(&p("desktop.ini")));
        // Case-insensitive — Windows case-folds, and macOS case-folded
        // volumes lookup either way.
        assert!(matches_partial_pattern(&p("DESKTOP.INI")));
    }

    // ---------- matches_partial_pattern: negative cases (vault content) ----------

    #[test]
    fn vault_files_not_caught() {
        // None of the real vault filenames may be filtered as partial.
        assert!(!matches_partial_pattern(&p("manifest.cbor.enc")));
        assert!(!matches_partial_pattern(&p(
            "block_01234567890123456789012345678901.cbor.enc"
        )));
        assert!(!matches_partial_pattern(&p("vault.toml")));
        assert!(!matches_partial_pattern(&p("identity.bundle.enc")));
    }

    #[test]
    fn empty_path_not_caught() {
        // Path with no basename (root) — function returns false rather
        // than panicking.
        assert!(!matches_partial_pattern(&p("/")));
    }

    // ---------- is_size_stable: stable + unstable cases ----------

    #[test]
    fn size_stable_when_no_writes_between_reads() {
        let mut f = tempfile::NamedTempFile::new().expect("temp file");
        writeln!(f, "stable").expect("write");
        let m1 = std::fs::metadata(f.path()).expect("metadata 1");
        let m2 = std::fs::metadata(f.path()).expect("metadata 2");
        assert!(is_size_stable(&m1, &m2));
    }

    #[test]
    fn size_unstable_after_write() {
        let mut f = tempfile::NamedTempFile::new().expect("temp file");
        writeln!(f, "first").expect("write 1");
        let m1 = std::fs::metadata(f.path()).expect("metadata 1");
        // Sleep MTIME_GAP so mtime advances on coarse-resolution
        // filesystems; the size will also have changed, which is the
        // primary failure axis we're pinning.
        std::thread::sleep(MTIME_GAP);
        writeln!(f, "second").expect("write 2");
        let m2 = std::fs::metadata(f.path()).expect("metadata 2");
        assert!(!is_size_stable(&m1, &m2));
    }

    // ---------- wait_for_ready: orchestrator branches ----------

    #[test]
    fn wait_for_ready_rejects_partial_marker() {
        // Use a tempdir so the `.icloud` sidecar is cleaned up
        // automatically (don't leak files into /tmp).
        let dir = tempfile::tempdir().expect("temp dir");
        let icloud_path = dir.path().join("payload.icloud");
        std::fs::write(&icloud_path, b"x").expect("write");
        let clock = InstantClock;
        assert!(!wait_for_ready(&icloud_path, &clock, Duration::ZERO).expect("ready"));
    }

    #[test]
    fn wait_for_ready_accepts_stable_file() {
        let mut f = tempfile::NamedTempFile::new().expect("temp file");
        writeln!(f, "stable data").expect("write");
        let clock = InstantClock;
        assert!(wait_for_ready(f.path(), &clock, Duration::ZERO).expect("ready"));
    }

    #[test]
    fn wait_for_ready_rejects_empty_file() {
        // NamedTempFile::new() creates a zero-byte file; the empty
        // check fires before the size-stability probe.
        let f = tempfile::NamedTempFile::new().expect("temp file");
        let clock = InstantClock;
        assert!(!wait_for_ready(f.path(), &clock, Duration::ZERO).expect("ready"));
    }

    #[test]
    fn wait_for_ready_errors_on_missing_file() {
        // Path inside a tempdir that we never write — first stat()
        // returns ENOENT, propagated as io::Error.
        let dir = tempfile::tempdir().expect("temp dir");
        let missing = dir.path().join("not-there");
        let clock = InstantClock;
        let result = wait_for_ready(&missing, &clock, Duration::ZERO);
        assert!(result.is_err(), "expected ENOENT, got {result:?}");
    }
}
