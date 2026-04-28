//! Atomic-write helpers for the vault's on-disk files
//! (`docs/vault-format.md` §9, lines 424-431).
//!
//! The format mandates that every file write be atomic: write to a
//! `<filename>.tmp.<random>` sibling, fsync the data, rename over the
//! target, then fsync the parent directory. The block-and-manifest
//! sequencing in PR-B's orchestrators (`create_vault`, `save_block`,
//! `share_block`) writes the block first and the manifest second; a
//! crash between the two leaves a fresh block plus a stale manifest,
//! which subsequent code can detect and recover from. None of that
//! recovery logic is correct unless individual writes are truly
//! atomic, which is what these two helpers guarantee.
//!
//! [`write_atomic`] is the only function the orchestrators in
//! [`super`] should call to put bytes on disk; [`fsync_dir`] is
//! exposed alongside it both because `write_atomic` calls it and
//! because future callers (e.g. directory-creation paths) may want
//! the same POSIX durability hardening without reissuing a write.
//!
//! Atomicity is provided by `tempfile::NamedTempFile::persist`, which
//! wraps `rename(2)` on POSIX and `MoveFileExW` with replace semantics
//! on Windows. The dir-fsync step is POSIX-only: NTFS metadata is
//! journaled separately and there is no portable equivalent of
//! `fsync(2)` on a Windows directory handle, so [`fsync_dir`] is a
//! no-op there.

#![forbid(unsafe_code)]

use std::path::Path;

/// Write `bytes` to `path` atomically, per `docs/vault-format.md` §9.
///
/// Steps:
/// 1. Resolve the parent directory of `path`. Returns `Err` (kind
///    `InvalidInput`) if `path` has no parent — i.e. the caller passed
///    a bare filename like `"foo.txt"` with no directory prefix. We do
///    not silently fall back to the current working directory because
///    the caller's intent is ambiguous and silently fsyncing `.` would
///    be surprising.
/// 2. Create `<path>.tmp.<random>` in that parent via
///    [`tempfile::NamedTempFile::new_in`]. The random suffix is
///    drawn from the OS RNG inside `tempfile`.
/// 3. Write `bytes` with `write_all`.
/// 4. `sync_all` on the temp file — this fsyncs the data and metadata
///    of the file *contents* before any rename is observable.
/// 5. `persist(path)` to atomically rename over the target. On
///    `persist` failure the underlying [`tempfile::NamedTempFile`] is
///    cleaned up automatically by `tempfile` (the temp file does not
///    leak).
/// 6. [`fsync_dir`] on the parent so the rename itself is durable.
///
/// The combined effect: after this function returns `Ok`, either the
/// old contents of `path` are still readable (if a crash happened
/// before step 5) or the new contents are durably on disk (if the
/// crash happened after step 6). There is no torn-write window in
/// between, modulo filesystem-level caveats that are outside this
/// helper's contract.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    use std::io::Write;

    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "write_atomic: path has no parent directory",
        )
    })?;

    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    fsync_dir(parent)?;
    Ok(())
}

/// fsync the directory at `parent` so a prior rename into it is
/// durable across power loss / kernel panic.
///
/// On POSIX this opens `parent` as a read-only `File` and calls
/// `sync_all`, which translates to `fsync(2)` on the directory's
/// inode. That flushes the rename's directory-entry update to stable
/// storage; without it the rename can be lost even though the
/// renamed file's data was already fsynced.
///
/// On non-Unix targets this is a no-op. NTFS journals metadata
/// separately and Windows does not expose a portable directory-handle
/// fsync; doing nothing is the documented best practice.
#[cfg(unix)]
pub fn fsync_dir(parent: &Path) -> Result<(), std::io::Error> {
    let dir = std::fs::File::open(parent)?;
    dir.sync_all()
}

/// Non-Unix stub for [`fsync_dir`]. See the Unix variant for the full
/// rationale; on Windows we cannot fsync a directory handle, so this
/// returns `Ok(())` unconditionally.
#[cfg(not(unix))]
pub fn fsync_dir(_parent: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip: write bytes, read them back, and confirm no temp
    /// sibling was left behind.
    #[test]
    fn write_atomic_round_trip_leaves_no_temp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.bin");
        let payload = b"hello vault io";

        write_atomic(&path, payload).unwrap();

        let read_back = std::fs::read(&path).unwrap();
        assert_eq!(read_back.as_slice(), payload);

        // No `*.tmp.*` (or any leftover sibling) remains in the dir.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n != "payload.bin")
            .collect();
        assert!(
            leftovers.is_empty(),
            "expected no leftover temp files, found {leftovers:?}"
        );
    }

    /// Overwrite is atomic: a 4 KiB pre-existing file is replaced
    /// wholesale, with no torn-write window.
    #[test]
    fn write_atomic_overwrite_is_clean() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("target.bin");

        let old = vec![0xAAu8; 4096];
        std::fs::write(&path, &old).unwrap();

        let new = vec![0x55u8; 4096];
        write_atomic(&path, &new).unwrap();

        let read_back = std::fs::read(&path).unwrap();
        assert_eq!(read_back, new);
    }

    /// Empty bytes produces a 0-byte file; not an error.
    #[test]
    fn write_atomic_empty_is_zero_byte_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.bin");

        write_atomic(&path, b"").unwrap();

        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.len(), 0);
    }

    /// If the parent directory does not exist, `write_atomic` errors
    /// out at the `NamedTempFile::new_in` step rather than creating
    /// directories silently.
    #[test]
    fn write_atomic_errors_when_parent_missing() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist").join("foo.txt");

        let err = write_atomic(&missing, b"x").unwrap_err();
        // We don't assert a specific kind — the OS may report
        // `NotFound`, `Other`, etc. — only that the call failed.
        let _ = err;
    }

    /// `fsync_dir` on a real, existing directory returns `Ok(())` on
    /// every supported platform. On Unix it actually fsyncs; on
    /// non-Unix it is a no-op by design.
    #[test]
    fn fsync_dir_on_tempdir_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        fsync_dir(dir.path()).unwrap();
    }
}
