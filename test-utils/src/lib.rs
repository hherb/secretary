//! Workspace-internal test helpers, shared across every crate's test suite
//! via `[dev-dependencies]`.
//!
//! This crate exists to hold the one canonical copy of helpers that were
//! previously hand-rolled per test module (#90, #186) — chiefly the
//! recursive fixture-copy used to stage a writable clone of a committed
//! vault fixture before a mutation test. It must stay tiny, dependency-lean,
//! and **must never become a normal dependency** of a shipping crate: the
//! lean mobile-binding boundary (#189, `ffi/scripts/check-lean-binding.sh`)
//! only checks normal-edge trees, and dev-only consumption is what keeps
//! this crate invisible to it.

use std::fs;
use std::path::{Path, PathBuf};

/// Absolute path to `core/tests/data/` — the workspace's committed fixture
/// repository (golden vaults, KATs, sync fixtures).
///
/// Resolved relative to this crate's own manifest dir, so it is correct from
/// any consuming crate's test target regardless of that crate's location in
/// the workspace.
pub fn core_test_data_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("test-utils crate dir has a parent (the workspace root)")
        .join("core")
        .join("tests")
        .join("data")
}

/// Recursively copy the directory tree at `src` into `dst`, creating `dst`
/// (and any missing parents) first.
///
/// Semantics — documented once here, for every staged-fixture test in the
/// workspace:
///
/// - **Merge, not replace:** an existing `dst` is merged into; a file at a
///   colliding relative path is overwritten, unrelated pre-existing files
///   are left in place. (Every current caller copies into a fresh tempdir,
///   where the distinction never surfaces.)
/// - **Not symlink-safe:** a symlink to a file copies the target's *bytes*
///   (via [`std::fs::copy`]); a symlink to a directory panics. The committed
///   fixtures contain no symlinks.
/// - **Permissions:** file permission bits follow [`std::fs::copy`];
///   directories are created with default permissions, not the source's.
///
/// # Panics
///
/// On any IO error, naming the offending path — this is a test helper, and
/// a loud early panic beats threading `Result` through fixture setup.
pub fn copy_dir_recursive(src: &Path, dst: &Path) {
    fs::create_dir_all(dst)
        .unwrap_or_else(|e| panic!("failed to create dst dir {}: {e}", dst.display()));
    let entries = fs::read_dir(src)
        .unwrap_or_else(|e| panic!("failed to read src dir {}: {e}", src.display()));
    for entry in entries {
        let entry = entry
            .unwrap_or_else(|e| panic!("failed to read dir entry under {}: {e}", src.display()));
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let file_type = entry
            .file_type()
            .unwrap_or_else(|e| panic!("failed to stat {}: {e}", from.display()));
        if file_type.is_dir() {
            copy_dir_recursive(&from, &to);
        } else {
            fs::copy(&from, &to).unwrap_or_else(|e| {
                panic!("failed to copy {} -> {}: {e}", from.display(), to.display())
            });
        }
    }
}

/// Copy the directory tree at `src` into a fresh [`tempfile::TempDir`] and
/// return the guard.
///
/// The caller MUST hold the returned guard for the duration of any use of
/// the copy — dropping it deletes the directory. Copy semantics and panics
/// are those of [`copy_dir_recursive`].
pub fn copy_dir_to_tempdir(src: &Path) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap_or_else(|e| {
        panic!(
            "failed to create tempdir for copy of {}: {e}",
            src.display()
        )
    });
    copy_dir_recursive(src, tmp.path());
    tmp
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a small source tree: a root file, a nested file, and an empty
    /// subdirectory (the empty dir is the case a naive file-walk drops).
    fn build_source_tree() -> tempfile::TempDir {
        let src = tempfile::tempdir().expect("src tempdir");
        fs::write(src.path().join("root.txt"), b"root contents").unwrap();
        fs::create_dir(src.path().join("sub")).unwrap();
        fs::write(src.path().join("sub/nested.bin"), [0u8, 1, 2, 255]).unwrap();
        fs::create_dir(src.path().join("empty")).unwrap();
        src
    }

    #[test]
    fn copies_nested_tree_including_empty_dirs() {
        let src = build_source_tree();
        let dst = tempfile::tempdir().expect("dst tempdir");

        copy_dir_recursive(src.path(), dst.path());

        assert_eq!(
            fs::read(dst.path().join("root.txt")).unwrap(),
            b"root contents"
        );
        assert_eq!(
            fs::read(dst.path().join("sub/nested.bin")).unwrap(),
            [0u8, 1, 2, 255]
        );
        assert!(
            dst.path().join("empty").is_dir(),
            "empty dirs must be preserved"
        );
    }

    #[test]
    fn merges_into_existing_dst_overwriting_collisions() {
        let src = build_source_tree();
        let dst = tempfile::tempdir().expect("dst tempdir");
        fs::write(dst.path().join("root.txt"), b"stale").unwrap();
        fs::write(dst.path().join("unrelated.txt"), b"keep me").unwrap();

        copy_dir_recursive(src.path(), dst.path());

        assert_eq!(
            fs::read(dst.path().join("root.txt")).unwrap(),
            b"root contents",
            "colliding file must be overwritten"
        );
        assert_eq!(
            fs::read(dst.path().join("unrelated.txt")).unwrap(),
            b"keep me",
            "unrelated pre-existing file must survive (merge, not replace)"
        );
    }

    #[test]
    #[should_panic(expected = "failed to read src dir")]
    fn panics_on_missing_src() {
        let dst = tempfile::tempdir().expect("dst tempdir");
        copy_dir_recursive(Path::new("/nonexistent/fixture/path"), dst.path());
    }

    #[test]
    fn copy_dir_to_tempdir_stages_an_independent_writable_copy() {
        let src = build_source_tree();

        let staged = copy_dir_to_tempdir(src.path());

        assert_eq!(
            fs::read(staged.path().join("root.txt")).unwrap(),
            b"root contents"
        );
        // Mutating the staged copy must not touch the source.
        fs::write(staged.path().join("root.txt"), b"mutated").unwrap();
        assert_eq!(
            fs::read(src.path().join("root.txt")).unwrap(),
            b"root contents"
        );
    }

    #[test]
    fn core_test_data_dir_points_at_the_committed_fixtures() {
        let golden = core_test_data_dir().join("golden_vault_001");
        assert!(
            golden.join("vault.toml").is_file(),
            "expected the golden vault fixture at {}",
            golden.display()
        );
    }
}
