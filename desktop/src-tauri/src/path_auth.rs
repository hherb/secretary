//! Path-authorization core for issue #353: binds webview-supplied path
//! arguments to paths the user chose in a native backend dialog.
//!
//! Pure and free of Tauri / `AppError`. `canonicalize_for_auth` defeats
//! `..` traversal and symlink escapes (resolving symlinks in the existing
//! prefix) while still handling not-yet-created targets; `is_contained`
//! compares on component boundaries. `PathApprovals` holds one approved
//! path per `PathPurpose` (last pick wins) and is consulted with a
//! per-command `MatchMode`.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

/// The kind of path a dialog produced and a command consumes. Part of the
/// approval key so an approval for one purpose never authorizes another.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum PathPurpose {
    VaultFolder,
    ContactCard,
    ExportDir,
}

/// How strictly a command's path must match its approved slot. Least-privilege:
/// only the create wizard's "subfolder" offer uses `Containment`.
#[derive(Clone, Copy, Debug)]
pub enum MatchMode {
    Exact,
    Containment,
}

/// Per-purpose last-approved slot. One canonical path per purpose; a new pick
/// overwrites the previous one. Cleared on vault lock.
#[derive(Default, Debug)]
pub struct PathApprovals {
    slots: HashMap<PathPurpose, PathBuf>,
}

impl PathApprovals {
    /// Record `canonical` (already `canonicalize_for_auth` output) as the
    /// approved path for `purpose`, replacing any prior slot value.
    pub fn approve(&mut self, purpose: PathPurpose, canonical: PathBuf) {
        self.slots.insert(purpose, canonical);
    }

    /// True iff `requested` is authorized for `purpose` under `mode`.
    /// Fail-closed: unknown purpose or a path that cannot be canonicalized
    /// (contains `..`, or its existing prefix fails to resolve) is rejected.
    pub fn is_authorized(&self, purpose: PathPurpose, requested: &Path, mode: MatchMode) -> bool {
        let Some(slot) = self.slots.get(&purpose) else {
            return false;
        };
        let Some(canonical) = canonicalize_for_auth(requested) else {
            return false;
        };
        match mode {
            MatchMode::Exact => canonical == *slot,
            MatchMode::Containment => is_contained(slot, &canonical),
        }
    }

    /// Drop every approved slot (called on vault lock).
    pub fn clear(&mut self) {
        self.slots.clear();
    }
}

/// Resolve `path` to a comparison-canonical form that defeats `..` traversal
/// and symlink escapes while still handling not-yet-created targets:
/// 1. reject any `..` component;
/// 2. canonicalize the deepest existing ancestor (resolves symlinks there);
/// 3. re-append the non-existent tail (only `Normal` components remain).
///
/// Returns `None` on a `..` component, an empty path, or a prefix that fails
/// to canonicalize. Deterministic and idempotent on its own output.
pub fn canonicalize_for_auth(path: &Path) -> Option<PathBuf> {
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return None;
    }
    let mut existing = path.to_path_buf();
    let mut tail: Vec<OsString> = Vec::new();
    while !existing.exists() {
        let name = existing.file_name()?.to_os_string();
        tail.push(name);
        if !existing.pop() {
            return None; // exhausted ancestors without finding an existing one
        }
    }
    let mut canonical = std::fs::canonicalize(&existing).ok()?;
    for name in tail.iter().rev() {
        canonical.push(name);
    }
    Some(canonical)
}

/// True iff `descendant` is `ancestor` or lies beneath it on a component
/// boundary. Both arguments must already be `canonicalize_for_auth` output.
/// Uses `Path::starts_with` (component-wise) so `/a/vaults` does not match
/// `/a/vaults-evil`.
pub fn is_contained(ancestor: &Path, descendant: &Path) -> bool {
    descendant.starts_with(ancestor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::tempdir;

    #[test]
    fn canonicalize_rejects_parent_dir_component() {
        assert!(canonicalize_for_auth(Path::new("/tmp/../etc/passwd")).is_none());
    }

    #[test]
    fn canonicalize_resolves_existing_path_idempotently() {
        let dir = tempdir().unwrap();
        let once = canonicalize_for_auth(dir.path()).expect("canonicalizes");
        let twice = canonicalize_for_auth(&once).expect("idempotent");
        assert_eq!(once, twice);
    }

    #[test]
    fn canonicalize_handles_nonexistent_tail_under_existing_prefix() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("does-not-exist-yet");
        let canonical = canonicalize_for_auth(&target).expect("prefix exists");
        let canonical_parent = canonicalize_for_auth(dir.path()).unwrap();
        assert_eq!(canonical, canonical_parent.join("does-not-exist-yet"));
    }

    #[test]
    fn is_contained_requires_component_boundary() {
        assert!(is_contained(Path::new("/a/vaults"), Path::new("/a/vaults/x")));
        assert!(is_contained(Path::new("/a/vaults"), Path::new("/a/vaults")));
        // Sibling that merely shares a string prefix must NOT match.
        assert!(!is_contained(Path::new("/a/vaults"), Path::new("/a/vaults-evil")));
    }

    #[test]
    fn exact_mode_rejects_descendant_that_containment_accepts() {
        let dir = tempdir().unwrap();
        let child = dir.path().join("child");
        std::fs::create_dir(&child).unwrap();
        let mut approvals = PathApprovals::default();
        approvals.approve(
            PathPurpose::VaultFolder,
            canonicalize_for_auth(dir.path()).unwrap(),
        );
        // Descendant: Containment accepts, Exact rejects (least-privilege).
        assert!(approvals.is_authorized(PathPurpose::VaultFolder, &child, MatchMode::Containment));
        assert!(!approvals.is_authorized(PathPurpose::VaultFolder, &child, MatchMode::Exact));
    }

    #[test]
    fn unapproved_purpose_is_never_authorized() {
        let dir = tempdir().unwrap();
        let approvals = PathApprovals::default();
        assert!(!approvals.is_authorized(PathPurpose::VaultFolder, dir.path(), MatchMode::Exact));
    }

    #[test]
    fn approval_is_isolated_per_purpose() {
        let dir = tempdir().unwrap();
        let canonical = canonicalize_for_auth(dir.path()).unwrap();
        let mut approvals = PathApprovals::default();
        approvals.approve(PathPurpose::ContactCard, canonical);
        // A ContactCard approval must not authorize a VaultFolder command.
        assert!(!approvals.is_authorized(PathPurpose::VaultFolder, dir.path(), MatchMode::Exact));
        assert!(approvals.is_authorized(PathPurpose::ContactCard, dir.path(), MatchMode::Exact));
    }

    #[test]
    fn re_pick_overwrites_the_slot() {
        let a = tempdir().unwrap();
        let b = tempdir().unwrap();
        let mut approvals = PathApprovals::default();
        approvals.approve(PathPurpose::VaultFolder, canonicalize_for_auth(a.path()).unwrap());
        approvals.approve(PathPurpose::VaultFolder, canonicalize_for_auth(b.path()).unwrap());
        assert!(!approvals.is_authorized(PathPurpose::VaultFolder, a.path(), MatchMode::Exact));
        assert!(approvals.is_authorized(PathPurpose::VaultFolder, b.path(), MatchMode::Exact));
    }

    #[test]
    fn clear_drops_all_slots() {
        let dir = tempdir().unwrap();
        let mut approvals = PathApprovals::default();
        approvals.approve(PathPurpose::VaultFolder, canonicalize_for_auth(dir.path()).unwrap());
        approvals.clear();
        assert!(!approvals.is_authorized(PathPurpose::VaultFolder, dir.path(), MatchMode::Exact));
    }
}
