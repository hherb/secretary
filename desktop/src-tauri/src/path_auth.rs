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
    /// Parent folder for vault creation (#378). Kept separate from
    /// `VaultFolder` so an unlock pick (matched `Exact`) can never authorize
    /// a `Containment`-matched `create_vault` / `probe_create_target` in a
    /// subfolder of the unlocked vault's folder.
    CreateParent,
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

    /// Like [`approve`](Self::approve), but only if `purpose` has no slot yet.
    /// Returns whether the approval was recorded. For non-gesture seeders
    /// (#446 `use_recent_vault`): a path the user actually picked must never
    /// be overwritten by a stored one, regardless of arrival order.
    pub fn approve_if_vacant(&mut self, purpose: PathPurpose, canonical: PathBuf) -> bool {
        match self.slots.entry(purpose) {
            std::collections::hash_map::Entry::Occupied(_) => false,
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(canonical);
                true
            }
        }
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
///
/// Intended for absolute paths as produced by native file/folder dialogs; a
/// relative path with no existing on-disk ancestor also returns `None`
/// (fail-closed).
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
        assert!(is_contained(
            Path::new("/a/vaults"),
            Path::new("/a/vaults/x")
        ));
        assert!(is_contained(Path::new("/a/vaults"), Path::new("/a/vaults")));
        // Sibling that merely shares a string prefix must NOT match.
        assert!(!is_contained(
            Path::new("/a/vaults"),
            Path::new("/a/vaults-evil")
        ));
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

    /// #378 regression: an unlock pick (`VaultFolder`) must never authorize a
    /// create in a subfolder — create/probe consult the `CreateParent` slot,
    /// which only `pick_create_folder` populates.
    #[test]
    fn vault_folder_approval_never_authorizes_create_parent() {
        let dir = tempdir().unwrap();
        let sub = dir.path().join("sub");
        let mut approvals = PathApprovals::default();
        approvals.approve(
            PathPurpose::VaultFolder,
            canonicalize_for_auth(dir.path()).unwrap(),
        );
        assert!(!approvals.is_authorized(PathPurpose::CreateParent, &sub, MatchMode::Containment));
        assert!(!approvals.is_authorized(
            PathPurpose::CreateParent,
            dir.path(),
            MatchMode::Containment
        ));
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
    fn approve_if_vacant_yields_to_an_existing_approval() {
        let a = tempdir().unwrap();
        let b = tempdir().unwrap();
        let canonical_a = canonicalize_for_auth(a.path()).unwrap();
        let canonical_b = canonicalize_for_auth(b.path()).unwrap();

        let mut approvals = PathApprovals::default();
        // Vacant slot: the seed lands.
        assert!(approvals.approve_if_vacant(PathPurpose::VaultFolder, canonical_a));
        assert!(approvals.is_authorized(PathPurpose::VaultFolder, a.path(), MatchMode::Exact));
        // Occupied slot: the seed is refused, the prior approval survives.
        assert!(!approvals.approve_if_vacant(PathPurpose::VaultFolder, canonical_b));
        assert!(approvals.is_authorized(PathPurpose::VaultFolder, a.path(), MatchMode::Exact));
        assert!(!approvals.is_authorized(PathPurpose::VaultFolder, b.path(), MatchMode::Exact));
    }

    #[test]
    fn re_pick_overwrites_the_slot() {
        let a = tempdir().unwrap();
        let b = tempdir().unwrap();
        let mut approvals = PathApprovals::default();
        approvals.approve(
            PathPurpose::VaultFolder,
            canonicalize_for_auth(a.path()).unwrap(),
        );
        approvals.approve(
            PathPurpose::VaultFolder,
            canonicalize_for_auth(b.path()).unwrap(),
        );
        assert!(!approvals.is_authorized(PathPurpose::VaultFolder, a.path(), MatchMode::Exact));
        assert!(approvals.is_authorized(PathPurpose::VaultFolder, b.path(), MatchMode::Exact));
    }

    #[test]
    fn clear_drops_all_slots() {
        let dir = tempdir().unwrap();
        let mut approvals = PathApprovals::default();
        approvals.approve(
            PathPurpose::VaultFolder,
            canonicalize_for_auth(dir.path()).unwrap(),
        );
        approvals.clear();
        assert!(!approvals.is_authorized(PathPurpose::VaultFolder, dir.path(), MatchMode::Exact));
    }

    /// A symlink inside the approved base that points outside it must not
    /// authorize a path traversing through that symlink: `canonicalize_for_auth`
    /// resolves symlinks in the existing prefix, so `base/link/secret` canonicalizes
    /// to somewhere under the *outside* dir, which is neither equal to nor contained
    /// in the approved `base` slot.
    #[cfg(unix)]
    #[test]
    fn symlink_escape_from_approved_base_is_rejected() {
        use std::os::unix::fs::symlink;

        let outside = tempdir().unwrap();
        let base = tempdir().unwrap();
        let link = base.path().join("link");
        symlink(outside.path(), &link).unwrap();

        let mut approvals = PathApprovals::default();
        approvals.approve(
            PathPurpose::VaultFolder,
            canonicalize_for_auth(base.path()).unwrap(),
        );

        // Does not exist: canonicalize_for_auth must still resolve `link` (which does
        // exist) and land the result outside `base`.
        let escaped = link.join("secret");
        assert!(!approvals.is_authorized(
            PathPurpose::VaultFolder,
            &escaped,
            MatchMode::Containment
        ));
        assert!(!approvals.is_authorized(PathPurpose::VaultFolder, &escaped, MatchMode::Exact));
    }
}
