//! `use_recent_vault` command (#446): pre-fill the unlock dialog with the
//! most recently opened vault.
//!
//! The frontend never supplies the remembered path — this command reads it
//! from the desktop-local `recent.json` (written only by a successful unlock,
//! see `recent_vault`), routes it through the SAME `canonicalize_for_auth` →
//! `PathPurpose::VaultFolder` slot as a `pick_vault_folder` dialog choice
//! (#353), and returns the display string for the folder field. The
//! subsequent `unlock_with_password` therefore passes the approval gate with
//! no bypass and no weakening of the exact-match check.
//!
//! Fail-safe toward the fresh-install behavior: an absent or corrupt record,
//! a path that no longer canonicalizes, or a folder that no longer looks like
//! a vault (moved, deleted, emptied) all yield `Ok(None)` and leave the
//! approval slot untouched.
//!
//! Two structural guards keep the non-gesture seed harmless:
//! - **Locked sessions only.** Against an unlocked session the command
//!   returns `None` without touching the slot, so it can never re-establish
//!   the approval that `populate_unlocked`'s post-unlock clear revoked — the
//!   guard is enforced here, not merely emergent from today's slot consumers
//!   all rejecting `AlreadyUnlocked`.
//! - **Never clobbers a pick.** Seeding uses `approve_path_if_vacant`: if a
//!   `pick_vault_folder` choice already occupies the slot (the lookup and the
//!   picker are concurrent by design), the user's pick wins and this returns
//!   `None`.

use std::sync::Mutex;

use tauri::State;

use crate::commands::shared::lock_session;
use crate::commands::unlock::validate_vault_path;
use crate::errors::AppError;
use crate::path_auth::{canonicalize_for_auth, PathPurpose};
use crate::recent_vault;
use crate::session::VaultSession;

/// Tauri-side entry point. Thin delegating shell; logic lives in
/// [`use_recent_vault_impl`].
#[tauri::command]
pub async fn use_recent_vault(
    state: State<'_, Mutex<VaultSession>>,
) -> Result<Option<String>, AppError> {
    use_recent_vault_impl(state.inner())
}

/// Testable core. Returns the canonical display path of the remembered vault
/// after seeding the `VaultFolder` approval slot, or `None` (with the slot
/// untouched) when there is nothing usable to pre-fill.
pub fn use_recent_vault_impl(state: &Mutex<VaultSession>) -> Result<Option<String>, AppError> {
    // Short lock: refuse post-unlock use structurally (not merely because
    // today's slot consumers happen to reject `AlreadyUnlocked`) and grab the
    // device dir.
    let data_dir = {
        let session = lock_session(state)?;
        if session.is_unlocked() {
            return Ok(None);
        }
        session.device_data_dir_clone()
    };

    // Filesystem work OUTSIDE the session lock (mirrors
    // `unlock_with_password_impl`): a stalled network mount must not block
    // the auto-lock tick or concurrent commands on the session mutex.
    let Some(stored) = recent_vault::load_recent_in(&data_dir) else {
        return Ok(None);
    };
    let Some(canonical) = canonicalize_for_auth(&stored) else {
        return Ok(None);
    };
    let display = canonical.to_string_lossy().into_owned();
    // The remembered folder must still look like a vault (same file-presence
    // check the unlock command applies) — otherwise treat it as absent rather
    // than seeding the approval slot with a doomed path.
    if validate_vault_path(&canonical, &display).is_err() {
        return Ok(None);
    }

    // Re-lock only to seed — and never clobber: if a picker choice landed
    // while this lookup was doing IO (or before it was even dispatched), the
    // user's fresher pick wins and the pre-fill is abandoned.
    if !lock_session(state)?.approve_path_if_vacant(PathPurpose::VaultFolder, canonical) {
        return Ok(None);
    }
    Ok(Some(display))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path_auth::MatchMode;
    use std::path::Path;
    use tempfile::tempdir;

    /// Make `dir` pass `validate_vault_path`'s file-presence check (the
    /// cryptographic proof is the bridge's job, not this command's). Uses the
    /// same filename constants as the real check so a vault-shape change can
    /// never leave this fixture silently green against a stale shape.
    fn make_vault_shaped(dir: &Path) {
        use crate::commands::unlock::{IDENTITY_BUNDLE_FILENAME, VAULT_TOML_FILENAME};
        std::fs::write(dir.join(VAULT_TOML_FILENAME), b"[v1]\n").unwrap();
        std::fs::write(dir.join(IDENTITY_BUNDLE_FILENAME), b"sealed").unwrap();
    }

    fn state_with_device_dir(device_dir: &Path) -> Mutex<VaultSession> {
        Mutex::new(VaultSession::new(device_dir.to_path_buf()))
    }

    #[test]
    fn no_recent_file_yields_none_and_no_approval() {
        let device_dir = tempdir().unwrap();
        let state = state_with_device_dir(device_dir.path());
        assert_eq!(use_recent_vault_impl(&state).unwrap(), None);
        let session = state.lock().unwrap();
        assert!(!session.is_path_approved(
            PathPurpose::VaultFolder,
            Path::new("/tmp"),
            MatchMode::Exact
        ));
    }

    #[test]
    fn recent_vault_prefills_and_approves_the_slot() {
        let device_dir = tempdir().unwrap();
        let vault_dir = tempdir().unwrap();
        make_vault_shaped(vault_dir.path());
        recent_vault::save_recent_in(device_dir.path(), vault_dir.path()).unwrap();

        let state = state_with_device_dir(device_dir.path());
        let display = use_recent_vault_impl(&state)
            .unwrap()
            .expect("recorded vault pre-fills");

        // The returned display string is the canonical form — byte-identical
        // to what a picker choice of the same folder would have returned.
        let canonical = canonicalize_for_auth(vault_dir.path()).unwrap();
        assert_eq!(display, canonical.to_string_lossy());

        // And the slot is seeded so the follow-up unlock passes the #353 gate.
        let session = state.lock().unwrap();
        assert!(session.is_path_approved(
            PathPurpose::VaultFolder,
            vault_dir.path(),
            MatchMode::Exact
        ));
    }

    /// A recorded vault that has since been moved/deleted behaves like a
    /// fresh install — and crucially does NOT seed the approval slot.
    #[test]
    fn vanished_recent_path_yields_none_and_no_approval() {
        let device_dir = tempdir().unwrap();
        let vault_dir = tempdir().unwrap();
        let gone = vault_dir.path().join("moved-away");
        recent_vault::save_recent_in(device_dir.path(), &gone).unwrap();

        let state = state_with_device_dir(device_dir.path());
        assert_eq!(use_recent_vault_impl(&state).unwrap(), None);
        let session = state.lock().unwrap();
        assert!(!session.is_path_approved(PathPurpose::VaultFolder, &gone, MatchMode::Exact));
    }

    /// A folder that exists but no longer holds the canonical vault files
    /// (e.g. the user emptied it) is equally not worth pre-filling.
    #[test]
    fn non_vault_recent_path_yields_none_and_no_approval() {
        let device_dir = tempdir().unwrap();
        let empty_dir = tempdir().unwrap();
        recent_vault::save_recent_in(device_dir.path(), empty_dir.path()).unwrap();

        let state = state_with_device_dir(device_dir.path());
        assert_eq!(use_recent_vault_impl(&state).unwrap(), None);
        let session = state.lock().unwrap();
        assert!(!session.is_path_approved(
            PathPurpose::VaultFolder,
            empty_dir.path(),
            MatchMode::Exact
        ));
    }

    /// Race guard: if the user already picked a folder (the picker seeded the
    /// slot) before this lookup's backend work finished, the fresher pick must
    /// win — the late seed is skipped and `None` returned so the frontend
    /// leaves the user's choice alone.
    #[test]
    fn a_prior_user_pick_is_not_clobbered_by_a_late_lookup() {
        let device_dir = tempdir().unwrap();
        let recorded_vault = tempdir().unwrap();
        make_vault_shaped(recorded_vault.path());
        recent_vault::save_recent_in(device_dir.path(), recorded_vault.path()).unwrap();

        let picked = tempdir().unwrap();
        let state = state_with_device_dir(device_dir.path());
        state.lock().unwrap().approve_path(
            PathPurpose::VaultFolder,
            canonicalize_for_auth(picked.path()).unwrap(),
        );

        assert_eq!(use_recent_vault_impl(&state).unwrap(), None);
        let session = state.lock().unwrap();
        assert!(
            session.is_path_approved(PathPurpose::VaultFolder, picked.path(), MatchMode::Exact),
            "the user's pick must survive a late recent-vault seed"
        );
        assert!(!session.is_path_approved(
            PathPurpose::VaultFolder,
            recorded_vault.path(),
            MatchMode::Exact
        ));
    }

    #[test]
    fn corrupt_recent_file_yields_none() {
        let device_dir = tempdir().unwrap();
        let path = recent_vault::recent_path_in(device_dir.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"garbage").unwrap();

        let state = state_with_device_dir(device_dir.path());
        assert_eq!(use_recent_vault_impl(&state).unwrap(), None);
    }
}
