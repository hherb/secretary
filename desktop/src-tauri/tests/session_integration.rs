//! Integration tests for the `VaultSession` + settings I/O facade.
//!
//! Uses the workspace-shared `core/tests/data/golden_vault_001/` reference
//! vault for the unlock-against-known-good-vault path, plus
//! `tempfile::tempdir()`-based ephemeral copies for the write-path tests
//! (the golden vault stays read-only — write tests mutate a copy).
//!
//! Hermeticity: each test injects its own `TempDir` for the per-vault
//! device UUID file via [`VaultSession::new`], so no test pollutes the
//! user's real `~/Library/Application Support/secretary-desktop/` (or
//! XDG equivalent on Linux).

use std::path::{Path, PathBuf};

use secretary_desktop::errors::AppError;
use secretary_desktop::session::VaultSession;
use secretary_desktop::settings::Settings;
use tempfile::TempDir;

/// Known-good password for `core/tests/data/golden_vault_001/`. Sourced
/// from `core/tests/data/golden_vault_001_inputs.json` (the deterministic
/// vault-rebuild inputs the core fixture builder uses). If that file's
/// `password` field ever changes the desktop tests will fail loudly.
const GOLDEN_VAULT_PASSWORD: &[u8] = b"correct horse battery staple";

/// Workspace-root-relative path to the read-only golden vault fixture.
/// `cargo test` sets CWD to the crate root (`desktop/src-tauri/`), so we
/// resolve via `CARGO_MANIFEST_DIR` to make the path independent of CWD.
fn golden_vault_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("desktop/")
        .parent()
        .expect("workspace root")
        .join("core/tests/data/golden_vault_001")
}

/// Convenience: spin up a fresh `(VaultSession, TempDir)` pair. The
/// `TempDir` owns the per-vault device UUID storage and must outlive
/// the session — every caller binds the returned `TempDir` to a local
/// variable to keep it alive.
fn fresh_session() -> (VaultSession, TempDir) {
    let device_dir = tempfile::tempdir().expect("device-uuid tempdir");
    let session = VaultSession::new(device_dir.path().to_path_buf());
    (session, device_dir)
}

#[test]
fn unlock_golden_vault_with_correct_password_succeeds() {
    let (mut session, _device_dir) = fresh_session();
    session
        .unlock(&golden_vault_path(), GOLDEN_VAULT_PASSWORD)
        .expect("unlock golden vault");
    assert!(
        session.is_unlocked(),
        "session must report unlocked after successful unlock"
    );
}

#[test]
fn unlock_with_wrong_password_returns_wrong_password() {
    let (mut session, _device_dir) = fresh_session();
    let err = session
        .unlock(&golden_vault_path(), b"definitely not the password")
        .expect_err("must reject wrong password");
    assert!(
        matches!(err, AppError::WrongPassword),
        "wrong password must map to AppError::WrongPassword, got {err:?}"
    );
    assert!(
        !session.is_unlocked(),
        "failed unlock must leave session locked"
    );
}

#[test]
fn unlock_then_lock_clears_inner_state() {
    let (mut session, _device_dir) = fresh_session();
    session
        .unlock(&golden_vault_path(), GOLDEN_VAULT_PASSWORD)
        .expect("unlock");
    assert!(session.is_unlocked());
    session.lock();
    assert!(
        !session.is_unlocked(),
        "session must report locked after lock()"
    );
}

#[test]
fn second_unlock_while_already_unlocked_returns_already_unlocked() {
    let (mut session, _device_dir) = fresh_session();
    session
        .unlock(&golden_vault_path(), GOLDEN_VAULT_PASSWORD)
        .expect("first unlock");
    let err = session
        .unlock(&golden_vault_path(), GOLDEN_VAULT_PASSWORD)
        .expect_err("second unlock must reject");
    assert!(
        matches!(err, AppError::AlreadyUnlocked),
        "double-unlock must surface AlreadyUnlocked, got {err:?}"
    );
}

#[test]
fn settings_load_from_vault_without_settings_block_returns_defaults() {
    let (mut session, _device_dir) = fresh_session();
    session
        .unlock(&golden_vault_path(), GOLDEN_VAULT_PASSWORD)
        .expect("unlock");
    let s = session.current_settings();
    assert_eq!(
        s,
        Settings::default(),
        "golden vault has no settings block ⇒ load must yield defaults"
    );
}

#[test]
fn pending_warnings_empty_on_clean_unlock() {
    let (mut session, _device_dir) = fresh_session();
    session
        .unlock(&golden_vault_path(), GOLDEN_VAULT_PASSWORD)
        .expect("unlock");
    assert!(
        session.pending_warnings().is_empty(),
        "clean unlock against a settings-less vault must produce no warnings"
    );
}

#[test]
fn pending_warnings_empty_while_locked() {
    let (session, _device_dir) = fresh_session();
    assert!(
        session.pending_warnings().is_empty(),
        "locked session must report no warnings"
    );
}

#[test]
fn unlock_then_lock_cycles_repeatedly() {
    let (mut session, _device_dir) = fresh_session();
    for i in 0..3 {
        session
            .unlock(&golden_vault_path(), GOLDEN_VAULT_PASSWORD)
            .unwrap_or_else(|e| panic!("unlock iteration {i} must succeed: {e:?}"));
        session.lock();
        assert!(!session.is_unlocked(), "iteration {i}: must be locked");
    }
}

#[test]
fn notify_activity_on_locked_session_is_silent_noop() {
    let (mut session, _device_dir) = fresh_session();
    // No unlock; session is locked.
    let before = session.last_activity_ms();
    session.notify_activity(); // must not panic, must not advance tracker
    let after = session.last_activity_ms();
    assert_eq!(
        before, after,
        "notify_activity while locked must NOT advance the idle tracker"
    );
    assert!(!session.is_unlocked());
}

#[test]
fn notify_activity_on_unlocked_session_advances_idle_tracker() {
    let (mut session, _device_dir) = fresh_session();
    session
        .unlock(&golden_vault_path(), GOLDEN_VAULT_PASSWORD)
        .expect("unlock");
    let t0 = session.last_activity_ms();
    std::thread::sleep(std::time::Duration::from_millis(5));
    session.notify_activity();
    let t1 = session.last_activity_ms();
    assert!(
        t1 > t0,
        "notify_activity while unlocked must advance the tracker: t0={t0}, t1={t1}"
    );
}

#[test]
fn lock_transitions_with_unlocked_from_ok_to_not_unlocked() {
    // Indirect proof of the `UnlockedSession::Drop` chain firing: before
    // lock, `with_unlocked` returns Ok(...) with manifest data. After lock,
    // it returns `Err(NotUnlocked)`. The bridge's per-handle zeroize tests
    // separately pin that wipe zeroes the underlying secret bytes; this test
    // pins the session-level state transition.
    let (mut session, _device_dir) = fresh_session();
    session
        .unlock(&golden_vault_path(), GOLDEN_VAULT_PASSWORD)
        .expect("unlock");

    let vault_uuid_pre = session
        .with_unlocked(|u| Ok(u.manifest.vault_uuid()))
        .expect("with_unlocked while unlocked must succeed");
    assert_eq!(
        vault_uuid_pre.len(),
        16,
        "vault_uuid is a 16-byte fixed identifier"
    );

    session.lock();

    let err = session
        .with_unlocked(|u| Ok(u.manifest.vault_uuid()))
        .expect_err("with_unlocked while locked must error");
    assert!(
        matches!(err, AppError::NotUnlocked),
        "post-lock with_unlocked must return NotUnlocked, got {err:?}"
    );
}

// ============================================================================
// Write-path tests — uses an ephemeral copy of the golden vault so we can
// mutate it without touching the read-only fixture.
// ============================================================================

/// Copy `golden_vault_001/` into a fresh tempdir + return both the
/// `TempDir` (to keep the lifetime tied to the test) and the path of the
/// copy.
fn ephemeral_golden_copy() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("vault tempdir");
    let dst = dir.path().to_path_buf();
    copy_recursive(&golden_vault_path(), &dst);
    (dir, dst)
}

fn copy_recursive(src: &Path, dst: &Path) {
    use std::fs;
    if src.is_file() {
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent).expect("mkdir parent");
        }
        fs::copy(src, dst).expect("copy file");
    } else if src.is_dir() {
        fs::create_dir_all(dst).expect("mkdir dir");
        for entry in fs::read_dir(src).expect("read_dir") {
            let entry = entry.expect("entry");
            let src_child = entry.path();
            let dst_child = dst.join(entry.file_name());
            copy_recursive(&src_child, &dst_child);
        }
    }
}

#[test]
fn set_settings_persists_and_reloads() {
    let (_vault_dir, vault_path) = ephemeral_golden_copy();
    let device_dir = tempfile::tempdir().expect("device tempdir");
    // 15 minutes — a non-default in-range value so the assertion below can
    // distinguish "loaded the new value" from "fell back to default".
    let new_value: u64 = 900_000;

    // First unlock + save.
    {
        let mut session = VaultSession::new(device_dir.path().to_path_buf());
        session
            .unlock(&vault_path, GOLDEN_VAULT_PASSWORD)
            .expect("unlock #1");
        session
            .set_settings(&Settings {
                auto_lock_timeout_ms: new_value,
                ..Default::default()
            })
            .expect("set_settings must succeed");
        // session drops at end of scope → UnlockedSession::Drop runs.
    }

    // Second unlock + verify the new value was persisted to disk + loaded.
    {
        let mut session = VaultSession::new(device_dir.path().to_path_buf());
        session
            .unlock(&vault_path, GOLDEN_VAULT_PASSWORD)
            .expect("unlock #2");
        assert_eq!(
            session.current_settings().auto_lock_timeout_ms,
            new_value,
            "second unlock must observe the persisted settings"
        );
    }
}

#[test]
fn set_settings_out_of_range_errors_without_writing() {
    let (_vault_dir, vault_path) = ephemeral_golden_copy();
    let device_dir = tempfile::tempdir().expect("device tempdir");

    {
        let mut session = VaultSession::new(device_dir.path().to_path_buf());
        session
            .unlock(&vault_path, GOLDEN_VAULT_PASSWORD)
            .expect("unlock");

        // Below the AUTO_LOCK_MIN_MS bound (60_000).
        let err_low = session
            .set_settings(&Settings {
                auto_lock_timeout_ms: 30_000,
                ..Default::default()
            })
            .expect_err("must reject below min");
        assert!(
            matches!(err_low, AppError::SettingsOutOfRange { .. }),
            "below-min must yield SettingsOutOfRange, got {err_low:?}"
        );

        // Above the AUTO_LOCK_MAX_MS bound (86_400_000).
        let err_high = session
            .set_settings(&Settings {
                auto_lock_timeout_ms: 86_400_001,
                ..Default::default()
            })
            .expect_err("must reject above max");
        assert!(
            matches!(err_high, AppError::SettingsOutOfRange { .. }),
            "above-max must yield SettingsOutOfRange, got {err_high:?}"
        );
    }

    // Verify no write actually happened: a fresh unlock must observe defaults.
    {
        let mut session = VaultSession::new(device_dir.path().to_path_buf());
        session
            .unlock(&vault_path, GOLDEN_VAULT_PASSWORD)
            .expect("unlock #2");
        assert_eq!(
            session.current_settings(),
            Settings::default(),
            "rejected save must not have persisted anything to disk"
        );
    }
}

// -----------------------------------------------------------------------
// D.1.1 Task 5 — auto-lock timer integration tests
// -----------------------------------------------------------------------
//
// Drive the pure `timer::tick` body against a real unlocked golden-vault
// session — the path that needs an `UnlockedSession` and therefore can't
// live inside `src/timer.rs`'s `#[cfg(test)]` block (which would have to
// reach the bridge crate). The locked / contended-mutex / no-action paths
// stay in `timer.rs` unit tests.

use std::sync::Mutex;

use secretary_desktop::timer::{tick, TickOutcome};

/// Wrap a fresh session in a `Mutex` for the timer tests. The TempDir
/// owns the device-UUID storage and must outlive the session.
fn locked_session_mutex() -> (Mutex<VaultSession>, TempDir) {
    let device_dir = tempfile::tempdir().expect("device-uuid tempdir");
    let session = VaultSession::new(device_dir.path().to_path_buf());
    (Mutex::new(session), device_dir)
}

#[test]
fn timer_tick_auto_locks_expired_unlocked_session() {
    let (mutex, _device_dir) = locked_session_mutex();

    // Unlock against the golden vault, then force the idle tracker to a
    // value that's expired against any positive threshold.
    {
        let mut session = mutex.lock().expect("session mutex");
        session
            .unlock(&golden_vault_path(), GOLDEN_VAULT_PASSWORD)
            .expect("unlock golden vault");
        session.force_expire_idle_tracker_for_test();
        assert!(session.is_unlocked(), "precondition: unlocked");
    }

    let outcome = tick(&mutex);
    assert_eq!(
        outcome,
        TickOutcome::AutoLocked,
        "expired unlocked session must auto-lock on tick"
    );

    let session = mutex.lock().expect("session mutex");
    assert!(
        !session.is_unlocked(),
        "tick(AutoLocked) must have dropped the unlocked inner state"
    );
}

#[test]
fn timer_tick_force_locks_poisoned_unlocked_session() {
    // Fail-secure (#147 follow-up): if a prior holder panicked while owning the
    // session mutex *with a vault unlocked*, the resident key material would
    // otherwise linger in memory until process exit (the timer can never make
    // progress on a poisoned mutex). `tick` recovers the guard via
    // `into_inner()` and force-locks — dropping (zeroizing) the unlocked inner
    // state — then reports `PoisonedLocked` so the loop edge emits `vault-locked`
    // and logs once. This is the *security-relevant* assertion: poison leaves no
    // secrets resident, it does not merely get reported.
    let (mutex, _device_dir) = locked_session_mutex();
    {
        let mut session = mutex.lock().expect("session mutex");
        session
            .unlock(&golden_vault_path(), GOLDEN_VAULT_PASSWORD)
            .expect("unlock golden vault");
        assert!(session.is_unlocked(), "precondition: unlocked");
    }

    // Poison the mutex by panicking a thread while it holds the (unlocked)
    // guard — the established `commands::shared` pattern. `thread::scope` lets
    // the child borrow the local mutex without an `Arc`; `.join()` swallows the
    // expected `Err(panicked)`.
    std::thread::scope(|s| {
        let _ = s
            .spawn(|| {
                let _guard = mutex.lock().expect("acquire to poison");
                panic!("deliberate poison while unlocked");
            })
            .join(); // Err(panicked)
    });
    assert!(mutex.is_poisoned(), "thread panic must poison the mutex");

    assert_eq!(
        tick(&mutex),
        TickOutcome::PoisonedLocked,
        "poisoned-while-unlocked tick must force-lock and report the transition"
    );

    // The mutex stays poisoned forever — recover the guard to inspect state.
    let session = mutex.lock().unwrap_or_else(|e| e.into_inner());
    assert!(
        !session.is_unlocked(),
        "force-lock must have dropped the unlocked inner state (secrets zeroized)"
    );
}

#[test]
fn timer_tick_no_action_on_unlocked_not_yet_expired() {
    let (mutex, _device_dir) = locked_session_mutex();

    {
        let mut session = mutex.lock().expect("session mutex");
        session
            .unlock(&golden_vault_path(), GOLDEN_VAULT_PASSWORD)
            .expect("unlock golden vault");
        // No `force_expire_idle_tracker_for_test()` — the session unlock
        // resets the idle tracker to "now", so any positive threshold
        // (default is `AUTO_LOCK_DEFAULT_MS` = 10 minutes) is far away.
        assert!(session.is_unlocked());
    }

    let outcome = tick(&mutex);
    assert_eq!(
        outcome,
        TickOutcome::NoAction,
        "fresh unlock must not trigger auto-lock"
    );

    let session = mutex.lock().expect("session mutex");
    assert!(
        session.is_unlocked(),
        "tick(NoAction) must leave the session unlocked"
    );
}

#[test]
fn timer_tick_reads_threshold_from_current_settings() {
    // Adaptation from the plan (see timer.rs design note): `tick` reads the
    // threshold from `session.current_settings()` inside the same lock
    // acquisition as `should_auto_lock`. This test pins that behaviour: an
    // unlocked session with the default `auto_lock_timeout_ms` and a
    // last-activity timestamp from "now" must NOT auto-lock — the threshold
    // observed by tick is `AUTO_LOCK_DEFAULT_MS`, not zero, not infinity.
    let (mutex, _device_dir) = locked_session_mutex();

    {
        let mut session = mutex.lock().expect("session mutex");
        session
            .unlock(&golden_vault_path(), GOLDEN_VAULT_PASSWORD)
            .expect("unlock golden vault");
        assert_eq!(
            session.current_settings(),
            Settings::default(),
            "golden vault carries default settings"
        );
    }

    // With the default threshold and a fresh idle tracker, tick must not
    // lock. If `tick` ever regresses to passing `threshold_ms = 0`, this
    // would lock the session and fail.
    assert_eq!(tick(&mutex), TickOutcome::NoAction);
}

#[test]
fn unlock_retains_vault_folder_on_the_unlocked_session() {
    let (mut session, _device_dir) = fresh_session();
    let folder = golden_vault_path();
    session
        .unlock(&folder, GOLDEN_VAULT_PASSWORD)
        .expect("unlock golden vault");

    let retained: PathBuf = session
        .with_unlocked(|u| Ok(u.vault_folder.clone()))
        .expect("session must be unlocked");

    assert_eq!(
        retained, folder,
        "unlock() must retain the vault folder on the UnlockedSession so \
         sync_now can pass it to the bridge sync_vault"
    );
}
