//! Integration tests for the Tauri IPC command layer.
//!
//! Drives each command's `*_impl` helper directly against the golden vault
//! and ephemeral write-path vaults — the `#[tauri::command]` wrappers are
//! thin shells around these helpers (see `commands/mod.rs` for the design
//! rationale on this pragmatic split).
//!
//! Three goals:
//! 1. Functional coverage of every command (happy path + locked path +
//!    domain errors).
//! 2. Wire-format pinning end-to-end — each happy-path response is
//!    serialized to JSON and the resulting `serde_json::Value` is asserted
//!    field by field, so a Task 6 TS-discriminated-union mismatch surfaces
//!    here rather than at Svelte runtime.
//! 3. AppError detail-strip enforcement — domain errors must serialize
//!    *without* their developer-facing `detail` fields, even on the path
//!    where the command propagates them (the unit tests in `errors.rs`
//!    pin the same property in isolation; these tests pin it end-to-end).
//!
//! Hermeticity: each test injects its own `TempDir` for the per-vault
//! device UUID file via `VaultSession::new`, and write-path tests
//! additionally copy the golden vault into a `TempDir` before mutating.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use secretary_desktop::commands::{browse, lock, settings, unlock, vault};
use secretary_desktop::dtos::SettingsInput;
use secretary_desktop::errors::AppError;
use secretary_desktop::session::VaultSession;
use tempfile::TempDir;

// ============================================================================
// Fixtures — mirror `session_integration.rs` for one-source-of-truth
// hermeticity. If the golden vault password ever rotates, the constant in
// `core/tests/data/golden_vault_001_inputs.json` is the canonical source;
// both this test file and session_integration.rs would fail loudly here.
// ============================================================================

const GOLDEN_VAULT_PASSWORD: &str = "correct horse battery staple";

const GOLDEN_BLOCK_UUID_HEX: &str = "112233445566778899aabbccddeeff00";
const GOLDEN_RECORD_UUID_HEX: &str = "33445566778899aabbccddeeff001122";

/// Auto-lock value used in the write-path tests. Picked as a non-default
/// in-range value so a "fell back to default" regression is distinguishable
/// from "loaded the new value". 15 minutes; well within the
/// [`AUTO_LOCK_MIN_MS`, `AUTO_LOCK_MAX_MS`] band.
const NEW_AUTO_LOCK_MS: u64 = 900_000;

/// Out-of-range value used in the set_settings rejection test. Below the
/// 60_000 ms minimum that `validate_save_value` enforces.
const BELOW_MIN_AUTO_LOCK_MS: u64 = 30_000;

fn golden_vault_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("desktop/")
        .parent()
        .expect("workspace root")
        .join("core/tests/data/golden_vault_001")
}

/// `(state, device_dir)` pair. Caller keeps `device_dir` alive — when it
/// drops the per-vault UUID file is reclaimed.
fn fresh_state() -> (Mutex<VaultSession>, TempDir) {
    let device_dir = tempfile::tempdir().expect("device-uuid tempdir");
    let session = VaultSession::new(device_dir.path().to_path_buf());
    (Mutex::new(session), device_dir)
}

/// Unlocked `(state, device_dir)`. Equivalent to `fresh_state` + a
/// successful unlock against the golden vault — every read-path test
/// starts from here.
fn unlocked_state() -> (Mutex<VaultSession>, TempDir) {
    let (state, device_dir) = fresh_state();
    let dto = unlock::unlock_with_password_impl(
        &state,
        golden_vault_path().to_str().expect("utf8 path"),
        GOLDEN_VAULT_PASSWORD.as_bytes(),
    )
    .expect("baseline unlock against golden vault");
    // Sanity: golden vault is a real vault with a 32-hex-char UUID.
    assert_eq!(
        dto.vault_uuid_hex.len(),
        32,
        "golden vault UUID should be 16 bytes / 32 hex chars"
    );
    (state, device_dir)
}

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
            copy_recursive(&entry.path(), &dst.join(entry.file_name()));
        }
    }
}

fn to_json<T: serde::Serialize>(value: &T) -> serde_json::Value {
    serde_json::from_str(&serde_json::to_string(value).expect("serialize"))
        .expect("re-parse as Value")
}

// ============================================================================
// unlock_with_password
// ============================================================================

#[test]
fn unlock_with_password_happy_path_returns_manifest_dto_with_warnings_field() {
    let (state, _device_dir) = fresh_state();
    let dto = unlock::unlock_with_password_impl(
        &state,
        golden_vault_path().to_str().expect("utf8 path"),
        GOLDEN_VAULT_PASSWORD.as_bytes(),
    )
    .expect("unlock golden vault");

    // Field-by-field structural assertions (the DTO unit tests cover serde
    // shape in isolation; this test pins the *bridge → DTO* projection).
    assert_eq!(
        dto.vault_uuid_hex.len(),
        32,
        "vault UUID is 16 bytes / 32 hex chars"
    );
    assert_eq!(dto.owner_user_uuid_hex.len(), 32, "owner UUID same length");
    // Golden vault has no blocks beyond the empty manifest baseline; the
    // block_count is whatever the fixture builder produced. Assert it's
    // self-consistent with the summaries vec length rather than pinning
    // an arbitrary number.
    assert_eq!(dto.block_count as usize, dto.block_summaries.len());
    // Clean vault ⇒ no settings-load warnings.
    assert!(dto.warnings.is_empty(), "clean unlock yields no warnings");

    // Verify the JSON wire format keys match what the TS frontend will
    // consume (camelCase, hex UUIDs as strings, not byte arrays).
    let v = to_json(&dto);
    assert!(v["vaultUuidHex"].is_string());
    assert!(v["ownerUserUuidHex"].is_string());
    assert!(v["blockCount"].is_number());
    assert!(v["blockSummaries"].is_array());
    assert!(v["warnings"].is_array());
}

#[test]
fn unlock_with_password_wrong_password_collapses_to_wrong_password() {
    let (state, _device_dir) = fresh_state();
    let err = unlock::unlock_with_password_impl(
        &state,
        golden_vault_path().to_str().expect("utf8 path"),
        b"definitely not the password",
    )
    .expect_err("wrong password must error");

    assert!(matches!(err, AppError::WrongPassword), "got {err:?}");
    // Wire-format check: code is `wrong_password`, no `detail` field.
    let v = to_json(&err);
    assert_eq!(v["code"], "wrong_password");
    assert!(v.get("detail").is_none(), "WrongPassword has no detail");
}

#[test]
fn unlock_with_password_nonexistent_folder_yields_vault_path_not_found() {
    let (state, device_dir) = fresh_state();
    // Inside the tempdir but a path that doesn't exist.
    let missing = device_dir.path().join("no-such-vault");
    let err = unlock::unlock_with_password_impl(
        &state,
        missing.to_str().expect("utf8 path"),
        GOLDEN_VAULT_PASSWORD.as_bytes(),
    )
    .expect_err("nonexistent path must error");

    match &err {
        AppError::VaultPathNotFound { path } => {
            assert_eq!(path, missing.to_str().expect("utf8 path"));
        }
        other => panic!("expected VaultPathNotFound, got {other:?}"),
    }
    let v = to_json(&err);
    assert_eq!(v["code"], "vault_path_not_found");
    assert_eq!(v["path"], missing.to_str().expect("utf8 path"));
}

#[test]
fn unlock_with_password_empty_folder_yields_vault_path_not_a_vault() {
    let (state, _device_dir) = fresh_state();
    let empty_folder = tempfile::tempdir().expect("empty tempdir");
    let path_str = empty_folder.path().to_str().expect("utf8 path");
    let err = unlock::unlock_with_password_impl(&state, path_str, GOLDEN_VAULT_PASSWORD.as_bytes())
        .expect_err("empty folder must error");

    match &err {
        AppError::VaultPathNotAVault { path } => assert_eq!(path, path_str),
        other => panic!("expected VaultPathNotAVault, got {other:?}"),
    }
    let v = to_json(&err);
    assert_eq!(v["code"], "vault_path_not_a_vault");
    assert_eq!(v["path"], path_str);
}

#[test]
fn unlock_with_password_already_unlocked_returns_already_unlocked() {
    let (state, _device_dir) = unlocked_state();
    let err = unlock::unlock_with_password_impl(
        &state,
        golden_vault_path().to_str().expect("utf8 path"),
        GOLDEN_VAULT_PASSWORD.as_bytes(),
    )
    .expect_err("second unlock must reject");

    assert!(matches!(err, AppError::AlreadyUnlocked), "got {err:?}");
    let v = to_json(&err);
    assert_eq!(v["code"], "already_unlocked");
}

// ============================================================================
// list_blocks / get_manifest
// ============================================================================

#[test]
fn list_blocks_while_locked_returns_not_unlocked() {
    let (state, _device_dir) = fresh_state();
    let err = vault::list_blocks_impl(&state).expect_err("must reject while locked");
    assert!(matches!(err, AppError::NotUnlocked), "got {err:?}");
    let v = to_json(&err);
    assert_eq!(v["code"], "not_unlocked");
}

#[test]
fn list_blocks_after_unlock_returns_consistent_summary_vec() {
    let (state, _device_dir) = unlocked_state();
    let summaries = vault::list_blocks_impl(&state).expect("list_blocks must succeed");

    // Each summary is a fully-projected DTO — hex UUID + plaintext name +
    // both timestamps. Walk the vec to catch any byte/hex slip-ups across
    // the entire fixture content rather than just the first entry.
    for s in &summaries {
        assert_eq!(s.block_uuid_hex.len(), 32, "uuid hex must be 32 chars");
        assert!(
            s.created_at_ms > 0,
            "created_at_ms is a Unix ms timestamp, not zero"
        );
        assert!(
            s.last_modified_ms >= s.created_at_ms,
            "last_modified_ms cannot precede created_at_ms"
        );
    }

    // Cross-check via get_manifest — the projected block_summaries vec
    // must match list_blocks exactly (same source, same projection).
    let manifest = vault::get_manifest_impl(&state).expect("get_manifest must succeed");
    assert_eq!(
        manifest.block_summaries.len(),
        summaries.len(),
        "get_manifest and list_blocks must project the same number of blocks"
    );
}

#[test]
fn get_manifest_returns_empty_warnings_on_subsequent_call() {
    // Warnings are an unlock-time concern; get_manifest is for periodic
    // refresh and must never re-emit them (which would produce duplicate
    // toasts on the frontend).
    let (state, _device_dir) = unlocked_state();
    let manifest = vault::get_manifest_impl(&state).expect("get_manifest");
    assert!(
        manifest.warnings.is_empty(),
        "get_manifest never re-emits warnings"
    );
}

#[test]
fn get_manifest_while_locked_returns_not_unlocked() {
    let (state, _device_dir) = fresh_state();
    let err = vault::get_manifest_impl(&state).expect_err("must reject while locked");
    assert!(matches!(err, AppError::NotUnlocked), "got {err:?}");
}

// ============================================================================
// get_settings / set_settings
// ============================================================================

#[test]
fn get_settings_while_locked_returns_not_unlocked() {
    let (state, _device_dir) = fresh_state();
    let err = settings::get_settings_impl(&state).expect_err("must reject while locked");
    assert!(matches!(err, AppError::NotUnlocked), "got {err:?}");
    let v = to_json(&err);
    assert_eq!(v["code"], "not_unlocked");
}

#[test]
fn get_settings_after_clean_unlock_returns_defaults_in_camel_case() {
    let (state, _device_dir) = unlocked_state();
    let dto = settings::get_settings_impl(&state).expect("get_settings must succeed");

    // Golden vault has no settings block ⇒ defaults.
    assert_eq!(dto.auto_lock_timeout_ms, 600_000);
    let v = to_json(&dto);
    assert_eq!(v["autoLockTimeoutMs"], 600_000_u64);
}

#[test]
fn set_settings_persists_and_subsequent_get_returns_new_value() {
    let (_vault_dir, vault_path) = ephemeral_golden_copy();
    let device_dir = tempfile::tempdir().expect("device tempdir");
    let state = Mutex::new(VaultSession::new(device_dir.path().to_path_buf()));

    unlock::unlock_with_password_impl(
        &state,
        vault_path.to_str().expect("utf8 path"),
        GOLDEN_VAULT_PASSWORD.as_bytes(),
    )
    .expect("unlock");

    settings::set_settings_impl(
        &state,
        &SettingsInput {
            auto_lock_timeout_ms: NEW_AUTO_LOCK_MS,
        },
    )
    .expect("set_settings must succeed");

    let dto = settings::get_settings_impl(&state).expect("get_settings after set");
    assert_eq!(dto.auto_lock_timeout_ms, NEW_AUTO_LOCK_MS);
}

#[test]
fn set_settings_below_minimum_returns_out_of_range_without_writing() {
    let (_vault_dir, vault_path) = ephemeral_golden_copy();
    let device_dir = tempfile::tempdir().expect("device tempdir");
    let state = Mutex::new(VaultSession::new(device_dir.path().to_path_buf()));

    unlock::unlock_with_password_impl(
        &state,
        vault_path.to_str().expect("utf8 path"),
        GOLDEN_VAULT_PASSWORD.as_bytes(),
    )
    .expect("unlock");

    let err = settings::set_settings_impl(
        &state,
        &SettingsInput {
            auto_lock_timeout_ms: BELOW_MIN_AUTO_LOCK_MS,
        },
    )
    .expect_err("below-min input must reject");

    match &err {
        AppError::SettingsOutOfRange { min, max } => {
            assert_eq!(*min, 60_000);
            assert_eq!(*max, 86_400_000);
        }
        other => panic!("expected SettingsOutOfRange, got {other:?}"),
    }

    // Verify the rejected write didn't persist anything — current_settings
    // must still report defaults (the unlock-time loaded value).
    let dto = settings::get_settings_impl(&state).expect("get_settings post-reject");
    assert_eq!(
        dto.auto_lock_timeout_ms, 600_000,
        "rejected set_settings must not mutate in-memory settings"
    );

    // Wire format: SettingsOutOfRange carries both bounds, no detail.
    let v = to_json(&err);
    assert_eq!(v["code"], "settings_out_of_range");
    assert_eq!(v["min"], 60_000_u64);
    assert_eq!(v["max"], 86_400_000_u64);
}

#[test]
fn set_settings_while_locked_returns_not_unlocked() {
    let (state, _device_dir) = fresh_state();
    let err = settings::set_settings_impl(
        &state,
        &SettingsInput {
            auto_lock_timeout_ms: NEW_AUTO_LOCK_MS,
        },
    )
    .expect_err("must reject while locked");
    assert!(matches!(err, AppError::NotUnlocked), "got {err:?}");
}

// ============================================================================
// lock / notify_activity
// ============================================================================

#[test]
fn lock_after_unlock_returns_true_and_clears_state() {
    let (state, _device_dir) = unlocked_state();
    let was_unlocked = lock::lock_impl(&state).expect("lock must succeed");
    assert!(
        was_unlocked,
        "post-unlock lock must report was_unlocked=true"
    );

    // State must be cleared.
    let session = state.lock().expect("mutex");
    assert!(!session.is_unlocked(), "session must report locked");
}

#[test]
fn lock_on_already_locked_returns_false_idempotently() {
    let (state, _device_dir) = fresh_state();
    let was_unlocked = lock::lock_impl(&state).expect("lock on locked must succeed");
    assert!(
        !was_unlocked,
        "lock on already-locked session must report was_unlocked=false"
    );
    // Second call still idempotent.
    let was_unlocked_2 = lock::lock_impl(&state).expect("second lock");
    assert!(!was_unlocked_2);
}

#[test]
fn notify_activity_when_locked_is_silent_noop() {
    let (state, _device_dir) = fresh_state();
    let before = state.lock().expect("mutex").last_activity_ms();
    lock::notify_activity_impl(&state).expect("must not error");
    let after = state.lock().expect("mutex").last_activity_ms();
    assert_eq!(
        before, after,
        "notify_activity while locked must not advance tracker"
    );
}

#[test]
fn notify_activity_when_unlocked_advances_tracker() {
    let (state, _device_dir) = unlocked_state();
    let t0 = state.lock().expect("mutex").last_activity_ms();
    std::thread::sleep(std::time::Duration::from_millis(5));
    lock::notify_activity_impl(&state).expect("must succeed");
    let t1 = state.lock().expect("mutex").last_activity_ms();
    assert!(t1 > t0, "tracker must advance: t0={t0}, t1={t1}");
}

// ============================================================================
// read_block
// ============================================================================

#[test]
fn read_block_projects_records_and_fields_without_secrets() {
    let (state, _device_dir) = unlocked_state();
    let dto = browse::read_block_impl(&state, GOLDEN_BLOCK_UUID_HEX).expect("read_block ok");

    assert_eq!(dto.block_uuid_hex, GOLDEN_BLOCK_UUID_HEX);
    assert_eq!(dto.block_name, "Personal logins");
    assert_eq!(dto.records.len(), 1);

    let rec = &dto.records[0];
    assert_eq!(rec.record_uuid_hex, GOLDEN_RECORD_UUID_HEX);
    assert_eq!(rec.record_type, "login");
    assert_eq!(rec.tags, vec!["work".to_string()]);
    assert_eq!(rec.field_count, 2);

    let names: Vec<&str> = rec.fields.iter().map(|f| f.name.as_str()).collect();
    assert!(names.contains(&"username"));
    assert!(names.contains(&"password"));
    assert!(rec.fields.iter().all(|f| f.is_text && !f.is_bytes));

    let json = serde_json::to_string(&dto).expect("serialize");
    assert!(
        !json.contains("hunter2"),
        "plaintext password must not be in read_block DTO"
    );
    assert!(
        !json.contains("owner@example.com"),
        "plaintext username must not be in DTO"
    );
}

#[test]
fn read_block_unknown_uuid_is_block_not_found() {
    let (state, _device_dir) = unlocked_state();
    let err = browse::read_block_impl(&state, "ffffffffffffffffffffffffffffffff")
        .expect_err("unknown block must error");
    assert!(matches!(err, AppError::BlockNotFound { .. }));
}

#[test]
fn read_block_when_locked_is_not_unlocked() {
    let (state, _device_dir) = fresh_state();
    let err =
        browse::read_block_impl(&state, GOLDEN_BLOCK_UUID_HEX).expect_err("locked must error");
    assert!(matches!(err, AppError::NotUnlocked));
}
