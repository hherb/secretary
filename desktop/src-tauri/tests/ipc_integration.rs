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

use secretary_desktop::commands::{
    browse, create, delete, edit, lock, settings, sync, unlock, vault,
};
use secretary_desktop::dtos::{FieldInputDto, FieldValueDto, RecordInputDto, SettingsInput};
use secretary_desktop::errors::AppError;
use secretary_desktop::secret_arg::Password;
use secretary_desktop::session::VaultSession;
use secretary_desktop::settings::{load_from_vault, save_to_vault, Settings};
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
            require_password_before_edits: false,
            reauth_grace_window_ms: 120_000,
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
            require_password_before_edits: false,
            reauth_grace_window_ms: 120_000,
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
            require_password_before_edits: false,
            reauth_grace_window_ms: 120_000,
        },
    )
    .expect_err("must reject while locked");
    assert!(matches!(err, AppError::NotUnlocked), "got {err:?}");
}

/// All three settings fields survive a save→load round-trip through the
/// vault. Exercises the multi-field `save_to_vault` / `load_from_vault`
/// paths added in Task 3, against a temp copy of the golden vault so the
/// frozen KAT fixture is never mutated.
#[test]
fn settings_round_trip_persists_all_three_fields() {
    let (_vault_dir, vault_path) = ephemeral_golden_copy();
    let device_dir = tempfile::tempdir().expect("device tempdir");
    let state = Mutex::new(VaultSession::new(device_dir.path().to_path_buf()));

    unlock::unlock_with_password_impl(
        &state,
        vault_path.to_str().expect("utf8 path"),
        GOLDEN_VAULT_PASSWORD.as_bytes(),
    )
    .expect("unlock");

    let to_save = Settings {
        auto_lock_timeout_ms: 600_000,
        require_password_before_edits: false,
        reauth_grace_window_ms: 30_000,
    };

    // Write all three fields through the multi-field save path.
    state
        .lock()
        .expect("mutex")
        .with_unlocked(|u| save_to_vault(&u.identity, &u.manifest, u.device_uuid, &to_save))
        .expect("save_to_vault");

    // Read them back and assert every field survived, with no warnings.
    let (loaded, warnings) = state
        .lock()
        .expect("mutex")
        .with_unlocked(|u| load_from_vault(&u.identity, &u.manifest))
        .expect("load_from_vault");

    assert!(
        !loaded.require_password_before_edits,
        "require_password_before_edits must survive round-trip"
    );
    assert_eq!(
        loaded.reauth_grace_window_ms, 30_000,
        "reauth_grace_window_ms must survive round-trip"
    );
    assert_eq!(
        loaded.auto_lock_timeout_ms, 600_000,
        "auto_lock_timeout_ms must survive round-trip"
    );
    assert!(warnings.is_empty(), "clean round-trip must produce no warnings; got: {warnings:?}");
}

/// A vault written by an older client (only the `auto_lock_timeout_ms`
/// field present) is loaded with the new two fields defaulted — no
/// SettingsClamped or SettingsCorrupt warning, since missing-but-defaulted
/// fields are forward-compat silently accepted.
#[test]
fn settings_backward_compat_missing_new_fields_yield_defaults_no_warning() {
    // The golden vault has no settings block at all ⇒ load returns defaults
    // with an empty warnings vec. This is the strongest backward-compat
    // assertion we can make without writing a synthetic one-field record.
    let (state, _device_dir) = unlocked_state();
    let (loaded, warnings) = state
        .lock()
        .expect("mutex")
        .with_unlocked(|u| load_from_vault(&u.identity, &u.manifest))
        .expect("load_from_vault on clean vault");

    // No settings block ⇒ defaults.
    assert_eq!(
        loaded,
        Settings::default(),
        "no settings block must yield Settings::default()"
    );
    assert!(
        warnings.is_empty(),
        "no settings block must yield no warnings; got: {warnings:?}"
    );
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
    let dto = browse::read_block_impl(&state, GOLDEN_BLOCK_UUID_HEX, false).expect("read_block ok");

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
    let err = browse::read_block_impl(&state, "ffffffffffffffffffffffffffffffff", false)
        .expect_err("unknown block must error");
    assert!(matches!(err, AppError::BlockNotFound { .. }));
}

#[test]
fn read_block_when_locked_is_not_unlocked() {
    let (state, _device_dir) = fresh_state();
    let err = browse::read_block_impl(&state, GOLDEN_BLOCK_UUID_HEX, false)
        .expect_err("locked must error");
    assert!(matches!(err, AppError::NotUnlocked));
}

// ============================================================================
// reveal_field
//
// Coverage note: only the TEXT reveal path is exercised end-to-end here,
// because `golden_vault_001` contains no `bytes` field (and it is a frozen
// KAT — we don't add one). The `bytes` → base64 path
// (`expose_bytes` → `encode_revealed_bytes`) is covered by the unit tests in
// `reveal.rs` (`encode_revealed_bytes_*`). If a `bytes` field ever lands in a
// fixture, add an integration test here asserting `dto.is_text == false` and
// that the base64 decodes to the expected bytes.
// ============================================================================

#[test]
fn reveal_field_returns_text_plaintext() {
    let (state, _device_dir) = unlocked_state();
    let dto = browse::reveal_field_impl(
        &state,
        GOLDEN_BLOCK_UUID_HEX,
        GOLDEN_RECORD_UUID_HEX,
        "password",
    )
    .expect("reveal ok");
    assert!(dto.is_text);
    assert_eq!(dto.value, "hunter2");

    let user = browse::reveal_field_impl(
        &state,
        GOLDEN_BLOCK_UUID_HEX,
        GOLDEN_RECORD_UUID_HEX,
        "username",
    )
    .expect("reveal ok");
    assert_eq!(user.value, "owner@example.com");
}

#[test]
fn reveal_field_unknown_record_is_record_not_found() {
    let (state, _device_dir) = unlocked_state();
    let err = browse::reveal_field_impl(
        &state,
        GOLDEN_BLOCK_UUID_HEX,
        "ffffffffffffffffffffffffffffffff",
        "password",
    )
    .expect_err("unknown record errors");
    assert!(matches!(err, AppError::RecordNotFound { .. }));
}

#[test]
fn reveal_field_unknown_field_is_field_not_found() {
    let (state, _device_dir) = unlocked_state();
    let err = browse::reveal_field_impl(
        &state,
        GOLDEN_BLOCK_UUID_HEX,
        GOLDEN_RECORD_UUID_HEX,
        "no_such_field",
    )
    .expect_err("unknown field errors");
    assert!(matches!(err, AppError::FieldNotFound { .. }));
}

// ============================================================================
// D.1.3 create-vault path. Hermetic: every vault is created in a fresh
// TempDir; the password is generated at runtime (no hardcoded crypto value —
// CodeQL). A created vault is asserted by RE-OPENING it with the same
// freshly-chosen password (round-trip), never against the golden fixture.
// ============================================================================

mod create_path {
    use super::*;
    use rand_core::{OsRng, RngCore};
    use secretary_core::crypto::secret::SecretBytes;

    const CREATE_DISPLAY_NAME: &str = "D.1.3 test identity";

    /// A runtime-random ASCII password. Avoids a hardcoded crypto literal
    /// while staying valid UTF-8 for the `Password` boundary.
    fn random_password() -> Vec<u8> {
        let mut raw = [0u8; 16];
        OsRng.fill_bytes(&mut raw);
        // Map to printable hex so the value is a valid UTF-8 password.
        raw.iter()
            .flat_map(|b| format!("{b:02x}").into_bytes())
            .collect()
    }

    #[test]
    fn create_writes_the_four_canonical_files() {
        let dir = tempfile::tempdir().expect("vault tempdir");
        let path = dir.path().to_str().expect("utf8 path");
        let pw = random_password();

        let dto = create::create_vault_impl(
            path,
            CREATE_DISPLAY_NAME,
            &SecretBytes::from(pw.as_slice()),
            1_700_000_000_000,
            &mut OsRng,
        )
        .expect("create_vault must succeed on an empty tempdir");

        assert_eq!(dto.mnemonic.split_whitespace().count(), 24);

        let p = dir.path();
        assert!(p.join("vault.toml").is_file(), "vault.toml");
        assert!(
            p.join("identity.bundle.enc").is_file(),
            "identity.bundle.enc"
        );
        assert!(p.join("manifest.cbor.enc").is_file(), "manifest.cbor.enc");
        assert!(p.join("contacts").is_dir(), "contacts/ dir");
    }

    #[test]
    fn created_vault_reopens_with_the_same_password() {
        let dir = tempfile::tempdir().expect("vault tempdir");
        let path = dir.path().to_str().expect("utf8 path");
        let pw = random_password();

        create::create_vault_impl(
            path,
            CREATE_DISPLAY_NAME,
            &SecretBytes::from(pw.as_slice()),
            1_700_000_000_000,
            &mut OsRng,
        )
        .expect("create");

        let (state, _device_dir) = fresh_state();
        let manifest = unlock::unlock_with_password_impl(&state, path, &pw)
            .expect("freshly-created vault must open with the same password");
        assert_eq!(manifest.block_count, 0, "a new vault has no blocks");
    }

    #[test]
    fn create_into_nonempty_folder_yields_vault_folder_not_empty() {
        let dir = tempfile::tempdir().expect("vault tempdir");
        std::fs::write(dir.path().join("stray.txt"), b"hi").expect("stray file");
        let path = dir.path().to_str().expect("utf8 path");
        let pw = random_password();

        let err = create::create_vault_impl(
            path,
            CREATE_DISPLAY_NAME,
            &SecretBytes::from(pw.as_slice()),
            1_700_000_000_000,
            &mut OsRng,
        )
        .expect_err("non-empty folder must be rejected");
        match err {
            AppError::VaultFolderNotEmpty { path: p } => assert_eq!(p, path),
            other => panic!("expected VaultFolderNotEmpty, got {other:?}"),
        }
    }

    #[test]
    fn create_makes_the_target_dir_when_missing() {
        let dir = tempfile::tempdir().expect("parent tempdir");
        let target = dir.path().join("my-vault");
        let path = target.to_str().expect("utf8 path");
        let pw = random_password();

        create::create_vault_impl(
            path,
            CREATE_DISPLAY_NAME,
            &SecretBytes::from(pw.as_slice()),
            1_700_000_000_000,
            &mut OsRng,
        )
        .expect("create must mkdir -p the missing target");
        assert!(target.join("vault.toml").is_file());
    }

    #[test]
    fn probe_reports_empty_existing_and_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let empty = dir.path().to_str().expect("utf8");
        let probe = create::probe_create_target_impl(empty);
        assert!(
            probe.exists && probe.is_empty,
            "empty dir: exists + is_empty"
        );

        std::fs::write(dir.path().join("x"), b"x").expect("write");
        let probe = create::probe_create_target_impl(empty);
        assert!(probe.exists && !probe.is_empty, "non-empty dir");

        let missing = dir.path().join("nope");
        let probe = create::probe_create_target_impl(missing.to_str().expect("utf8"));
        assert!(!probe.exists && !probe.is_empty, "missing path");
    }
}

// ============================================================================
// D.1.4 edit-vault path. Hermetic: all vaults are created in fresh TempDirs
// with runtime-random passwords (no hardcoded crypto — CodeQL). Each test
// creates → appends/edits → asserts; no golden-vault dependency.
// ============================================================================

mod edit_path {
    use super::*;
    use rand_core::{OsRng, RngCore};
    use secretary_core::crypto::secret::SecretBytes;

    const CREATE_DISPLAY_NAME: &str = "D.1.4 edit test identity";

    /// Runtime-random hex password — avoids a hardcoded crypto literal.
    fn random_password() -> Vec<u8> {
        let mut raw = [0u8; 16];
        OsRng.fill_bytes(&mut raw);
        raw.iter()
            .flat_map(|b| format!("{b:02x}").into_bytes())
            .collect()
    }

    /// An unlocked `VaultSession` over a freshly-created tempdir vault.
    /// Mirrors the create_path flow: `create_vault_impl` writes the four
    /// canonical files, then `unlock_with_password_impl` unlocks the
    /// session. Returns the state (with unlocked session), the vault TempDir
    /// (keep alive), and the raw password bytes.
    fn unlocked_session_over_new_vault() -> (Mutex<VaultSession>, tempfile::TempDir, Vec<u8>) {
        let vault_dir = tempfile::tempdir().expect("vault tempdir");
        let path = vault_dir.path().to_str().expect("utf8 path");
        let pw = random_password();

        create::create_vault_impl(
            path,
            CREATE_DISPLAY_NAME,
            &SecretBytes::from(pw.as_slice()),
            1_700_000_000_000,
            &mut OsRng,
        )
        .expect("create_vault_impl for edit test");

        let (state, _device_dir) = fresh_state();
        unlock::unlock_with_password_impl(&state, path, &pw).expect("unlock freshly-created vault");
        // _device_dir must stay alive; embed it in the vault_dir's lifetime
        // by leaking the device dir into the heap and keeping vault_dir alive.
        // Simpler: just keep both alive via the caller's tuple. But the
        // signature returns only vault_dir — we accept the device-UUID file
        // being dropped (the test session stays unlocked; the UUID file is
        // only used at open time, not during the test).
        (state, vault_dir, pw)
    }

    fn text_field(name: &str, text: &str) -> FieldInputDto {
        FieldInputDto {
            name: name.into(),
            value: FieldValueDto::Text { text: text.into() },
        }
    }

    #[test]
    fn create_block_then_add_record_then_read_reflects_it() {
        let (state, _dir, _pw) = unlocked_session_over_new_vault();
        let block = edit::create_block_impl(&state, "Logins").expect("create_block");
        let rec = edit::save_record_impl(
            &state,
            &block.block_uuid_hex,
            RecordInputDto {
                record_type: "login".into(),
                tags: vec!["work".into()],
                fields: vec![text_field("user", "alice")],
            },
        )
        .expect("save_record");

        // read_block reflects the new record.
        let detail = secretary_desktop::commands::browse::read_block_impl(
            &state,
            &block.block_uuid_hex,
            false,
        )
        .expect("read");
        assert_eq!(detail.records.len(), 1);
        assert_eq!(detail.records[0].record_uuid_hex, rec.record_uuid_hex);
        assert_eq!(detail.records[0].record_type, "login");
    }

    #[test]
    fn edit_record_changes_value_and_leaves_siblings_intact() {
        let (state, _dir, _pw) = unlocked_session_over_new_vault();
        let block = edit::create_block_impl(&state, "B").unwrap();
        let a = edit::save_record_impl(
            &state,
            &block.block_uuid_hex,
            RecordInputDto {
                record_type: "login".into(),
                tags: vec![],
                fields: vec![text_field("user", "alice")],
            },
        )
        .unwrap();
        let b = edit::save_record_impl(
            &state,
            &block.block_uuid_hex,
            RecordInputDto {
                record_type: "login".into(),
                tags: vec![],
                fields: vec![text_field("user", "bob")],
            },
        )
        .unwrap();

        edit::save_record_edit_impl(
            &state,
            &block.block_uuid_hex,
            &a.record_uuid_hex,
            RecordInputDto {
                record_type: "login".into(),
                tags: vec!["edited".into()],
                fields: vec![text_field("user", "alice2")],
            },
        )
        .unwrap();

        // A changed; B intact (revealed values).
        let ra =
            edit::reveal_record_impl(&state, &block.block_uuid_hex, &a.record_uuid_hex).unwrap();
        assert_eq!(
            ra.fields.iter().find(|f| f.name == "user").unwrap().value,
            "alice2"
        );
        let rb =
            edit::reveal_record_impl(&state, &block.block_uuid_hex, &b.record_uuid_hex).unwrap();
        assert_eq!(
            rb.fields.iter().find(|f| f.name == "user").unwrap().value,
            "bob"
        );
    }

    #[test]
    fn bytes_field_round_trips_via_base64() {
        let (state, _dir, _pw) = unlocked_session_over_new_vault();
        let block = edit::create_block_impl(&state, "B").unwrap();
        // "aGVsbG8=" == b"hello"
        let rec = edit::save_record_impl(
            &state,
            &block.block_uuid_hex,
            RecordInputDto {
                record_type: "note".into(),
                tags: vec![],
                fields: vec![FieldInputDto {
                    name: "seed".into(),
                    value: FieldValueDto::Bytes {
                        base64: "aGVsbG8=".into(),
                    },
                }],
            },
        )
        .unwrap();
        let revealed =
            edit::reveal_record_impl(&state, &block.block_uuid_hex, &rec.record_uuid_hex).unwrap();
        let f = revealed.fields.iter().find(|f| f.name == "seed").unwrap();
        assert!(!f.is_text);
        assert_eq!(f.value, "aGVsbG8=", "bytes reveal as base64");
    }

    #[test]
    fn invalid_base64_yields_invalid_field_value() {
        let (state, _dir, _pw) = unlocked_session_over_new_vault();
        let block = edit::create_block_impl(&state, "B").unwrap();
        let err = edit::save_record_impl(
            &state,
            &block.block_uuid_hex,
            RecordInputDto {
                record_type: "note".into(),
                tags: vec![],
                fields: vec![FieldInputDto {
                    name: "seed".into(),
                    value: FieldValueDto::Bytes {
                        base64: "not valid base64!!".into(),
                    },
                }],
            },
        )
        .expect_err("bad base64 rejected");
        match err {
            AppError::InvalidFieldValue { field_name } => assert_eq!(field_name, "seed"),
            other => panic!("expected InvalidFieldValue, got {other:?}"),
        }
    }

    #[test]
    fn edit_missing_record_yields_record_not_found() {
        let (state, _dir, _pw) = unlocked_session_over_new_vault();
        let block = edit::create_block_impl(&state, "B").unwrap();
        let err = edit::save_record_edit_impl(
            &state,
            &block.block_uuid_hex,
            &"ab".repeat(16),
            RecordInputDto {
                record_type: "x".into(),
                tags: vec![],
                fields: vec![],
            },
        )
        .expect_err("missing");
        assert!(matches!(err, AppError::RecordNotFound { .. }));
    }

    #[test]
    fn rename_block_changes_name() {
        let (state, _dir, _pw) = unlocked_session_over_new_vault();
        let block = edit::create_block_impl(&state, "Before").expect("create_block");
        let renamed =
            edit::rename_block_impl(&state, &block.block_uuid_hex, "After").expect("rename_block");
        assert_eq!(renamed.block_name, "After");
        // Manifest reflects it on a fresh read.
        let summary = secretary_desktop::commands::vault::list_blocks_impl(&state)
            .expect("list_blocks")
            .into_iter()
            .find(|b| b.block_uuid_hex == block.block_uuid_hex)
            .expect("block present");
        assert_eq!(summary.block_name, "After");
    }

    #[test]
    fn rename_block_blank_name_is_invalid_argument() {
        let (state, _dir, _pw) = unlocked_session_over_new_vault();
        let block = edit::create_block_impl(&state, "Keep").unwrap();
        let err = edit::rename_block_impl(&state, &block.block_uuid_hex, "   ")
            .expect_err("blank name must be rejected");
        assert!(
            matches!(err, AppError::InvalidArgument { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn move_record_copies_to_target_and_tombstones_source() {
        let (state, _dir, _pw) = unlocked_session_over_new_vault();
        let src = edit::create_block_impl(&state, "Source").unwrap();
        let dst = edit::create_block_impl(&state, "Target").unwrap();
        let rec = edit::save_record_impl(
            &state,
            &src.block_uuid_hex,
            RecordInputDto {
                record_type: "login".into(),
                tags: vec![],
                fields: vec![text_field("user", "alice")],
            },
        )
        .unwrap();

        let moved = edit::move_record_impl(
            &state,
            &src.block_uuid_hex,
            &dst.block_uuid_hex,
            &rec.record_uuid_hex,
        )
        .expect("move_record");
        assert_eq!(moved.block_uuid_hex, dst.block_uuid_hex);
        assert_ne!(
            moved.record_uuid_hex, rec.record_uuid_hex,
            "fresh uuid in target"
        );

        // Source live view no longer shows it; include_deleted shows the tombstone.
        let src_live = browse::read_block_impl(&state, &src.block_uuid_hex, false).unwrap();
        assert_eq!(src_live.records.len(), 0, "source record tombstoned");
        let src_all = browse::read_block_impl(&state, &src.block_uuid_hex, true).unwrap();
        assert_eq!(src_all.records.len(), 1);
        assert!(
            src_all.records[0].tombstoned,
            "source record marked tombstoned"
        );

        // Target has the live copy.
        let dst_all = browse::read_block_impl(&state, &dst.block_uuid_hex, false).unwrap();
        assert_eq!(dst_all.records.len(), 1);
        assert_eq!(dst_all.records[0].record_uuid_hex, moved.record_uuid_hex);
    }

    #[test]
    fn move_record_same_block_is_invalid_argument() {
        let (state, _dir, _pw) = unlocked_session_over_new_vault();
        let b = edit::create_block_impl(&state, "B").unwrap();
        let rec = edit::save_record_impl(
            &state,
            &b.block_uuid_hex,
            RecordInputDto {
                record_type: "login".into(),
                tags: vec![],
                fields: vec![text_field("user", "x")],
            },
        )
        .unwrap();
        let err = edit::move_record_impl(
            &state,
            &b.block_uuid_hex,
            &b.block_uuid_hex,
            &rec.record_uuid_hex,
        )
        .expect_err("same-block move must be rejected");
        assert!(
            matches!(err, AppError::InvalidArgument { .. }),
            "got {err:?}"
        );

        // A hex-case variant of the source is the SAME uuid (hex decodes
        // case-insensitively), so it must also be rejected, not treated as a
        // distinct target.
        let err_upper = edit::move_record_impl(
            &state,
            &b.block_uuid_hex,
            &b.block_uuid_hex.to_uppercase(),
            &rec.record_uuid_hex,
        )
        .expect_err("case-variant same-block move must be rejected");
        assert!(
            matches!(err_upper, AppError::InvalidArgument { .. }),
            "got {err_upper:?}"
        );
    }
}

/// D.1.5 delete/trash IPC commands over ephemeral tempdir vaults. Mirrors
/// `edit_path`'s local helpers (no hardcoded crypto values; random password +
/// fresh create+unlock per test).
mod delete_path {
    use super::*;
    use rand_core::{OsRng, RngCore};
    use secretary_core::crypto::secret::SecretBytes;

    const CREATE_DISPLAY_NAME: &str = "D.1.5 delete test identity";

    fn random_password() -> Vec<u8> {
        let mut raw = [0u8; 16];
        OsRng.fill_bytes(&mut raw);
        raw.iter()
            .flat_map(|b| format!("{b:02x}").into_bytes())
            .collect()
    }

    fn unlocked_session_over_new_vault() -> (Mutex<VaultSession>, tempfile::TempDir, Vec<u8>) {
        let vault_dir = tempfile::tempdir().expect("vault tempdir");
        let path = vault_dir.path().to_str().expect("utf8 path");
        let pw = random_password();

        create::create_vault_impl(
            path,
            CREATE_DISPLAY_NAME,
            &SecretBytes::from(pw.as_slice()),
            1_700_000_000_000,
            &mut OsRng,
        )
        .expect("create_vault_impl for delete test");

        let (state, _device_dir) = fresh_state();
        unlock::unlock_with_password_impl(&state, path, &pw).expect("unlock freshly-created vault");
        (state, vault_dir, pw)
    }

    fn text_field(name: &str, text: &str) -> FieldInputDto {
        FieldInputDto {
            name: name.into(),
            value: FieldValueDto::Text { text: text.into() },
        }
    }

    fn add_one_record(state: &Mutex<VaultSession>, block_hex: &str) -> String {
        edit::save_record_impl(
            state,
            block_hex,
            RecordInputDto {
                record_type: "login".into(),
                tags: vec![],
                fields: vec![text_field("user", "alice")],
            },
        )
        .expect("save_record")
        .record_uuid_hex
    }

    #[test]
    fn tombstone_hides_by_default_and_shows_with_include_deleted() {
        let (state, _dir, _pw) = unlocked_session_over_new_vault();
        let block = edit::create_block_impl(&state, "Logins").expect("create_block");
        let rec_hex = add_one_record(&state, &block.block_uuid_hex);

        delete::tombstone_record_impl(&state, &block.block_uuid_hex, &rec_hex)
            .expect("tombstone_record");

        // Live view hides the tombstoned record.
        let live =
            browse::read_block_impl(&state, &block.block_uuid_hex, false).expect("read live");
        assert_eq!(live.records.len(), 0, "tombstoned record hidden by default");

        // include_deleted surfaces it, flagged.
        let all = browse::read_block_impl(&state, &block.block_uuid_hex, true)
            .expect("read with deleted");
        assert_eq!(all.records.len(), 1, "tombstoned record visible with flag");
        assert!(all.records[0].tombstoned, "record flagged tombstoned");
    }

    #[test]
    fn resurrect_returns_record_to_live_view() {
        let (state, _dir, _pw) = unlocked_session_over_new_vault();
        let block = edit::create_block_impl(&state, "Logins").expect("create_block");
        let rec_hex = add_one_record(&state, &block.block_uuid_hex);

        delete::tombstone_record_impl(&state, &block.block_uuid_hex, &rec_hex)
            .expect("tombstone_record");
        delete::resurrect_record_impl(&state, &block.block_uuid_hex, &rec_hex)
            .expect("resurrect_record");

        let live =
            browse::read_block_impl(&state, &block.block_uuid_hex, false).expect("read live");
        assert_eq!(
            live.records.len(),
            1,
            "resurrected record back in live view"
        );
        assert!(
            !live.records[0].tombstoned,
            "resurrected record not flagged"
        );
    }

    #[test]
    fn trash_then_list_by_name_then_restore() {
        let (state, _dir, _pw) = unlocked_session_over_new_vault();
        let block = edit::create_block_impl(&state, "Bank logins").expect("create_block");
        let block_hex = block.block_uuid_hex.clone();
        add_one_record(&state, &block_hex);

        delete::trash_block_impl(&state, &block_hex).expect("trash_block");

        let trashed = delete::list_trashed_blocks_impl(&state).expect("list_trashed");
        let entry = trashed
            .iter()
            .find(|t| t.block_uuid_hex == block_hex)
            .expect("trashed entry present");
        assert_eq!(entry.block_name, "Bank logins");

        let restored = delete::restore_block_impl(&state, &block_hex).expect("restore_block");
        assert_eq!(
            restored.block_uuid_hex, block_hex,
            "restore returns the block"
        );

        let after = delete::list_trashed_blocks_impl(&state).expect("list after restore");
        assert!(
            !after.iter().any(|t| t.block_uuid_hex == block_hex),
            "restored block no longer in trash list"
        );
    }

    #[test]
    fn restore_never_trashed_block_is_trash_entry_not_found() {
        // A UUID that is neither live nor in trash. Core checks the live
        // collision first (that path yields `BlockRestoreConflict`), so to
        // exercise the `TrashEntryNotFound` path the UUID must be unknown to
        // the vault entirely — a random, never-created block.
        let (state, _dir, _pw) = unlocked_session_over_new_vault();

        let mut raw = [0u8; 16];
        OsRng.fill_bytes(&mut raw);
        let unknown_block_hex = hex::encode(raw);

        let err = delete::restore_block_impl(&state, &unknown_block_hex)
            .expect_err("restore of never-trashed block must fail");
        assert!(matches!(err, AppError::TrashEntryNotFound { .. }));
    }

    #[test]
    fn tombstone_absent_record_is_record_not_found() {
        let (state, _dir, _pw) = unlocked_session_over_new_vault();
        let block = edit::create_block_impl(&state, "Logins").expect("create_block");

        let mut raw = [0u8; 16];
        OsRng.fill_bytes(&mut raw);
        let random_record_hex = hex::encode(raw);

        let err = delete::tombstone_record_impl(&state, &block.block_uuid_hex, &random_record_hex)
            .expect_err("tombstone of absent record must fail");
        assert!(matches!(err, AppError::RecordNotFound { .. }));
    }
}

// ============================================================================
// D.1.6 contacts path. L3 coverage of the three contacts IPC commands over a
// real vault: list / import / share.
//
// CRITICAL fixture facts (the contacts commands MUTATE the vault — share
// re-keys a block, import writes into contacts/), so every test runs against
// an EPHEMERAL COPY of the golden vault, never the tracked fixture.
//
// The golden vault `contacts/` ships THREE cards: the owner plus two peers.
// `enumerate_contact_cards` OMITS the owner, so `list_contacts` on a fresh
// golden copy returns 2 contacts (the two peers), NOT 0. These tests therefore
// use a BASELINE + DELTA shape: capture `before.contacts.len()`, import a
// brand-new random peer, and assert the new list has `before + 1` entries and
// contains the imported peer by UUID — rather than pinning an absolute count.
// ============================================================================

mod contacts_path {
    use super::*;
    use rand_core::{OsRng, RngCore};
    use secretary_core::crypto::secret::SecretBytes;
    use secretary_desktop::commands::contacts;

    const PEER_DISPLAY_NAME: &str = "D.1.6 peer identity";

    /// Runtime-random hex password — avoids a hardcoded crypto literal.
    fn random_password() -> Vec<u8> {
        let mut raw = [0u8; 16];
        OsRng.fill_bytes(&mut raw);
        raw.iter()
            .flat_map(|b| format!("{b:02x}").into_bytes())
            .collect()
    }

    /// Create a throwaway vault via `create_vault_impl` in a fresh tempdir and
    /// return its single owner `.card` file under `<dir>/contacts/`. The peer's
    /// identity is random (no seed collision with the golden vault), so the
    /// card is always importable into / shareable to the golden copy without a
    /// duplicate or already-recipient clash. Mirrors the `create_vault_impl`
    /// call sites in `create_path` for the `SecretBytes` / `OsRng` imports.
    fn peer_card_file() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("peer vault tempdir");
        let path = dir.path().to_str().expect("utf8 path");
        let pw = random_password();

        create::create_vault_impl(
            path,
            PEER_DISPLAY_NAME,
            &SecretBytes::from(pw.as_slice()),
            1_700_000_000_000,
            &mut OsRng,
        )
        .expect("create_vault_impl for peer card");

        // A fresh vault writes exactly one card into contacts/ — the owner's
        // own self-card. That is the card a peer would hand us to import.
        let contacts_dir = dir.path().join("contacts");
        let mut cards: Vec<PathBuf> = std::fs::read_dir(&contacts_dir)
            .expect("read peer contacts/ dir")
            .map(|e| e.expect("dir entry").path())
            .filter(|p| p.extension().map(|x| x == "card").unwrap_or(false))
            .collect();
        assert_eq!(
            cards.len(),
            1,
            "a freshly-created vault has exactly one (owner) card in contacts/"
        );
        let card = cards.pop().expect("the single owner card");
        (dir, card)
    }

    /// An unlocked `VaultSession` over an EPHEMERAL COPY of the golden vault.
    /// Returns the state, the vault-copy TempDir guard, and the device-UUID
    /// TempDir guard — both must stay alive for the duration of the test.
    fn unlocked_ephemeral() -> (Mutex<VaultSession>, tempfile::TempDir, tempfile::TempDir) {
        let (vault_dir, vault_path) = ephemeral_golden_copy();
        let (state, device_dir) = fresh_state();
        unlock::unlock_with_password_impl(
            &state,
            vault_path.to_str().expect("utf8 path"),
            GOLDEN_VAULT_PASSWORD.as_bytes(),
        )
        .expect("unlock ephemeral golden copy");
        (state, vault_dir, device_dir)
    }

    #[test]
    fn list_contacts_excludes_owner_then_shows_imported_peer() {
        let (state, _vault_dir, _device_dir) = unlocked_ephemeral();

        // Baseline: the golden copy ships two peer cards (owner is omitted by
        // `enumerate_contact_cards`). We don't pin the absolute count — we
        // capture it and assert the +1 delta after import.
        let before = contacts::list_contacts_impl(&state).expect("baseline list_contacts");

        // Import a brand-new random peer.
        let (_peer_dir, card) = peer_card_file();
        let imported = contacts::import_contact_impl(&state, card.to_str().expect("utf8 path"))
            .expect("import the peer card");

        // The imported peer must NOT have already been present (random identity).
        assert!(
            !before
                .contacts
                .iter()
                .any(|c| c.contact_uuid_hex == imported.contact_uuid_hex),
            "freshly-created peer cannot already be in the baseline list"
        );

        let after = contacts::list_contacts_impl(&state).expect("post-import list_contacts");
        assert_eq!(
            after.contacts.len(),
            before.contacts.len() + 1,
            "importing one peer adds exactly one contact"
        );
        assert!(
            after
                .contacts
                .iter()
                .any(|c| c.contact_uuid_hex == imported.contact_uuid_hex),
            "the imported peer must appear in the post-import list"
        );
    }

    #[test]
    fn import_contact_duplicate_is_typed_error() {
        let (state, _vault_dir, _device_dir) = unlocked_ephemeral();
        let (_peer_dir, card) = peer_card_file();
        let card_path = card.to_str().expect("utf8 path");

        contacts::import_contact_impl(&state, card_path).expect("first import succeeds");

        let err = contacts::import_contact_impl(&state, card_path)
            .expect_err("re-importing the same card must fail");
        assert!(
            matches!(err, AppError::ContactAlreadyExists { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn share_block_happy_and_typed_errors() {
        let (state, _vault_dir, _device_dir) = unlocked_ephemeral();

        // Import a fresh peer to share with.
        let (_peer_dir, card) = peer_card_file();
        let peer = contacts::import_contact_impl(&state, card.to_str().expect("utf8 path"))
            .expect("import peer for share test");

        // Happy path: share an owner-authored golden block to the new peer.
        contacts::share_block_impl(&state, GOLDEN_BLOCK_UUID_HEX, &peer.contact_uuid_hex)
            .expect("share ok");

        // Re-sharing to the same (now-present) recipient is a typed error.
        let err = contacts::share_block_impl(&state, GOLDEN_BLOCK_UUID_HEX, &peer.contact_uuid_hex)
            .expect_err("re-share to an existing recipient must fail");
        assert!(
            matches!(err, AppError::RecipientAlreadyPresent),
            "got {err:?}"
        );

        // Unknown recipient (valid hex, but no contact card on disk).
        let unknown_recipient_hex = "99999999999999999999999999999999";
        let err = contacts::share_block_impl(&state, GOLDEN_BLOCK_UUID_HEX, unknown_recipient_hex)
            .expect_err("sharing to an unknown recipient must fail");
        assert!(
            matches!(err, AppError::ContactNotFound { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn revoke_block_from_happy_and_typed_errors() {
        let (state, _vault_dir, _device_dir) = unlocked_ephemeral();

        // Import a fresh peer and share an owner-authored golden block to it.
        let (_peer_dir, card) = peer_card_file();
        let peer = contacts::import_contact_impl(&state, card.to_str().expect("utf8 path"))
            .expect("import peer for revoke test");
        contacts::share_block_impl(&state, GOLDEN_BLOCK_UUID_HEX, &peer.contact_uuid_hex)
            .expect("share before revoke");

        // Happy path: revoke the recipient we just shared to.
        contacts::revoke_block_from_impl(&state, GOLDEN_BLOCK_UUID_HEX, &peer.contact_uuid_hex)
            .expect("revoke ok");

        // Revoking the same peer again — no longer a recipient — is a typed error.
        let err =
            contacts::revoke_block_from_impl(&state, GOLDEN_BLOCK_UUID_HEX, &peer.contact_uuid_hex)
                .expect_err("revoking a non-recipient must fail");
        assert!(matches!(err, AppError::RecipientNotPresent), "got {err:?}");

        // Revoking the owner is rejected fail-fast (owner is always a recipient
        // and cannot be removed; D.1.10 CannotRevokeOwner guard).
        let manifest = vault::get_manifest_impl(&state).expect("get_manifest");
        let err = contacts::revoke_block_from_impl(
            &state,
            GOLDEN_BLOCK_UUID_HEX,
            &manifest.owner_user_uuid_hex,
        )
        .expect_err("revoking the owner must fail");
        assert!(matches!(err, AppError::CannotRevokeOwner), "got {err:?}");
    }

    // ── D.1.9 list_contact_blocks ────────────────────────────────────────────

    #[test]
    fn list_contact_blocks_lists_shared_block_for_peer() {
        let (state, _vault_dir, _device_dir) = unlocked_ephemeral();

        // Import a fresh peer and share an owner-authored golden block to it.
        let (_peer_dir, card) = peer_card_file();
        let peer = contacts::import_contact_impl(&state, card.to_str().expect("utf8 path"))
            .expect("import peer");
        contacts::share_block_impl(&state, GOLDEN_BLOCK_UUID_HEX, &peer.contact_uuid_hex)
            .expect("share golden block to peer");

        // The peer's reverse map now contains exactly that block.
        let blocks = contacts::list_contact_blocks_impl(&state, &peer.contact_uuid_hex)
            .expect("list_contact_blocks ok");
        assert_eq!(
            blocks.len(),
            1,
            "peer receives exactly the one shared block"
        );
        assert_eq!(blocks[0].block_uuid_hex, GOLDEN_BLOCK_UUID_HEX);
        assert_eq!(blocks[0].block_name, "Personal logins");

        // A peer with no shares (use a random valid uuid) gets an empty list.
        let empty = contacts::list_contact_blocks_impl(&state, "99999999999999999999999999999999")
            .expect("list_contact_blocks ok for unknown uuid");
        assert!(
            empty.is_empty(),
            "an unshared/unknown uuid receives no blocks"
        );
    }

    // ── D.1.7 export_contact_card / delete_contact_card ─────────────────────

    /// `export_contact_card_impl` writes the owner's self-card to the requested
    /// directory and returns an `ExportedCardDto` whose `path` ends in `.card`
    /// and points to an existing file.
    #[test]
    fn export_contact_card_writes_importable_file() {
        let (state, _vault_dir, _device_dir) = unlocked_ephemeral();

        // Use a fresh tempdir as the export destination (user-chosen folder).
        let dest_dir = tempfile::tempdir().expect("export destination tempdir");
        let dest_path = dest_dir.path().to_str().expect("utf8 dest path");

        let dto = contacts::export_contact_card_impl(&state, dest_path)
            .expect("export_contact_card_impl should succeed");

        assert!(
            dto.path.ends_with(".card"),
            "exported path must end with .card; got {:?}",
            dto.path
        );
        assert!(
            std::path::Path::new(&dto.path).exists(),
            "exported file must exist on disk at {:?}",
            dto.path
        );
    }

    /// `delete_contact_card_impl` with a valid-hex UUID that has no card on
    /// disk returns `AppError::ContactNotFound`.
    #[test]
    fn delete_contact_card_impl_absent_is_not_found() {
        let (state, _vault_dir, _device_dir) = unlocked_ephemeral();

        // A well-formed UUID hex that has no card in the vault's contacts/.
        let absent_uuid_hex = "00112233445566778899aabbccddeeff";
        let err = contacts::delete_contact_card_impl(&state, absent_uuid_hex)
            .expect_err("deleting a non-existent contact must fail");

        assert!(
            matches!(err, AppError::ContactNotFound { .. }),
            "expected ContactNotFound, got {err:?}"
        );
    }
}

// ---- D.1.14 sync commands: seam-only hermetic coverage (NotUnlocked). ----
// The end-to-end sync path is covered hermetically by the bridge's own
// TempDir tests (ffi/secretary-ffi-bridge/src/sync/*) and by the mandatory
// manual GUI smoke; the bridge's public sync_status/sync_vault use the
// default OS state dir, so driving them here would be non-hermetic.

#[test]
fn sync_status_on_locked_session_yields_not_unlocked() {
    let (state, _device_dir) = fresh_state();
    let err = sync::sync_status_impl(&state).expect_err("locked session must error");
    assert!(matches!(err, AppError::NotUnlocked), "got {err:?}");
}

#[test]
fn sync_now_on_locked_session_yields_not_unlocked() {
    let (state, _device_dir) = fresh_state();
    let pw = Password::from_bytes(b"unused while locked");
    let err = sync::sync_now_impl(&state, &pw, 0).expect_err("locked session must error");
    assert!(matches!(err, AppError::NotUnlocked), "got {err:?}");
}

#[test]
fn sync_commit_decisions_impl_requires_unlock() {
    let (state, _device_dir) = fresh_state();
    let pw = Password::from_bytes(b"unused while locked");
    let err = sync::sync_commit_decisions_impl(&state, &pw, Vec::new(), Vec::new(), 0)
        .expect_err("locked session must error");
    assert!(matches!(err, AppError::NotUnlocked), "got {err:?}");
}
