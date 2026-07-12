//! Integration tests for the bridge settings orchestrators
//! (`read_settings` / `write_settings`) against a writable copy of
//! `golden_vault_001`. Proves: read of an absent settings block returns
//! defaults; write-then-read round-trips; and a partial update (touching
//! only retention) preserves every other field.

#[allow(dead_code)]
mod share_block_helpers;

use secretary_core::crypto::secret::SecretString;
use secretary_ffi_bridge::settings::{read_settings, write_settings, Settings};
use secretary_ffi_bridge::{
    deterministic_uuid_16, save_block, BlockInput, FieldInput, FieldInputValue, RecordInput,
    SettingsWarning, MS_PER_DAY, REAUTH_WINDOW_DEFAULT_MS, SETTINGS_BLOCK_NAME,
    SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS, SETTINGS_RECORD_TYPE,
};

use share_block_helpers::{fresh_writable_vault, DEVICE_UUID, NOW_MS_BASE};

#[test]
fn read_absent_settings_block_returns_defaults() {
    let (_tmp, identity, manifest) = fresh_writable_vault();
    let (settings, warnings) = read_settings(&identity, &manifest).expect("read");
    assert_eq!(settings, Settings::default());
    assert!(warnings.is_empty());
}

#[test]
fn write_then_read_round_trips() {
    let (_tmp, identity, manifest) = fresh_writable_vault();
    let want = Settings {
        auto_lock_timeout_ms: 900_000,
        require_password_before_edits: false,
        reauth_grace_window_ms: 30_000,
        retention_window_ms: 45 * MS_PER_DAY,
    };
    write_settings(&identity, &manifest, &want, DEVICE_UUID, NOW_MS_BASE).expect("write");
    let (got, warnings) = read_settings(&identity, &manifest).expect("read");
    assert_eq!(got, want);
    assert!(warnings.is_empty());
}

#[test]
fn partial_update_preserves_other_fields() {
    let (_tmp, identity, manifest) = fresh_writable_vault();
    // Seed all 4 fields at non-default values (as desktop would).
    let seeded = Settings {
        auto_lock_timeout_ms: 900_000,
        require_password_before_edits: false,
        reauth_grace_window_ms: 42_000,
        retention_window_ms: 30 * MS_PER_DAY,
    };
    write_settings(&identity, &manifest, &seeded, DEVICE_UUID, NOW_MS_BASE).expect("seed");

    // Mobile-style read → mutate ONLY retention → write.
    let (mut s, _) = read_settings(&identity, &manifest).expect("read");
    s.retention_window_ms = 90 * MS_PER_DAY;
    write_settings(&identity, &manifest, &s, DEVICE_UUID, NOW_MS_BASE + 1).expect("write");

    let (got, _) = read_settings(&identity, &manifest).expect("read");
    assert_eq!(
        got.retention_window_ms,
        90 * MS_PER_DAY,
        "retention updated"
    );
    assert_eq!(got.auto_lock_timeout_ms, 900_000, "auto-lock preserved");
    assert!(
        !got.require_password_before_edits,
        "require-password preserved"
    );
    assert_eq!(got.reauth_grace_window_ms, 42_000, "reauth grace preserved");
    // Sanity: the default is 120_000, so a preserved 42_000 proves it wasn't reset.
    assert_ne!(got.reauth_grace_window_ms, REAUTH_WINDOW_DEFAULT_MS);
}

/// Plant a settings block whose sole record carries an unrecognized
/// `record_type` (simulating a future schema version this build doesn't
/// know), via the low-level `save_block` (NOT `write_settings`, which
/// always writes a valid v1 record). `read_settings` must not error: the
/// bridge's `read_settings` is deliberately lenient so a broken/unknown
/// settings record never blocks vault access — it falls back to
/// `Settings::default()` plus a `SettingsWarning::Corrupt`.
#[test]
fn read_unknown_version_record_falls_back_to_defaults_with_warning() {
    let (_tmp, identity, manifest) = fresh_writable_vault();

    let block_uuid = deterministic_uuid_16(SETTINGS_BLOCK_NAME);
    let record_uuid = deterministic_uuid_16("secretary.settings.v99");
    let input = BlockInput {
        block_uuid,
        block_name: SETTINGS_BLOCK_NAME.to_string(),
        records: vec![RecordInput {
            record_uuid,
            record_type: "secretary.settings.v99".to_string(),
            tags: Vec::new(),
            fields: vec![FieldInput {
                name: SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS.to_string(),
                value: FieldInputValue::Text(SecretString::from("600000")),
            }],
        }],
    };
    save_block(&identity, &manifest, input, DEVICE_UUID, NOW_MS_BASE).expect("save_block");

    let (settings, warnings) = read_settings(&identity, &manifest).expect("read");
    assert_eq!(settings, Settings::default());
    assert!(!warnings.is_empty());
    assert!(
        warnings
            .iter()
            .any(|w| matches!(w, SettingsWarning::Corrupt { .. })),
        "expected a Corrupt warning, got {warnings:?}"
    );
}

/// Plant a valid-v1-record_type settings block whose numeric field text is
/// not an integer, via the low-level `save_block`. `read_settings` must not
/// error: it falls back to `Settings::default()` plus a
/// `SettingsWarning::Corrupt` rather than blocking vault access.
#[test]
fn read_non_integer_field_falls_back_to_defaults_with_warning() {
    let (_tmp, identity, manifest) = fresh_writable_vault();

    let block_uuid = deterministic_uuid_16(SETTINGS_BLOCK_NAME);
    let record_uuid = deterministic_uuid_16(SETTINGS_RECORD_TYPE);
    let input = BlockInput {
        block_uuid,
        block_name: SETTINGS_BLOCK_NAME.to_string(),
        records: vec![RecordInput {
            record_uuid,
            record_type: SETTINGS_RECORD_TYPE.to_string(),
            tags: Vec::new(),
            fields: vec![FieldInput {
                name: SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS.to_string(),
                value: FieldInputValue::Text(SecretString::from("not-a-number")),
            }],
        }],
    };
    save_block(&identity, &manifest, input, DEVICE_UUID, NOW_MS_BASE).expect("save_block");

    let (settings, warnings) = read_settings(&identity, &manifest).expect("read");
    assert_eq!(settings, Settings::default());
    assert!(!warnings.is_empty());
    assert!(
        warnings
            .iter()
            .any(|w| matches!(w, SettingsWarning::Corrupt { .. })),
        "expected a Corrupt warning, got {warnings:?}"
    );
}
