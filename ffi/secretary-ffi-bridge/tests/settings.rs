//! Integration tests for the bridge settings orchestrators
//! (`read_settings` / `write_settings`) against a writable copy of
//! `golden_vault_001`. Proves: read of an absent settings block returns
//! defaults; write-then-read round-trips; and a partial update (touching
//! only retention) preserves every other field.

#[allow(dead_code)]
mod share_block_helpers;

use secretary_ffi_bridge::settings::{read_settings, write_settings, Settings};
use secretary_ffi_bridge::{MS_PER_DAY, REAUTH_WINDOW_DEFAULT_MS};

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
