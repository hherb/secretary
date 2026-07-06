//! Serde round-trip + `map_ffi_error` routing tests.
//!
//! These pin the IPC wire-format contract: the `{ "code": ... }`
//! discriminator strings and the presence/absence of each payload field
//! (the frontend `errors.ts` union depends on the exact `code` strings, and
//! `detail` fields must NOT cross the seam). Kept in a module named `tests`
//! under `errors` so cross-references like
//! `errors::tests::settings_clamped_warning_carries_both_values` stay valid.

use super::{map_ffi_error, AppError, AppWarning};
use secretary_ffi_bridge::error::FfiVaultError;
use serde_json::Value;

fn round_trip(err: &AppError) -> Value {
    serde_json::from_str(&serde_json::to_string(err).expect("serialize")).expect("parse")
}

#[test]
fn wrong_password_has_code_only() {
    let v = round_trip(&AppError::WrongPassword);
    assert_eq!(v["code"], "wrong_password");
    assert_eq!(v.as_object().expect("object").len(), 1);
}

#[test]
fn kdf_too_weak_carries_payload() {
    let v = round_trip(&AppError::KdfTooWeak {
        current_memory_kib: 32_768,
        min_memory_kib: 65_536,
    });
    assert_eq!(v["code"], "kdf_too_weak");
    assert_eq!(v["current_memory_kib"], 32_768);
    assert_eq!(v["min_memory_kib"], 65_536);
}

#[test]
fn vault_corrupt_detail_is_stripped() {
    let v = round_trip(&AppError::VaultCorrupt {
        detail: "sensitive dev info".to_string(),
    });
    assert_eq!(v["code"], "vault_corrupt");
    assert!(v.get("detail").is_none(), "detail must NOT cross IPC");
}

#[test]
fn settings_out_of_range_carries_bounds() {
    let v = round_trip(&AppError::SettingsOutOfRange {
        min: 60_000,
        max: 86_400_000,
    });
    assert_eq!(v["code"], "settings_out_of_range");
    assert_eq!(v["min"], 60_000);
    assert_eq!(v["max"], 86_400_000);
}

#[test]
fn settings_clamped_warning_carries_both_values() {
    let w = AppWarning::SettingsClamped {
        original_ms: 30_000,
        clamped_ms: 60_000,
    };
    let v: Value = serde_json::from_str(&serde_json::to_string(&w).expect("ser")).expect("parse");
    assert_eq!(v["code"], "settings_clamped");
    assert_eq!(v["original_ms"], 30_000);
    assert_eq!(v["clamped_ms"], 60_000);
}

#[test]
fn unknown_version_warning_carries_version_string() {
    let w = AppWarning::SettingsUnknownVersion {
        version: "secretary.settings.v99".to_string(),
    };
    let v: Value = serde_json::from_str(&serde_json::to_string(&w).expect("ser")).expect("parse");
    assert_eq!(v["code"], "settings_unknown_version");
    assert_eq!(v["version"], "secretary.settings.v99");
}

// Two additional From<FfiVaultError> spot-checks pin the anti-oracle
// collapse + the detail-stripping path at the bridge seam itself.
// These complement the variant-shape tests above by exercising the
// mapping logic, not just the serde shape.

#[test]
fn ffi_wrong_password_or_corrupt_collapses_to_wrong_password() {
    let mapped: AppError = FfiVaultError::WrongPasswordOrCorrupt.into();
    let v = round_trip(&mapped);
    assert_eq!(
        v["code"], "wrong_password",
        "anti-oracle: WrongPasswordOrCorrupt must collapse to WrongPassword"
    );
}

#[test]
fn block_not_found_carries_hex() {
    let v = round_trip(&AppError::BlockNotFound {
        block_uuid_hex: "112233445566778899aabbccddeeff00".to_string(),
    });
    assert_eq!(v["code"], "block_not_found");
    assert_eq!(v["block_uuid_hex"], "112233445566778899aabbccddeeff00");
}

#[test]
fn record_not_found_carries_hex() {
    let v = round_trip(&AppError::RecordNotFound {
        record_uuid_hex: "33445566778899aabbccddeeff001122".to_string(),
    });
    assert_eq!(v["code"], "record_not_found");
    assert_eq!(v["record_uuid_hex"], "33445566778899aabbccddeeff001122");
}

#[test]
fn field_not_found_carries_name() {
    let v = round_trip(&AppError::FieldNotFound {
        field_name: "password".to_string(),
    });
    assert_eq!(v["code"], "field_not_found");
    assert_eq!(v["field_name"], "password");
}

#[test]
fn vault_folder_not_empty_carries_path() {
    let v = round_trip(&AppError::VaultFolderNotEmpty {
        path: "/Users/h/Documents".to_string(),
    });
    assert_eq!(v["code"], "vault_folder_not_empty");
    assert_eq!(v["path"], "/Users/h/Documents");
}

#[test]
fn path_not_approved_round_trips_with_path() {
    let v = round_trip(&AppError::PathNotApproved {
        path: "/some/where".to_string(),
    });
    assert_eq!(v["code"], "path_not_approved");
    assert_eq!(v["path"], "/some/where");
}

#[test]
fn vault_create_failed_detail_is_stripped() {
    let v = round_trip(&AppError::VaultCreateFailed {
        detail: "argon2id derivation OOM".to_string(),
    });
    assert_eq!(v["code"], "vault_create_failed");
    assert!(v.get("detail").is_none(), "detail must NOT cross IPC");
}

#[test]
fn invalid_field_value_carries_field_name() {
    let v = round_trip(&AppError::InvalidFieldValue {
        field_name: "totp_seed".to_string(),
    });
    assert_eq!(v["code"], "invalid_field_value");
    assert_eq!(v["field_name"], "totp_seed");
}

#[test]
fn record_save_failed_detail_is_stripped() {
    let v = round_trip(&AppError::RecordSaveFailed {
        detail: "core save_block returned Io".to_string(),
    });
    assert_eq!(v["code"], "record_save_failed");
    assert!(v.get("detail").is_none(), "detail must NOT cross IPC");
}

#[test]
fn map_ffi_error_is_pure_no_log_side_effect_required() {
    // Calling the pure helper directly (not via `.into()` / `From`) must
    // produce the same routing as the `From` impl. Documents the public
    // API of the side-effect-free path so future callers that already
    // logged the source at a different level can reuse it.
    let mapped = map_ffi_error(FfiVaultError::WrongMnemonicOrCorrupt);
    let v = round_trip(&mapped);
    assert_eq!(v["code"], "wrong_password");
}

#[test]
fn ffi_corrupt_vault_detail_is_logged_but_stripped_on_serialize() {
    let mapped: AppError = FfiVaultError::CorruptVault {
        detail: "dev-facing crypto failure context".to_string(),
    }
    .into();
    let v = round_trip(&mapped);
    assert_eq!(v["code"], "vault_corrupt");
    assert!(
        v.get("detail").is_none(),
        "FfiVaultError::CorruptVault.detail must NOT cross IPC"
    );
}

#[test]
fn block_restore_conflict_carries_hex() {
    let v = round_trip(&AppError::BlockRestoreConflict {
        block_uuid_hex: "ab12".into(),
    });
    assert_eq!(v["code"], "block_restore_conflict");
    assert_eq!(v["block_uuid_hex"], "ab12");
}

#[test]
fn trash_entry_not_found_carries_hex() {
    let v = round_trip(&AppError::TrashEntryNotFound {
        block_uuid_hex: "ab12".into(),
    });
    assert_eq!(v["code"], "trash_entry_not_found");
    assert_eq!(v["block_uuid_hex"], "ab12");
}

#[test]
fn ffi_block_uuid_already_live_maps_to_restore_conflict() {
    let mapped = map_ffi_error(FfiVaultError::BlockUuidAlreadyLive {
        detail: "abcd".into(),
    });
    assert!(
        matches!(mapped, AppError::BlockRestoreConflict { block_uuid_hex } if block_uuid_hex == "abcd"),
        "BlockUuidAlreadyLive must map to BlockRestoreConflict carrying the hex"
    );
}

#[test]
fn ffi_block_not_in_trash_maps_to_trash_entry_not_found() {
    let mapped = map_ffi_error(FfiVaultError::BlockNotInTrash {
        detail: "ef01".into(),
    });
    assert!(
        matches!(mapped, AppError::TrashEntryNotFound { block_uuid_hex } if block_uuid_hex == "ef01"),
        "BlockNotInTrash must map to TrashEntryNotFound carrying the hex"
    );
}

#[test]
fn share_errors_serialize_typed() {
    assert_eq!(round_trip(&AppError::NotAuthor)["code"], "not_author");
    assert_eq!(
        round_trip(&AppError::RecipientAlreadyPresent)["code"],
        "recipient_already_present"
    );
    assert_eq!(
        round_trip(&AppError::RecipientNotPresent)["code"],
        "recipient_not_present"
    );
    assert_eq!(
        round_trip(&AppError::CannotRevokeOwner)["code"],
        "cannot_revoke_owner"
    );
    assert_eq!(
        round_trip(&AppError::MissingRecipientCard)["code"],
        "missing_recipient_card"
    );
    let v = round_trip(&AppError::ContactAlreadyExists {
        contact_uuid_hex: "ab".into(),
    });
    assert_eq!(v["code"], "contact_already_exists");
    assert_eq!(v["contact_uuid_hex"], "ab");
    let v = round_trip(&AppError::ContactNotFound {
        contact_uuid_hex: "cd".into(),
    });
    assert_eq!(v["code"], "contact_not_found");
    assert_eq!(v["contact_uuid_hex"], "cd");
}

#[test]
fn sync_decisions_incomplete_serializes_code() {
    let v = serde_json::to_value(AppError::SyncDecisionsIncomplete).unwrap();
    assert_eq!(
        v,
        serde_json::json!({ "code": "sync_decisions_incomplete" })
    );
}

#[test]
fn map_ffi_error_promotes_sync_decisions_incomplete() {
    let mapped = map_ffi_error(FfiVaultError::SyncDecisionsIncomplete);
    assert!(matches!(mapped, AppError::SyncDecisionsIncomplete));
}

#[test]
fn invalid_argument_serializes_without_detail() {
    let err = AppError::InvalidArgument {
        detail: "source_block_uuid and target_block_uuid must differ".into(),
    };
    let v = serde_json::to_value(&err).expect("serialize");
    assert_eq!(v, serde_json::json!({ "code": "invalid_argument" }));
}

#[test]
fn cannot_delete_owner_contact_round_trips() {
    let v = round_trip(&AppError::CannotDeleteOwnerContact);
    assert_eq!(v["code"], "cannot_delete_owner_contact");
}

#[test]
fn map_cannot_delete_owner_contact() {
    let m = map_ffi_error(FfiVaultError::CannotDeleteOwnerContact);
    assert!(matches!(m, AppError::CannotDeleteOwnerContact));
}

#[test]
fn ffi_share_variants_route_to_typed_app_errors() {
    let m: AppError = map_ffi_error(FfiVaultError::RecipientAlreadyPresent);
    assert_eq!(round_trip(&m)["code"], "recipient_already_present");
    let m: AppError = map_ffi_error(FfiVaultError::RecipientNotPresent);
    assert_eq!(round_trip(&m)["code"], "recipient_not_present");
    let m: AppError = map_ffi_error(FfiVaultError::CannotRevokeOwner);
    assert_eq!(round_trip(&m)["code"], "cannot_revoke_owner");
    let m = map_ffi_error(FfiVaultError::ContactAlreadyExists {
        uuid_hex: "ab".into(),
    });
    assert_eq!(round_trip(&m)["contact_uuid_hex"], "ab");
    let m = map_ffi_error(FfiVaultError::ContactNotFound {
        uuid_hex: "cd".into(),
    });
    assert_eq!(round_trip(&m)["contact_uuid_hex"], "cd");
    let m = map_ffi_error(FfiVaultError::NotAuthor {
        expected_fingerprint_hex: "x".into(),
        got_fingerprint_hex: "y".into(),
    });
    let v = round_trip(&m);
    assert_eq!(v["code"], "not_author");
    // The bridge fingerprints must be dropped at the seam — assert
    // their ABSENCE explicitly so a future refactor that adds a payload
    // to AppError::NotAuthor can't silently start leaking them.
    assert!(v.get("expected_fingerprint_hex").is_none());
    assert!(v.get("got_fingerprint_hex").is_none());
    assert_eq!(v.as_object().expect("object").len(), 1, "code only");
}

#[test]
fn vault_needs_repair_carries_block_uuid_hex() {
    let v = round_trip(&AppError::VaultNeedsRepair {
        block_uuid_hex: "11223344-5566-7788-99aa-bbccddeeff00".to_string(),
    });
    assert_eq!(v["code"], "vault_needs_repair");
    assert_eq!(v["block_uuid_hex"], "11223344-5566-7788-99aa-bbccddeeff00");
}

#[test]
fn repair_rejected_carries_block_uuid_hex_and_detail() {
    // Unlike most `detail` fields in this enum, RepairRejected's detail
    // is user-facing (not skip_serializing) — the bridge contract is
    // "the app should surface detail". Pin that it crosses the seam.
    let v = round_trip(&AppError::RepairRejected {
        block_uuid_hex: "11223344-5566-7788-99aa-bbccddeeff00".to_string(),
        detail: "clock relation Concurrent".to_string(),
    });
    assert_eq!(v["code"], "repair_rejected");
    assert_eq!(v["block_uuid_hex"], "11223344-5566-7788-99aa-bbccddeeff00");
    assert_eq!(v["detail"], "clock relation Concurrent");
}

#[test]
fn map_ffi_error_routes_vault_needs_repair() {
    let mapped = map_ffi_error(FfiVaultError::VaultNeedsRepair {
        block_uuid_hex: "11223344-5566-7788-99aa-bbccddeeff00".to_string(),
    });
    let AppError::VaultNeedsRepair { block_uuid_hex } = mapped else {
        panic!("expected VaultNeedsRepair");
    };
    assert_eq!(block_uuid_hex, "11223344-5566-7788-99aa-bbccddeeff00");
}

#[test]
fn map_ffi_error_routes_repair_rejected() {
    let mapped = map_ffi_error(FfiVaultError::RepairRejected {
        block_uuid_hex: "11223344-5566-7788-99aa-bbccddeeff00".to_string(),
        detail: "clock relation Concurrent".to_string(),
    });
    let AppError::RepairRejected {
        block_uuid_hex,
        detail,
    } = mapped
    else {
        panic!("expected RepairRejected");
    };
    assert_eq!(block_uuid_hex, "11223344-5566-7788-99aa-bbccddeeff00");
    assert_eq!(detail, "clock relation Concurrent");
}
