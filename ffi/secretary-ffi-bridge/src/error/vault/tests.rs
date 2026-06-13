//! Behavior-pinning tests for [`super::FfiVaultError`] and its
//! `From<secretary_core::vault::VaultError>` mapping.
//!
//! These tests are tightly coupled to the enum variants and their routing
//! decisions — most exist as *tripwires* that turn silent semantic drift
//! into a compile- or assertion-time failure. Test density is intrinsic
//! to the typed-error discipline; they live in a sibling file (per Issue
//! #44) only to keep the parent module under the 500-LOC threshold.

use super::*;
use secretary_core::unlock::UnlockError;
use secretary_core::vault::VaultError;

#[test]
fn vault_error_folder_invalid_display_uses_dedicated_text() {
    let ffi = FfiVaultError::FolderInvalid {
        detail: "fnord".to_string(),
    };
    let rendered = format!("{ffi}");
    assert!(
        rendered.contains("vault folder is not accessible"),
        "Display did not contain the dedicated FolderInvalid text: {rendered}",
    );
    assert!(rendered.contains("fnord"), "Display did not include detail");
}

#[test]
fn vault_error_save_crypto_failure_display_uses_dedicated_text() {
    let ffi = FfiVaultError::SaveCryptoFailure {
        detail: "encrypt_block aborted: pq sig generation failed".to_string(),
    };
    let rendered = format!("{ffi}");
    assert!(
        rendered.contains("save-time crypto failure"),
        "Display did not contain the dedicated SaveCryptoFailure text: {rendered}",
    );
    assert!(
        rendered.contains("encrypt_block aborted"),
        "Display did not include detail: {rendered}",
    );
}

#[test]
fn from_core_vault_error_unlock_arm_delegates_through_ffi_unlock_error() {
    // VaultError::Unlock(WrongPasswordOrCorrupt) → FfiVaultError::WrongPasswordOrCorrupt
    // via the FfiUnlockError translation. Test the full delegation path.
    let core_err = VaultError::Unlock(UnlockError::WrongPasswordOrCorrupt);
    let ffi: FfiVaultError = core_err.into();
    assert!(matches!(ffi, FfiVaultError::WrongPasswordOrCorrupt));
}

#[test]
fn from_core_vault_error_io_not_found_maps_to_folder_invalid() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "no such file");
    let core_err = VaultError::Io {
        context: "failed to read vault.toml",
        source: io_err,
    };
    let ffi: FfiVaultError = core_err.into();
    let FfiVaultError::FolderInvalid { detail } = ffi else {
        panic!("expected FolderInvalid, got {ffi:?}");
    };
    assert!(
        detail.contains("vault.toml") && detail.contains("no such file"),
        "FolderInvalid detail did not carry context + source: {detail}",
    );
}

#[test]
fn io_already_exists_maps_to_vault_folder_not_empty() {
    // ensure_empty_directory surfaces a non-empty target as
    // Io { ErrorKind::AlreadyExists }; it must route to the dedicated
    // typed variant, NOT fold to CorruptVault.
    let core_err = VaultError::Io {
        context: "vault folder is not empty",
        source: std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "expected an empty directory",
        ),
    };
    let ffi = FfiVaultError::from(core_err);
    assert!(
        matches!(ffi, FfiVaultError::VaultFolderNotEmpty),
        "Io{{AlreadyExists}} must map to VaultFolderNotEmpty, got {ffi:?}",
    );
}

#[test]
fn from_core_vault_error_io_permission_denied_maps_to_folder_invalid() {
    let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
    let core_err = VaultError::Io {
        context: "failed to read identity.bundle.enc",
        source: io_err,
    };
    let ffi: FfiVaultError = core_err.into();
    assert!(matches!(ffi, FfiVaultError::FolderInvalid { .. }));
}

#[test]
fn from_core_vault_error_io_other_kind_falls_through_to_corrupt_vault() {
    // Kinds other than NotFound / PermissionDenied are not foreign-
    // caller-actionable as "your path is wrong" — fold to CorruptVault.
    let io_err = std::io::Error::new(std::io::ErrorKind::InvalidData, "bad data");
    let core_err = VaultError::Io {
        context: "failed to parse manifest.cbor.enc",
        source: io_err,
    };
    let ffi: FfiVaultError = core_err.into();
    assert!(matches!(ffi, FfiVaultError::CorruptVault { .. }));
}

#[test]
fn from_core_vault_error_owner_uuid_mismatch_maps_to_corrupt_vault() {
    // Post-unlock integrity failure folds into CorruptVault catchall.
    let core_err = VaultError::OwnerUuidMismatch {
        vault: [0u8; 16],
        found: [1u8; 16],
    };
    let ffi: FfiVaultError = core_err.into();
    assert!(matches!(ffi, FfiVaultError::CorruptVault { .. }));
}

#[test]
fn from_core_vault_error_kdf_params_mismatch_maps_to_corrupt_vault() {
    // Post-unlock integrity failure pinned to CorruptVault.
    // Note: the variant in core is `KdfParamsMismatch` (not `ManifestKdfParamsMismatch`).
    let core_err = VaultError::KdfParamsMismatch;
    let ffi: FfiVaultError = core_err.into();
    assert!(matches!(ffi, FfiVaultError::CorruptVault { .. }));
}

#[test]
fn device_slot_not_found_promotes_to_dedicated_variant() {
    // ADR 0009 (B.2): DeviceSlotNotFound is now a first-class FfiVaultError
    // variant (was folded to CorruptVault in B.1 before the device-slot FFI
    // surface existed). The B.1 CorruptVault fold is intentionally inverted here.
    let core = VaultError::DeviceSlotNotFound;
    let ffi: FfiVaultError = core.into();
    assert!(
        matches!(ffi, FfiVaultError::DeviceSlotNotFound),
        "got {ffi:?}"
    );
}

#[test]
fn unlock_wrong_device_secret_promotes_on_vault_error() {
    let core = VaultError::Unlock(UnlockError::WrongDeviceSecretOrCorrupt);
    let ffi: FfiVaultError = core.into();
    assert!(
        matches!(ffi, FfiVaultError::WrongDeviceSecretOrCorrupt),
        "got {ffi:?}"
    );
}

#[test]
fn unlock_device_uuid_mismatch_promotes_on_vault_error() {
    let core = VaultError::Unlock(UnlockError::DeviceUuidMismatch);
    let ffi: FfiVaultError = core.into();
    assert!(
        matches!(ffi, FfiVaultError::DeviceUuidMismatch { .. }),
        "got {ffi:?}"
    );
}

#[test]
fn unlock_malformed_device_file_folds_to_corrupt_vault() {
    use secretary_core::unlock::device_file::DeviceFileError;
    let core = VaultError::Unlock(UnlockError::MalformedDeviceFile(
        DeviceFileError::BadMagic { got: 0 },
    ));
    let ffi: FfiVaultError = core.into();
    assert!(
        matches!(ffi, FfiVaultError::CorruptVault { .. }),
        "got {ffi:?}"
    );
}

#[test]
fn unlock_malformed_device_secret_folds_to_corrupt_vault_unreachable() {
    // Structurally unreachable through any FFI surface (bridge takes &[u8;32]);
    // the binding raises InvalidArgument first. Pinned like WeakKdfParams.
    let core = VaultError::Unlock(UnlockError::MalformedDeviceSecret { len: 7 });
    let ffi: FfiVaultError = core.into();
    assert!(
        matches!(ffi, FfiVaultError::CorruptVault { .. }),
        "got {ffi:?}"
    );
}

#[test]
fn from_core_vault_error_manifest_author_mismatch_maps_to_corrupt_vault() {
    // Issue #40 explicit-arm pin: post-unlock structural mismatch
    // between manifest header `author_fingerprint` and owner card
    // fingerprint folds to CorruptVault.
    let ffi: FfiVaultError = VaultError::ManifestAuthorMismatch.into();
    assert!(matches!(ffi, FfiVaultError::CorruptVault { .. }));
}

#[test]
fn from_core_vault_error_manifest_vault_uuid_mismatch_maps_to_corrupt_vault() {
    // Issue #40 explicit-arm pin: §4.3 step-5 cross-check failure
    // (manifest header vs body vault_uuid disagreement) folds to
    // CorruptVault.
    let ffi: FfiVaultError = VaultError::ManifestVaultUuidMismatch {
        header: [0u8; 16],
        body: [1u8; 16],
    }
    .into();
    assert!(matches!(ffi, FfiVaultError::CorruptVault { .. }));
}

#[test]
fn from_core_vault_error_clock_overflow_maps_to_corrupt_vault() {
    // Issue #40 explicit-arm pin: vector-clock saturation (a
    // post-unlock structural failure) folds to CorruptVault.
    let ffi: FfiVaultError = VaultError::ClockOverflow {
        device_uuid: [0xee; 16],
    }
    .into();
    assert!(matches!(ffi, FfiVaultError::CorruptVault { .. }));
}

#[test]
fn from_core_vault_error_rollback_maps_to_corrupt_vault() {
    // Issue #40 explicit-arm pin: §10 rollback-resistance rejection
    // currently folds to CorruptVault. (Future UI work may want a
    // dedicated typed variant so the foreign side can show a
    // "restoring from backup; accept anyway" affordance — until
    // then, drift-prevention tests pin the current routing.)
    let ffi: FfiVaultError = VaultError::Rollback {
        local_clock: vec![],
        incoming_clock: vec![],
    }
    .into();
    assert!(matches!(ffi, FfiVaultError::CorruptVault { .. }));
}

// =============================================================================
// FfiVaultError::BlockNotFound — new in B.4b (block lookup failure variant)
// =============================================================================

#[test]
fn vault_error_block_not_found_display_pins_uuid_hex() {
    // Tripwire: the BlockNotFound variant's Display string must contain
    // the uuid_hex verbatim. A future refactor that strips it (e.g.
    // changes to a generic "block not found" message without the UUID)
    // would degrade the foreign caller's debugging affordance and must
    // be a deliberate decision rather than a silent regression.
    let ffi = FfiVaultError::BlockNotFound {
        uuid_hex: "112233445566778899aabbccddeeff00".to_string(),
    };
    let rendered = format!("{ffi}");
    assert!(
        rendered.contains("block not found"),
        "Display did not contain the BlockNotFound text: {rendered}",
    );
    assert!(
        rendered.contains("112233445566778899aabbccddeeff00"),
        "Display did not include uuid_hex: {rendered}",
    );
}

#[test]
fn vault_error_block_not_found_carries_uuid_hex_field() {
    // Pin the field name + accessibility. The foreign callers
    // (PyO3 + uniffi) destructure this variant to surface uuid_hex
    // as a typed exception attribute; renaming the field would break
    // both binding-flavor crates without a compile error if they
    // stop using exhaustive `match`.
    let ffi = FfiVaultError::BlockNotFound {
        uuid_hex: "deadbeef".to_string(),
    };
    let FfiVaultError::BlockNotFound { uuid_hex } = ffi else {
        panic!("expected BlockNotFound variant");
    };
    assert_eq!(uuid_hex, "deadbeef");
}

// =============================================================================
// FfiVaultError::{NotAuthor, RecipientAlreadyPresent, MissingRecipientCard,
//                 CardDecodeFailure} — new in B.4d (share_block error surface)
// =============================================================================

#[test]
fn vault_error_not_author_display_pins_string() {
    let e = FfiVaultError::NotAuthor {
        expected_fingerprint_hex: "aa".repeat(16),
        got_fingerprint_hex: "bb".repeat(16),
    };
    assert_eq!(e.to_string(), "only the block author can share this block");
}

#[test]
fn vault_error_not_author_from_core_preserves_fingerprints_as_hex() {
    let core_err = VaultError::NotAuthor {
        expected: [0xaa; 16],
        got: [0xbb; 16],
    };
    let ffi: FfiVaultError = core_err.into();
    match ffi {
        FfiVaultError::NotAuthor {
            expected_fingerprint_hex,
            got_fingerprint_hex,
        } => {
            assert_eq!(expected_fingerprint_hex, "aa".repeat(16));
            assert_eq!(got_fingerprint_hex, "bb".repeat(16));
        }
        other => panic!("expected NotAuthor, got {other:?}"),
    }
}

#[test]
fn vault_error_recipient_already_present_display_pins_string() {
    let e = FfiVaultError::RecipientAlreadyPresent;
    assert_eq!(
        e.to_string(),
        "recipient is already present in the block's recipient set",
    );
}

#[test]
fn vault_error_recipient_already_present_from_core_preserves_variant() {
    let ffi: FfiVaultError = VaultError::RecipientAlreadyPresent.into();
    assert!(matches!(ffi, FfiVaultError::RecipientAlreadyPresent));
}

#[test]
fn vault_error_recipient_not_present_from_core_preserves_variant() {
    let ffi: FfiVaultError = VaultError::RecipientNotPresent.into();
    assert!(matches!(ffi, FfiVaultError::RecipientNotPresent));
}

#[test]
fn vault_error_cannot_revoke_owner_from_core_preserves_variant() {
    let ffi: FfiVaultError = VaultError::CannotRevokeOwner.into();
    assert!(matches!(ffi, FfiVaultError::CannotRevokeOwner));
}

#[test]
fn vault_error_missing_recipient_card_display_pins_hex() {
    let e = FfiVaultError::MissingRecipientCard {
        recipient_fingerprint_hex: "cc".repeat(16),
    };
    let rendered = e.to_string();
    assert!(
        rendered.contains("missing contact card for recipient"),
        "Display did not contain the MissingRecipientCard text: {rendered}",
    );
    assert!(
        rendered.contains(&"cc".repeat(16)),
        "Display did not include recipient_fingerprint_hex: {rendered}",
    );
}

#[test]
fn vault_error_missing_recipient_card_from_core_preserves_fingerprint_as_hex() {
    let ffi: FfiVaultError = VaultError::MissingRecipientCard {
        fingerprint: [0xcc; 16],
    }
    .into();
    match ffi {
        FfiVaultError::MissingRecipientCard {
            recipient_fingerprint_hex,
        } => assert_eq!(recipient_fingerprint_hex, "cc".repeat(16)),
        other => panic!("expected MissingRecipientCard, got {other:?}"),
    }
}

#[test]
fn vault_error_card_decode_failure_display_pins_string() {
    // CardDecodeFailure is bridge-internal; never reachable through
    // From<core::VaultError>. Pin Display + field accessibility only.
    let e = FfiVaultError::CardDecodeFailure {
        detail: "malformed CBOR".into(),
    };
    assert_eq!(
        e.to_string(),
        "failed to decode contact card: malformed CBOR"
    );
}

#[test]
fn from_core_block_uuid_already_live_routes_to_block_uuid_already_live() {
    let core_err = VaultError::BlockUuidAlreadyLive {
        block_uuid: [0xaa; 16],
    };
    let ffi: FfiVaultError = core_err.into();
    let FfiVaultError::BlockUuidAlreadyLive { detail } = ffi else {
        panic!("expected BlockUuidAlreadyLive");
    };
    assert!(detail.contains("aa"));
}

#[test]
fn from_core_block_not_in_trash_routes_to_block_not_in_trash() {
    let core_err = VaultError::BlockNotInTrash {
        block_uuid: [0xbb; 16],
    };
    let ffi: FfiVaultError = core_err.into();
    let FfiVaultError::BlockNotInTrash { detail } = ffi else {
        panic!("expected BlockNotInTrash");
    };
    assert!(detail.contains("bb"));
}

#[test]
fn from_core_restore_verification_failed_folds_to_corrupt_vault() {
    let core_err = VaultError::RestoreVerificationFailed {
        block_uuid: [0xcc; 16],
        detail: "sig mismatch".into(),
    };
    let ffi: FfiVaultError = core_err.into();
    let FfiVaultError::CorruptVault { detail } = ffi else {
        panic!("expected CorruptVault");
    };
    assert!(detail.contains("sig mismatch"));
    assert!(detail.contains("verification"));
}

#[test]
fn block_uuid_already_live_display_format() {
    let e = FfiVaultError::BlockUuidAlreadyLive {
        detail: "[1, 2, 3]".into(),
    };
    assert_eq!(
        e.to_string(),
        "block is currently live and trashed: [1, 2, 3]"
    );
}

#[test]
fn block_not_in_trash_display_format() {
    let e = FfiVaultError::BlockNotInTrash {
        detail: "[4, 5, 6]".into(),
    };
    assert_eq!(e.to_string(), "block is not in trash: [4, 5, 6]");
}
