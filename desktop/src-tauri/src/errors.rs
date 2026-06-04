//! `AppError` + `AppWarning` types crossing the Tauri IPC boundary.
//!
//! See spec §9 for the full mapping rules. Key disciplines:
//!
//! - Every variant `#[serde(tag = "code", rename_all = "snake_case")]` so
//!   the wire format is `{ "code": "wrong_password", ... }`.
//! - Developer-facing `detail` fields are `#[serde(skip_serializing)]` — they're
//!   logged via `tracing` on the Rust side but NEVER cross the IPC seam.
//! - The mapping from `FfiVaultError` is split into a pure [`map_ffi_error`]
//!   function (no side effects, exhaustive match) and an `impl From` that
//!   logs at `warn` before delegating. The side effect is visible at the
//!   call site rather than buried inside the `From` body.
//! - `WrongPassword` collapse rule: anything decryption-failure-shaped becomes
//!   `WrongPassword` (info-leak prevention per `docs/threat-model.md` §13).
//!
//! # Variant coverage versus FfiVaultError
//!
//! The `map_ffi_error` match is exhaustive (no `_` catch-all) so every new
//! bridge variant forces a deliberate UI-mapping choice rather than silently
//! folding to `Internal`. Most bridge variants now route to a typed
//! `AppError` — including the D.1.5 trash/restore preconditions and the
//! D.1.6 block-share + contacts variants (`NotAuthor`,
//! `RecipientAlreadyPresent`, `RecipientNotPresent`, `CannotRevokeOwner`,
//! `MissingRecipientCard`,
//! `ContactAlreadyExists`, `ContactNotFound`). A residual few that should never fire on a reachable
//! UI path (e.g. a stale block UUID into `read_block`) fold to
//! `Internal { detail }` so a regression surfaces as a clear "this is a bug"
//! rather than a silent miscategorisation.
//!
//! Note: the bridge already collapses `WeakKdfParams` into `CorruptVault`
//! (post-unlock detail string). `AppError::KdfTooWeak` therefore has no
//! producer in this `From` impl — it survives as a typed variant for the
//! future where the bridge exposes the parameter pair structurally, and
//! its serialization shape is pinned by `kdf_too_weak_carries_payload`.

use secretary_ffi_bridge::error::FfiVaultError;

// `AppError` variants `VaultPathNotFound` / `VaultPathNotAVault` /
// `VaultPathLocked` / `AlreadyUnlocked` / `NotUnlocked` are constructed by
// the Task 4 command handlers (which have access to the user-picked path
// and the session-state mutex) rather than by the `From<FfiVaultError>`
// impl. They appear in the wire-format schema from day one so the
// frontend's TS discriminated union (Task 6) mirrors the full surface,
// but the Rust producers land in Task 4.
//
// `AppWarning::SettingsCorrupt` is constructed by the Task 3 vault-load
// path when the settings record decodes but its field shapes don't match
// the schema (vs `SettingsClamped` which fires on out-of-range numeric
// values, already produced by `settings::parse_settings_field`).
#[allow(dead_code)]
#[derive(thiserror::Error, Debug, serde::Serialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum AppError {
    #[error("Vault folder does not exist or is not readable")]
    VaultPathNotFound { path: String },

    #[error("Folder exists but doesn't contain a vault")]
    VaultPathNotAVault { path: String },

    #[error("Vault is currently locked by another process")]
    VaultPathLocked { path: String },

    #[error("Wrong password")]
    WrongPassword,

    #[error("Vault uses KDF parameters below the minimum")]
    KdfTooWeak {
        current_memory_kib: u32,
        min_memory_kib: u32,
    },

    #[error("Vault is corrupted; consider restoring from a backup")]
    VaultCorrupt {
        #[serde(skip_serializing)]
        detail: String,
    },

    #[error("Vault already unlocked")]
    AlreadyUnlocked,

    #[error("No vault currently unlocked")]
    NotUnlocked,

    #[error("Block not found — it may have been removed")]
    BlockNotFound { block_uuid_hex: String },

    #[error("Record not found")]
    RecordNotFound { record_uuid_hex: String },

    #[error("Field value is invalid")]
    InvalidFieldValue { field_name: String },

    #[error("Could not save the record")]
    RecordSaveFailed {
        #[serde(skip_serializing)]
        detail: String,
    },

    #[error("Cannot restore: a block with this id is already live")]
    BlockRestoreConflict { block_uuid_hex: String },

    #[error("That trashed block is no longer available")]
    TrashEntryNotFound { block_uuid_hex: String },

    #[error("Only the block's author can share it")]
    NotAuthor,

    #[error("This block is already shared with that contact")]
    RecipientAlreadyPresent,

    #[error("That contact is not currently a recipient of this block")]
    RecipientNotPresent,

    #[error("You cannot remove yourself as the owner of this block")]
    CannotRevokeOwner,

    #[error("A recipient's contact card is missing")]
    MissingRecipientCard,

    #[error("That contact is already in your vault")]
    ContactAlreadyExists { contact_uuid_hex: String },

    #[error("That contact is not in your vault")]
    ContactNotFound { contact_uuid_hex: String },

    #[error("Your own contact card can't be deleted")]
    CannotDeleteOwnerContact,

    #[error("Field not found")]
    FieldNotFound { field_name: String },

    #[error("Vault folder is not empty")]
    VaultFolderNotEmpty { path: String },

    #[error("Could not create the vault")]
    VaultCreateFailed {
        #[serde(skip_serializing)]
        detail: String,
    },

    #[error("Settings record is malformed; using defaults")]
    SettingsCorrupt {
        #[serde(skip_serializing)]
        detail: String,
    },

    #[error("Settings record uses an unknown schema version")]
    SettingsUnknownVersion { version: String },

    #[error("Auto-lock timeout must be between {min} and {max} ms")]
    SettingsOutOfRange { min: u64, max: u64 },

    #[error("Filesystem error")]
    Io {
        #[serde(skip_serializing)]
        detail: String,
    },

    #[error("Internal error — this is a bug")]
    Internal {
        #[serde(skip_serializing)]
        detail: String,
    },
}

// All three variants are part of the IPC wire-format schema; renaming to
// drop the `Settings` prefix would change the on-wire `code` discriminator
// strings (e.g. `"settings_clamped"` → `"clamped"`) which would be a
// frontend-visible contract break. The shared prefix is intentional —
// these are the settings-domain warnings, and future non-settings
// warnings would NOT share the prefix.
// `Clone` is derived so `VaultSession::pending_warnings()` can hand owned
// copies to IPC commands without coupling the caller's borrow lifetime to
// the session mutex — every variant is a small fixed-size payload, so
// the clone is cheap.
#[allow(clippy::enum_variant_names)]
#[allow(dead_code)]
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum AppWarning {
    SettingsCorrupt {
        #[serde(skip_serializing)]
        detail: String,
    },
    SettingsClamped {
        original_ms: u64,
        clamped_ms: u64,
    },
    SettingsUnknownVersion {
        version: String,
    },
}

/// Pure mapping from `FfiVaultError` to `AppError`. No side effects — the
/// `tracing::warn!` that records the developer-facing detail before it's
/// stripped at the IPC seam lives in `impl From<FfiVaultError> for AppError`
/// so the side effect is visible at the call site.
///
/// Exposed as a function (not just an `impl From` body) so callers that
/// want the mapping without the log line — e.g. unit tests checking variant
/// routing, or future call sites that have already logged the source error
/// at a different level — can use it directly.
///
/// Adding a new `FfiVaultError` variant in the bridge crate will surface
/// here as a compile error (the match must be exhaustive), forcing a
/// deliberate UI-mapping choice.
///
/// The bridge's `WrongPasswordOrCorrupt` / `WrongMnemonicOrCorrupt`
/// variants are deliberately conflated per `docs/threat-model.md` §13's
/// anti-oracle property; both fold to `WrongPassword` here (the user's
/// affordance is "retry credential" in both cases). Block-share
/// authorisation + contacts variants (`NotAuthor`,
/// `RecipientAlreadyPresent`, `RecipientNotPresent`, `CannotRevokeOwner`,
/// `MissingRecipientCard`,
/// `ContactAlreadyExists`, `ContactNotFound`) and the trash/restore
/// preconditions route to typed `AppError`s. The few variants that
/// should never reach a live UI path (e.g. recovery-phrase
/// pre-validation, an unknown block UUID into `read_block`) fold to
/// `Internal { detail }` so a regression that lets them fire surfaces
/// as a clear bug-report path.
///
/// `FolderInvalid` folds to `Io { detail }` here because the bridge
/// surfaces the underlying IO context but not the caller's chosen path.
/// Task 4's command handlers, which DO know the user-picked path, will
/// construct `VaultPathNotFound` / `VaultPathNotAVault` directly at the
/// boundary so the UI can render the path-specific affordance.
pub fn map_ffi_error(e: FfiVaultError) -> AppError {
    match e {
        // Decryption-failure-shaped → WrongPassword (info-leak prevention).
        // Both bridge variants conflate "wrong credential" and "corruption"
        // per the anti-oracle property; we preserve the conflation at the
        // UI boundary too.
        FfiVaultError::WrongPasswordOrCorrupt | FfiVaultError::WrongMnemonicOrCorrupt => {
            AppError::WrongPassword
        }

        // Genuine cryptographic / integrity failures → VaultCorrupt.
        FfiVaultError::CorruptVault { detail }
        | FfiVaultError::SaveCryptoFailure { detail }
        | FfiVaultError::CardDecodeFailure { detail } => AppError::VaultCorrupt { detail },

        // vault.toml ↔ identity.bundle.enc mismatch is a corruption-class
        // failure from the user's perspective: the on-disk state is
        // inconsistent and they need to re-pair from backups. We synthesise
        // a detail string (this variant carries no payload).
        FfiVaultError::VaultMismatch => AppError::VaultCorrupt {
            detail: "vault.toml and identity.bundle.enc reference different vaults".to_string(),
        },

        // Pre-decryption mnemonic validation failure. Unreachable from
        // D.1.1's password-only unlock path; if it ever fires here, it's
        // a bug — surface as Internal with detail for the bug report.
        FfiVaultError::InvalidMnemonic { detail } => AppError::Internal {
            detail: format!("invalid mnemonic on password-only unlock path: {detail}"),
        },

        // Pre-unlock filesystem failure. Task 4's command handlers replace
        // this with the path-aware VaultPathNotFound / VaultPathNotAVault
        // construction at the boundary; here we fold to the generic Io
        // bucket so any pre-Task-4 code path surfaces something coherent.
        FfiVaultError::FolderInvalid { detail } => AppError::Io { detail },

        // Block-lookup miss. Reachable in D.1.1 if a caller passes a
        // stale block UUID to read_block (e.g. between a settings-block
        // creation and the subsequent manifest refresh). Surface as
        // Internal — D.1.1's settings flow never asks for an unknown
        // UUID, so this firing means a bug.
        FfiVaultError::BlockNotFound { uuid_hex } => AppError::Internal {
            detail: format!("block not found in manifest: {uuid_hex}"),
        },

        // Record-lookup miss from the D.1.4 `edit_record` primitive: the
        // user (or a stale frontend) asked to edit a record that is absent
        // or tombstoned. Surface the dedicated typed variant so the editor
        // can react (e.g. the record was deleted under it). The uuid hex is
        // non-secret (a caller-minted UUID) and crosses the seam.
        FfiVaultError::RecordNotFound { uuid_hex } => AppError::RecordNotFound {
            record_uuid_hex: uuid_hex,
        },

        // Restore precondition: the UUID has both a live and a trashed entry.
        // Typed variant so the UI can tell the user to trash the live copy first.
        //
        // Contract: the bridge constructs both restore-precondition variants
        // with `detail = hex::encode(block_uuid)` (see
        // `trash::orchestration` restore-error mapping), so moving `detail`
        // into `block_uuid_hex` is exact — NOT a prose message mislabeled as a
        // UUID. If that bridge mapping ever changes, this relabel breaks.
        FfiVaultError::BlockUuidAlreadyLive { detail } => AppError::BlockRestoreConflict {
            block_uuid_hex: detail,
        },

        // Restore precondition: no TrashEntry or file exists for this UUID.
        // Typed variant so the UI can distinguish "already restored" from
        // corruption. Same bridge contract as above: `detail` is the bare hex.
        FfiVaultError::BlockNotInTrash { detail } => AppError::TrashEntryNotFound {
            block_uuid_hex: detail,
        },

        // Block-share authorization failures and recipient table mismatches,
        // plus contact-table preconditions: now typed (D.1.6 share UI). The
        // recipient fingerprints in `NotAuthor` are dropped at the seam — the
        // user's affordance ("you aren't the author") needs no payload; the
        // contact UUID hex (caller-minted, non-secret) crosses for the others.
        FfiVaultError::NotAuthor { .. } => AppError::NotAuthor,
        FfiVaultError::RecipientAlreadyPresent => AppError::RecipientAlreadyPresent,
        FfiVaultError::RecipientNotPresent => AppError::RecipientNotPresent,
        FfiVaultError::CannotRevokeOwner => AppError::CannotRevokeOwner,
        FfiVaultError::MissingRecipientCard { .. } => AppError::MissingRecipientCard,
        FfiVaultError::ContactAlreadyExists { uuid_hex } => AppError::ContactAlreadyExists {
            contact_uuid_hex: uuid_hex,
        },
        FfiVaultError::ContactNotFound { uuid_hex } => AppError::ContactNotFound {
            contact_uuid_hex: uuid_hex,
        },
        FfiVaultError::CannotDeleteOwnerContact => AppError::CannotDeleteOwnerContact,
    }
}

impl From<FfiVaultError> for AppError {
    /// Logs the source error at `warn` level (developer-facing detail goes
    /// to stderr / log sink before being stripped at the IPC seam), then
    /// delegates to the pure mapping in [`map_ffi_error`].
    fn from(e: FfiVaultError) -> Self {
        tracing::warn!(?e, "FfiVaultError surfacing to AppError");
        map_ffi_error(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let v: Value =
            serde_json::from_str(&serde_json::to_string(&w).expect("ser")).expect("parse");
        assert_eq!(v["code"], "settings_clamped");
        assert_eq!(v["original_ms"], 30_000);
        assert_eq!(v["clamped_ms"], 60_000);
    }

    #[test]
    fn unknown_version_warning_carries_version_string() {
        let w = AppWarning::SettingsUnknownVersion {
            version: "secretary.settings.v99".to_string(),
        };
        let v: Value =
            serde_json::from_str(&serde_json::to_string(&w).expect("ser")).expect("parse");
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
}
