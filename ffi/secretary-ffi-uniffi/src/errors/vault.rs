//! uniffi-side `VaultError` mirroring `FfiVaultError` + the uniffi-only
//! `InvalidArgument` variant for wrong-shape FFI inputs.

use secretary_ffi_bridge::FfiVaultError;

/// uniffi projection of FfiVaultError + one extra variant for FFI input-
/// shape errors (`InvalidArgument`). Flat variants matching the UDL
/// declaration.
///
/// The structured-field rename rationale is the same as UnlockError's:
/// uniffi 0.31's Kotlin codegen has overload-resolution conflicts between
/// `Throwable.message` and a UDL-declared `message` field, so structured
/// fields are named `detail`.
///
/// The `InvalidArgument` variant has no counterpart in the bridge's
/// `FfiVaultError` — it's uniffi-side only because uniffi 0.31 has no
/// native `ValueError` equivalent at the namespace-fn level, so wrong-
/// length / malformed FFI inputs (e.g. `block_uuid` ≠ 16 bytes) need to
/// ride inside `VaultError`. PyO3 raises Python `ValueError` for the
/// equivalent case (see `secretary-ffi-py/src/lib.rs::read_block`); the
/// dedicated uniffi variant keeps the semantic clean rather than abusing
/// `FolderInvalid` (which means "your filesystem path is wrong").
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("wrong password or vault corruption")]
    WrongPasswordOrCorrupt,
    #[error("wrong recovery phrase or vault corruption")]
    WrongMnemonicOrCorrupt,
    #[error("invalid recovery phrase: {detail}")]
    InvalidMnemonic { detail: String },
    #[error("vault.toml and identity.bundle.enc reference different vaults")]
    VaultMismatch,
    #[error("vault data integrity failure: {detail}")]
    CorruptVault { detail: String },
    #[error("vault folder is not accessible: {detail}")]
    FolderInvalid { detail: String },
    #[error("block not found in manifest: {uuid_hex}")]
    BlockNotFound { uuid_hex: String },
    /// Record UUID not found among the block's live records. Mirrors
    /// `FfiVaultError::RecordNotFound` (D.1.4 `edit_record`).
    #[error("record not found in block: {uuid_hex}")]
    RecordNotFound { uuid_hex: String },
    #[error("invalid argument: {detail}")]
    InvalidArgument { detail: String },
    #[error("save-time crypto failure: {detail}")]
    SaveCryptoFailure { detail: String },
    /// Block-share authorization failure: only the block author can share.
    /// Mirrors `FfiVaultError::NotAuthor`.
    #[error("only the block author can share this block")]
    NotAuthor {
        expected_fingerprint_hex: String,
        got_fingerprint_hex: String,
    },
    /// Block-share dedup: caller's `new_recipient` is already in the
    /// block's recipient table. Mirrors `FfiVaultError::RecipientAlreadyPresent`.
    #[error("recipient is already present in the block's recipient set")]
    RecipientAlreadyPresent,
    /// Revoke target is not a current recipient of the block. Mirrors
    /// `FfiVaultError::RecipientNotPresent`.
    #[error("recipient is not present on the block")]
    RecipientNotPresent,
    /// Revoke target is the block owner, who is always a recipient and
    /// must remain one. Mirrors `FfiVaultError::CannotRevokeOwner`.
    #[error("cannot revoke the block owner")]
    CannotRevokeOwner,
    /// Caller's `existing_recipient_cards` is missing a card whose
    /// fingerprint appears on disk. Mirrors `FfiVaultError::MissingRecipientCard`.
    #[error("missing contact card for recipient: {recipient_fingerprint_hex}")]
    MissingRecipientCard { recipient_fingerprint_hex: String },
    /// Caller-supplied ContactCard bytes are not valid canonical CBOR.
    /// Mirrors `FfiVaultError::CardDecodeFailure`.
    #[error("failed to decode contact card: {detail}")]
    CardDecodeFailure { detail: String },
    /// Mirrors `FfiVaultError::BlockUuidAlreadyLive`. Restore was
    /// requested on a UUID that exists both in trash and live in
    /// `manifest.blocks`.
    #[error("block is currently live and trashed: {detail}")]
    BlockUuidAlreadyLive { detail: String },
    /// Mirrors `FfiVaultError::BlockNotInTrash`. Restore was requested
    /// on a UUID with no `TrashEntry` and no matching trash file.
    #[error("block is not in trash: {detail}")]
    BlockNotInTrash { detail: String },
    /// A contact card with this `contact_uuid` is already present in the
    /// vault's `contacts/` directory. Mirrors `FfiVaultError::ContactAlreadyExists`.
    #[error("contact already exists in vault: {uuid_hex}")]
    ContactAlreadyExists { uuid_hex: String },
    /// A contact card referenced by a share operation has no `.card` file
    /// in `contacts/`. Mirrors `FfiVaultError::ContactNotFound`.
    #[error("contact not found in vault: {uuid_hex}")]
    ContactNotFound { uuid_hex: String },
    /// The owner's own contact card cannot be deleted.
    /// Mirrors `FfiVaultError::CannotDeleteOwnerContact`.
    #[error("the vault owner's own contact card cannot be deleted")]
    CannotDeleteOwnerContact,
    /// The on-disk `SyncState` cache is for a different vault than the one being synced.
    /// Mirrors `FfiVaultError::SyncStateVaultMismatch`.
    #[error("sync state file belongs to a different vault")]
    SyncStateVaultMismatch,
    /// The `SyncState` CBOR failed to decode or re-encode; local cache is corrupt, vault untouched.
    /// Mirrors `FfiVaultError::SyncStateCorrupt`.
    #[error("sync state cache is corrupt: {detail}")]
    SyncStateCorrupt { detail: String },
    /// A concurrent writer changed the manifest mid-pass; no write occurred, retry.
    /// Mirrors `FfiVaultError::SyncEvidenceStale`.
    #[error("vault changed on disk during sync; retry")]
    SyncEvidenceStale,
    /// Another process holds the per-vault sync lockfile; no write occurred.
    /// Mirrors `FfiVaultError::SyncInProgress`.
    #[error("another sync is already in progress for this vault")]
    SyncInProgress,
    /// Internal or unexpected sync failure; vault unchanged.
    /// Mirrors `FfiVaultError::SyncFailed`.
    #[error("sync failed: {detail}")]
    SyncFailed { detail: String },
    /// `commit_with_decisions` could not match the supplied decisions to the
    /// recomputed veto set. Mirrors `FfiVaultError::SyncDecisionsIncomplete`.
    #[error("sync decisions did not cover the pending conflicts")]
    SyncDecisionsIncomplete,
}

impl From<FfiVaultError> for VaultError {
    fn from(e: FfiVaultError) -> Self {
        match e {
            FfiVaultError::WrongPasswordOrCorrupt => VaultError::WrongPasswordOrCorrupt,
            FfiVaultError::WrongMnemonicOrCorrupt => VaultError::WrongMnemonicOrCorrupt,
            FfiVaultError::InvalidMnemonic { detail } => VaultError::InvalidMnemonic { detail },
            FfiVaultError::VaultMismatch => VaultError::VaultMismatch,
            FfiVaultError::CorruptVault { detail } => VaultError::CorruptVault { detail },
            FfiVaultError::FolderInvalid { detail } => VaultError::FolderInvalid { detail },
            FfiVaultError::BlockNotFound { uuid_hex } => VaultError::BlockNotFound { uuid_hex },
            FfiVaultError::RecordNotFound { uuid_hex } => VaultError::RecordNotFound { uuid_hex },
            FfiVaultError::SaveCryptoFailure { detail } => VaultError::SaveCryptoFailure { detail },
            FfiVaultError::NotAuthor {
                expected_fingerprint_hex,
                got_fingerprint_hex,
            } => VaultError::NotAuthor {
                expected_fingerprint_hex,
                got_fingerprint_hex,
            },
            FfiVaultError::RecipientAlreadyPresent => VaultError::RecipientAlreadyPresent,
            FfiVaultError::RecipientNotPresent => VaultError::RecipientNotPresent,
            FfiVaultError::CannotRevokeOwner => VaultError::CannotRevokeOwner,
            FfiVaultError::MissingRecipientCard {
                recipient_fingerprint_hex,
            } => VaultError::MissingRecipientCard {
                recipient_fingerprint_hex,
            },
            FfiVaultError::CardDecodeFailure { detail } => VaultError::CardDecodeFailure { detail },
            FfiVaultError::BlockUuidAlreadyLive { detail } => {
                VaultError::BlockUuidAlreadyLive { detail }
            }
            FfiVaultError::BlockNotInTrash { detail } => VaultError::BlockNotInTrash { detail },
            FfiVaultError::ContactAlreadyExists { uuid_hex } => {
                VaultError::ContactAlreadyExists { uuid_hex }
            }
            FfiVaultError::ContactNotFound { uuid_hex } => VaultError::ContactNotFound { uuid_hex },
            FfiVaultError::CannotDeleteOwnerContact => VaultError::CannotDeleteOwnerContact,
            FfiVaultError::SyncStateVaultMismatch => VaultError::SyncStateVaultMismatch,
            FfiVaultError::SyncStateCorrupt { detail } => VaultError::SyncStateCorrupt { detail },
            FfiVaultError::SyncEvidenceStale => VaultError::SyncEvidenceStale,
            FfiVaultError::SyncInProgress => VaultError::SyncInProgress,
            FfiVaultError::SyncFailed { detail } => VaultError::SyncFailed { detail },
            FfiVaultError::SyncDecisionsIncomplete => VaultError::SyncDecisionsIncomplete,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------
    // B.4a: pin the From<FfiVaultError> for VaultError mapping.
    // -------------------------------------------------------------------

    #[test]
    fn vault_error_maps_each_variant_one_to_one() {
        use FfiVaultError as B;
        assert!(matches!(
            VaultError::from(B::WrongPasswordOrCorrupt),
            VaultError::WrongPasswordOrCorrupt
        ));
        assert!(matches!(
            VaultError::from(B::WrongMnemonicOrCorrupt),
            VaultError::WrongMnemonicOrCorrupt
        ));
        let inv = VaultError::from(B::InvalidMnemonic {
            detail: "x".to_string(),
        });
        let VaultError::InvalidMnemonic { detail } = inv else {
            panic!("expected InvalidMnemonic")
        };
        assert_eq!(detail, "x");
        assert!(matches!(
            VaultError::from(B::VaultMismatch),
            VaultError::VaultMismatch
        ));
        let cor = VaultError::from(B::CorruptVault {
            detail: "y".to_string(),
        });
        let VaultError::CorruptVault { detail } = cor else {
            panic!("expected CorruptVault")
        };
        assert_eq!(detail, "y");
        let fol = VaultError::from(B::FolderInvalid {
            detail: "z".to_string(),
        });
        let VaultError::FolderInvalid { detail } = fol else {
            panic!("expected FolderInvalid")
        };
        assert_eq!(detail, "z");
    }

    // -------------------------------------------------------------------
    // B.4b: pin the BlockNotFound variant translation + the wrong-length
    // block_uuid → InvalidArgument decision.
    // -------------------------------------------------------------------

    #[test]
    fn vault_error_block_not_found_maps_one_to_one() {
        // Pin the BlockNotFound variant translation. A future rename would
        // fail here first.
        use FfiVaultError as B;
        let bnf = VaultError::from(B::BlockNotFound {
            uuid_hex: "abc123".to_string(),
        });
        let VaultError::BlockNotFound { uuid_hex } = bnf else {
            panic!("expected BlockNotFound");
        };
        assert_eq!(uuid_hex, "abc123");
    }

    #[test]
    fn vault_error_record_not_found_maps_one_to_one() {
        // Pin the D.1.4 RecordNotFound variant translation. A future
        // rename or accidental remap to BlockNotFound would fail here.
        use FfiVaultError as B;
        let rnf = VaultError::from(B::RecordNotFound {
            uuid_hex: "def456".to_string(),
        });
        let VaultError::RecordNotFound { uuid_hex } = rnf else {
            panic!("expected RecordNotFound");
        };
        assert_eq!(uuid_hex, "def456");
    }

    #[test]
    fn invalid_argument_display_pins_detail_text() {
        // Pin the Display contract for the uniffi-only variant. uniffi
        // 0.31 codegen uses the #[error(...)] attribute to drive the
        // Swift / Kotlin generated message text; a future rename of the
        // attribute would silently change the foreign-side exception
        // message and must be a deliberate decision.
        let err = VaultError::InvalidArgument {
            detail: "fnord".to_string(),
        };
        let rendered = format!("{err}");
        assert!(
            rendered.contains("invalid argument"),
            "Display did not contain the InvalidArgument prefix: {rendered}",
        );
        assert!(rendered.contains("fnord"), "Display did not include detail");
    }

    // -------------------------------------------------------------------
    // B.4c: pin the SaveCryptoFailure variant translation.
    // -------------------------------------------------------------------

    #[test]
    fn vault_error_save_crypto_failure_maps_one_to_one() {
        // Pin the SaveCryptoFailure variant translation. A future rename
        // or accidental remap to CorruptVault / FolderInvalid would fail
        // here first.
        let bridge_err = FfiVaultError::SaveCryptoFailure {
            detail: "test detail".to_string(),
        };
        let uniffi_err = VaultError::from(bridge_err);
        let VaultError::SaveCryptoFailure { detail } = uniffi_err else {
            panic!("expected SaveCryptoFailure");
        };
        assert_eq!(detail, "test detail");
    }

    #[test]
    fn save_crypto_failure_display_pins_detail_text() {
        // Pin the Display contract — same rationale as
        // invalid_argument_display_pins_detail_text. uniffi 0.31 codegen
        // emits the #[error(...)] string into Swift / Kotlin error
        // messages, so a wording change must be a deliberate decision.
        let err = VaultError::SaveCryptoFailure {
            detail: "fnord".to_string(),
        };
        let rendered = format!("{err}");
        assert!(
            rendered.contains("save-time crypto failure"),
            "Display did not contain the SaveCryptoFailure prefix: {rendered}",
        );
        assert!(rendered.contains("fnord"), "Display did not include detail");
    }

    // -------------------------------------------------------------------
    // B.4d: pin the 4 share_block variants — Display + From mapping.
    // Same pattern as B.4c's SaveCryptoFailure pair.
    // -------------------------------------------------------------------

    #[test]
    fn vault_error_not_author_maps_one_to_one() {
        let bridge_err = FfiVaultError::NotAuthor {
            expected_fingerprint_hex: "aa".repeat(16),
            got_fingerprint_hex: "bb".repeat(16),
        };
        match VaultError::from(bridge_err) {
            VaultError::NotAuthor {
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
    fn not_author_display_pins_text() {
        let err = VaultError::NotAuthor {
            expected_fingerprint_hex: "aa".repeat(16),
            got_fingerprint_hex: "bb".repeat(16),
        };
        let rendered = format!("{err}");
        assert!(
            rendered.contains("only the block author can share this block"),
            "Display did not contain the NotAuthor text: {rendered}",
        );
    }

    #[test]
    fn vault_error_recipient_already_present_maps_one_to_one() {
        let bridge_err = FfiVaultError::RecipientAlreadyPresent;
        assert!(matches!(
            VaultError::from(bridge_err),
            VaultError::RecipientAlreadyPresent
        ));
    }

    #[test]
    fn recipient_already_present_display_pins_text() {
        let err = VaultError::RecipientAlreadyPresent;
        let rendered = format!("{err}");
        assert!(
            rendered.contains("recipient is already present in the block's recipient set"),
            "Display did not contain the RecipientAlreadyPresent text: {rendered}",
        );
    }

    #[test]
    fn vault_error_missing_recipient_card_maps_one_to_one() {
        let bridge_err = FfiVaultError::MissingRecipientCard {
            recipient_fingerprint_hex: "cc".repeat(16),
        };
        match VaultError::from(bridge_err) {
            VaultError::MissingRecipientCard {
                recipient_fingerprint_hex,
            } => assert_eq!(recipient_fingerprint_hex, "cc".repeat(16)),
            other => panic!("expected MissingRecipientCard, got {other:?}"),
        }
    }

    #[test]
    fn missing_recipient_card_display_pins_hex() {
        let err = VaultError::MissingRecipientCard {
            recipient_fingerprint_hex: "cc".repeat(16),
        };
        let rendered = format!("{err}");
        assert!(
            rendered.contains("missing contact card for recipient"),
            "Display did not contain the MissingRecipientCard prefix: {rendered}",
        );
        assert!(
            rendered.contains(&"cc".repeat(16)),
            "Display did not include recipient_fingerprint_hex: {rendered}",
        );
    }

    #[test]
    fn vault_error_card_decode_failure_maps_one_to_one() {
        let bridge_err = FfiVaultError::CardDecodeFailure {
            detail: "bad CBOR".into(),
        };
        match VaultError::from(bridge_err) {
            VaultError::CardDecodeFailure { detail } => assert_eq!(detail, "bad CBOR"),
            other => panic!("expected CardDecodeFailure, got {other:?}"),
        }
    }

    #[test]
    fn card_decode_failure_display_pins_detail() {
        let err = VaultError::CardDecodeFailure {
            detail: "bad CBOR".into(),
        };
        let rendered = format!("{err}");
        assert!(
            rendered.contains("failed to decode contact card"),
            "Display did not contain the CardDecodeFailure prefix: {rendered}",
        );
        assert!(
            rendered.contains("bad CBOR"),
            "Display did not include detail"
        );
    }

    // -------------------------------------------------------------------
    // B.5: pin the 2 trash/restore variants — Display + From mapping.
    // -------------------------------------------------------------------

    #[test]
    fn ffi_to_uniffi_block_uuid_already_live() {
        let ffi = FfiVaultError::BlockUuidAlreadyLive {
            detail: "[1,2,3]".into(),
        };
        let uniffi: VaultError = ffi.into();
        let VaultError::BlockUuidAlreadyLive { detail } = uniffi else {
            panic!("expected BlockUuidAlreadyLive");
        };
        assert_eq!(detail, "[1,2,3]");
    }

    #[test]
    fn ffi_to_uniffi_block_not_in_trash() {
        let ffi = FfiVaultError::BlockNotInTrash {
            detail: "[4,5,6]".into(),
        };
        let uniffi: VaultError = ffi.into();
        let VaultError::BlockNotInTrash { detail } = uniffi else {
            panic!("expected BlockNotInTrash");
        };
        assert_eq!(detail, "[4,5,6]");
    }

    #[test]
    fn uniffi_block_uuid_already_live_display() {
        let e = VaultError::BlockUuidAlreadyLive {
            detail: "abc".into(),
        };
        assert_eq!(e.to_string(), "block is currently live and trashed: abc");
    }

    #[test]
    fn uniffi_block_not_in_trash_display() {
        let e = VaultError::BlockNotInTrash {
            detail: "xyz".into(),
        };
        assert_eq!(e.to_string(), "block is not in trash: xyz");
    }

    // -------------------------------------------------------------------
    // D.1.6: pin the 2 contacts share variants — Display + From mapping.
    // -------------------------------------------------------------------

    #[test]
    fn ffi_to_uniffi_contact_already_exists() {
        let ffi = FfiVaultError::ContactAlreadyExists {
            uuid_hex: "aa".repeat(16),
        };
        let uniffi: VaultError = ffi.into();
        let VaultError::ContactAlreadyExists { uuid_hex } = uniffi else {
            panic!("expected ContactAlreadyExists");
        };
        assert_eq!(uuid_hex, "aa".repeat(16));
    }

    #[test]
    fn ffi_to_uniffi_contact_not_found() {
        let ffi = FfiVaultError::ContactNotFound {
            uuid_hex: "bb".repeat(16),
        };
        let uniffi: VaultError = ffi.into();
        let VaultError::ContactNotFound { uuid_hex } = uniffi else {
            panic!("expected ContactNotFound");
        };
        assert_eq!(uuid_hex, "bb".repeat(16));
    }

    #[test]
    fn uniffi_contact_already_exists_display() {
        let e = VaultError::ContactAlreadyExists {
            uuid_hex: "abc".into(),
        };
        assert_eq!(e.to_string(), "contact already exists in vault: abc");
    }

    #[test]
    fn uniffi_contact_not_found_display() {
        let e = VaultError::ContactNotFound {
            uuid_hex: "xyz".into(),
        };
        assert_eq!(e.to_string(), "contact not found in vault: xyz");
    }

    #[test]
    fn cannot_delete_owner_contact_maps_across() {
        let ffi = FfiVaultError::CannotDeleteOwnerContact;
        let uniffi: VaultError = ffi.into();
        assert!(matches!(uniffi, VaultError::CannotDeleteOwnerContact));
    }
}
