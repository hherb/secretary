//! uniffi-side error types and bridge-to-uniffi error translations.
//!
//! Both `UnlockError` and `VaultError` mirror the bridge crate's
//! `FfiUnlockError` / `FfiVaultError` shape. uniffi auto-marshals these to
//! Swift `enum ...: Error` and Kotlin `sealed class ...`. The structured
//! field is named `detail` rather than `message` because uniffi 0.31's
//! Kotlin codegen produces an "overload resolution ambiguity" between
//! `Throwable.message` and a user-defined `message` field.
//!
//! `VaultError` carries one extra variant (`InvalidArgument`) that has no
//! counterpart in the bridge's `FfiVaultError` — it's uniffi-side only
//! because uniffi 0.31 has no native `ValueError` equivalent at the
//! namespace-fn level, so wrong-length / malformed FFI inputs need to ride
//! inside `VaultError`. Pythoning out wrong-length inputs as `ValueError`
//! is the parallel pattern in `secretary-ffi-py`.

use secretary_ffi_bridge::{FfiUnlockError, FfiVaultError};

// =============================================================================
// UnlockError (mirrors FfiUnlockError 5-variant shape)
// =============================================================================

/// uniffi-side error type. uniffi auto-marshals this to Swift `enum
/// UnlockError: Error` and Kotlin `sealed class UnlockError`. Mirrors
/// the bridge crate's `FfiUnlockError` shape exactly.
///
/// The structured field is named `detail` rather than `message` because
/// uniffi 0.31's Kotlin codegen produces an "overload resolution
/// ambiguity" between `Throwable.message` and a user-defined `message`
/// field. `detail` keeps the field structured-accessible on Swift /
/// Kotlin while avoiding the codegen collision. The field name must
/// stay in sync with `secretary.udl`.
#[derive(Debug, thiserror::Error)]
pub enum UnlockError {
    /// Wrong password OR vault corruption — deliberately conflated per
    /// `docs/threat-model.md` §13. Returned by `open_with_password`.
    #[error("wrong password or vault corruption")]
    WrongPasswordOrCorrupt,
    /// Wrong recovery phrase OR vault corruption — parallel to the password
    /// path. Returned by `open_with_recovery`.
    #[error("wrong recovery phrase or vault corruption")]
    WrongMnemonicOrCorrupt,
    /// Invalid recovery phrase — pre-decryption BIP-39 validation failure
    /// (wrong word count, unknown word, bad checksum, or invalid UTF-8).
    /// NOT a security oracle.
    #[error("invalid recovery phrase: {detail}")]
    InvalidMnemonic {
        /// Diagnostic text; free-form.
        detail: String,
    },
    /// `vault.toml` and `identity.bundle.enc` reference different vaults.
    #[error("vault.toml and identity.bundle.enc reference different vaults")]
    VaultMismatch,
    /// Vault data integrity failure — covers BOTH directions: open-path
    /// failure (vault file is malformed / unreadable) AND create-path
    /// failure (couldn't even produce the vault bytes; rare, e.g. Argon2id
    /// system-OOM or CBOR serialization failure of the in-memory bundle).
    /// Carries a diagnostic `detail` string for debugging; not
    /// pattern-matchable on the inner cause.
    #[error("vault data integrity failure: {detail}")]
    CorruptVault {
        /// Diagnostic text from the inner `core::UnlockError` variant's
        /// `Display` impl. Free-form; not part of the API contract.
        detail: String,
    },
}

impl From<FfiUnlockError> for UnlockError {
    fn from(e: FfiUnlockError) -> Self {
        match e {
            FfiUnlockError::WrongPasswordOrCorrupt => Self::WrongPasswordOrCorrupt,
            FfiUnlockError::WrongMnemonicOrCorrupt => Self::WrongMnemonicOrCorrupt,
            FfiUnlockError::InvalidMnemonic { detail } => Self::InvalidMnemonic { detail },
            FfiUnlockError::VaultMismatch => Self::VaultMismatch,
            FfiUnlockError::CorruptVault { detail } => Self::CorruptVault { detail },
        }
    }
}

// =============================================================================
// VaultError (mirrors FfiVaultError 8 variants + uniffi-only InvalidArgument)
// =============================================================================

/// uniffi projection of FfiVaultError + one extra variant for FFI input-
/// shape errors (`InvalidArgument`). Nine flat variants matching the UDL
/// declaration.
///
/// The structured-field rename rationale is the same as UnlockError's:
/// uniffi 0.31's Kotlin codegen has overload-resolution conflicts between
/// `Throwable.message` and a UDL-declared `message` field, so structured
/// fields are named `detail`.
///
/// The eighth variant `InvalidArgument` has no counterpart in the bridge's
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
            FfiVaultError::SaveCryptoFailure { detail } => VaultError::SaveCryptoFailure { detail },
            FfiVaultError::NotAuthor {
                expected_fingerprint_hex,
                got_fingerprint_hex,
            } => VaultError::NotAuthor {
                expected_fingerprint_hex,
                got_fingerprint_hex,
            },
            FfiVaultError::RecipientAlreadyPresent => VaultError::RecipientAlreadyPresent,
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------
    // B.2: pin the From<FfiUnlockError> for UnlockError mapping.
    //
    // The bridge crate already tests core → FfiUnlockError; these tests
    // pin the FfiUnlockError → uniffi-side UnlockError translation
    // explicitly so a future variant rename / reorder can't silently
    // remap one variant to another.
    // -------------------------------------------------------------------

    #[test]
    fn from_bridge_wrong_password_or_corrupt_maps_one_to_one() {
        let bridge_err = FfiUnlockError::WrongPasswordOrCorrupt;
        let uniffi_err: UnlockError = bridge_err.into();
        assert!(matches!(uniffi_err, UnlockError::WrongPasswordOrCorrupt));
    }

    #[test]
    fn from_bridge_vault_mismatch_maps_one_to_one() {
        let bridge_err = FfiUnlockError::VaultMismatch;
        let uniffi_err: UnlockError = bridge_err.into();
        assert!(matches!(uniffi_err, UnlockError::VaultMismatch));
    }

    #[test]
    fn from_bridge_corrupt_vault_preserves_detail() {
        // B.3a renamed the bridge's CorruptVault field from `message` to
        // `detail` for naming uniformity with InvalidMnemonic { detail }.
        // Both layers now use `detail`; the From translation is a struct-
        // shorthand pass-through.
        let bridge_err = FfiUnlockError::CorruptVault {
            detail: "fnord".to_string(),
        };
        let uniffi_err: UnlockError = bridge_err.into();
        let UnlockError::CorruptVault { detail } = uniffi_err else {
            panic!("expected CorruptVault");
        };
        assert_eq!(detail, "fnord");
    }

    #[test]
    fn from_bridge_wrong_mnemonic_or_corrupt_maps_one_to_one() {
        let bridge_err = FfiUnlockError::WrongMnemonicOrCorrupt;
        let uniffi_err: UnlockError = bridge_err.into();
        assert!(matches!(uniffi_err, UnlockError::WrongMnemonicOrCorrupt));
    }

    #[test]
    fn from_bridge_invalid_mnemonic_preserves_detail() {
        let bridge_err = FfiUnlockError::InvalidMnemonic {
            detail: "expected 24 words, got 3".to_string(),
        };
        let uniffi_err: UnlockError = bridge_err.into();
        let UnlockError::InvalidMnemonic { detail } = uniffi_err else {
            panic!("expected InvalidMnemonic");
        };
        assert_eq!(detail, "expected 24 words, got 3");
    }

    #[test]
    fn corrupt_vault_display_uses_path_neutral_text() {
        // Mirror of the bridge crate's tripwire (see ffi/secretary-ffi-bridge/
        // src/error.rs). The uniffi-side UnlockError carries its own Display
        // attributes (because uniffi codegen uses this enum to produce the
        // Swift / Kotlin error messages); this test pins the path-neutral
        // wording so a future revert here is a deliberate decision.
        let err = UnlockError::CorruptVault {
            detail: "fnord".to_string(),
        };
        let rendered = format!("{err}");
        assert!(
            rendered.contains("vault data integrity failure"),
            "Display did not contain the path-neutral text: {rendered}",
        );
        assert!(rendered.contains("fnord"), "Display did not include detail");
        assert!(
            !rendered.contains("corrupt or unreadable"),
            "Display still contains the old read-path-only text: {rendered}",
        );
    }

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
        // Pin the 7th variant translation. A future rename would fail
        // here first.
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
    fn invalid_argument_display_pins_detail_text() {
        // Pin the Display contract for the new uniffi-only variant. uniffi
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
        // Pin the 9th variant translation. A future rename or accidental
        // remap to CorruptVault / FolderInvalid would fail here first.
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
    // B.4d: pin the 4 new share_block variants — Display + From mapping.
    // Same pattern as B.4c's SaveCryptoFailure pair (a31e6e6).
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
}
