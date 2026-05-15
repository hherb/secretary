//! uniffi-side `UnlockError` mirroring the bridge crate's `FfiUnlockError`.

use secretary_ffi_bridge::FfiUnlockError;

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
}
