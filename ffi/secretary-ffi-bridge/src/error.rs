//! Thinned 3-variant FFI-friendly error type.
//!
//! `core::unlock::UnlockError` has 7 variants reachable from
//! `open_with_password`, three of which wrap inner enums with their own
//! variant counts (`MalformedVaultToml(VaultTomlError)`, etc.). Mirroring
//! exactly to the foreign side either re-exposes ~15 inner types per
//! language (huge surface, churns on every internal refactor) or collapses
//! inners to strings (anti-pattern; foreign callers parse strings to
//! understand failure causes).
//!
//! [`FfiUnlockError`] thins to 3 variants expressing **user-actionable
//! intent**:
//!
//! - [`FfiUnlockError::WrongPasswordOrCorrupt`] — "your password is wrong,
//!   try again". **Deliberately conflates wrong-password and corruption**
//!   per `docs/threat-model.md` §13's anti-oracle property; this MUST NOT
//!   be split into separate variants on the foreign side.
//! - [`FfiUnlockError::VaultMismatch`] — "vault.toml and identity.bundle.enc
//!   reference different vaults; re-pair from backups".
//! - [`FfiUnlockError::CorruptVault`] — collapses
//!   `{core::CorruptVault, all MalformedX, KdfFailure}`. Carries a
//!   diagnostic `message: String` for debugging; structured pattern-
//!   matching on the inner cause is intentionally not supported.

use thiserror::Error;

/// FFI-friendly thinned error type for `open_with_password`. See [module
/// docs](self) for the rationale.
#[derive(Debug, Error)]
pub enum FfiUnlockError {
    /// Wrong password OR vault corruption — deliberately conflated per
    /// `docs/threat-model.md` §13.
    #[error("wrong password or vault corruption")]
    WrongPasswordOrCorrupt,

    /// `vault.toml` and `identity.bundle.enc` reference different vaults.
    #[error("vault.toml and identity.bundle.enc reference different vaults")]
    VaultMismatch,

    /// Vault is corrupt or unreadable. Carries a diagnostic message for
    /// debugging; not pattern-matchable on the inner cause.
    #[error("vault is corrupt or unreadable: {message}")]
    CorruptVault {
        /// Diagnostic text from the inner `core::UnlockError` variant's
        /// `Display` impl. Free-form; not part of the API contract.
        message: String,
    },
}

impl From<secretary_core::unlock::UnlockError> for FfiUnlockError {
    fn from(e: secretary_core::unlock::UnlockError) -> Self {
        use secretary_core::unlock::UnlockError as E;

        // Explicit match arms (no wildcard) so future core variants force a
        // compile error here. The defensive arms at the bottom map currently-
        // unreachable variants for forward-compat: if a future change to
        // `open_with_password` makes them reachable, they fold into
        // `CorruptVault { message }` rather than panicking.
        match e {
            E::WrongPasswordOrCorrupt => Self::WrongPasswordOrCorrupt,
            E::VaultMismatch => Self::VaultMismatch,

            E::CorruptVault
            | E::MalformedVaultToml(_)
            | E::MalformedBundleFile(_)
            | E::MalformedBundle(_)
            | E::KdfFailure(_) => Self::CorruptVault { message: e.to_string() },

            // Defensive forward-compat: variants currently unreachable from
            // open_with_password (they require open_with_recovery or
            // create_vault) but mapped here so a future core change doesn't
            // silently cause a panic at the FFI boundary.
            E::WrongMnemonicOrCorrupt
            | E::InvalidMnemonic(_)
            | E::WeakKdfParams { .. } => Self::CorruptVault { message: e.to_string() },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secretary_core::unlock::{
        bundle::BundleError, bundle_file::BundleFileError, vault_toml::VaultTomlError,
        UnlockError,
    };
    use secretary_core::crypto::kdf::KdfError;

    #[test]
    fn wrong_password_or_corrupt_maps_one_to_one() {
        let core_err = UnlockError::WrongPasswordOrCorrupt;
        let ffi: FfiUnlockError = core_err.into();
        assert!(matches!(ffi, FfiUnlockError::WrongPasswordOrCorrupt));
    }

    #[test]
    fn vault_mismatch_maps_one_to_one() {
        let core_err = UnlockError::VaultMismatch;
        let ffi: FfiUnlockError = core_err.into();
        assert!(matches!(ffi, FfiUnlockError::VaultMismatch));
    }

    #[test]
    fn corrupt_vault_collapses_to_corrupt_vault() {
        let core_err = UnlockError::CorruptVault;
        let ffi: FfiUnlockError = core_err.into();
        let FfiUnlockError::CorruptVault { message } = ffi else {
            panic!("expected CorruptVault");
        };
        assert!(message.contains("vault data integrity failure"));
    }

    #[test]
    fn malformed_vault_toml_collapses_to_corrupt_vault_with_inner_display() {
        // VaultTomlError::MissingField takes &'static str (not String).
        // "missing field: kdf" contains "kdf"; outer wraps to
        // "malformed vault.toml: missing field: kdf".
        let inner = VaultTomlError::MissingField("kdf");
        let core_err = UnlockError::MalformedVaultToml(inner);
        let ffi: FfiUnlockError = core_err.into();
        let FfiUnlockError::CorruptVault { message } = ffi else {
            panic!("expected CorruptVault");
        };
        assert!(message.contains("malformed vault.toml"));
        assert!(message.contains("kdf"));
    }

    #[test]
    fn malformed_bundle_file_collapses_to_corrupt_vault() {
        // BundleFileError has no TruncatedHeader unit variant; use Truncated { offset }.
        let inner = BundleFileError::Truncated { offset: 0 };
        let core_err = UnlockError::MalformedBundleFile(inner);
        let ffi: FfiUnlockError = core_err.into();
        assert!(matches!(ffi, FfiUnlockError::CorruptVault { .. }));
    }

    #[test]
    fn malformed_bundle_collapses_to_corrupt_vault() {
        // BundleError has no MalformedCbor variant; use CborError(String).
        let inner = BundleError::CborError("bad header".to_string());
        let core_err = UnlockError::MalformedBundle(inner);
        let ffi: FfiUnlockError = core_err.into();
        assert!(matches!(ffi, FfiUnlockError::CorruptVault { .. }));
    }

    #[test]
    fn kdf_failure_collapses_to_corrupt_vault() {
        // KdfError has no OutputLengthOutOfRange variant; use ParamsBelowV1Floor.
        let inner = KdfError::ParamsBelowV1Floor;
        let core_err = UnlockError::KdfFailure(inner);
        let ffi: FfiUnlockError = core_err.into();
        assert!(matches!(ffi, FfiUnlockError::CorruptVault { .. }));
    }

    #[test]
    fn wrong_mnemonic_or_corrupt_maps_defensively_to_corrupt_vault() {
        let core_err = UnlockError::WrongMnemonicOrCorrupt;
        let ffi: FfiUnlockError = core_err.into();
        assert!(matches!(ffi, FfiUnlockError::CorruptVault { .. }));
    }

    #[test]
    fn weak_kdf_params_maps_defensively_to_corrupt_vault() {
        let core_err = UnlockError::WeakKdfParams {
            memory_kib: 8,
            min_memory_kib: 65536,
        };
        let ffi: FfiUnlockError = core_err.into();
        assert!(matches!(ffi, FfiUnlockError::CorruptVault { .. }));
    }

    #[test]
    fn display_format_is_stable_for_each_variant() {
        assert_eq!(
            FfiUnlockError::WrongPasswordOrCorrupt.to_string(),
            "wrong password or vault corruption",
        );
        assert_eq!(
            FfiUnlockError::VaultMismatch.to_string(),
            "vault.toml and identity.bundle.enc reference different vaults",
        );
        let corrupt = FfiUnlockError::CorruptVault {
            message: "fnord".to_string(),
        };
        assert_eq!(
            corrupt.to_string(),
            "vault is corrupt or unreadable: fnord",
        );
    }
}
