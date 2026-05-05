//! Thinned 5-variant FFI-friendly error type.
//!
//! `core::unlock::UnlockError` has 7 variants reachable from
//! `open_with_password`, three of which wrap inner enums with their own
//! variant counts (`MalformedVaultToml(VaultTomlError)`, etc.). Mirroring
//! exactly to the foreign side either re-exposes ~15 inner types per
//! language (huge surface, churns on every internal refactor) or collapses
//! inners to strings (anti-pattern; foreign callers parse strings to
//! understand failure causes).
//!
//! [`FfiUnlockError`] thins to 5 variants expressing **user-actionable
//! intent** rather than mirroring the core enum's structural shape:
//!
//! - [`FfiUnlockError::WrongPasswordOrCorrupt`] — "your password is wrong,
//!   try again". Returned by `open_with_password`. **Deliberately conflates
//!   wrong-password and corruption** per `docs/threat-model.md` §13's
//!   anti-oracle property; this MUST NOT be split into separate variants.
//! - [`FfiUnlockError::WrongMnemonicOrCorrupt`] — parallel to the above for
//!   the `open_with_recovery` path. Same anti-oracle conflation under
//!   `recovery_kek`.
//! - [`FfiUnlockError::InvalidMnemonic`] — pre-decryption: the input does
//!   not validate as a 24-word BIP-39 phrase (wrong word count, unknown
//!   word, bad checksum, or invalid UTF-8). NOT a security oracle.
//! - [`FfiUnlockError::VaultMismatch`] — "vault.toml and identity.bundle.enc
//!   reference different vaults; re-pair from backups".
//! - [`FfiUnlockError::CorruptVault`] — collapses
//!   `{core::CorruptVault, all MalformedX, KdfFailure, WeakKdfParams}`.
//!   Carries a diagnostic `detail: String` for debugging; structured
//!   pattern-matching on the inner cause is intentionally not supported.
//!   Display text is path-neutral (`"vault data integrity failure"`)
//!   so the variant reads correctly on BOTH the open path (where it
//!   fires when a vault file is malformed) AND the create path (where
//!   it fires on rare system-level failures during vault production).

use thiserror::Error;

/// FFI-friendly thinned error type for the unlock entry points
/// (`open_with_password` and `open_with_recovery`). See [module docs](self)
/// for the rationale.
#[derive(Debug, Error)]
pub enum FfiUnlockError {
    /// Wrong password OR vault corruption — deliberately conflated per
    /// `docs/threat-model.md` §13. Returned by `open_with_password`.
    #[error("wrong password or vault corruption")]
    WrongPasswordOrCorrupt,

    /// Wrong recovery phrase OR vault corruption — parallel to
    /// `WrongPasswordOrCorrupt` for the recovery path. Same anti-oracle
    /// conflation: AEAD tag failure under `recovery_kek` is
    /// indistinguishable from corruption to the cryptography. Returned by
    /// `open_with_recovery`.
    #[error("wrong recovery phrase or vault corruption")]
    WrongMnemonicOrCorrupt,

    /// Invalid recovery phrase — pre-decryption validation failure
    /// (wrong word count, unknown word, bad checksum, or invalid UTF-8).
    /// Carries a free-form `detail` string for UI rendering. NOT a
    /// security oracle: BIP-39 wordlist + checksum validation runs on
    /// the input *before* any vault byte is touched, so the failure
    /// mode is "fix the typo and retry" rather than "vault is gone".
    #[error("invalid recovery phrase: {detail}")]
    InvalidMnemonic {
        /// Diagnostic text from the inner `MnemonicError` variant's
        /// `Display` impl, or `"phrase contained invalid UTF-8"` when
        /// the FFI input slice is not valid UTF-8.
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
        ///
        /// Renamed from `message` to `detail` in B.3a for naming
        /// uniformity with `InvalidMnemonic { detail }`. The uniffi
        /// projection layer was already using `detail` in B.2 to
        /// avoid a Kotlin `Throwable.message` collision; B.3a propagates
        /// the rename back to the bridge so all layers agree.
        detail: String,
    },
}

impl From<secretary_core::unlock::UnlockError> for FfiUnlockError {
    fn from(e: secretary_core::unlock::UnlockError) -> Self {
        use secretary_core::unlock::UnlockError as E;

        // Explicit match arms (no wildcard) so future core variants force a
        // compile error here. Each arm is chosen to preserve the §13
        // anti-oracle property where applicable: WrongPasswordOrCorrupt and
        // WrongMnemonicOrCorrupt each conflate "wrong key OR corrupt"
        // independently for their respective unlock path; InvalidMnemonic is
        // pre-decryption and is NOT an oracle.
        match e {
            E::WrongPasswordOrCorrupt => Self::WrongPasswordOrCorrupt,
            E::WrongMnemonicOrCorrupt => Self::WrongMnemonicOrCorrupt,
            E::InvalidMnemonic(inner) => Self::InvalidMnemonic {
                detail: inner.to_string(),
            },
            E::VaultMismatch => Self::VaultMismatch,

            E::CorruptVault
            | E::MalformedVaultToml(_)
            | E::MalformedBundleFile(_)
            | E::MalformedBundle(_)
            | E::KdfFailure(_) => Self::CorruptVault {
                detail: e.to_string(),
            },

            // SECURITY: defensive forward-compat for the only currently-
            // unreachable variant. `WeakKdfParams` is returned by `create_vault`
            // (which enforces the §1.2 v1 floor at write time); neither
            // `open_with_password` nor `open_with_recovery` enforces the floor
            // at read time. With `create_vault` deferred to B.3b, the variant
            // is unreachable through B.3a's surface; the mapping is forward-
            // compat insurance. If `create_vault` enters scope, re-validate
            // the mapping (and either expose `WeakKdfParams` as its own variant
            // or leave it folded into `CorruptVault`).
            E::WeakKdfParams { .. } => Self::CorruptVault {
                detail: e.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secretary_core::crypto::kdf::KdfError;
    use secretary_core::unlock::{
        bundle::BundleError, bundle_file::BundleFileError, vault_toml::VaultTomlError, UnlockError,
    };

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
        let FfiUnlockError::CorruptVault { detail } = ffi else {
            panic!("expected CorruptVault");
        };
        assert!(detail.contains("vault data integrity failure"));
    }

    #[test]
    fn malformed_vault_toml_collapses_to_corrupt_vault_with_inner_display() {
        let inner = VaultTomlError::MissingField("kdf");
        let core_err = UnlockError::MalformedVaultToml(inner);
        let ffi: FfiUnlockError = core_err.into();
        let FfiUnlockError::CorruptVault { detail } = ffi else {
            panic!("expected CorruptVault");
        };
        assert!(detail.contains("malformed vault.toml"));
        assert!(detail.contains("kdf"));
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
    fn wrong_mnemonic_or_corrupt_maps_to_dedicated_variant() {
        // B.3a promotes WrongMnemonicOrCorrupt from a defensive fold-into-
        // WrongPasswordOrCorrupt to its own dedicated FFI variant. The two
        // variants are now mutually exclusive by call site (open_with_password
        // emits the password variant; open_with_recovery emits the mnemonic
        // variant). The §13 anti-oracle conflation is preserved within each
        // path independently.
        let core_err = UnlockError::WrongMnemonicOrCorrupt;
        let ffi: FfiUnlockError = core_err.into();
        assert!(matches!(ffi, FfiUnlockError::WrongMnemonicOrCorrupt));
    }

    #[test]
    fn display_format_is_stable_for_each_variant() {
        // These strings are anchored in FfiUnlockError's own #[error(...)]
        // attributes (NOT derived from core::UnlockError's Display), and
        // they must not change — the foreign smoke runners in Tasks 8/10
        // (Python pytest, Swift, Kotlin) will assert against them when
        // checking exception messages.
        assert_eq!(
            FfiUnlockError::WrongPasswordOrCorrupt.to_string(),
            "wrong password or vault corruption",
        );
        assert_eq!(
            FfiUnlockError::VaultMismatch.to_string(),
            "vault.toml and identity.bundle.enc reference different vaults",
        );
        let corrupt = FfiUnlockError::CorruptVault {
            detail: "fnord".to_string(),
        };
        assert_eq!(corrupt.to_string(), "vault data integrity failure: fnord",);
    }

    #[test]
    fn invalid_mnemonic_wrong_length_carries_detail() {
        use secretary_core::unlock::mnemonic::MnemonicError;
        let core_err = UnlockError::InvalidMnemonic(MnemonicError::WrongLength { got: 3 });
        let ffi: FfiUnlockError = core_err.into();
        let FfiUnlockError::InvalidMnemonic { detail } = ffi else {
            panic!("expected InvalidMnemonic, got {ffi:?}");
        };
        assert!(
            detail.contains("got 3"),
            "detail did not carry word count: {detail}"
        );
    }

    #[test]
    fn invalid_mnemonic_unknown_word_carries_detail() {
        use secretary_core::unlock::mnemonic::MnemonicError;
        let core_err =
            UnlockError::InvalidMnemonic(MnemonicError::UnknownWord("xyzzy".to_string()));
        let ffi: FfiUnlockError = core_err.into();
        let FfiUnlockError::InvalidMnemonic { detail } = ffi else {
            panic!("expected InvalidMnemonic, got {ffi:?}");
        };
        assert!(
            detail.contains("xyzzy"),
            "detail did not carry the offending word: {detail}"
        );
    }

    #[test]
    fn invalid_mnemonic_bad_checksum_carries_detail() {
        use secretary_core::unlock::mnemonic::MnemonicError;
        let core_err = UnlockError::InvalidMnemonic(MnemonicError::BadChecksum);
        let ffi: FfiUnlockError = core_err.into();
        let FfiUnlockError::InvalidMnemonic { detail } = ffi else {
            panic!("expected InvalidMnemonic, got {ffi:?}");
        };
        assert!(
            detail.to_lowercase().contains("checksum"),
            "detail did not mention checksum: {detail}"
        );
    }

    #[test]
    fn weak_kdf_params_remains_defensively_mapped_to_corrupt_vault() {
        // SECURITY: with create_vault deferred to B.3b, this variant is
        // unreachable from open_with_password / open_with_recovery. The
        // defensive mapping here is forward-compat insurance — if create_vault
        // enters scope, re-validate whether WeakKdfParams should be exposed
        // as its own variant or stay folded into CorruptVault.
        let core_err = UnlockError::WeakKdfParams {
            memory_kib: 16,
            min_memory_kib: 65536,
        };
        let ffi: FfiUnlockError = core_err.into();
        assert!(matches!(ffi, FfiUnlockError::CorruptVault { .. }));
    }

    #[test]
    fn corrupt_vault_field_renamed_to_detail() {
        // Pin the field rename: B.2 used `message`, B.3a renames to `detail`
        // for uniformity with InvalidMnemonic { detail }. This test is a
        // tripwire — a future refactor that reverts to `message` would fail
        // here AND break the uniffi/PyO3 forwarders, so it must be deliberate.
        let ffi = FfiUnlockError::CorruptVault {
            detail: "tripwire".to_string(),
        };
        let rendered = format!("{ffi}");
        assert!(rendered.contains("tripwire"));
        let FfiUnlockError::CorruptVault { detail } = ffi else {
            unreachable!()
        };
        assert_eq!(detail, "tripwire");
    }

    #[test]
    fn corrupt_vault_display_uses_path_neutral_text() {
        // B.3b changed the Display text from "vault is corrupt or unreadable"
        // (read-path-only) to "vault data integrity failure" (path-neutral)
        // so the variant reads correctly on the create path too. This test
        // is a tripwire: a future refactor that reverts to read-path-only
        // text would fail here, forcing a deliberate decision rather than
        // a silent regression.
        let ffi = FfiUnlockError::CorruptVault {
            detail: "fnord".to_string(),
        };
        let rendered = format!("{ffi}");
        assert!(
            rendered.contains("vault data integrity failure"),
            "Display did not contain the path-neutral text: {rendered}",
        );
        assert!(rendered.contains("fnord"), "Display did not include detail");
        // Negative: must NOT contain the old read-path-only phrasing.
        assert!(
            !rendered.contains("corrupt or unreadable"),
            "Display still contains the old read-path-only text: {rendered}",
        );
    }
}
