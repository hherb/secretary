//! Thinned FFI-friendly error types for the bridge layer.
//!
//! [`FfiUnlockError`] — 5-variant thinned error for the **bytes-in** unlock
//! entry points (`open_with_password`, `open_with_recovery`, `create_vault`).
//! [`FfiVaultError`] — 8-variant **folder-in** error type. Mirrors
//! `FfiUnlockError`'s 5 unlock-class variants byte-identically (variant
//! name + Display string) plus a new `FolderInvalid { detail }` for missing
//! or inaccessible vault folders. Returned by `open_vault_with_password` /
//! `open_vault_with_recovery`.
//!
//! # Why thinned (FfiUnlockError rationale)
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
//!
//! # Why a separate FfiVaultError (mirror property)
//!
//! The bytes-in unlock paths cannot raise IO errors — they take owned byte
//! slices, not paths. The folder-in vault paths read four files from disk
//! (`vault.toml`, `identity.bundle.enc`, `manifest.cbor.enc`,
//! `contacts/<owner_uuid>.card`) and need a way to surface "your path is
//! wrong" distinctly from "your data is corrupt". The 5 overlapping
//! variants share **byte-identical** Display strings with their
//! `FfiUnlockError` counterparts — pinned by a tripwire test in this
//! module. The drift-resistance comes from `From<core::vault::VaultError>`
//! delegating unlock-class translation through a private
//! `From<FfiUnlockError>` arm; if a future change adds a 6th variant to
//! `FfiUnlockError`, the new variant automatically picks up the right
//! `FfiVaultError` mapping via the delegation.

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

            // SECURITY: defensive forward-compat for a structurally-
            // unreachable variant. `core::UnlockError::WeakKdfParams` is
            // returned ONLY by `core::unlock::create_vault` when the
            // caller-supplied `Argon2idParams` falls below the §1.2 v1
            // floor; neither `open_with_password` nor `open_with_recovery`
            // enforces the floor at read time. The bridge's
            // [`crate::create::create_vault`] hardcodes
            // `Argon2idParams::V1_DEFAULT` (m=256 MiB, well above the
            // 64 MiB floor), so this variant cannot fire through any
            // current FFI surface. The fold-into-`CorruptVault` mapping
            // stays as forward-compat insurance for any future surface
            // that exposes caller-tunable KDF params; if such a surface
            // ever lands, re-validate whether `WeakKdfParams` should be
            // exposed as its own variant or stay folded.
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
        // SECURITY: `WeakKdfParams` is unreachable through every current
        // FFI surface — `open_with_password` / `open_with_recovery` do not
        // enforce the §1.2 v1 floor at read time, and the bridge's
        // `create_vault` hardcodes `Argon2idParams::V1_DEFAULT`. The
        // fold-into-`CorruptVault` mapping is forward-compat insurance for
        // a future surface that exposes caller-tunable KDF params; this
        // test pins the mapping so a future refactor that re-routes
        // `WeakKdfParams` (e.g. promotes it to its own variant) is a
        // deliberate decision rather than a silent regression.
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

    // =============================================================================
    // FfiVaultError tests — mirror property + dedicated FolderInvalid + drift tripwire
    // =============================================================================

    #[test]
    fn vault_error_display_strings_mirror_unlock_error_byte_identical() {
        // Tripwire: the 5 overlapping variants MUST produce byte-identical
        // Display strings between FfiUnlockError and FfiVaultError. A future
        // rename on either side that breaks the mirror property would fail
        // here, forcing a deliberate decision rather than silent drift.
        assert_eq!(
            FfiUnlockError::WrongPasswordOrCorrupt.to_string(),
            FfiVaultError::WrongPasswordOrCorrupt.to_string(),
        );
        assert_eq!(
            FfiUnlockError::WrongMnemonicOrCorrupt.to_string(),
            FfiVaultError::WrongMnemonicOrCorrupt.to_string(),
        );
        assert_eq!(
            FfiUnlockError::InvalidMnemonic {
                detail: "test".to_string()
            }
            .to_string(),
            FfiVaultError::InvalidMnemonic {
                detail: "test".to_string()
            }
            .to_string(),
        );
        assert_eq!(
            FfiUnlockError::VaultMismatch.to_string(),
            FfiVaultError::VaultMismatch.to_string(),
        );
        assert_eq!(
            FfiUnlockError::CorruptVault {
                detail: "test".to_string()
            }
            .to_string(),
            FfiVaultError::CorruptVault {
                detail: "test".to_string()
            }
            .to_string(),
        );
    }

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
    fn from_ffi_unlock_error_translates_each_variant_one_to_one() {
        // The private bridge-internal From<FfiUnlockError> arm. This is
        // reachable from FfiVaultError::from(VaultError::Unlock(...)) but
        // worth pinning directly so any rename / variant addition fails here
        // first.
        assert!(matches!(
            FfiVaultError::from(FfiUnlockError::WrongPasswordOrCorrupt),
            FfiVaultError::WrongPasswordOrCorrupt,
        ));
        assert!(matches!(
            FfiVaultError::from(FfiUnlockError::WrongMnemonicOrCorrupt),
            FfiVaultError::WrongMnemonicOrCorrupt,
        ));
        let inv = FfiVaultError::from(FfiUnlockError::InvalidMnemonic {
            detail: "bad".to_string(),
        });
        let FfiVaultError::InvalidMnemonic { detail } = inv else {
            panic!("expected InvalidMnemonic, got {inv:?}");
        };
        assert_eq!(detail, "bad");
        assert!(matches!(
            FfiVaultError::from(FfiUnlockError::VaultMismatch),
            FfiVaultError::VaultMismatch,
        ));
        let corrupt = FfiVaultError::from(FfiUnlockError::CorruptVault {
            detail: "x".to_string(),
        });
        let FfiVaultError::CorruptVault { detail } = corrupt else {
            panic!("expected CorruptVault, got {corrupt:?}");
        };
        assert_eq!(detail, "x");
    }

    #[test]
    fn from_core_vault_error_unlock_arm_delegates_through_ffi_unlock_error() {
        // VaultError::Unlock(WrongPasswordOrCorrupt) → FfiVaultError::WrongPasswordOrCorrupt
        // via the FfiUnlockError translation. Test the full delegation path.
        use secretary_core::unlock::UnlockError;
        use secretary_core::vault::VaultError;
        let core_err = VaultError::Unlock(UnlockError::WrongPasswordOrCorrupt);
        let ffi: FfiVaultError = core_err.into();
        assert!(matches!(ffi, FfiVaultError::WrongPasswordOrCorrupt));
    }

    #[test]
    fn from_core_vault_error_io_not_found_maps_to_folder_invalid() {
        use secretary_core::vault::VaultError;
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
    fn from_core_vault_error_io_permission_denied_maps_to_folder_invalid() {
        use secretary_core::vault::VaultError;
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
        use secretary_core::vault::VaultError;
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
        use secretary_core::vault::VaultError;
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
        use secretary_core::vault::VaultError;
        let core_err = VaultError::KdfParamsMismatch;
        let ffi: FfiVaultError = core_err.into();
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
        use secretary_core::vault::VaultError as VE;
        let core_err = VE::NotAuthor {
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
        use secretary_core::vault::VaultError as VE;
        let ffi: FfiVaultError = VE::RecipientAlreadyPresent.into();
        assert!(matches!(ffi, FfiVaultError::RecipientAlreadyPresent));
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
        use secretary_core::vault::VaultError as VE;
        let ffi: FfiVaultError = VE::MissingRecipientCard {
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
}

// =============================================================================
// FfiVaultError — folder-in counterpart to FfiUnlockError
// =============================================================================

/// FFI-friendly thinned error type for the **folder-in** vault entry points
/// (`open_vault_with_password` and `open_vault_with_recovery`). Mirrors
/// [`FfiUnlockError`]'s 5 unlock-class variants byte-identically (variant
/// name + Display string) plus a new [`FfiVaultError::FolderInvalid`]
/// variant for missing or inaccessible vault folders.
///
/// # Why a separate error type
///
/// The bytes-in unlock entry points (B.2 / B.3a, returning `FfiUnlockError`)
/// cannot raise IO errors — they take owned byte slices, not paths. The
/// folder-in entry points (B.4a) read four files from disk
/// (`vault.toml`, `identity.bundle.enc`, `manifest.cbor.enc`,
/// `contacts/<owner_uuid>.card`) and need a way to surface "your path is
/// wrong" distinctly from "your data is corrupt". Promoting that distinction
/// to a separate variant with `detail: String` carrying the missing-file
/// name lets foreign UIs render the right affordance (fix the path vs.
/// re-pair from backups). Pre-unlock IO errors don't leak unlock-secret
/// information, so the §13 anti-oracle constraint allows the granularity.
///
/// # Mirror property
///
/// The 5 overlapping variants share **byte-identical** Display strings with
/// their `FfiUnlockError` counterparts. Foreign-side dispatch logic on a
/// folder-in `FfiVaultError` reads identically to dispatch on a bytes-in
/// `FfiUnlockError`. A code-quality tripwire test in this module pins the
/// strings byte-identical so a future variant rename on `FfiUnlockError`
/// cannot drift unnoticed.
#[derive(Debug, Error)]
pub enum FfiVaultError {
    /// Wrong password OR vault corruption — deliberately conflated per
    /// `docs/threat-model.md` §13. Returned by `open_vault_with_password`.
    /// Mirrors [`FfiUnlockError::WrongPasswordOrCorrupt`] in name and
    /// Display text.
    #[error("wrong password or vault corruption")]
    WrongPasswordOrCorrupt,

    /// Wrong recovery phrase OR vault corruption — parallel anti-oracle
    /// conflation for `open_vault_with_recovery`. Mirrors
    /// [`FfiUnlockError::WrongMnemonicOrCorrupt`] in name and Display text.
    #[error("wrong recovery phrase or vault corruption")]
    WrongMnemonicOrCorrupt,

    /// Invalid recovery phrase — pre-decryption validation failure (wrong
    /// word count, unknown word, bad checksum, or invalid UTF-8 input).
    /// Mirrors [`FfiUnlockError::InvalidMnemonic`] in name and Display text.
    #[error("invalid recovery phrase: {detail}")]
    InvalidMnemonic {
        /// Diagnostic text from the inner `MnemonicError` variant's
        /// `Display` impl, or `"phrase contained invalid UTF-8"` when
        /// the FFI input slice is not valid UTF-8.
        detail: String,
    },

    /// `vault.toml` and `identity.bundle.enc` reference different vaults.
    /// Mirrors [`FfiUnlockError::VaultMismatch`] in name and Display text.
    #[error("vault.toml and identity.bundle.enc reference different vaults")]
    VaultMismatch,

    /// Vault data integrity failure — covers BOTH the unlock-time corruption
    /// cases mirrored from [`FfiUnlockError::CorruptVault`] AND the
    /// post-unlock integrity failures specific to folder-in: manifest
    /// decrypt/parse/verify, owner-card decode/self-verify, fingerprint
    /// cross-check, KDF-params cross-check. Display text is path-neutral
    /// and matches [`FfiUnlockError::CorruptVault`] exactly. Carries a
    /// diagnostic `detail` string for debugging; not pattern-matchable on
    /// the inner cause.
    #[error("vault data integrity failure: {detail}")]
    CorruptVault {
        /// Diagnostic text from the inner `core::VaultError` variant's
        /// `Display` impl. Free-form; not part of the API contract.
        detail: String,
    },

    /// Vault folder doesn't exist, isn't readable, or is missing one of
    /// the required files (`vault.toml`, `identity.bundle.enc`,
    /// `manifest.cbor.enc`, `contacts/<owner_uuid>.card`). New variant
    /// introduced by B.4a — no counterpart on [`FfiUnlockError`] (bytes-in
    /// callers cannot raise IO errors against their own filesystem through
    /// the bridge). The `detail` string carries the IO context (e.g.
    /// `"failed to read vault.toml: No such file or directory (os error 2)"`).
    #[error("vault folder is not accessible: {detail}")]
    FolderInvalid {
        /// IO context string: which file we tried to read + the underlying
        /// `io::Error`'s Display.
        detail: String,
    },

    /// The requested block UUID does not appear in the manifest's live
    /// blocks list (`manifest.blocks`). Trashed blocks live in a
    /// separate list (`manifest.trash`, holding `TrashEntry` records
    /// with their own `block_uuid`) which `read_block` does NOT
    /// search; a trashed UUID therefore naturally falls through to
    /// `BlockNotFound` here. Sub-project C will introduce the
    /// restore-from-trash flow with full vector-clock context, at
    /// which point trashed UUIDs may surface through a dedicated
    /// recovery path instead.
    ///
    /// `uuid_hex` is the 32-char lowercase hex of the requested UUID, e.g.
    /// `"112233445566778899aabbccddeeff00"`. Stored as a `String` for
    /// consistency with other variants' `detail: String` payloads; the
    /// foreign caller can `bytes.fromhex(uuid_hex)` if needed.
    ///
    /// Distinct from `CorruptVault` — `BlockNotFound` means "the manifest
    /// doesn't list this block" (legitimate caller error or stale UUID),
    /// while `CorruptVault` means "the manifest lists it but the file is
    /// missing or unreadable" (data integrity failure). The wrong-length
    /// UUID case (≠16 bytes) does NOT fold here either — that's a
    /// programmer error and surfaces as `ValueError` (PyO3) /
    /// `VaultError::InvalidArgument` (uniffi) at the binding layer; the
    /// bridge function takes `&[u8; 16]` (compile-time enforced).
    #[error("block not found in manifest: {uuid_hex}")]
    BlockNotFound {
        /// 32-char lowercase hex of the requested 16-byte block UUID.
        /// See the variant-level doc for the contract + counter-cases.
        uuid_hex: String,
    },

    /// Save-time crypto failure on already-validated inputs. Distinguished
    /// from `CorruptVault` (which means on-disk bytes failed verification)
    /// because save failures here originate from in-memory state that
    /// passed `open_vault` checks, so the failure mode is post-unlock
    /// corruption / structural-impossibility rather than an on-disk corrupt
    /// envelope.
    ///
    /// Mapped from: `tick_clock` saturation, `MlKem768Public::from_bytes`
    /// failures on the owner card, canonical-CBOR encode failures,
    /// `encrypt_block` / `sign_manifest` / `encode_block_file` /
    /// `encode_manifest_file` failures, and post-unlock identity-bundle
    /// in-memory parse failures (see `SignerSecretKeysError::MlDsa65ParseFailed`).
    ///
    /// Constructed directly by `crate::save::save_block`'s error-mapping
    /// helper — NOT reachable through `From<core::VaultError>` (the read
    /// path's existing mapping correctly folds `core::VaultError` crypto
    /// failures onto `CorruptVault`, since for the read path the input is
    /// on-disk bytes).
    #[error("save-time crypto failure: {detail}")]
    SaveCryptoFailure {
        /// Diagnostic text describing which save-step failed. Free-form;
        /// not part of the API contract.
        detail: String,
    },

    /// Block-share authorization failure: the calling identity's
    /// `user_uuid` does not match the block's recorded `author_fingerprint`,
    /// OR the supplied `author_card`'s `contact_uuid` does not match the
    /// vault owner's `user_uuid`. v1 single-author: only the vault owner
    /// can share blocks they authored. The future "share-as-fork" path
    /// will lift this restriction; B.4d cements the v1 semantics.
    ///
    /// `expected_fingerprint_hex` is the 32-char lowercase hex of the
    /// fingerprint stored on disk in the block file's `author_fingerprint`
    /// field. `got_fingerprint_hex` is the 32-char lowercase hex of
    /// `fingerprint(author_card.to_canonical_cbor())`. Foreign callers can
    /// `bytes.fromhex(...)` either if needed.
    #[error("only the block author can share this block")]
    NotAuthor {
        /// 32-char lowercase hex of the on-disk author fingerprint.
        expected_fingerprint_hex: String,
        /// 32-char lowercase hex of the supplied author-card fingerprint.
        got_fingerprint_hex: String,
    },

    /// The supplied `new_recipient` is already in the block's wire-level
    /// recipient table (deduplication check performed by core, keyed on
    /// fingerprint). Foreign UX: idempotent — the recipient already has
    /// access; no further action needed.
    #[error("recipient is already present in the block's recipient set")]
    RecipientAlreadyPresent,

    /// The caller's `existing_recipient_cards` did not cover every
    /// recipient currently in the block's wire-level recipient table.
    /// `recipient_fingerprint_hex` is the 32-char lowercase hex of the
    /// missing recipient's fingerprint; foreign callers can use it to
    /// look up the contact card in their address book / contacts dir.
    #[error("missing contact card for recipient: {recipient_fingerprint_hex}")]
    MissingRecipientCard {
        /// 32-char lowercase hex of the missing recipient's fingerprint.
        recipient_fingerprint_hex: String,
    },

    /// One of the canonical-CBOR `ContactCard` byte slices passed to
    /// [`crate::share::share_block`] failed to decode via
    /// `ContactCard::from_canonical_cbor`. Constructed directly inside the
    /// bridge — NOT reachable through `From<core::VaultError>` (mirrors
    /// [`Self::SaveCryptoFailure`]'s bridge-internal pattern).
    #[error("failed to decode contact card: {detail}")]
    CardDecodeFailure {
        /// Diagnostic text from the inner `CardError` variant's `Display`
        /// impl. Free-form; not part of the API contract.
        detail: String,
    },
}

impl From<secretary_core::vault::VaultError> for FfiVaultError {
    fn from(e: secretary_core::vault::VaultError) -> Self {
        use secretary_core::vault::VaultError as VE;

        match e {
            // Unlock-class errors: delegate to the FfiUnlockError translation
            // logic so the 5 mirrored variants stay drift-free. If a future
            // refactor adds a 6th variant to FfiUnlockError, the new variant
            // automatically picks up the right FfiVaultError mapping via the
            // private From<FfiUnlockError> arm below.
            VE::Unlock(unlock_err) => {
                let intermediate: FfiUnlockError = unlock_err.into();
                intermediate.into()
            }

            // Pre-unlock IO errors → FolderInvalid. The matched ErrorKinds
            // are the foreign-caller-actionable ones (path is wrong, no
            // permission). Any other IO error kind (e.g. interrupted, broken
            // pipe) falls through to CorruptVault since it's neither
            // user-actionable nor data-integrity-clean.
            VE::Io { context, source }
                if matches!(
                    source.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                ) =>
            {
                FfiVaultError::FolderInvalid {
                    detail: format!("{context}: {source}"),
                }
            }

            // Block-lookup failure (the manifest does not list this UUID).
            // core::read_block + core::share_block + core::save_block all
            // surface this; folding to CorruptVault would mask a benign
            // "stale UUID" / "trashed block" caller mistake as a data-
            // integrity failure.
            VE::BlockNotFound { block_uuid } => FfiVaultError::BlockNotFound {
                uuid_hex: hex::encode(block_uuid),
            },

            // Block-share authorization failure: caller's identity is not
            // the author. Both fingerprints are public material (BLAKE3 of
            // a non-secret contact card); rendering as hex preserves the
            // foreign-side debugging affordance without leaking secrets.
            VE::NotAuthor { expected, got } => FfiVaultError::NotAuthor {
                expected_fingerprint_hex: hex::encode(expected),
                got_fingerprint_hex: hex::encode(got),
            },

            // Block-share dedup failure: caller is trying to add a recipient
            // that already has access. Foreign UX: idempotent.
            VE::RecipientAlreadyPresent => FfiVaultError::RecipientAlreadyPresent,

            // Block-share input shape failure: caller's
            // `existing_recipient_cards` did not cover every recipient on
            // disk. The caller can recover by fetching the missing card
            // (e.g. from their contacts dir) and retrying. The core
            // variant's field is `fingerprint`; the FFI variant adds the
            // `recipient_` prefix for clarity at the foreign-API boundary.
            VE::MissingRecipientCard { fingerprint } => FfiVaultError::MissingRecipientCard {
                recipient_fingerprint_hex: hex::encode(fingerprint),
            },

            // Post-unlock integrity failures and unexpected IO kinds: fold
            // into CorruptVault catchall. These cannot leak unlock-secret
            // information (the IBK was already recovered when they fire).
            // Manifest decode, owner-card verification, UUID mismatches,
            // KDF-params mismatch, vector-clock overflow, signature
            // primitive failure, etc. all land here.
            other => FfiVaultError::CorruptVault {
                detail: format!("{other}"),
            },
        }
    }
}

/// Bridge-internal translation of an unlock-class error into the vault-
/// class error surface. Private free function so the bridge crate has a
/// single place to evolve the mapping; the `pub` `From` impl below is a
/// thin delegator.
///
/// The translation is one-to-one because every unlock-class variant maps
/// to a name-identical vault-class variant (the vault-class enum is a
/// strict superset of the unlock-class enum). Future variant additions
/// belong here, not in the `From` impl body.
fn unlock_err_to_vault_err(e: FfiUnlockError) -> FfiVaultError {
    match e {
        FfiUnlockError::WrongPasswordOrCorrupt => FfiVaultError::WrongPasswordOrCorrupt,
        FfiUnlockError::WrongMnemonicOrCorrupt => FfiVaultError::WrongMnemonicOrCorrupt,
        FfiUnlockError::InvalidMnemonic { detail } => FfiVaultError::InvalidMnemonic { detail },
        FfiUnlockError::VaultMismatch => FfiVaultError::VaultMismatch,
        FfiUnlockError::CorruptVault { detail } => FfiVaultError::CorruptVault { detail },
    }
}

/// Bridge-internal conversion. This impl is necessarily `pub` (it
/// implements the standard `From` trait, whose visibility cannot be
/// restricted), but it is **not part of the stable FFI surface**. Do not
/// use this arm directly from foreign-projection code — it would couple
/// the binding-flavor crates (`secretary-ffi-py`, `secretary-ffi-uniffi`)
/// to a private translation step. Foreign code goes through
/// `From<core::vault::VaultError>`, which delegates to
/// `unlock_err_to_vault_err` internally for the unlock-class variants.
impl From<FfiUnlockError> for FfiVaultError {
    fn from(e: FfiUnlockError) -> Self {
        unlock_err_to_vault_err(e)
    }
}
