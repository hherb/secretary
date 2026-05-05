//! Fallible, secret-bearing unlock operations:
//! [`open_with_password`] (master-password path) and
//! [`open_with_recovery`] (24-word BIP-39 recovery-phrase path).
//!
//! FFI-friendly wrappers around `secretary_core::unlock::*`. Each function
//! maps the `Result<core::UnlockedIdentity, core::UnlockError>` shape to
//! `Result<UnlockedIdentity, FfiUnlockError>` (thinned + opaque). Both
//! paths converge on byte-identical secret state per the §3/§4 dual-KEK
//! design.
//!
//! For the password path, the input slice is wrapped in [`SecretBytes`],
//! which zeroizes on drop. The recovery path takes the mnemonic input as
//! `&[u8]` (UTF-8 bytes) and runs `std::str::from_utf8` as the bridge's
//! sole pre-core validation seam; downstream BIP-39 validation lives in
//! `core::unlock::mnemonic::parse`. In both cases, the caller's
//! foreign-side buffer is the caller's concern — see the per-language
//! READMEs for the documented zeroize discipline.

use crate::{FfiUnlockError, UnlockedIdentity};

/// Unlock a vault using its master password. Returns an opaque handle
/// that exposes non-secret accessors and an explicit `close()`.
///
/// # Errors
///
/// - [`FfiUnlockError::WrongPasswordOrCorrupt`] — password is wrong, OR
///   one of the encrypted files has been tampered with. Indistinguishable
///   by design (anti-oracle property).
/// - [`FfiUnlockError::VaultMismatch`] — `vault_toml_bytes` and
///   `identity_bundle_bytes` reference different vault UUIDs / timestamps.
/// - [`FfiUnlockError::CorruptVault`] — the inputs cannot be decoded as
///   well-formed v1 vault files.
pub fn open_with_password(
    vault_toml_bytes: &[u8],
    identity_bundle_bytes: &[u8],
    password: &[u8],
) -> Result<UnlockedIdentity, FfiUnlockError> {
    let pw = secretary_core::crypto::secret::SecretBytes::new(password.to_vec());
    let unlocked =
        secretary_core::unlock::open_with_password(vault_toml_bytes, identity_bundle_bytes, &pw)?;
    Ok(UnlockedIdentity::new(unlocked))
    // pw drops here → SecretBytes ZeroizeOnDrop wipes our local copy.
    // The caller's foreign-side password buffer is THEIR concern.
}

/// Unlock a vault using its 24-word BIP-39 recovery phrase. Returns an
/// opaque handle that exposes non-secret accessors and an explicit `close()`.
///
/// The `mnemonic_bytes` input is UTF-8-encoded; the bridge calls
/// `std::str::from_utf8` and surfaces a malformed-UTF-8 input as
/// [`FfiUnlockError::InvalidMnemonic`] with `detail: "phrase contained
/// invalid UTF-8"`. Past that, `core::unlock::mnemonic::parse` does NFKD
/// normalization, lowercase, whitespace-collapse, BIP-39 wordlist lookup,
/// and checksum validation; the bridge does not duplicate any of that.
///
/// The input slice is borrowed; the bridge does not retain it. Wrapper-
/// side `Vec<u8>` zeroize is the binding-flavor crate's responsibility
/// (matches the B.2 password-input pattern).
///
/// # Errors
///
/// - [`FfiUnlockError::WrongMnemonicOrCorrupt`] — phrase is wrong, OR
///   one of the encrypted files has been tampered with. Indistinguishable
///   by design (anti-oracle property), parallel to
///   [`FfiUnlockError::WrongPasswordOrCorrupt`].
/// - [`FfiUnlockError::InvalidMnemonic`] — phrase failed BIP-39 validation
///   *before* any decryption was attempted (wrong word count, unknown
///   word, bad checksum, or invalid UTF-8 input).
/// - [`FfiUnlockError::VaultMismatch`] — `vault_toml_bytes` and
///   `identity_bundle_bytes` reference different vault UUIDs / timestamps.
/// - [`FfiUnlockError::CorruptVault`] — the inputs cannot be decoded as
///   well-formed v1 vault files.
pub fn open_with_recovery(
    vault_toml_bytes: &[u8],
    identity_bundle_bytes: &[u8],
    mnemonic_bytes: &[u8],
) -> Result<UnlockedIdentity, FfiUnlockError> {
    let mnemonic_str =
        std::str::from_utf8(mnemonic_bytes).map_err(|_| FfiUnlockError::InvalidMnemonic {
            detail: "phrase contained invalid UTF-8".to_string(),
        })?;
    let unlocked = secretary_core::unlock::open_with_recovery(
        vault_toml_bytes,
        identity_bundle_bytes,
        mnemonic_str,
    )?;
    Ok(UnlockedIdentity::new(unlocked))
    // mnemonic_str borrows from caller's slice; nothing to drop here.
    // The caller's foreign-side mnemonic buffer is THEIR concern (matches
    // the B.2 password-input pattern).
}

#[cfg(test)]
mod tests {
    use super::*;

    // Embed the on-disk fixtures via include_bytes! so the integration
    // tests don't depend on test-time filesystem layout.
    //
    // Cross-crate coupling: the relative paths reach across the workspace
    // into `core/tests/data/`. Acceptable for v1 (the fixture set is the
    // single source of truth and a path break fails at compile time, not
    // at runtime), but if we ever need to reuse fixtures from more than
    // one binding crate, the next step is a `secretary-core::testing`
    // module that re-exports the bytes — making the dependency explicit
    // rather than path-walked. Tracked as a future cleanup, not a v1
    // blocker.
    const VAULT_001_TOML: &[u8] =
        include_bytes!("../../../core/tests/data/golden_vault_001/vault.toml");
    const VAULT_001_BUNDLE: &[u8] =
        include_bytes!("../../../core/tests/data/golden_vault_001/identity.bundle.enc");
    const VAULT_002_BUNDLE: &[u8] =
        include_bytes!("../../../core/tests/data/golden_vault_002/identity.bundle.enc");

    /// Pinned 24-word BIP-39 recovery phrase for golden_vault_001.
    /// Source of truth: `core/tests/data/golden_vault_001_inputs.json`'s
    /// `recovery_mnemonic_phrase` field. The fixture builder asserts that
    /// field matches `bip39::Mnemonic::from_entropy(pinned_entropy).to_string()`,
    /// so this hardcoded copy stays honest as long as the JSON does. If
    /// the JSON drifts, the open_with_recovery_success test fails loudly
    /// with WrongMnemonicOrCorrupt.
    const VAULT_001_PHRASE: &[u8] = b"wall annual clay zebra cost cricket choose light small neck mimic season fix situate love asset dismiss online island disease turkey grab dish that";

    /// Pinned 24-word BIP-39 recovery phrase for golden_vault_002.
    /// Source of truth: `core/tests/data/golden_vault_002_inputs.json`'s
    /// `recovery_mnemonic_phrase` field. Same drift-detection invariant
    /// as `VAULT_001_PHRASE` — the fixture builder asserts the JSON pin
    /// matches `bip39::Mnemonic::from_entropy(pinned_entropy).to_string()`.
    const VAULT_002_PHRASE: &[u8] = b"debate pride tunnel elder caution media glass joke that rabbit mean write eager across furnace volume lawn cage decline fat path guess slogan hunt";

    const VAULT_001_PASSWORD: &[u8] = b"correct horse battery staple";
    const VAULT_001_OWNER_DISPLAY_NAME: &str = "Owner";
    /// Pinned KAT: hex `bf08a3300cd994b877e1a15baa28df35` from
    /// golden_vault_001_inputs.json. If this changes, all FFI smoke
    /// runners must update in the same commit.
    const VAULT_001_OWNER_USER_UUID: &[u8] = &[
        0xbf, 0x08, 0xa3, 0x30, 0x0c, 0xd9, 0x94, 0xb8, 0x77, 0xe1, 0xa1, 0x5b, 0xaa, 0x28, 0xdf,
        0x35,
    ];

    #[test]
    fn open_with_password_success_returns_unlocked_handle() {
        let id = open_with_password(VAULT_001_TOML, VAULT_001_BUNDLE, VAULT_001_PASSWORD)
            .expect("unlock should succeed");
        assert_eq!(id.display_name(), VAULT_001_OWNER_DISPLAY_NAME);
        assert_eq!(id.user_uuid(), VAULT_001_OWNER_USER_UUID);
    }

    #[test]
    fn open_with_password_wrong_password_returns_thinned_error() {
        let err = open_with_password(
            VAULT_001_TOML,
            VAULT_001_BUNDLE,
            b"definitely the wrong password",
        )
        .unwrap_err();
        assert!(matches!(err, FfiUnlockError::WrongPasswordOrCorrupt));
    }

    #[test]
    fn open_with_password_swapped_files_returns_vault_mismatch() {
        // vault_001's vault.toml + vault_002's identity.bundle.enc → cross-check
        // at core's vault_uuid + created_at_ms comparison fails before any KDF
        // work.
        let err =
            open_with_password(VAULT_001_TOML, VAULT_002_BUNDLE, VAULT_001_PASSWORD).unwrap_err();
        assert!(
            matches!(err, FfiUnlockError::VaultMismatch),
            "expected VaultMismatch, got {err:?}",
        );
    }

    #[test]
    fn open_with_password_truncated_vault_toml_returns_corrupt_vault() {
        // Slice off the last 50 bytes of vault.toml — produces invalid TOML.
        //
        // Why this is robust under v1: vault.toml is plain TOML and contains
        // no AEAD-framed payloads (those live in identity.bundle.enc). Any
        // truncation of vault.toml fails at TOML parse / required-field-
        // present checks long before reaching the AEAD step that produces
        // WrongPasswordOrCorrupt — so this test cannot accidentally fall
        // through into the wrong error variant for the current architecture.
        // If a future format places AEAD content in vault.toml, re-validate
        // this test (and its pytest / Swift / Kotlin siblings, which all
        // pin the same 50-byte distance).
        let truncated = &VAULT_001_TOML[..VAULT_001_TOML.len().saturating_sub(50)];
        let err = open_with_password(truncated, VAULT_001_BUNDLE, VAULT_001_PASSWORD).unwrap_err();
        assert!(
            matches!(err, FfiUnlockError::CorruptVault { .. }),
            "expected CorruptVault, got {err:?}",
        );
    }

    #[test]
    fn open_with_recovery_success_returns_unlocked_handle() {
        let id = open_with_recovery(VAULT_001_TOML, VAULT_001_BUNDLE, VAULT_001_PHRASE)
            .expect("recovery unlock should succeed against vault_001");
        // Same KAT as open_with_password_success — both unlock paths must
        // converge on byte-identical secret state (§3/§4 dual-KEK design).
        assert_eq!(id.display_name(), VAULT_001_OWNER_DISPLAY_NAME);
        assert_eq!(id.user_uuid(), VAULT_001_OWNER_USER_UUID);
    }

    #[test]
    fn open_with_recovery_wrong_mnemonic_returns_thinned_error() {
        // vault_002's phrase against vault_001's vault — valid 24-word phrase
        // but wrong vault, so AEAD-decrypt under recovery_kek tag-fails →
        // WrongMnemonicOrCorrupt (anti-oracle preserving).
        let err =
            open_with_recovery(VAULT_001_TOML, VAULT_001_BUNDLE, VAULT_002_PHRASE).unwrap_err();
        assert!(
            matches!(err, FfiUnlockError::WrongMnemonicOrCorrupt),
            "expected WrongMnemonicOrCorrupt, got {err:?}",
        );
    }

    #[test]
    fn open_with_recovery_wrong_length_returns_invalid_mnemonic() {
        let err =
            open_with_recovery(VAULT_001_TOML, VAULT_001_BUNDLE, b"only three words").unwrap_err();
        let FfiUnlockError::InvalidMnemonic { detail } = err else {
            panic!("expected InvalidMnemonic, got {err:?}");
        };
        assert!(
            detail.contains("got 3"),
            "detail did not carry word count: {detail}",
        );
    }

    #[test]
    fn open_with_recovery_invalid_utf8_returns_invalid_mnemonic() {
        // 0xFF is not valid UTF-8 in any byte position. The bridge's UTF-8
        // validation seam runs BEFORE the BIP-39 wordlist lookup so this
        // produces the bridge-specific "phrase contained invalid UTF-8"
        // detail rather than a wordlist failure.
        let bad_utf8 = [0xFFu8; 32];
        let err = open_with_recovery(VAULT_001_TOML, VAULT_001_BUNDLE, &bad_utf8).unwrap_err();
        let FfiUnlockError::InvalidMnemonic { detail } = err else {
            panic!("expected InvalidMnemonic, got {err:?}");
        };
        assert!(
            detail.contains("UTF-8"),
            "detail did not mention UTF-8: {detail}",
        );
    }

    #[test]
    fn open_with_recovery_swapped_files_returns_vault_mismatch() {
        // vault_001 toml + vault_002 bundle + vault_001 phrase →
        // VaultMismatch fires at core's vault_uuid + created_at_ms comparison
        // BEFORE the mnemonic is even parsed, so the mnemonic correctness
        // (or otherwise) is irrelevant to this assertion.
        let err =
            open_with_recovery(VAULT_001_TOML, VAULT_002_BUNDLE, VAULT_001_PHRASE).unwrap_err();
        assert!(
            matches!(err, FfiUnlockError::VaultMismatch),
            "expected VaultMismatch, got {err:?}",
        );
    }
}
