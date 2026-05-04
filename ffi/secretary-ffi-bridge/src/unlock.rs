//! `open_with_password` — fallible, secret-bearing operation: vault unlock
//! by master password.
//!
//! FFI-friendly wrapper around `secretary_core::unlock::open_with_password`.
//! Maps the `Result<core::UnlockedIdentity, core::UnlockError>` shape to
//! `Result<UnlockedIdentity, FfiUnlockError>` (thinned + opaque).
//!
//! The input password slice is wrapped in [`SecretBytes`], which zeroizes
//! on drop. The caller's foreign-side buffer is the caller's concern —
//! see the per-language READMEs for the documented discipline.

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
    let unlocked = secretary_core::unlock::open_with_password(
        vault_toml_bytes,
        identity_bundle_bytes,
        &pw,
    )?;
    Ok(UnlockedIdentity::new(unlocked))
    // pw drops here → SecretBytes ZeroizeOnDrop wipes our local copy.
    // The caller's foreign-side password buffer is THEIR concern.
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
    const VAULT_001_TOML: &[u8] = include_bytes!(
        "../../../core/tests/data/golden_vault_001/vault.toml"
    );
    const VAULT_001_BUNDLE: &[u8] = include_bytes!(
        "../../../core/tests/data/golden_vault_001/identity.bundle.enc"
    );
    const VAULT_002_BUNDLE: &[u8] = include_bytes!(
        "../../../core/tests/data/golden_vault_002/identity.bundle.enc"
    );

    const VAULT_001_PASSWORD: &[u8] = b"correct horse battery staple";
    const VAULT_001_OWNER_DISPLAY_NAME: &str = "Owner";
    /// Pinned KAT: hex `bf08a3300cd994b877e1a15baa28df35` from
    /// golden_vault_001_inputs.json. If this changes, all FFI smoke
    /// runners must update in the same commit.
    const VAULT_001_OWNER_USER_UUID: &[u8] = &[
        0xbf, 0x08, 0xa3, 0x30, 0x0c, 0xd9, 0x94, 0xb8,
        0x77, 0xe1, 0xa1, 0x5b, 0xaa, 0x28, 0xdf, 0x35,
    ];

    #[test]
    fn open_with_password_success_returns_unlocked_handle() {
        let id = open_with_password(
            VAULT_001_TOML, VAULT_001_BUNDLE, VAULT_001_PASSWORD,
        ).expect("unlock should succeed");
        assert_eq!(id.display_name(), VAULT_001_OWNER_DISPLAY_NAME);
        assert_eq!(id.user_uuid(), VAULT_001_OWNER_USER_UUID);
    }

    #[test]
    fn open_with_password_wrong_password_returns_thinned_error() {
        let err = open_with_password(
            VAULT_001_TOML, VAULT_001_BUNDLE, b"definitely the wrong password",
        ).unwrap_err();
        assert!(matches!(err, FfiUnlockError::WrongPasswordOrCorrupt));
    }

    #[test]
    fn open_with_password_swapped_files_returns_vault_mismatch() {
        // vault_001's vault.toml + vault_002's identity.bundle.enc → cross-check
        // at core's vault_uuid + created_at_ms comparison fails before any KDF
        // work.
        let err = open_with_password(
            VAULT_001_TOML, VAULT_002_BUNDLE, VAULT_001_PASSWORD,
        ).unwrap_err();
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
        let err = open_with_password(
            truncated, VAULT_001_BUNDLE, VAULT_001_PASSWORD,
        ).unwrap_err();
        assert!(
            matches!(err, FfiUnlockError::CorruptVault { .. }),
            "expected CorruptVault, got {err:?}",
        );
    }
}
