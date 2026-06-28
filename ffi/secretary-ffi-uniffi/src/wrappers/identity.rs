//! Identity-related opaque handles: `UnlockedIdentity`, `MnemonicOutput`,
//! and the `CreateVaultOutput` dictionary that holds them.

/// uniffi-side opaque handle. Newtype around bridge's `UnlockedIdentity`;
/// methods are thin forwarders. Drops on foreign refcount → 0 (RAII safety
/// net via uniffi's generated `AutoCloseable.close()` on Kotlin /
/// `deinit` on Swift) or via explicit `wipe()` (preferred — zeroizes
/// the wrapped secrets at exactly the moment of the call).
///
/// The explicit-zeroize method is named `wipe` rather than `close` to
/// avoid colliding with uniffi's auto-generated Kotlin
/// `AutoCloseable.close()`; see `secretary.udl` for the rationale.
pub struct UnlockedIdentity(pub(crate) secretary_ffi_bridge::UnlockedIdentity);

impl UnlockedIdentity {
    /// User-facing display name. Returns `""` if the handle has been wiped.
    pub fn display_name(&self) -> String {
        self.0.display_name()
    }

    /// 16-byte stable identifier. Returns 16 zero bytes if wiped.
    pub fn user_uuid(&self) -> Vec<u8> {
        self.0.user_uuid()
    }

    /// Drop the wrapped identity now, zeroizing all secret fields. Idempotent.
    ///
    /// Forwards to the bridge crate's `UnlockedIdentity::wipe()`. Every
    /// bridge-side handle exposes its explicit-zeroize method as `wipe()`
    /// (no `close()` remains on the bridge surface), so all six wrapper
    /// `wipe()` impls in this module call `self.0.wipe()` uniformly.
    pub fn wipe(&self) {
        self.0.wipe();
    }
}

/// uniffi-side opaque-handle wrapper around
/// `secretary_ffi_bridge::MnemonicOutput`. Newtype; methods are thin
/// forwarders.
///
/// One-shot semantics: `take_phrase()` returns `Some(bytes)` once, then
/// `None` on every subsequent call. `wipe()` is idempotent.
///
/// The explicit-zeroize method is named `wipe` rather than `close` for
/// the same reason as `UnlockedIdentity`: uniffi 0.31's Kotlin codegen
/// auto-generates an `AutoCloseable.close()` and a UDL-declared
/// `close()` would collide.
pub struct MnemonicOutput(pub(crate) secretary_ffi_bridge::MnemonicOutput);

impl MnemonicOutput {
    /// Take the recovery phrase as UTF-8 bytes. ONE-SHOT — second call
    /// returns `None`. Bytes are caller-owned heap; caller MUST zeroize
    /// after use.
    pub fn take_phrase(&self) -> Option<Vec<u8>> {
        self.0.take_phrase()
    }

    /// Drop any still-resident inner mnemonic now, zeroizing its
    /// `Sensitive<...>` fields. Idempotent.
    pub fn wipe(&self) {
        self.0.wipe();
    }
}

/// uniffi-side dictionary (struct-by-value) for `create_vault_in_folder`'s
/// return shape. One `Vec<u8>` (the 16-byte vault UUID, non-secret) plus one
/// `Arc<Interface>` (uniffi marshals interface-typed dictionary fields as
/// `Arc` handles).
pub struct CreatedVaultInFolder {
    /// 16-byte vault identifier from the freshly-written vault.toml.
    pub vault_uuid: Vec<u8>,
    /// One-shot opaque handle for the recovery phrase.
    pub mnemonic: std::sync::Arc<MnemonicOutput>,
}

/// uniffi-side dictionary (struct-by-value) for `create_vault`'s return
/// shape. Two `Vec<u8>` (non-secret) plus two `Arc<Interface>` (uniffi
/// marshals interface-typed dictionary fields as `Arc` handles).
pub struct CreateVaultOutput {
    /// Vault metadata bytes — non-secret. Persist atomically.
    pub vault_toml_bytes: Vec<u8>,
    /// Encrypted identity bundle bytes — non-secret. Persist atomically.
    pub identity_bundle_bytes: Vec<u8>,
    /// Live opaque handle to the just-created identity. Ready for vault
    /// operations immediately; no second `open_with_password` call needed.
    pub identity: std::sync::Arc<UnlockedIdentity>,
    /// One-shot opaque handle for the recovery phrase.
    pub mnemonic: std::sync::Arc<MnemonicOutput>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::namespace::create_vault;

    // -------------------------------------------------------------------
    // B.3b: uniffi-side projection of create_vault.
    //
    // The bridge crate already covers MnemonicOutput contract semantics
    // in isolation (one-shot take_phrase, idempotent wipe, 24-word phrase).
    // The two tests below pin the uniffi-layer wrapper plumbing only:
    // one slow integration test (real Argon2id) and one fast wrapper test
    // (synthesized MnemonicOutput, no Argon2id).
    // -------------------------------------------------------------------

    #[test]
    fn create_vault_returns_live_identity_and_mnemonic() {
        // Slow test: real Argon2id. ~1s. Sole uniffi-layer integration test
        // for create_vault; the bridge crate already covers MnemonicOutput
        // contract semantics in isolation.
        let out = create_vault(
            b"hunter2".to_vec(),
            "UniffiTest".to_string(),
            1_700_000_000_000,
        )
        .expect("create_vault should succeed");
        assert_eq!(out.identity.display_name(), "UniffiTest");
        assert_eq!(out.identity.user_uuid().len(), 16);
        assert!(!out.vault_toml_bytes.is_empty());
        assert!(!out.identity_bundle_bytes.is_empty());

        let phrase = out.mnemonic.take_phrase().expect("phrase available");
        assert_eq!(
            phrase.split(|&b| b == b' ').count(),
            24,
            "expected 24-word phrase",
        );

        let second = out.mnemonic.take_phrase();
        assert!(second.is_none(), "second take_phrase must return None");
    }

    #[test]
    fn mnemonic_output_wipe_is_idempotent_through_uniffi_wrapper() {
        // Fast test: synthesize a MnemonicOutput from a seeded mnemonic
        // generation. No Argon2id; checks the wrapper plumbing only.
        use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
        use secretary_core::unlock::mnemonic;
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let m = mnemonic::generate(&mut rng);
        let bridge_mo = secretary_ffi_bridge::MnemonicOutput::new_for_test(m);
        let mo = MnemonicOutput(bridge_mo);
        mo.wipe();
        mo.wipe(); // must not panic
        assert!(mo.take_phrase().is_none());
    }

    #[test]
    fn created_vault_in_folder_wrapper_one_shot_through_mnemonic() {
        // Fast test: synthesize a CreatedVaultInFolder with a known vault UUID
        // and a seeded MnemonicOutput. No Argon2id; checks wrapper plumbing only.
        use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
        use secretary_core::unlock::mnemonic;
        use std::sync::Arc;
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        let m = mnemonic::generate(&mut rng);
        let bridge_mo = secretary_ffi_bridge::MnemonicOutput::new_for_test(m);
        let known_uuid: Vec<u8> = (0u8..16).collect();
        let out = CreatedVaultInFolder {
            vault_uuid: known_uuid.clone(),
            mnemonic: Arc::new(MnemonicOutput(bridge_mo)),
        };
        assert_eq!(out.vault_uuid.len(), 16);
        assert_eq!(out.vault_uuid, known_uuid);
        let phrase = out.mnemonic.take_phrase();
        assert!(phrase.is_some(), "first take_phrase must return Some");
        let second = out.mnemonic.take_phrase();
        assert!(second.is_none(), "second take_phrase must return None (one-shot)");
    }
}
