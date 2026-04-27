//! Master-password and recovery-key unlock paths.
//! See `docs/crypto-design.md` §3 (Master KEK), §4 (Recovery KEK), §5 (Identity Bundle wrap)
//! and `docs/vault-format.md` §2 (vault.toml), §3 (identity.bundle.enc).

pub mod bundle;
pub mod bundle_file;
pub mod mnemonic;
pub mod vault_toml;

use core::fmt;
use rand_core::{CryptoRng, RngCore};

use crate::crypto::aead::{decrypt, encrypt, AeadError};
use crate::crypto::kdf::{
    derive_master_kek, derive_recovery_kek, Argon2idParams, KdfError, TAG_ID_BUNDLE,
    TAG_ID_WRAP_PW, TAG_ID_WRAP_REC,
};
use crate::crypto::secret::{SecretBytes, Sensitive};

#[derive(Debug, thiserror::Error)]
pub enum UnlockError {
    #[error("wrong password or vault corruption")]
    WrongPasswordOrCorrupt,
    #[error("wrong recovery mnemonic or vault corruption")]
    WrongMnemonicOrCorrupt,
    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(#[from] mnemonic::MnemonicError),
    #[error("vault data integrity failure")]
    CorruptVault,
    #[error("vault.toml and identity.bundle.enc reference different vaults")]
    VaultMismatch,

    #[error("malformed vault.toml: {0}")]
    MalformedVaultToml(#[from] vault_toml::VaultTomlError),
    #[error("malformed identity.bundle.enc: {0}")]
    MalformedBundleFile(#[from] bundle_file::BundleFileError),
    #[error("malformed identity bundle plaintext: {0}")]
    MalformedBundle(#[from] bundle::BundleError),

    #[error("KDF failure: {0}")]
    KdfFailure(#[from] KdfError),
    #[error("AEAD primitive failure")]
    AeadFailure,
}

impl From<AeadError> for UnlockError {
    fn from(_: AeadError) -> Self {
        // AEAD primitive errors collapse to AeadFailure — see spec §Error model.
        // Position-specific user-facing variants (WrongPasswordOrCorrupt etc.)
        // are produced explicitly at call sites, not via From.
        UnlockError::AeadFailure
    }
}

// ---------------------------------------------------------------------------
// create_vault output types
// ---------------------------------------------------------------------------

pub struct CreatedVault {
    pub vault_toml_bytes: Vec<u8>,
    pub identity_bundle_bytes: Vec<u8>,
    pub recovery_mnemonic: mnemonic::Mnemonic,
    pub identity_block_key: Sensitive<[u8; 32]>,
    pub identity: bundle::IdentityBundle,
}

pub struct UnlockedIdentity {
    pub identity_block_key: Sensitive<[u8; 32]>,
    pub identity: bundle::IdentityBundle,
}

/// Redacted Debug for CreatedVault — mirrors IdentityBundle / Mnemonic policy.
/// Secret fields are replaced with `<redacted>`; byte-vector lengths and the
/// non-secret display_name are shown so logs remain useful.
impl fmt::Debug for CreatedVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreatedVault")
            .field("vault_toml_bytes_len", &self.vault_toml_bytes.len())
            .field("identity_bundle_bytes_len", &self.identity_bundle_bytes.len())
            .field("recovery_mnemonic", &self.recovery_mnemonic) // delegates to Mnemonic's redacting Debug
            .field("identity_block_key", &"<redacted>")
            .field("identity", &self.identity) // delegates to IdentityBundle's redacting Debug
            .finish()
    }
}

/// Redacted Debug for UnlockedIdentity — same no-leak-via-Debug policy as
/// CreatedVault; the identity_block_key is the symmetric root secret.
impl fmt::Debug for UnlockedIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnlockedIdentity")
            .field("identity_block_key", &"<redacted>")
            .field("identity", &self.identity)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// create_vault orchestrator (§3 Master KEK, §4 Recovery KEK, §5 bundle wrap)
// ---------------------------------------------------------------------------

pub fn create_vault(
    password: &SecretBytes,
    display_name: &str,
    created_at_ms: u64,
    kdf_params: Argon2idParams,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<CreatedVault, UnlockError> {
    // Step 1: identifiers and salt
    let mut vault_uuid = [0u8; 16];
    rng.fill_bytes(&mut vault_uuid);
    let mut argon2_salt = [0u8; 32];
    rng.fill_bytes(&mut argon2_salt);

    // Step 2: Master KEK
    let master_kek = derive_master_kek(password, &argon2_salt, &kdf_params)?;

    // Step 3: mnemonic + Recovery KEK
    let recovery_mnemonic = mnemonic::generate(rng);
    let recovery_kek = derive_recovery_kek(recovery_mnemonic.entropy());

    // Step 4: Identity Block Key — fresh CSPRNG bytes wrapped in Sensitive.
    // SECURITY: rng.fill_bytes writes into a stack array, then Sensitive::new
    // MOVES that array into the Sensitive wrapper — the original stack slot
    // is logically dead but its bytes are not zeroized. This is a known Rust
    // limitation (no MaybeUninit-aware fill_bytes). The Sensitive wrapper's
    // Drop impl handles zeroization for the wrapped copy; the residual stack
    // bytes persist briefly until the next stack frame overwrites them.
    // Same pattern as bundle::generate's Identity Bundle keys.
    let mut ibk = [0u8; 32];
    rng.fill_bytes(&mut ibk);
    let identity_block_key = Sensitive::new(ibk);

    // Step 5: generate identity + canonical CBOR
    let identity = bundle::generate(display_name, created_at_ms, rng);
    let bundle_plaintext = identity.to_canonical_cbor()?;

    // Step 6: three independent 24-byte AEAD nonces — one per AEAD call below.
    // Each key (IBK, master_kek, recovery_kek) is used exactly once, but
    // independent draws make the "never reuse nonce+key" §13 mandate visible
    // rather than implicit, and survive future refactors that might share keys.
    let mut nonce_id = [0u8; 24];
    rng.fill_bytes(&mut nonce_id);
    let mut nonce_pw = [0u8; 24];
    rng.fill_bytes(&mut nonce_pw);
    let mut nonce_rec = [0u8; 24];
    rng.fill_bytes(&mut nonce_rec);

    // Step 7: AEAD-encrypt bundle under IBK.
    // identity_block_key: Sensitive<[u8;32]> == AeadKey, pass by reference.
    let bundle_aad = compose_aad(TAG_ID_BUNDLE, &vault_uuid);
    let bundle_ct_with_tag = encrypt(&identity_block_key, &nonce_id, &bundle_aad, &bundle_plaintext)?;

    // Step 8: wrap_pw — AEAD-encrypt the IBK bytes under master_kek.
    // identity_block_key.expose() -> &[u8; 32] coerces to &[u8] (plaintext).
    let wrap_pw_aad = compose_aad(TAG_ID_WRAP_PW, &vault_uuid);
    let wrap_pw_with_tag = encrypt(
        &master_kek,
        &nonce_pw,
        &wrap_pw_aad,
        identity_block_key.expose(),
    )?;
    let wrap_pw_arr: [u8; 48] = wrap_pw_with_tag
        .as_slice()
        .try_into()
        .expect("32-byte plaintext + 16-byte tag = 48 bytes");

    // Step 9: wrap_rec — AEAD-encrypt the IBK bytes under recovery_kek.
    let wrap_rec_aad = compose_aad(TAG_ID_WRAP_REC, &vault_uuid);
    let wrap_rec_with_tag = encrypt(
        &recovery_kek,
        &nonce_rec,
        &wrap_rec_aad,
        identity_block_key.expose(),
    )?;
    let wrap_rec_arr: [u8; 48] = wrap_rec_with_tag
        .as_slice()
        .try_into()
        .expect("32-byte plaintext + 16-byte tag = 48 bytes");

    // Step 10: pack into BundleFile → identity_bundle_bytes
    let bf = bundle_file::BundleFile {
        vault_uuid,
        created_at_ms,
        wrap_pw_nonce: nonce_pw,
        wrap_pw_ct_with_tag: wrap_pw_arr,
        wrap_rec_nonce: nonce_rec,
        wrap_rec_ct_with_tag: wrap_rec_arr,
        bundle_nonce: nonce_id,
        bundle_ct_with_tag,
    };
    let identity_bundle_bytes = bundle_file::encode(&bf);

    // Step 11: emit vault.toml (§2) — KDF params mirror kdf_params so the
    // vault is portable across devices that open with derive_master_kek (§3).
    let vt = vault_toml::VaultToml {
        format_version: 1,
        suite_id: 1,
        vault_uuid,
        created_at_ms,
        kdf: vault_toml::KdfSection {
            algorithm: "argon2id".to_string(),
            version: "1.3".to_string(),
            memory_kib: kdf_params.memory_kib,
            iterations: kdf_params.iterations,
            parallelism: kdf_params.parallelism,
            salt: argon2_salt,
        },
    };
    let vault_toml_bytes = vault_toml::encode(&vt).into_bytes();

    // master_kek and recovery_kek go out of scope here → Sensitive Drop zeroizes.

    Ok(CreatedVault {
        vault_toml_bytes,
        identity_bundle_bytes,
        recovery_mnemonic,
        identity_block_key,
        identity,
    })
}

/// Concatenate a domain-separation tag with a vault UUID to form the AEAD AAD.
fn compose_aad(tag: &[u8], vault_uuid: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tag.len() + vault_uuid.len());
    out.extend_from_slice(tag);
    out.extend_from_slice(vault_uuid);
    out
}

/// Construct the layered error returned when vault.toml bytes aren't UTF-8.
/// Used by both open paths; the underlying `MalformedToml` variant is the
/// right inner error since "non-UTF-8 bytes" is a parse failure, not a
/// missing field.
fn vault_toml_not_utf8() -> UnlockError {
    UnlockError::MalformedVaultToml(vault_toml::VaultTomlError::MalformedToml(
        "non-UTF-8 input".to_string(),
    ))
}

// ---------------------------------------------------------------------------
// open_with_password (§3 Master KEK unlock path)
// ---------------------------------------------------------------------------

pub fn open_with_password(
    vault_toml_bytes: &[u8],
    identity_bundle_bytes: &[u8],
    password: &SecretBytes,
) -> Result<UnlockedIdentity, UnlockError> {
    // Step 1: parse vault.toml. Reject non-UTF-8 input cleanly rather than
    // letting it surface as a `MalformedVaultToml(MalformedToml(...))`
    // double-wrap — the underlying VaultTomlError's MalformedToml carries
    // a String, but the codebase uses MissingField / UnsupportedXxx for
    // structured errors, leaving MalformedToml for genuine parse failures.
    // Non-UTF-8 input IS a parse failure, so the inner MalformedToml is
    // appropriate here.
    let vt_str = std::str::from_utf8(vault_toml_bytes).map_err(|_| vault_toml_not_utf8())?;
    let vt = vault_toml::decode(vt_str)?;

    // Step 2: parse identity.bundle.enc; check vault_uuid match across both files.
    let bf = bundle_file::decode(identity_bundle_bytes)?;
    if bf.vault_uuid != vt.vault_uuid {
        return Err(UnlockError::VaultMismatch);
    }

    // Step 3: derive Master KEK using parameters from vault.toml.
    let kdf_params = Argon2idParams::new(vt.kdf.memory_kib, vt.kdf.iterations, vt.kdf.parallelism);
    let master_kek = derive_master_kek(password, &vt.kdf.salt, &kdf_params)?;

    // Step 4: AEAD-decrypt wrap_pw → IBK bytes. AEAD failure here means
    // wrong password (or vault corruption — indistinguishable on auth-tag
    // failure, which is the design for §13's "wrong key looks like
    // corruption to crypto" property). UI surfaces this as wrong-password.
    let wrap_pw_aad = compose_aad(TAG_ID_WRAP_PW, &vt.vault_uuid);
    let ibk_bytes = decrypt(
        &master_kek,
        &bf.wrap_pw_nonce,
        &wrap_pw_aad,
        &bf.wrap_pw_ct_with_tag,
    )
    .map_err(|_| UnlockError::WrongPasswordOrCorrupt)?;

    // ibk_bytes is SecretBytes wrapping a Vec<u8>. The wrap_pw plaintext
    // is exactly 32 bytes (an IBK). Anything else is a corrupt vault.
    // SECURITY: ibk_arr leaves a residual copy of the IBK on the stack after
    // Sensitive::new moves it. Same limitation as create_vault's IBK
    // construction — see the SECURITY note there for details.
    let ibk_arr: [u8; 32] = ibk_bytes.expose().try_into()
        .map_err(|_| UnlockError::CorruptVault)?;
    let identity_block_key = Sensitive::new(ibk_arr);

    // Step 5: AEAD-decrypt the bundle plaintext under the IBK. AEAD failure
    // here is post-IBK-recovery: any failure is unequivocally corruption,
    // not user error.
    let bundle_aad = compose_aad(TAG_ID_BUNDLE, &vt.vault_uuid);
    let bundle_plaintext = decrypt(
        &identity_block_key,
        &bf.bundle_nonce,
        &bundle_aad,
        &bf.bundle_ct_with_tag,
    )
    .map_err(|_| UnlockError::CorruptVault)?;

    // Step 6: CBOR decode (the From<BundleError> impl maps malformed CBOR cleanly).
    let identity = bundle::IdentityBundle::from_canonical_cbor(bundle_plaintext.expose())?;

    Ok(UnlockedIdentity { identity_block_key, identity })
}

// ---------------------------------------------------------------------------
// open_with_recovery (§4 Recovery KEK unlock path)
// ---------------------------------------------------------------------------

pub fn open_with_recovery(
    vault_toml_bytes: &[u8],
    identity_bundle_bytes: &[u8],
    mnemonic_words: &str,
) -> Result<UnlockedIdentity, UnlockError> {
    // Steps 1-2: vault.toml + bundle file (mirror open_with_password)
    let vt_str = std::str::from_utf8(vault_toml_bytes).map_err(|_| vault_toml_not_utf8())?;
    let vt = vault_toml::decode(vt_str)?;
    let bf = bundle_file::decode(identity_bundle_bytes)?;
    if bf.vault_uuid != vt.vault_uuid {
        return Err(UnlockError::VaultMismatch);
    }

    // Step 3: parse mnemonic. Bad word-count / unknown word / bad checksum
    // surfaces as InvalidMnemonic via the From impl — distinct from
    // WrongMnemonicOrCorrupt because the failure mode is "this isn't a
    // valid BIP-39 phrase at all" rather than "valid phrase, wrong vault."
    let parsed_mnemonic = mnemonic::parse(mnemonic_words)?;

    // Step 4: derive Recovery KEK from the parsed entropy.
    let recovery_kek = derive_recovery_kek(parsed_mnemonic.entropy());

    // Step 5: AEAD-decrypt wrap_rec → IBK bytes. AEAD failure here means wrong
    // mnemonic (or vault corruption — indistinguishable on auth-tag failure,
    // matching the §13 "wrong key looks like corruption" property). UI surfaces
    // this as wrong-mnemonic.
    let wrap_rec_aad = compose_aad(TAG_ID_WRAP_REC, &vt.vault_uuid);
    let ibk_bytes = decrypt(
        &recovery_kek,
        &bf.wrap_rec_nonce,
        &wrap_rec_aad,
        &bf.wrap_rec_ct_with_tag,
    )
    .map_err(|_| UnlockError::WrongMnemonicOrCorrupt)?;

    // SECURITY: ibk_arr leaves a residual copy of the IBK on the stack after
    // Sensitive::new moves it. Same limitation as create_vault's IBK
    // construction — see the SECURITY note there for details.
    let ibk_arr: [u8; 32] = ibk_bytes.expose().try_into()
        .map_err(|_| UnlockError::CorruptVault)?;
    let identity_block_key = Sensitive::new(ibk_arr);

    // Step 6: AEAD-decrypt the bundle plaintext under IBK. Post-IBK-recovery
    // failure is unequivocally tampering, not user error.
    let bundle_aad = compose_aad(TAG_ID_BUNDLE, &vt.vault_uuid);
    let bundle_plaintext = decrypt(
        &identity_block_key,
        &bf.bundle_nonce,
        &bundle_aad,
        &bf.bundle_ct_with_tag,
    )
    .map_err(|_| UnlockError::CorruptVault)?;

    let identity = bundle::IdentityBundle::from_canonical_cbor(bundle_plaintext.expose())?;
    Ok(UnlockedIdentity { identity_block_key, identity })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod create_tests {
    use super::*;
    // NOTE: Argon2idParams is visible here via `super::*` because it is imported
    // at module scope in mod.rs (`use crate::crypto::kdf::{..., Argon2idParams, ...}`).
    // The explicit `use crate::crypto::kdf::Argon2idParams` import was therefore
    // redundant and has been removed.
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    #[test]
    fn create_then_open_with_password_roundtrips() {
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let password = SecretBytes::new(b"hunter2".to_vec());
        let params = Argon2idParams::new(8, 1, 1);
        let v = create_vault(&password, "Alice", 0, params, &mut rng).unwrap();

        let opened = open_with_password(&v.vault_toml_bytes, &v.identity_bundle_bytes, &password)
            .expect("open");
        assert_eq!(opened.identity_block_key.expose(), v.identity_block_key.expose());
        assert_eq!(opened.identity.user_uuid, v.identity.user_uuid);
        assert_eq!(opened.identity.display_name, v.identity.display_name);
        assert_eq!(opened.identity.x25519_sk.expose(), v.identity.x25519_sk.expose());
    }

    #[test]
    fn open_with_wrong_password_returns_wrong_password_or_corrupt() {
        let mut rng = ChaCha20Rng::from_seed([8u8; 32]);
        let password = SecretBytes::new(b"hunter2".to_vec());
        let params = Argon2idParams::new(8, 1, 1);
        let v = create_vault(&password, "Alice", 0, params, &mut rng).unwrap();

        let bad = SecretBytes::new(b"hunter3".to_vec());
        let err = open_with_password(&v.vault_toml_bytes, &v.identity_bundle_bytes, &bad)
            .unwrap_err();
        assert!(matches!(err, UnlockError::WrongPasswordOrCorrupt));
    }

    #[test]
    fn create_vault_produces_well_formed_artifacts() {
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        // Use minimal Argon2id params for test speed (memory floor relaxed via ::new).
        let params = Argon2idParams::new(8, 1, 1);
        let v = create_vault(&password, "Alice", 1_714_060_800_000, params, &mut rng)
            .expect("create_vault");
        assert!(!v.vault_toml_bytes.is_empty());
        assert!(!v.identity_bundle_bytes.is_empty());
        assert_eq!(v.recovery_mnemonic.phrase().split_whitespace().count(), 24);
        assert_eq!(v.identity.display_name, "Alice");

        // Confirm vault_toml_bytes parses back to valid TOML with our kdf params.
        let parsed_vt = vault_toml::decode(
            std::str::from_utf8(&v.vault_toml_bytes).expect("vault_toml is utf-8"),
        )
        .expect("vault_toml decode");
        assert_eq!(parsed_vt.kdf.memory_kib, 8);
        assert_eq!(parsed_vt.kdf.iterations, 1);
        assert_eq!(parsed_vt.kdf.parallelism, 1);
        assert_eq!(parsed_vt.format_version, 1);
        assert_eq!(parsed_vt.suite_id, 1);
    }

    #[test]
    fn create_then_open_with_recovery_roundtrips() {
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        let password = SecretBytes::new(b"hunter2".to_vec());
        let params = Argon2idParams::new(8, 1, 1);
        let v = create_vault(&password, "Alice", 0, params, &mut rng).unwrap();

        let words = v.recovery_mnemonic.phrase().to_string();
        let opened = open_with_recovery(&v.vault_toml_bytes, &v.identity_bundle_bytes, &words)
            .expect("open");
        assert_eq!(opened.identity_block_key.expose(), v.identity_block_key.expose());
        assert_eq!(opened.identity.user_uuid, v.identity.user_uuid);
        assert_eq!(opened.identity.display_name, v.identity.display_name);
        assert_eq!(opened.identity.x25519_sk.expose(), v.identity.x25519_sk.expose());
    }

    #[test]
    fn open_with_wrong_mnemonic_returns_wrong_mnemonic_or_corrupt() {
        let mut rng = ChaCha20Rng::from_seed([10u8; 32]);
        let password = SecretBytes::new(b"hunter2".to_vec());
        let params = Argon2idParams::new(8, 1, 1);
        let v = create_vault(&password, "Alice", 0, params, &mut rng).unwrap();

        // A different fresh mnemonic — valid checksum, just not this vault's.
        let mut other_rng = ChaCha20Rng::from_seed([99u8; 32]);
        let other = mnemonic::generate(&mut other_rng);
        let err = open_with_recovery(&v.vault_toml_bytes, &v.identity_bundle_bytes, other.phrase())
            .unwrap_err();
        assert!(matches!(err, UnlockError::WrongMnemonicOrCorrupt));
    }

    #[test]
    fn open_with_invalid_mnemonic_returns_invalid_mnemonic() {
        let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
        let v = create_vault(
            &SecretBytes::new(b"x".to_vec()), "Alice", 0,
            Argon2idParams::new(8, 1, 1), &mut rng,
        ).unwrap();
        let err = open_with_recovery(&v.vault_toml_bytes, &v.identity_bundle_bytes, "abandon abandon")
            .unwrap_err();
        assert!(matches!(err, UnlockError::InvalidMnemonic(mnemonic::MnemonicError::WrongLength { .. })));
    }

    #[test]
    fn both_unlock_paths_yield_same_identity_block_key() {
        let mut rng = ChaCha20Rng::from_seed([12u8; 32]);
        let password = SecretBytes::new(b"hunter2".to_vec());
        let v = create_vault(&password, "Alice", 0, Argon2idParams::new(8, 1, 1), &mut rng).unwrap();

        let by_pw = open_with_password(&v.vault_toml_bytes, &v.identity_bundle_bytes, &password).unwrap();
        let by_rec = open_with_recovery(&v.vault_toml_bytes, &v.identity_bundle_bytes, v.recovery_mnemonic.phrase()).unwrap();
        assert_eq!(by_pw.identity_block_key.expose(), by_rec.identity_block_key.expose());
    }
}
