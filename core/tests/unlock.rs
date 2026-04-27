//! Integration tests for the unlock module — exercises the public surface
//! across realistic scenarios: corruption detection, vault mismatch, and the
//! full create→open round-trip with both unlock paths.

mod common;

use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

use secretary_core::crypto::kdf::{Argon2idParams, derive_recovery_kek, TAG_RECOVERY_KEK};
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::unlock::{
    self, bundle_file, create_vault, open_with_password, open_with_recovery, UnlockError,
};

fn fast_params() -> Argon2idParams {
    // Below v1 floor — only legal via Argon2idParams::new (not try_new_v1).
    // Used here to keep tests fast (~ms instead of seconds).
    Argon2idParams::new(8, 1, 1)
}

fn create(seed: u8, pw: &[u8]) -> unlock::CreatedVault {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    create_vault(
        &SecretBytes::new(pw.to_vec()),
        "Alice",
        1_714_060_800_000,
        fast_params(),
        &mut rng,
    )
    .expect("create_vault")
}

#[test]
fn flipped_bundle_ct_byte_returns_corrupt_vault() {
    let pw = b"hunter2";
    let v = create(1, pw);

    // Decode the bundle file, flip a byte deep in bundle_ct_with_tag, re-encode.
    let mut bf = bundle_file::decode(&v.identity_bundle_bytes).unwrap();
    let mid = bf.bundle_ct_with_tag.len() / 2;
    bf.bundle_ct_with_tag[mid] ^= 0xFF;
    let tampered = bundle_file::encode(&bf);

    let err = open_with_password(&v.vault_toml_bytes, &tampered, &SecretBytes::new(pw.to_vec()))
        .unwrap_err();
    // wrap_pw decrypts fine (we didn't touch it) → bundle AEAD fails →
    // CorruptVault.
    assert!(matches!(err, UnlockError::CorruptVault));
}

#[test]
fn swapped_bundle_file_returns_vault_mismatch() {
    let pw = b"hunter2";
    let a = create(1, pw);
    let b = create(2, pw);

    // Open vault A's vault.toml with vault B's identity.bundle.enc.
    let err = open_with_password(
        &a.vault_toml_bytes,
        &b.identity_bundle_bytes,
        &SecretBytes::new(pw.to_vec()),
    )
    .unwrap_err();
    assert!(matches!(err, UnlockError::VaultMismatch));
}

#[test]
fn mismatched_created_at_ms_returns_vault_mismatch() {
    // Tamper the bundle file's created_at_ms while leaving vault_uuid intact —
    // the cross-check should reject this as a swap-like attack on the
    // cleartext vault.toml metadata.
    let pw = b"hunter2";
    let v = create(7, pw);

    let mut bf = bundle_file::decode(&v.identity_bundle_bytes).unwrap();
    bf.created_at_ms = bf.created_at_ms.wrapping_add(1);
    let tampered = bundle_file::encode(&bf);

    let err = open_with_password(
        &v.vault_toml_bytes,
        &tampered,
        &SecretBytes::new(pw.to_vec()),
    )
    .unwrap_err();
    assert!(matches!(err, UnlockError::VaultMismatch));
}

#[test]
fn mnemonic_not_24_words_returns_invalid_mnemonic() {
    let v = create(3, b"x");
    let err = open_with_recovery(
        &v.vault_toml_bytes,
        &v.identity_bundle_bytes,
        "abandon abandon abandon",
    )
    .unwrap_err();
    assert!(matches!(err, UnlockError::InvalidMnemonic(_)));
}

#[test]
fn flipped_bundle_ct_byte_returns_corrupt_vault_via_recovery() {
    let pw = b"hunter2";
    let v = create(4, pw);

    let mut bf = bundle_file::decode(&v.identity_bundle_bytes).unwrap();
    let mid = bf.bundle_ct_with_tag.len() / 2;
    bf.bundle_ct_with_tag[mid] ^= 0xFF;
    let tampered = bundle_file::encode(&bf);

    let err = open_with_recovery(
        &v.vault_toml_bytes,
        &tampered,
        v.recovery_mnemonic.phrase(),
    ).unwrap_err();
    // wrap_rec decrypts fine → bundle AEAD fails → CorruptVault.
    assert!(matches!(err, UnlockError::CorruptVault));
}

#[test]
fn non_utf8_vault_toml_returns_malformed_vault_toml() {
    use secretary_core::unlock::vault_toml::VaultTomlError;

    // Create a valid vault, then submit garbage non-UTF-8 bytes as vault.toml.
    let v = create(5, b"hunter2");
    let invalid: &[u8] = &[0xFF, 0xFE, 0x00, 0x80];

    let err = open_with_password(invalid, &v.identity_bundle_bytes, &SecretBytes::new(b"hunter2".to_vec()))
        .unwrap_err();
    assert!(matches!(
        err,
        UnlockError::MalformedVaultToml(VaultTomlError::MalformedToml(ref m)) if m.contains("non-UTF-8")
    ));
}

#[test]
fn bip39_recovery_kat_vectors() {
    use common::{load_kat, Bip39RecoveryKat};
    use secretary_core::crypto::secret::Sensitive;
    use secretary_core::unlock::mnemonic;

    let kat: Bip39RecoveryKat = load_kat("bip39_recovery_kat.json");
    assert!(!kat.vectors.is_empty(), "KAT file has no vectors");
    for v in &kat.vectors {
        // Pin 1: mnemonic → entropy (BIP-39 English wordlist + checksum).
        let parsed = mnemonic::parse(&v.mnemonic).unwrap_or_else(|e| {
            panic!("vector {}: parse failed: {e}", v.name)
        });
        assert_eq!(
            parsed.entropy().expose(), &v.entropy,
            "vector {}: mnemonic→entropy mismatch", v.name,
        );

        // Pin 2: info_tag is exactly TAG_RECOVERY_KEK bytes.
        assert_eq!(
            v.info_tag, TAG_RECOVERY_KEK,
            "vector {}: info_tag does not match TAG_RECOVERY_KEK", v.name,
        );

        // Pin 3: entropy → recovery_kek (HKDF-SHA-256, 32-zero-byte salt, info=tag).
        let kek = derive_recovery_kek(&Sensitive::new(v.entropy));
        assert_eq!(
            kek.expose(), &v.expected_recovery_kek,
            "vector {}: HKDF output mismatch", v.name,
        );
    }
}
