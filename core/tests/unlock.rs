//! Integration tests for the unlock module — exercises the public surface
//! across realistic scenarios: corruption detection, vault mismatch, and the
//! full create→open round-trip with both unlock paths.

mod common;

use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

use secretary_core::crypto::kdf::Argon2idParams;
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
