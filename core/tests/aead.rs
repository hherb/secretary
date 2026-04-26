//! XChaCha20-Poly1305 AEAD wrapper integration tests.

mod common;
use common::{load_kat, XChaCha20Poly1305Kat};

use secretary_core::crypto::aead::{decrypt, encrypt, AeadError, AeadKey, AeadNonce, AEAD_TAG_LEN};
use secretary_core::crypto::secret::Sensitive;

fn key_from(bytes: [u8; 32]) -> AeadKey {
    Sensitive::new(bytes)
}

#[test]
fn roundtrip_basic() {
    let key = key_from([0x11; 32]);
    let nonce: AeadNonce = [0x22; 24];
    let plaintext = b"hello, world";
    let ct = encrypt(&key, &nonce, b"", plaintext).expect("encrypt");
    // Output is plaintext length + tag.
    assert_eq!(ct.len(), plaintext.len() + AEAD_TAG_LEN);

    let pt = decrypt(&key, &nonce, b"", &ct).expect("decrypt");
    assert_eq!(pt.expose(), plaintext);
}

#[test]
fn roundtrip_with_aad() {
    let key = key_from([0x33; 32]);
    let nonce: AeadNonce = [0x44; 24];
    let plaintext = b"some plaintext payload";
    let aad = b"secretary-v1-id-bundle\x00\x00\x00\x00";

    let ct = encrypt(&key, &nonce, aad, plaintext).expect("encrypt");
    let pt = decrypt(&key, &nonce, aad, &ct).expect("decrypt");
    assert_eq!(pt.expose(), plaintext);
}

// Contract test name from threat-model §5. Do not rename without updating
// the threat model.
#[test]
fn test_aead_decrypt_with_wrong_key_fails() {
    let key_a = key_from([0xAA; 32]);
    let key_b = key_from([0xBB; 32]);
    let nonce: AeadNonce = [0; 24];
    let ct = encrypt(&key_a, &nonce, b"", b"secret message").expect("encrypt");
    let err = decrypt(&key_b, &nonce, b"", &ct).unwrap_err();
    assert!(matches!(err, AeadError::Decryption));
}

#[test]
fn wrong_aad_fails() {
    let key = key_from([0x55; 32]);
    let nonce: AeadNonce = [1; 24];
    let ct = encrypt(&key, &nonce, b"aad-one", b"plaintext").expect("encrypt");
    let err = decrypt(&key, &nonce, b"aad-two", &ct).unwrap_err();
    assert!(matches!(err, AeadError::Decryption));
}

#[test]
fn wrong_nonce_fails() {
    let key = key_from([0x66; 32]);
    let nonce_a: AeadNonce = [0xAB; 24];
    let mut nonce_b = nonce_a;
    nonce_b[0] ^= 0x01;
    let ct = encrypt(&key, &nonce_a, b"", b"plaintext").expect("encrypt");
    let err = decrypt(&key, &nonce_b, b"", &ct).unwrap_err();
    assert!(matches!(err, AeadError::Decryption));
}

#[test]
fn tampered_ciphertext_fails() {
    let key = key_from([0x77; 32]);
    let nonce: AeadNonce = [0x88; 24];
    let mut ct = encrypt(&key, &nonce, b"", b"original plaintext").expect("encrypt");
    // Flip one bit in the ciphertext (not the tag) — verification must fail.
    ct[0] ^= 0x01;
    let err = decrypt(&key, &nonce, b"", &ct).unwrap_err();
    assert!(matches!(err, AeadError::Decryption));
}

// Contract test name from threat-model §5. Do not rename without updating
// the threat model.
#[test]
fn test_aead_tag_failure_on_byte_flip() {
    let key = key_from([0x99; 32]);
    let nonce: AeadNonce = [0xAA; 24];
    let mut ct = encrypt(&key, &nonce, b"", b"abc").expect("encrypt");
    // Flip last byte (inside the Poly1305 tag).
    let last = ct.len() - 1;
    ct[last] ^= 0x01;
    let err = decrypt(&key, &nonce, b"", &ct).unwrap_err();
    assert!(matches!(err, AeadError::Decryption));
}

// ---------------------------------------------------------------------------
// Edge cases — empty plaintext and all-zero key. Both can break naive
// wrappers ("len > 0" assumptions, "zero key means uninitialized → error"
// defensive code). XChaCha20-Poly1305 has no such restrictions; pin that.
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_empty_plaintext() {
    let key = key_from([0x44; 32]);
    let nonce: AeadNonce = [0x55; 24];
    let ct = encrypt(&key, &nonce, b"some-aad", b"").expect("encrypt empty");
    // Output is just the 16-byte tag.
    assert_eq!(ct.len(), AEAD_TAG_LEN);

    let pt = decrypt(&key, &nonce, b"some-aad", &ct).expect("decrypt empty");
    assert_eq!(pt.expose(), b"");
}

#[test]
fn roundtrip_all_zero_key() {
    // A zero key is not a real-world concern (the CSPRNG never produces one
    // with non-negligible probability), but pinning the round-trip guards
    // against accidental "zero == uninitialized → return error" logic in
    // future wrappers.
    let key = key_from([0u8; 32]);
    let nonce: AeadNonce = [0xEE; 24];
    let ct = encrypt(&key, &nonce, b"", b"hello").expect("encrypt");
    let pt = decrypt(&key, &nonce, b"", &ct).expect("decrypt");
    assert_eq!(pt.expose(), b"hello");
}

#[test]
fn truncated_input_fails() {
    let key = key_from([0xCC; 32]);
    let nonce: AeadNonce = [0xDD; 24];
    // Not enough bytes for even a tag — must report InvalidLength rather
    // than panicking inside the underlying crate.
    let err = decrypt(&key, &nonce, b"", &[0u8; AEAD_TAG_LEN - 1]).unwrap_err();
    assert!(matches!(err, AeadError::InvalidLength));
}

#[test]
fn xchacha20_poly1305_kat_draft_irtf_cfrg_xchacha_03() {
    // KAT loaded from tests/data/xchacha20poly1305_kat.json (vector source:
    // draft-irtf-cfrg-xchacha-03 §A.3.1).
    let kat: XChaCha20Poly1305Kat = load_kat("xchacha20poly1305_kat.json");
    for v in &kat.vectors {
        let key_bytes: [u8; 32] = v.key.as_slice().try_into().expect("key = 32 B");
        let nonce: AeadNonce = v.nonce.as_slice().try_into().expect("nonce = 24 B");
        let key = key_from(key_bytes);

        let mut expected = v.ciphertext.clone();
        expected.extend_from_slice(&v.tag);

        let actual = encrypt(&key, &nonce, &v.aad, &v.plaintext).expect("encrypt");
        assert_eq!(
            actual, expected,
            "vector {}: ciphertext+tag mismatch",
            v.name
        );

        // Round-trip: the wrapper must also decrypt its own KAT output.
        let pt = decrypt(&key, &nonce, &v.aad, &actual).expect("decrypt");
        assert_eq!(pt.expose(), v.plaintext.as_slice());
    }
}
