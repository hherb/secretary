//! XChaCha20-Poly1305 AEAD wrapper integration tests.

use secretary_core::crypto::aead::{decrypt, encrypt, AeadError, AeadKey, AeadNonce, AEAD_TAG_LEN};
use secretary_core::crypto::secret::Sensitive;

/// Decode hex string to Vec<u8>. Test-only helper.
fn hex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd-length hex string");
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        out.push((nib(chunk[0]) << 4) | nib(chunk[1]));
    }
    out
}

fn nib(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("non-hex char"),
    }
}

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

#[test]
fn wrong_key_fails() {
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

#[test]
fn tampered_tag_fails() {
    let key = key_from([0x99; 32]);
    let nonce: AeadNonce = [0xAA; 24];
    let mut ct = encrypt(&key, &nonce, b"", b"abc").expect("encrypt");
    // Flip last byte (inside the Poly1305 tag).
    let last = ct.len() - 1;
    ct[last] ^= 0x01;
    let err = decrypt(&key, &nonce, b"", &ct).unwrap_err();
    assert!(matches!(err, AeadError::Decryption));
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
    // Test vector: draft-irtf-cfrg-xchacha-03 §A.3.1.
    //   key:        80818283 8485 8687 8889 8a8b 8c8d 8e8f
    //               90919293 9495 9697 9899 9a9b 9c9d 9e9f
    //   nonce:      40414243 4445 4647 4849 4a4b 4c4d 4e4f
    //               50515253 5455 5657
    //   aad:        50515253 c0c1 c2c3 c4c5 c6c7
    //   plaintext:  "Ladies and Gentlemen of the class of '99: If I could
    //               offer you only one tip for the future, sunscreen
    //               would be it."  (114 bytes ASCII)
    //   ciphertext: bd6d179d 3e83 d43b 9576 5794 93c0 e939
    //               572a1700 252b facc bed2 902c 2139 6cbb
    //               731c7f1b 0b4a a644 0bf3 a82f 4eda 7e39
    //               ae64c670 8c54 c216 cb96 b72e 1213 b452
    //               2f8c9ba4 0db5 d945 b11b 69b9 82c1 bb9e
    //               3f3fac2b c369 488f 76b2 3835 65d3 fff9
    //               21f9664c 9763 7da9 7688 12f6 15c6 8b13
    //               b52e
    //   tag:        c0875924 c1c7 9879 47de afd8 780a cf49
    let key_bytes: [u8; 32] = hex(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
    )
    .try_into()
    .unwrap();
    let nonce: AeadNonce = hex("404142434445464748494a4b4c4d4e4f5051525354555657")
        .try_into()
        .unwrap();
    let aad = hex("50515253c0c1c2c3c4c5c6c7");
    let plaintext: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    let expected_ct = hex(concat!(
        "bd6d179d3e83d43b9576579493c0e939",
        "572a1700252bfaccbed2902c21396cbb",
        "731c7f1b0b4aa6440bf3a82f4eda7e39",
        "ae64c6708c54c216cb96b72e1213b452",
        "2f8c9ba40db5d945b11b69b982c1bb9e",
        "3f3fac2bc369488f76b2383565d3fff9",
        "21f9664c97637da9768812f615c68b13",
        "b52e",
    ));
    let expected_tag = hex("c0875924c1c7987947deafd8780acf49");

    let key = key_from(key_bytes);
    let mut expected = expected_ct.clone();
    expected.extend_from_slice(&expected_tag);

    let actual = encrypt(&key, &nonce, &aad, plaintext).expect("encrypt");
    assert_eq!(actual, expected, "KAT ciphertext+tag mismatch");

    // Round-trip: ensure the wrapper can decrypt its own KAT output too.
    let pt = decrypt(&key, &nonce, &aad, &actual).expect("decrypt");
    assert_eq!(pt.expose(), plaintext);
}
