//! Hash primitive integration tests.
//!
//! Vectors are inlined as byte literals; once the volume warrants it the
//! plan is to move them to `core/tests/data/*.json`. Until then, the source
//! of each constant is documented next to the assertion.

use secretary_core::crypto::hash::{hash, keyed_hash, sha256, sha3_256, Blake3Hash};

/// Decode a hex string into a fixed-size array. Test-only helper.
fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    assert_eq!(s.len(), 64, "expected 64 hex chars, got {}", s.len());
    for (i, byte_out) in out.iter_mut().enumerate() {
        let hi = char_to_nibble(s.as_bytes()[i * 2]);
        let lo = char_to_nibble(s.as_bytes()[i * 2 + 1]);
        *byte_out = (hi << 4) | lo;
    }
    out
}

fn char_to_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("non-hex char"),
    }
}

#[test]
fn blake3_test_vector_empty() {
    // BLAKE3 reference test_vectors.json: input_len 0, first 32 bytes of the
    // extended output:
    //   af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262
    let expected =
        hex32("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
    let h: Blake3Hash = hash(b"");
    assert_eq!(h.as_bytes(), &expected);
}

#[test]
fn blake3_test_vector_single_byte() {
    // BLAKE3 reference test_vectors.json: input_len 1 with the standard
    // pattern (byte i = i % 251), so input = [0x00]; first 32 bytes:
    //   2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213
    let expected =
        hex32("2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213");
    let h = hash(&[0x00]);
    assert_eq!(h.as_bytes(), &expected);
}

#[test]
fn blake3_keyed_test_vector_empty() {
    // Key: BLAKE3 reference test-vector key
    //   b"whats-the-Elvish-word-for-friend" (exactly 32 ASCII bytes).
    // Cross-verified against the upstream Python `blake3` package
    // (independent implementation):
    //   c0fa1ec5a2f16afde90fa99736471974265db0129a9a84646e6a0e873956e76f
    let key = *b"whats-the-Elvish-word-for-friend";
    let expected =
        hex32("c0fa1ec5a2f16afde90fa99736471974265db0129a9a84646e6a0e873956e76f");
    let h = keyed_hash(&key, b"");
    assert_eq!(h.as_bytes(), &expected);
}

#[test]
fn blake3_keyed_test_vector_single_byte() {
    // Same key, input [0x00]. Cross-verified against Python `blake3`:
    //   d8826b69f9e32cd167faf0b7a729763b5fd97c5dce9b9e905ea9a5d043beabbc
    let key = *b"whats-the-Elvish-word-for-friend";
    let expected =
        hex32("d8826b69f9e32cd167faf0b7a729763b5fd97c5dce9b9e905ea9a5d043beabbc");
    let h = keyed_hash(&key, &[0x00]);
    assert_eq!(h.as_bytes(), &expected);
}

#[test]
fn sha3_256_test_vector_empty() {
    // FIPS 202: SHA3-256("") =
    //   a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
    let expected =
        hex32("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    assert_eq!(sha3_256(b""), expected);
}

#[test]
fn sha256_test_vector_abc() {
    // FIPS 180-4: SHA-256("abc") =
    //   ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    let expected =
        hex32("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(sha256(b"abc"), expected);
}

#[test]
fn blake3_hash_is_deterministic() {
    // Smoke test: same input → same output.
    let a = hash(b"the quick brown fox");
    let b = hash(b"the quick brown fox");
    assert_eq!(a, b);
}

#[test]
fn blake3_keyed_differs_from_unkeyed() {
    // A keyed hash with any key should not equal the unkeyed hash (negligible
    // collision probability — this is a sanity check, not a security claim).
    let key = [0xAB; 32];
    let unkeyed = hash(b"hello");
    let keyed = keyed_hash(&key, b"hello");
    assert_ne!(unkeyed, keyed);
}
