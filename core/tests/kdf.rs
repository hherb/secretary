//! KDF integration tests: Argon2id (Master KEK), HKDF-SHA-256 (Recovery KEK
//! and primitive). Each KAT cites its source.

use secretary_core::crypto::kdf::{
    derive_master_kek, derive_recovery_kek, hkdf_sha256_extract_and_expand, Argon2idParams,
    KdfError, TAG_RECOVERY_KEK,
};
use secretary_core::crypto::secret::{SecretBytes, Sensitive};

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

// ---------------------------------------------------------------------------
// Argon2id
// ---------------------------------------------------------------------------

#[test]
fn argon2id_kat_small_memory() {
    // Self-derived KAT, computed via the libargon2 reference implementation
    // (Python `argon2-cffi`, which wraps the official Argon2 C reference)
    // and pinned here. Small memory (8 MiB) keeps the test fast; the v1
    // production floor is 64 MiB and is enforced by `try_new_v1`, but the
    // raw `Argon2idParams::new` constructor accepts any valid value.
    //
    //   password = b"masterpassword12"   (16 bytes ASCII)
    //   salt     = [0x00; 32]
    //   memory   = 8192 KiB              (8 MiB)
    //   iter     = 1
    //   parallel = 1
    //   version  = 0x13 (Argon2 v1.3)
    //   output   = 32 bytes
    let password = SecretBytes::new(b"masterpassword12".to_vec());
    let salt = [0u8; 32];
    let params = Argon2idParams::new(8192, 1, 1);
    let expected =
        hex("3344bda57af2b472b9a7854da6340a57f33270d22fff6c807150c98068af3651");
    let kek = derive_master_kek(&password, &salt, &params);
    assert_eq!(kek.expose()[..], expected[..]);
}

#[test]
fn argon2id_v1_default_dimensions() {
    // Smoke test: derive with v1 default params (256 MiB / 3 iter / 1p) and
    // confirm the output length is 32 bytes. This is slow (~1s on a fast
    // machine), but proves the v1 default path works end to end.
    let password = SecretBytes::new(b"some user password".to_vec());
    let salt = [0xAB; 32];
    let kek = derive_master_kek(&password, &salt, &Argon2idParams::V1_DEFAULT);
    assert_eq!(kek.expose().len(), 32);
}

#[test]
fn argon2id_params_try_new_v1_rejects_low_memory() {
    let err = Argon2idParams::try_new_v1(65535, 3, 1).unwrap_err();
    assert!(matches!(err, KdfError::ParamsBelowV1Floor));
}

#[test]
fn argon2id_params_try_new_v1_accepts_floor() {
    let p = Argon2idParams::try_new_v1(65536, 1, 1).expect("at floor");
    assert_eq!(p.memory_kib, 65536);
    assert_eq!(p.iterations, 1);
    assert_eq!(p.parallelism, 1);
}

#[test]
fn argon2id_params_try_new_v1_rejects_zero_iterations() {
    let err = Argon2idParams::try_new_v1(262144, 0, 1).unwrap_err();
    assert!(matches!(err, KdfError::ParamsBelowV1Floor));
}

#[test]
fn argon2id_params_try_new_v1_rejects_zero_parallelism() {
    let err = Argon2idParams::try_new_v1(262144, 3, 0).unwrap_err();
    assert!(matches!(err, KdfError::ParamsBelowV1Floor));
}

#[test]
fn argon2id_params_v1_default_matches_spec() {
    assert_eq!(Argon2idParams::V1_DEFAULT.memory_kib, 262144);
    assert_eq!(Argon2idParams::V1_DEFAULT.iterations, 3);
    assert_eq!(Argon2idParams::V1_DEFAULT.parallelism, 1);
}

// ---------------------------------------------------------------------------
// Recovery KEK (§4)
// ---------------------------------------------------------------------------

#[test]
fn recovery_kek_test_vector_zero_entropy() {
    // §4 with all-zero entropy (32 bytes). Cross-verified against the
    // `cryptography` Python package (independent HKDF-SHA-256 implementation).
    let entropy: Sensitive<[u8; 32]> = Sensitive::new([0u8; 32]);
    let expected =
        hex("32267cba4b0f75fcd6204457687526dce5e381e28878323b3e550ccff0898da8");
    let kek = derive_recovery_kek(&entropy);
    assert_eq!(kek.expose()[..], expected[..]);
}

#[test]
fn recovery_kek_uses_recovery_kek_tag() {
    // Defensive: deriving with a different info would produce a different
    // output. This both pins the tag constant value and proves it's what
    // `derive_recovery_kek` actually feeds into HKDF.
    let entropy: Sensitive<[u8; 32]> = Sensitive::new([0u8; 32]);
    let manual = hkdf_sha256_extract_and_expand(&[0u8; 32], &[0u8; 32], TAG_RECOVERY_KEK, 32);
    let derived = derive_recovery_kek(&entropy);
    assert_eq!(derived.expose()[..], manual[..]);
}

// ---------------------------------------------------------------------------
// HKDF-SHA-256 primitive (RFC 5869)
// ---------------------------------------------------------------------------

#[test]
fn hkdf_rfc5869_test_case_1() {
    // RFC 5869 §A.1 (basic test case 1, SHA-256):
    //   IKM   = 22 bytes of 0x0b
    //   salt  = 0x000102030405060708090a0b0c
    //   info  = 0xf0f1f2f3f4f5f6f7f8f9
    //   L     = 42
    //   OKM   = 0x3cb25f25faacd57a90434f64d0362f2a
    //              2d2d0a90cf1a5a4c5db02d56ecc4c5bf
    //              34007208d5b887185865
    let ikm = vec![0x0b; 22];
    let salt = hex("000102030405060708090a0b0c");
    let info = hex("f0f1f2f3f4f5f6f7f8f9");
    let expected = hex(concat!(
        "3cb25f25faacd57a90434f64d0362f2a",
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
        "34007208d5b887185865",
    ));
    let okm = hkdf_sha256_extract_and_expand(&salt, &ikm, &info, 42);
    assert_eq!(okm, expected);
}

#[test]
fn hkdf_rfc5869_test_case_3_empty_salt_and_info() {
    // RFC 5869 §A.3 (test case 3, SHA-256):
    //   IKM   = 22 bytes of 0x0b
    //   salt  = empty (treated as 32 bytes of zero per RFC 5869 §2.2)
    //   info  = empty
    //   L     = 42
    //   OKM   = 0x8da4e775a563c18f715f802a063c5a31
    //              b8a11f5c5ee1879ec3454e5f3c738d2d
    //              9d201395faa4b61a96c8
    let ikm = vec![0x0b; 22];
    let expected = hex(concat!(
        "8da4e775a563c18f715f802a063c5a31",
        "b8a11f5c5ee1879ec3454e5f3c738d2d",
        "9d201395faa4b61a96c8",
    ));
    let okm = hkdf_sha256_extract_and_expand(&[], &ikm, &[], 42);
    assert_eq!(okm, expected);
}

#[test]
#[should_panic(expected = "HKDF-SHA-256 output capped at")]
fn hkdf_rejects_oversized_output() {
    // 8161 bytes is one over the RFC 5869 limit (255 * 32 = 8160).
    let _ = hkdf_sha256_extract_and_expand(&[], b"ikm", &[], 8161);
}

#[test]
fn hkdf_accepts_max_output() {
    // Exactly at the limit must succeed.
    let okm = hkdf_sha256_extract_and_expand(&[], b"ikm", &[], 8160);
    assert_eq!(okm.len(), 8160);
}
