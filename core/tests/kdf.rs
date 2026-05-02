//! KDF integration tests: Argon2id (Master KEK), HKDF-SHA-256 (Recovery KEK
//! and primitive). Each KAT cites its source.

mod common;
use common::{load_kat, Argon2idKat, HkdfSha256Kat};

use secretary_core::crypto::kdf::{
    derive_master_kek, derive_recovery_kek, hkdf_sha256_extract_and_expand, Argon2idParams,
    KdfError, TAG_RECOVERY_KEK,
};
use secretary_core::crypto::secret::{SecretBytes, Sensitive};

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex string");
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
    // KAT loaded from tests/data/argon2id_kat.json; cross-verified against
    // argon2-cffi (libargon2 reference). Small memory (8 MiB) keeps the test
    // fast; v1 production floor is enforced by Argon2idParams::try_new_v1
    // separately.
    let kat: Argon2idKat = load_kat("argon2id_kat.json");
    let v = kat
        .vectors
        .iter()
        .find(|v| v.name == "small_memory")
        .expect("vector");
    let salt: [u8; 32] = v.salt.as_slice().try_into().expect("salt = 32 B");
    let password = SecretBytes::new(v.password.clone());
    let params = Argon2idParams::new(v.memory_kib, v.iterations, v.parallelism);
    let kek = derive_master_kek(&password, &salt, &params).expect("valid params");
    assert_eq!(kek.expose().len(), v.out_len);
    assert_eq!(kek.expose()[..], v.expected[..]);
}

#[test]
fn argon2id_v1_default_dimensions() {
    // Smoke test: derive with v1 default params (256 MiB / 3 iter / 1p) and
    // confirm the output length is 32 bytes. This is slow (~1s on a fast
    // machine), but proves the v1 default path works end to end.
    let password = SecretBytes::new(b"some user password".to_vec());
    let salt = [0xAB; 32];
    let kek = derive_master_kek(&password, &salt, &Argon2idParams::V1_DEFAULT)
        .expect("v1 default params are valid");
    assert_eq!(kek.expose().len(), 32);
}

// Contract test name from threat-model §5. Do not rename without updating
// the threat model.
#[test]
fn test_kdf_params_minimum_memory_kib() {
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
// Attacker-controlled vault.toml — derive_master_kek must report an error
// rather than panic on params the underlying argon2 crate rejects. The fields
// of `Argon2idParams` are `pub`, so even a future loader that goes through
// `try_new_v1` cannot keep someone from constructing the struct directly with
// raw values — the defense has to live in `derive_master_kek` itself.
// ---------------------------------------------------------------------------

#[test]
fn derive_master_kek_rejects_zero_iterations() {
    let password = SecretBytes::new(b"x".to_vec());
    let salt = [0u8; 32];
    let bad = Argon2idParams {
        memory_kib: 8192,
        iterations: 0,
        parallelism: 1,
    };
    let err = derive_master_kek(&password, &salt, &bad).expect_err("must reject");
    assert!(matches!(err, KdfError::Argon2ParamsRejected));
}

#[test]
fn derive_master_kek_rejects_zero_parallelism() {
    let password = SecretBytes::new(b"x".to_vec());
    let salt = [0u8; 32];
    let bad = Argon2idParams {
        memory_kib: 8192,
        iterations: 1,
        parallelism: 0,
    };
    let err = derive_master_kek(&password, &salt, &bad).expect_err("must reject");
    assert!(matches!(err, KdfError::Argon2ParamsRejected));
}

#[test]
fn derive_master_kek_rejects_zero_memory() {
    let password = SecretBytes::new(b"x".to_vec());
    let salt = [0u8; 32];
    let bad = Argon2idParams {
        memory_kib: 0,
        iterations: 1,
        parallelism: 1,
    };
    let err = derive_master_kek(&password, &salt, &bad).expect_err("must reject");
    assert!(matches!(err, KdfError::Argon2ParamsRejected));
}

#[test]
fn derive_master_kek_rejects_memory_below_8x_parallelism() {
    // argon2 crate rule: m_cost >= 8 * p_cost. memory=8, parallel=2 violates.
    let password = SecretBytes::new(b"x".to_vec());
    let salt = [0u8; 32];
    let bad = Argon2idParams {
        memory_kib: 8,
        iterations: 1,
        parallelism: 2,
    };
    let err = derive_master_kek(&password, &salt, &bad).expect_err("must reject");
    assert!(matches!(err, KdfError::Argon2ParamsRejected));
}

// ---------------------------------------------------------------------------
// Recovery KEK (§4)
// ---------------------------------------------------------------------------

#[test]
fn recovery_kek_test_vector_zero_entropy() {
    // §4 with all-zero entropy (32 bytes). Cross-verified against the
    // `cryptography` Python package (independent HKDF-SHA-256 implementation).
    let entropy: Sensitive<[u8; 32]> = Sensitive::new([0u8; 32]);
    let expected = hex("32267cba4b0f75fcd6204457687526dce5e381e28878323b3e550ccff0898da8");
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
fn hkdf_rfc5869_kats() {
    // RFC 5869 vectors loaded from tests/data/hkdf_sha256_kat.json. Includes
    // test case 1 (§A.1) and test case 3 (§A.3, empty salt and info — RFC 5869
    // §2.2 says empty salt is treated as 32 bytes of zero).
    let kat: HkdfSha256Kat = load_kat("hkdf_sha256_kat.json");
    assert!(!kat.vectors.is_empty(), "no HKDF vectors");
    for v in &kat.vectors {
        let okm = hkdf_sha256_extract_and_expand(&v.salt, &v.ikm, &v.info, v.okm_len);
        assert_eq!(okm.len(), v.okm_len, "vector {}: okm_len mismatch", v.name);
        assert_eq!(okm, v.okm, "vector {}: okm mismatch", v.name);
    }
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
