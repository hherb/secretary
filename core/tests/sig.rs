//! Hybrid-signature integration tests (`docs/crypto-design.md` §8).
//!
//! KATs come in three layers:
//!   1. Underlying primitives — RFC 8032 Ed25519 vector and an ML-DSA-65
//!      deterministic-sign round-trip with size pinning. These prove the
//!      wrapped crates work as expected.
//!   2. The pure role-prefix helper — `signed_message` cross-checked against
//!      a hand-computed concatenation. Pins the §8 step-1 wiring.
//!   3. End-to-end — round-trip plus six tampering negatives that pin the §8
//!      composition (each verify-failed variant must surface in the right
//!      situation).

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use secretary_core::crypto::kdf::{TAG_BLOCK_SIG, TAG_CARD_SIG, TAG_MANIFEST_SIG};
use secretary_core::crypto::sig::{
    generate_ed25519, generate_ml_dsa_65, sign, signed_message, verify, HybridSig, MlDsa65Public,
    MlDsa65Sig, SigError, SigRole, ED25519_PK_LEN, ED25519_SIG_LEN, ED25519_SK_LEN,
    ML_DSA_65_PK_LEN, ML_DSA_65_SEED_LEN, ML_DSA_65_SIG_LEN,
};

// ---------------------------------------------------------------------------
// Tiny hex helper (mirrors the one in tests/kdf.rs and tests/kem.rs).
// ---------------------------------------------------------------------------

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

fn hex32(s: &str) -> [u8; 32] {
    let v = hex(s);
    assert_eq!(v.len(), 32, "expected 32-byte hex");
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

fn hex64(s: &str) -> [u8; 64] {
    let v = hex(s);
    assert_eq!(v.len(), 64, "expected 64-byte hex");
    let mut out = [0u8; 64];
    out.copy_from_slice(&v);
    out
}

// ---------------------------------------------------------------------------
// 1. Underlying Ed25519 primitive — RFC 8032 §7.1 test 1 (the all-zero-ish
//    canonical vector: empty message, sk = 9d61b1...). This pins the
//    `ed25519-dalek` wrapping: byte order, signature framing, deterministic
//    signing per RFC 8032.
// ---------------------------------------------------------------------------

#[test]
fn ed25519_kat_rfc8032_test1() {
    use ed25519_dalek::ed25519::signature::Signer as _;
    use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

    let sk_bytes = hex32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let expected_pk =
        hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let expected_sig = hex64(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );

    let sk = SigningKey::from_bytes(&sk_bytes);
    let pk: VerifyingKey = sk.verifying_key();
    assert_eq!(pk.to_bytes(), expected_pk);

    let sig: Signature = sk.sign(b"");
    assert_eq!(sig.to_bytes(), expected_sig);
}

// ---------------------------------------------------------------------------
// 2. Underlying ML-DSA-65 primitive — deterministic from_seed + sign +
//    round-trip, plus size pinning against §14.
//
// We don't pin a literal signature value: cross-verification would require an
// independent FIPS-204-final implementation, which (like ML-KEM-768 last
// session) is not yet conveniently available in Python. The determinism +
// round-trip + size assertions together are strong evidence the wrapped crate
// works as expected. NIST FIPS 204 KATs would tighten this further and are a
// future hardening item.
//
// Note: this crate stores the ML-DSA-65 signing key as its 32-byte FIPS 204
// seed (per `ml-dsa`'s recommendation; the 4032-byte ExpandedSigningKey
// encoding is `#[deprecated]`). Hence `ML_DSA_65_SEED_LEN = 32`, not 4032.
// ---------------------------------------------------------------------------

#[test]
fn ml_dsa_65_roundtrip() {
    use ml_dsa::signature::{Keypair as _, Signer as _, Verifier as _};
    use ml_dsa::{KeyGen as _, MlDsa65, B32};

    let seed: B32 = B32::from([0xAAu8; 32]);
    let kp = MlDsa65::from_seed(&seed);
    let sk = kp.signing_key();
    let vk = kp.verifying_key();

    // Size pinning against §14 (and the seed-form sk).
    assert_eq!(vk.encode().len(), ML_DSA_65_PK_LEN);
    assert_eq!(kp.to_seed().len(), ML_DSA_65_SEED_LEN);

    let msg = b"hybrid-sig roundtrip probe";
    let sig1 = sk.sign(msg);
    assert_eq!(sig1.encode().len(), ML_DSA_65_SIG_LEN);

    // Same inputs → same output (deterministic ML-DSA per the crate's default
    // Signer impl).
    let sig2 = sk.sign(msg);
    assert_eq!(sig1.encode().as_slice(), sig2.encode().as_slice());

    // Round-trip verification.
    vk.verify(msg, &sig1).expect("ML-DSA-65 verify failed");

    // Tampered message rejects.
    assert!(vk.verify(b"different message", &sig1).is_err());
}

// ---------------------------------------------------------------------------
// 3. signed_message KAT — fixed role + fixed message.
//
// The output is `TAG_*_SIG || message` byte-exact. Pins the §8 step-1 wiring.
// ---------------------------------------------------------------------------

#[test]
fn signed_message_kat() {
    let m = b"the quick brown fox";

    let mut expected_block = Vec::new();
    expected_block.extend_from_slice(TAG_BLOCK_SIG);
    expected_block.extend_from_slice(m);
    assert_eq!(signed_message(SigRole::Block, m), expected_block);

    let mut expected_manifest = Vec::new();
    expected_manifest.extend_from_slice(TAG_MANIFEST_SIG);
    expected_manifest.extend_from_slice(m);
    assert_eq!(signed_message(SigRole::Manifest, m), expected_manifest);

    let mut expected_card = Vec::new();
    expected_card.extend_from_slice(TAG_CARD_SIG);
    expected_card.extend_from_slice(m);
    assert_eq!(signed_message(SigRole::Card, m), expected_card);

    // Empty message gets the prefix alone.
    assert_eq!(signed_message(SigRole::Block, b""), TAG_BLOCK_SIG.to_vec());
}

// ---------------------------------------------------------------------------
// 4–10: end-to-end round-trip and tampering negatives.
//
// Helper: a fully populated identity (both keypairs) seeded for determinism.
// ---------------------------------------------------------------------------

struct Identity {
    ed_sk: secretary_core::crypto::sig::Ed25519Secret,
    ed_pk: secretary_core::crypto::sig::Ed25519Public,
    pq_sk: secretary_core::crypto::sig::MlDsa65Secret,
    pq_pk: MlDsa65Public,
}

fn build_identity(seed: u64) -> Identity {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let (ed_sk, ed_pk) = generate_ed25519(&mut rng);
    let (pq_sk, pq_pk) = generate_ml_dsa_65(&mut rng);
    Identity {
        ed_sk,
        ed_pk,
        pq_sk,
        pq_pk,
    }
}

#[test]
fn keypair_size_pinning() {
    let id = build_identity(0xA1);
    assert_eq!(id.ed_sk.expose().len(), ED25519_SK_LEN);
    assert_eq!(id.ed_pk.len(), ED25519_PK_LEN);
    assert_eq!(id.pq_pk.as_bytes().len(), ML_DSA_65_PK_LEN);
    assert_eq!(id.pq_sk.expose().len(), ML_DSA_65_SEED_LEN);
}

#[test]
fn hybrid_sig_roundtrip() {
    let id = build_identity(0xA2);
    let msg = b"signed and sealed";
    let sig = sign(SigRole::Block, msg, &id.ed_sk, &id.pq_sk).expect("sign");
    assert_eq!(sig.sig_ed.len(), ED25519_SIG_LEN);
    assert_eq!(sig.sig_pq.as_bytes().len(), ML_DSA_65_SIG_LEN);
    verify(SigRole::Block, msg, &sig, &id.ed_pk, &id.pq_pk).expect("verify");
}

#[test]
fn hybrid_sig_wrong_ed_pk_fails() {
    let id_signer = build_identity(0xB1);
    let id_other = build_identity(0xB2);
    let msg = b"audit log entry 42";
    let sig = sign(SigRole::Manifest, msg, &id_signer.ed_sk, &id_signer.pq_sk).expect("sign");
    let r = verify(
        SigRole::Manifest,
        msg,
        &sig,
        &id_other.ed_pk, // wrong ed pk
        &id_signer.pq_pk,
    );
    assert!(matches!(r, Err(SigError::Ed25519VerifyFailed)));
}

#[test]
fn hybrid_sig_wrong_pq_pk_fails() {
    let id_signer = build_identity(0xC1);
    let id_other = build_identity(0xC2);
    let msg = b"audit log entry 42";
    let sig = sign(SigRole::Manifest, msg, &id_signer.ed_sk, &id_signer.pq_sk).expect("sign");
    let r = verify(
        SigRole::Manifest,
        msg,
        &sig,
        &id_signer.ed_pk,
        &id_other.pq_pk, // wrong pq pk
    );
    assert!(matches!(r, Err(SigError::MlDsa65VerifyFailed)));
}

#[test]
fn hybrid_sig_tampered_ed_sig_fails() {
    let id = build_identity(0xD1);
    let msg = b"contact card v1";
    let mut sig = sign(SigRole::Card, msg, &id.ed_sk, &id.pq_sk).expect("sign");
    sig.sig_ed[0] ^= 0x01;
    let r = verify(SigRole::Card, msg, &sig, &id.ed_pk, &id.pq_pk);
    assert!(matches!(r, Err(SigError::Ed25519VerifyFailed)));
}

#[test]
fn hybrid_sig_tampered_pq_sig_fails() {
    let id = build_identity(0xD2);
    let msg = b"contact card v1";
    let sig_orig = sign(SigRole::Card, msg, &id.ed_sk, &id.pq_sk).expect("sign");

    // Tamper a copy of the pq sig bytes.
    let mut pq_bytes = sig_orig.sig_pq.as_bytes().to_vec();
    pq_bytes[0] ^= 0x01;
    let tampered = HybridSig {
        sig_ed: sig_orig.sig_ed,
        sig_pq: MlDsa65Sig::from_bytes(&pq_bytes).expect("len ok"),
    };
    let r = verify(SigRole::Card, msg, &tampered, &id.ed_pk, &id.pq_pk);
    assert!(matches!(r, Err(SigError::MlDsa65VerifyFailed)));
}

#[test]
fn hybrid_sig_tampered_message_fails() {
    let id = build_identity(0xE1);
    let msg = b"original";
    let sig = sign(SigRole::Block, msg, &id.ed_sk, &id.pq_sk).expect("sign");

    // Verify against a different message — exactly one of the two primitives
    // will reject first; we don't pin which (either is fine; the §8 spec
    // requires *both* succeed for a valid signature).
    let r = verify(SigRole::Block, b"tampered", &sig, &id.ed_pk, &id.pq_pk);
    assert!(matches!(
        r,
        Err(SigError::Ed25519VerifyFailed) | Err(SigError::MlDsa65VerifyFailed)
    ));
}

#[test]
fn hybrid_sig_wrong_role_fails() {
    let id = build_identity(0xE2);
    let msg = b"role-bound message";
    let sig = sign(SigRole::Block, msg, &id.ed_sk, &id.pq_sk).expect("sign");

    // Sign as Block, verify as Manifest — the prefix bytes differ, so the
    // bytes presented to each underlying primitive differ; both will reject.
    let r = verify(SigRole::Manifest, msg, &sig, &id.ed_pk, &id.pq_pk);
    assert!(matches!(
        r,
        Err(SigError::Ed25519VerifyFailed) | Err(SigError::MlDsa65VerifyFailed)
    ));
}
