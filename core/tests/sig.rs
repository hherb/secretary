#![forbid(unsafe_code)]

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

mod common;
use common::{load_kat, Ed25519Kat, HybridSigKat, MlDsa65Kat};

use secretary_core::crypto::kdf::{TAG_BLOCK_SIG, TAG_CARD_SIG, TAG_MANIFEST_SIG};
use secretary_core::crypto::sig::{
    generate_ed25519, generate_ml_dsa_65, sign, signed_message, verify, HybridSig, MlDsa65Public,
    MlDsa65Secret, MlDsa65Sig, SigError, SigRole, ED25519_PK_LEN, ED25519_SIG_LEN, ED25519_SK_LEN,
    ML_DSA_65_PK_LEN, ML_DSA_65_SEED_LEN, ML_DSA_65_SIG_LEN,
};

// ---------------------------------------------------------------------------
// 1. Underlying Ed25519 primitive — RFC 8032 §7.1 test 1 (the all-zero-ish
//    canonical vector: empty message, sk = 9d61b1...). This pins the
//    `ed25519-dalek` wrapping: byte order, signature framing, deterministic
//    signing per RFC 8032. Vectors loaded from tests/data/ed25519_kat.json.
// ---------------------------------------------------------------------------

#[test]
fn ed25519_kat_rfc8032_test1() {
    // RFC 8032 §7.1 test 1, loaded from tests/data/ed25519_kat.json.
    use ed25519_dalek::ed25519::signature::Signer as _;
    use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

    let kat: Ed25519Kat = load_kat("ed25519_kat.json");
    assert!(!kat.vectors.is_empty(), "no Ed25519 vectors");
    for v in &kat.vectors {
        let sk_bytes: [u8; 32] = v.sk.as_slice().try_into().expect("sk = 32 B");
        let expected_pk: [u8; 32] = v.pk.as_slice().try_into().expect("pk = 32 B");
        let expected_sig: [u8; 64] = v.sig.as_slice().try_into().expect("sig = 64 B");

        let sk = SigningKey::from_bytes(&sk_bytes);
        let pk: VerifyingKey = sk.verifying_key();
        assert_eq!(pk.to_bytes(), expected_pk, "vector {}: pk mismatch", v.name);

        let sig: Signature = sk.sign(&v.msg);
        assert_eq!(
            sig.to_bytes(),
            expected_sig,
            "vector {}: sig mismatch",
            v.name
        );
    }
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

    // `verify` checks Ed25519 first; with both halves stale (the message
    // bytes presented to each primitive differ from what was signed), the
    // first failure is the Ed25519 half. Pinning the exact variant rather
    // than `Ed | MlDsa` guards against an implementation that silently skips
    // the Ed branch and relies on the PQ branch to reject. The PQ branch's
    // independent rejection is proven by
    // `test_hybrid_sig_fails_when_only_one_half_valid`.
    let r = verify(SigRole::Block, b"tampered", &sig, &id.ed_pk, &id.pq_pk);
    assert!(matches!(r, Err(SigError::Ed25519VerifyFailed)), "got {r:?}");
}

// ---------------------------------------------------------------------------
// Contract test name from threat-model §5: §8 "AND verification" — if exactly
// one half of the hybrid signature is valid, verify must reject. Pins both
// directions explicitly so an implementation that silently accepts a zero PQ
// half (or zero Ed half) cannot pass.
// ---------------------------------------------------------------------------

#[test]
fn test_hybrid_sig_fails_when_only_one_half_valid() {
    let id = build_identity(0xF1);
    let msg = b"both-must-verify";
    let good = sign(SigRole::Block, msg, &id.ed_sk, &id.pq_sk).expect("sign");

    // Case 1: valid Ed25519 half, garbage PQ half.
    let zero_pq = MlDsa65Sig::from_bytes(&[0u8; ML_DSA_65_SIG_LEN][..]).expect("len");
    let only_ed_valid = HybridSig {
        sig_ed: good.sig_ed,
        sig_pq: zero_pq,
    };
    let r = verify(SigRole::Block, msg, &only_ed_valid, &id.ed_pk, &id.pq_pk);
    assert!(
        matches!(r, Err(SigError::MlDsa65VerifyFailed)),
        "ed-only-valid must reject with MlDsa65VerifyFailed, got {r:?}",
    );

    // Case 2: garbage Ed25519 half, valid PQ half.
    let only_pq_valid = HybridSig {
        sig_ed: [0u8; ED25519_SIG_LEN],
        sig_pq: good.sig_pq.clone(),
    };
    let r = verify(SigRole::Block, msg, &only_pq_valid, &id.ed_pk, &id.pq_pk);
    assert!(
        matches!(r, Err(SigError::Ed25519VerifyFailed)),
        "pq-only-valid must reject with Ed25519VerifyFailed, got {r:?}",
    );
}

#[test]
fn hybrid_sig_wrong_role_fails() {
    let id = build_identity(0xE2);
    let msg = b"role-bound message";
    let sig = sign(SigRole::Block, msg, &id.ed_sk, &id.pq_sk).expect("sign");

    // Same reasoning as `hybrid_sig_tampered_message_fails`: pin the
    // deterministic first rejection (Ed25519); independent PQ-half rejection
    // is covered by `test_hybrid_sig_fails_when_only_one_half_valid`.
    let r = verify(SigRole::Manifest, msg, &sig, &id.ed_pk, &id.pq_pk);
    assert!(matches!(r, Err(SigError::Ed25519VerifyFailed)), "got {r:?}");
}

// ---------------------------------------------------------------------------
// Hybrid signature wire-byte KAT — pins the §8 sign output for fixed seeds
// and inputs across all three SigRole variants. Loaded from
// tests/data/hybrid_sig_kat.json. A clean-room implementation that wants
// to interop must reproduce these wire bytes byte-for-byte.
// ---------------------------------------------------------------------------

#[test]
fn hybrid_sig_wire_kat() {
    let kat: HybridSigKat = load_kat("hybrid_sig_kat.json");
    let identity_seed: [u8; 32] = kat
        .identity_seed
        .as_slice()
        .try_into()
        .expect("seed = 32 B");

    let mut rng = ChaCha20Rng::from_seed(identity_seed);
    let (ed_sk, ed_pk) = generate_ed25519(&mut rng);
    let (pq_sk, pq_pk) = generate_ml_dsa_65(&mut rng);

    // Public keys must match the JSON-pinned values.
    assert_eq!(ed_pk.as_slice(), kat.ed_pk, "ed_pk diverges from KAT");
    assert_eq!(
        pq_pk.as_bytes(),
        kat.ml_dsa_65_pk,
        "ml_dsa_65_pk diverges from KAT"
    );

    // Each role-tagged signature is also pinned.
    for v in &kat.vectors {
        let role = match v.role.as_str() {
            "Block" => SigRole::Block,
            "Manifest" => SigRole::Manifest,
            "Card" => SigRole::Card,
            other => panic!("unknown role in KAT: {other}"),
        };
        let s = sign(role, &kat.msg, &ed_sk, &pq_sk).expect("sign");
        assert_eq!(
            s.sig_ed.as_slice(),
            v.sig_ed,
            "role {}: sig_ed mismatch",
            v.role
        );
        assert_eq!(
            s.sig_pq.as_bytes(),
            v.sig_pq,
            "role {}: sig_pq mismatch",
            v.role
        );
    }
}

// ---------------------------------------------------------------------------
// NIST FIPS 204 KATs for ML-DSA-65. Cross-validates the underlying ml-dsa
// crate against the NIST upstream conformance contract. Loaded from
// tests/data/ml_dsa_65_kat.json (10-vector subset of NIST ACVP-Server).
//
// Sign-side determinism is exercised by ml_dsa_65_roundtrip and by the
// hybrid_sig_wire_kat above (which pin our crate's sign output for fixed
// inputs). The NIST sigGen vectors here exercise the verify-side: a
// NIST-conformant (pk, msg, ctx, sig) tuple must verify under the
// `verify_with_context` API.
// ---------------------------------------------------------------------------

#[test]
fn ml_dsa_65_nist_keygen_kat() {
    use ml_dsa::signature::Keypair as _;
    use ml_dsa::{KeyGen as _, MlDsa65, B32};
    let kat: MlDsa65Kat = load_kat("ml_dsa_65_kat.json");
    assert!(!kat.keygen_vectors.is_empty(), "no NIST keygen vectors");

    for v in &kat.keygen_vectors {
        let seed_arr: [u8; 32] = v.seed.as_slice().try_into().expect("seed = 32 B");
        let seed: B32 = B32::from(seed_arr);
        let kp = MlDsa65::from_seed(&seed);
        let pk_bytes = kp.verifying_key().encode();
        assert_eq!(
            pk_bytes.as_slice(),
            v.pk.as_slice(),
            "tcId {}: pk diverges from NIST",
            v.tc_id
        );
    }
}

#[test]
fn ml_dsa_65_nist_sigver_kat() {
    use ml_dsa::{
        EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature as MlDsaSignature,
        VerifyingKey as MlDsaVerifyingKey,
    };
    let kat: MlDsa65Kat = load_kat("ml_dsa_65_kat.json");
    assert!(!kat.sigver_vectors.is_empty(), "no NIST sigver vectors");

    for v in &kat.sigver_vectors {
        let pk_arr: EncodedVerifyingKey<MlDsa65> = v.pk.as_slice().try_into().expect("pk length");
        let vk = MlDsaVerifyingKey::<MlDsa65>::decode(&pk_arr);

        let sig_arr: EncodedSignature<MlDsa65> = v.sig.as_slice().try_into().expect("sig length");
        let sig = MlDsaSignature::<MlDsa65>::decode(&sig_arr).expect("sig decode");

        assert!(
            vk.verify_with_context(&v.msg, &v.ctx, &sig),
            "tcId {}: NIST-conformant signature failed to verify",
            v.tc_id
        );
    }
}

// ---------------------------------------------------------------------------
// NIST FIPS 204 sigGen KATs for ML-DSA-65 — sign-side cross-validation.
//
// The sigver KAT above pins the verify-side; this one closes the §15 sigGen
// gap by feeding NIST's expanded-form signing key (FIPS 204 Algorithm 24
// `skEncode`, 4032 bytes for ML-DSA-65) and NIST's (message, ctx) into the
// deterministic ML-DSA.Sign and asserting the resulting 3309-byte signature
// matches NIST's reference output byte-for-byte.
//
// Source group is ACVP-Server `ML-DSA-sigGen-FIPS204` tgId=3:
// parameterSet=ML-DSA-65, AFT, deterministic=true, signatureInterface=external,
// preHash=pure. That maps onto `ExpandedSigningKey::sign_deterministic(M, ctx)`
// in the `ml-dsa` crate (Algorithm 2 ML-DSA.Sign, deterministic variant).
//
// `ExpandedSigningKey::from_expanded` is `#[deprecated]` in `ml-dsa 0.1.0-rc.8`
// because the modern API is seed-only (`from_seed` / `to_seed`). We
// `#[allow(deprecated)]` *locally on this fn* (not on a wider scope) because:
//   1. NIST publishes vectors against the expanded form, so cross-validating
//      against the authoritative reference requires loading expanded sks.
//   2. The seed-only API cannot accept an arbitrary expanded sk that wasn't
//      produced by the same seed expansion — NIST's vectors are independently
//      generated, and re-deriving the seed from the expanded sk is not
//      defined by FIPS 204.
//   3. When `ml-dsa` ships a non-deprecated way to load expanded sks (or its
//      own NIST KAT harness), this test should switch over.
// ---------------------------------------------------------------------------

#[test]
#[allow(deprecated)] // see fn-level comment above for the rationale + upgrade path.
fn ml_dsa_65_nist_siggen_kat() {
    use ml_dsa::{ExpandedSigningKey, ExpandedSigningKeyBytes, MlDsa65};

    let kat: MlDsa65Kat = load_kat("ml_dsa_65_kat.json");
    assert!(!kat.siggen_vectors.is_empty(), "no NIST siggen vectors");

    for v in &kat.siggen_vectors {
        // Each vector pins the FIPS 204 §14 sizes implicitly via try_into:
        // sk → 4032 B, sig → 3309 B. Mis-sized vectors fail with a clear msg.
        assert_eq!(
            v.sk.len(),
            ML_DSA_65_EXPANDED_SK_LEN,
            "tcId {}: sk len {} != FIPS 204 expanded sk len {}",
            v.tc_id,
            v.sk.len(),
            ML_DSA_65_EXPANDED_SK_LEN,
        );

        let sk_bytes: ExpandedSigningKeyBytes<MlDsa65> =
            v.sk.as_slice().try_into().expect("sk length");
        let sk = ExpandedSigningKey::<MlDsa65>::from_expanded(&sk_bytes);

        // ACVP `signatureInterface=external, preHash=pure, deterministic=true`
        // → Algorithm 2 ML-DSA.Sign, deterministic variant, called via the
        // crate's `sign_deterministic(M, ctx)`. ctx may be empty (some
        // vectors carry a 0-byte ctx); `sign_deterministic` accepts that.
        let sig = sk
            .sign_deterministic(&v.msg, &v.ctx)
            .expect("sign_deterministic");
        let sig_bytes = sig.encode();
        assert_eq!(sig_bytes.len(), ML_DSA_65_SIG_LEN);

        assert_eq!(
            sig_bytes.as_slice(),
            v.sig.as_slice(),
            "tcId {}: sigGen output diverges from NIST",
            v.tc_id
        );
    }
}

/// FIPS 204 §14 expanded-form ML-DSA-65 signing key length, asserted by
/// `ml_dsa_65_nist_siggen_kat`. The crate stores sks as the 32-byte seed in
/// production; this constant is the size the *NIST KAT* sks come in.
const ML_DSA_65_EXPANDED_SK_LEN: usize = 4032;

// ---------------------------------------------------------------------------
// Newtype-level Zeroize discipline.
//
// `MlDsa65Secret` wraps `SecretBytes` (a `Vec<u8>` newtype that is itself
// `ZeroizeOnDrop`), so bytes are wiped on drop regardless. The outer newtype
// additionally derives `Zeroize` / `ZeroizeOnDrop` so callers can wipe a
// still-live value before scope-end. This test pins that the outer derive
// reaches through to the inner field.
//
// Post-zeroize observable contract: `Vec<u8>::zeroize` overwrites the bytes
// in place, then truncates `len` to 0 (capacity is preserved but inaccessible
// safely). The only post-condition observable through the public API is
// therefore `expose().is_empty()` — which we assert directly. The
// byte-overwrite-before-truncation step is a guarantee of the `zeroize`
// crate's `Vec<T>` impl, pinned here by the exact-version dependency on
// `zeroize = "=1.8.2"` in `core/Cargo.toml`.
// ---------------------------------------------------------------------------

#[test]
fn ml_dsa_65_secret_zeroize_clears_inner_bytes() {
    use zeroize::Zeroize as _;

    let mut sk = MlDsa65Secret::from_bytes(&[0xAB; ML_DSA_65_SEED_LEN])
        .expect("32-byte seed must construct");
    assert_eq!(
        sk.expose().len(),
        ML_DSA_65_SEED_LEN,
        "sanity: pre-zeroize length must match the seed size"
    );
    assert!(
        sk.expose().iter().any(|&b| b != 0),
        "sanity: pre-zeroize bytes must not already be zero"
    );

    sk.zeroize();

    assert!(
        sk.expose().is_empty(),
        "expected MlDsa65Secret buffer to be cleared (len == 0) after .zeroize()"
    );
}
