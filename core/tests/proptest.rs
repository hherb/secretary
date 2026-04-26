//! Property-based tests for the crypto core, per FIXME.md §Item 2.
//!
//! These complement the fixed KATs in the sibling test files. Fixed KATs catch
//! regressions on the inputs we anticipated; property tests fuzz the same
//! constructions over arbitrary inputs to surface encoder/decoder asymmetry,
//! sign/verify drift, and decap divergence on inputs nobody thought of.
//!
//! Runtime budget. ML-DSA / ML-KEM keygens dominate cost, so the properties
//! that exercise them run with a reduced case count via `ProptestConfig`. The
//! AEAD and CBOR properties run at the proptest default. Target: full file
//! under 30 s on `cargo test --release`.

use proptest::prelude::*;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

use secretary_core::crypto::aead::{decrypt, encrypt, AeadKey, AeadNonce};
use secretary_core::crypto::kem::{
    decap, encap, generate_ml_kem_768, generate_x25519, KemError, MlKem768Public, MlKem768Secret,
    BLOCK_CONTENT_KEY_LEN, ML_KEM_768_CT_LEN,
};
use secretary_core::crypto::secret::Sensitive;
use secretary_core::crypto::sig::{
    generate_ed25519, generate_ml_dsa_65, sign, verify, Ed25519Public, Ed25519Secret,
    MlDsa65Public, MlDsa65Secret, SigRole, ED25519_SIG_LEN, ML_DSA_65_PK_LEN, ML_DSA_65_SIG_LEN,
};
use secretary_core::identity::card::{ContactCard, CARD_VERSION_V1, ML_KEM_768_PK_LEN};

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

/// Vec<u8> of an exact length. Helper around `prop::collection::vec`.
fn vec_exact(len: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), len..=len)
}

/// `[u8; 16]` strategy.
fn arr16() -> impl Strategy<Value = [u8; 16]> {
    any::<[u8; 16]>()
}

/// `[u8; 32]` strategy.
fn arr32() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>()
}

/// Strategy for `SigRole` — the three variants with equal weight.
fn role_strategy() -> impl Strategy<Value = SigRole> {
    prop_oneof![
        Just(SigRole::Block),
        Just(SigRole::Manifest),
        Just(SigRole::Card),
    ]
}

/// Strategy for an arbitrary well-formed `ContactCard`. The pk/sig field
/// lengths are enforced by `from_canonical_cbor`, so the strategy only
/// generates structurally valid cards — the property under test is encode/
/// decode symmetry, not parser leniency.
///
/// `display_name` is generated as up to 256 arbitrary Unicode chars (≤1024
/// UTF-8 bytes after encoding).
fn card_strategy() -> impl Strategy<Value = ContactCard> {
    (
        arr16(),                                       // contact_uuid
        prop::collection::vec(any::<char>(), 0..=256), // display_name chars
        arr32(),                                       // x25519_pk
        vec_exact(ML_KEM_768_PK_LEN),                  // ml_kem_768_pk (1184)
        arr32(),                                       // ed25519_pk
        vec_exact(ML_DSA_65_PK_LEN),                   // ml_dsa_65_pk (1952)
        any::<u64>(),                                  // created_at_ms
        any::<[u8; ED25519_SIG_LEN]>(),                // self_sig_ed (64)
        vec_exact(ML_DSA_65_SIG_LEN),                  // self_sig_pq (3309)
    )
        .prop_map(
            |(uuid, name_chars, xpk, mk_pk, ed_pk, md_pk, ts, sig_ed, sig_pq)| ContactCard {
                card_version: CARD_VERSION_V1,
                contact_uuid: uuid,
                display_name: name_chars.into_iter().collect(),
                x25519_pk: xpk,
                ml_kem_768_pk: mk_pk,
                ed25519_pk: ed_pk,
                ml_dsa_65_pk: md_pk,
                created_at_ms: ts,
                self_sig_ed: sig_ed,
                self_sig_pq: sig_pq,
            },
        )
}

// ---------------------------------------------------------------------------
// Helpers — keypair / recipient construction from a seed
// ---------------------------------------------------------------------------

struct Identity {
    ed_sk: Ed25519Secret,
    ed_pk: Ed25519Public,
    pq_sk: MlDsa65Secret,
    pq_pk: MlDsa65Public,
}

fn build_identity(seed: [u8; 32]) -> Identity {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let (ed_sk, ed_pk) = generate_ed25519(&mut rng);
    let (pq_sk, pq_pk) = generate_ml_dsa_65(&mut rng);
    Identity {
        ed_sk,
        ed_pk,
        pq_sk,
        pq_pk,
    }
}

struct Recipient {
    fp: [u8; 16],
    pk_bundle: Vec<u8>,
    x_sk: Sensitive<[u8; 32]>,
    x_pk: [u8; 32],
    pq_sk: MlKem768Secret,
    pq_pk: MlKem768Public,
}

fn build_recipient(seed: [u8; 32], fp: [u8; 16], bundle: Vec<u8>) -> Recipient {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let (x_sk, x_pk) = generate_x25519(&mut rng);
    let (pq_sk, pq_pk) = generate_ml_kem_768(&mut rng);
    Recipient {
        fp,
        pk_bundle: bundle,
        x_sk,
        x_pk,
        pq_sk,
        pq_pk,
    }
}

// ---------------------------------------------------------------------------
// Properties — light-weight (default case count)
// ---------------------------------------------------------------------------

proptest! {
    /// `from_canonical_cbor(to_canonical_cbor(card)) == card` for any
    /// well-formed card. Catches encoder/decoder asymmetry that fixed KATs
    /// miss by construction.
    #[test]
    fn prop_card_canonical_cbor_roundtrip(card in card_strategy()) {
        let bytes = card.to_canonical_cbor().expect("encode");
        let parsed = ContactCard::from_canonical_cbor(&bytes).expect("decode");
        prop_assert_eq!(parsed, card);
    }

    /// `decrypt(encrypt(...)) == plaintext` for any (key, nonce, aad,
    /// plaintext). Trivial but catches future refactors that break length
    /// handling on edge sizes.
    #[test]
    fn prop_aead_roundtrip(
        key_bytes in arr32(),
        nonce in any::<[u8; 24]>(),
        aad in prop::collection::vec(any::<u8>(), 0..=256),
        plaintext in prop::collection::vec(any::<u8>(), 0..=4096),
    ) {
        let key: AeadKey = Sensitive::new(key_bytes);
        let nonce: AeadNonce = nonce;
        let ct = encrypt(&key, &nonce, &aad, &plaintext).expect("encrypt");
        let pt = decrypt(&key, &nonce, &aad, &ct).expect("decrypt");
        prop_assert_eq!(pt.expose(), plaintext.as_slice());
    }
}

// ---------------------------------------------------------------------------
// Properties — heavy (ML-DSA / ML-KEM keygen, run with reduced case count)
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// For any `(role, msg, seed)`, `verify(role, msg, sign(role, msg, sk),
    /// pk) == Ok(())`. Confirms the §8 sign/verify pair is symmetric on
    /// arbitrary inputs.
    #[test]
    fn prop_hybrid_sig_verify_after_sign(
        role in role_strategy(),
        seed in arr32(),
        msg in prop::collection::vec(any::<u8>(), 0..=4096),
    ) {
        let id = build_identity(seed);
        let s = sign(role, &msg, &id.ed_sk, &id.pq_sk).expect("sign");
        verify(role, &msg, &s, &id.ed_pk, &id.pq_pk).expect("verify");
    }

    /// For any `(role_a, role_b, msg, seed)` with `role_a != role_b`,
    /// verify under `role_b` rejects a signature made under `role_a`. Pins
    /// the §1.3 role-prefix domain separation under arbitrary inputs.
    #[test]
    fn prop_hybrid_sig_cross_role_rejects(
        role_a in role_strategy(),
        role_b in role_strategy(),
        seed in arr32(),
        msg in prop::collection::vec(any::<u8>(), 0..=1024),
    ) {
        prop_assume!(role_a != role_b);
        let id = build_identity(seed);
        let s = sign(role_a, &msg, &id.ed_sk, &id.pq_sk).expect("sign");
        let r = verify(role_b, &msg, &s, &id.ed_pk, &id.pq_pk);
        prop_assert!(r.is_err(), "verify under different role must fail, got {:?}", r);
    }

    /// For any `(seeds, block_uuid, bck)`, `decap(encap(K, ...)) == K`.
    /// Catches divergence between encap and decap that fixed KATs only catch
    /// on the specific inputs they pin.
    #[test]
    fn prop_hybrid_kem_roundtrip(
        sender_seed in arr32(),
        recipient_seed in arr32(),
        encap_seed in arr32(),
        sender_fp in arr16(),
        recipient_fp in arr16(),
        sender_bundle in prop::collection::vec(any::<u8>(), 16..=128),
        recipient_bundle in prop::collection::vec(any::<u8>(), 16..=128),
        block_uuid in arr16(),
        bck in arr32(),
    ) {
        let sender = build_recipient(sender_seed, sender_fp, sender_bundle);
        let recipient = build_recipient(recipient_seed, recipient_fp, recipient_bundle);
        let bck = Sensitive::new(bck);

        let mut rng = ChaCha20Rng::from_seed(encap_seed);
        let wrap = encap(
            &mut rng,
            &sender.fp,
            &recipient.fp,
            &sender.pk_bundle,
            &recipient.pk_bundle,
            &recipient.x_pk,
            &recipient.pq_pk,
            &block_uuid,
            &bck,
        ).expect("encap");

        // Pin §14 sizes — cheap invariant check on every property iteration.
        prop_assert_eq!(wrap.ct_x.len(), 32);
        prop_assert_eq!(wrap.ct_pq.len(), ML_KEM_768_CT_LEN);
        prop_assert_eq!(wrap.nonce_w.len(), 24);
        prop_assert_eq!(wrap.ct_w.len(), BLOCK_CONTENT_KEY_LEN + 16);

        let recovered = decap(
            &wrap,
            &sender.fp,
            &recipient.fp,
            &sender.pk_bundle,
            &recipient.pk_bundle,
            &recipient.x_sk,
            &recipient.pq_sk,
            &block_uuid,
        ).expect("decap");

        prop_assert_eq!(recovered.expose(), bck.expose());
    }

    /// For any `(..., field_idx, byte_idx)`, single-byte XOR-tamper one of
    /// the four wrap fields → decap must reject with `KemError::AeadFailure`.
    /// Rotates the existing fixed-byte tamper tests over arbitrary inputs.
    #[test]
    fn prop_hybrid_kem_tamper_any_field_rejects(
        sender_seed in arr32(),
        recipient_seed in arr32(),
        encap_seed in arr32(),
        block_uuid in arr16(),
        bck in arr32(),
        field_idx in 0u8..4,
        byte_idx in any::<u32>(),
        xor_byte in 1u8..=255,
    ) {
        let sender = build_recipient(sender_seed, [0xA1; 16], vec![0xB1; 64]);
        let recipient = build_recipient(recipient_seed, [0xA2; 16], vec![0xB2; 64]);
        let bck = Sensitive::new(bck);

        let mut rng = ChaCha20Rng::from_seed(encap_seed);
        let mut wrap = encap(
            &mut rng,
            &sender.fp,
            &recipient.fp,
            &sender.pk_bundle,
            &recipient.pk_bundle,
            &recipient.x_pk,
            &recipient.pq_pk,
            &block_uuid,
            &bck,
        ).expect("encap");

        // Tamper one byte of one chosen field. `xor_byte` is non-zero so the
        // mutation is real; `byte_idx` is reduced mod the field length so any
        // u32 maps to a valid offset.
        match field_idx {
            0 => { let i = (byte_idx as usize) % wrap.ct_x.len(); wrap.ct_x[i] ^= xor_byte; }
            1 => { let i = (byte_idx as usize) % wrap.ct_pq.len(); wrap.ct_pq[i] ^= xor_byte; }
            2 => { let i = (byte_idx as usize) % wrap.nonce_w.len(); wrap.nonce_w[i] ^= xor_byte; }
            _ => { let i = (byte_idx as usize) % wrap.ct_w.len(); wrap.ct_w[i] ^= xor_byte; }
        }

        let r = decap(
            &wrap,
            &sender.fp,
            &recipient.fp,
            &sender.pk_bundle,
            &recipient.pk_bundle,
            &recipient.x_sk,
            &recipient.pq_sk,
            &block_uuid,
        );
        prop_assert!(
            matches!(r, Err(KemError::AeadFailure(_))),
            "expected AEAD failure on tamper of field {}, got {:?}",
            field_idx, r
        );
    }
}
