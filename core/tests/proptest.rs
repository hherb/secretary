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

// ---------------------------------------------------------------------------
// Properties — unlock module (bundle CBOR, bundle-file wire, vault.toml,
// and the full create/open path)
// ---------------------------------------------------------------------------

mod unlock {
    use proptest::prelude::*;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    use secretary_core::crypto::kdf::Argon2idParams;
    use secretary_core::crypto::secret::SecretBytes;
    use secretary_core::unlock::{
        bundle, bundle_file, create_vault, open_with_password, vault_toml,
    };

    proptest! {
        /// `from_canonical_cbor(to_canonical_cbor(b)) == b` for any seed.
        /// Also checks that encoding twice yields identical bytes (determinism).
        #[test]
        fn identity_bundle_canonical_cbor_roundtrip(seed: [u8; 32]) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let b = bundle::generate("X", 0, &mut rng);
            let bytes_1 = b.to_canonical_cbor().unwrap();
            let bytes_2 = b.to_canonical_cbor().unwrap();
            prop_assert_eq!(&bytes_1, &bytes_2, "encoding non-deterministic");
            let parsed = bundle::IdentityBundle::from_canonical_cbor(&bytes_1).unwrap();
            prop_assert_eq!(parsed.user_uuid, b.user_uuid);
            prop_assert_eq!(parsed.x25519_pk, b.x25519_pk);
        }

        /// `decode(encode(f)) == f` for any well-formed BundleFile.
        #[test]
        fn bundle_file_roundtrip(
            vault_uuid in any::<[u8; 16]>(),
            created_at_ms in any::<u64>(),
            wpw_nonce in any::<[u8; 24]>(),
            wpw_ct in any::<[u8; 48]>(),
            wrec_nonce in any::<[u8; 24]>(),
            wrec_ct in any::<[u8; 48]>(),
            bundle_nonce in any::<[u8; 24]>(),
            bundle_ct in proptest::collection::vec(any::<u8>(), 16..1024),
        ) {
            let f = bundle_file::BundleFile {
                vault_uuid,
                created_at_ms,
                wrap_pw_nonce: wpw_nonce,
                wrap_pw_ct_with_tag: wpw_ct,
                wrap_rec_nonce: wrec_nonce,
                wrap_rec_ct_with_tag: wrec_ct,
                bundle_nonce,
                bundle_ct_with_tag: bundle_ct,
            };
            let bytes = bundle_file::encode(&f);
            let parsed = bundle_file::decode(&bytes).unwrap();
            prop_assert_eq!(parsed, f);
        }

        /// `decode(encode(v)) == v` for any well-formed VaultToml.
        ///
        /// `created_at_ms` is bounded to `0..=i64::MAX as u64` — the representable
        /// range for TOML's signed 64-bit integer. Values above i64::MAX are covered
        /// by the `vault_toml_encode_rejects_timestamp_out_of_range` property below.
        #[test]
        fn vault_toml_roundtrip(
            vault_uuid in any::<[u8; 16]>(),
            created_at_ms in 0u64..=(i64::MAX as u64),
            memory_kib in 8u32..1024u32,
            iterations in 1u32..16u32,
            parallelism in 1u32..8u32,
            salt in any::<[u8; 32]>(),
        ) {
            let v = vault_toml::VaultToml {
                format_version: 1,
                suite_id: 1,
                vault_uuid,
                created_at_ms,
                kdf: vault_toml::KdfSection {
                    algorithm: "argon2id".to_string(),
                    version: "1.3".to_string(),
                    memory_kib,
                    iterations,
                    parallelism,
                    salt,
                },
            };
            let s = vault_toml::encode(&v).unwrap();
            let parsed = vault_toml::decode(&s).unwrap();
            prop_assert_eq!(parsed, v);
        }

        /// `encode` returns `TimestampOutOfRange` — not a panic — for any
        /// `created_at_ms` above i64::MAX. Documents and pins the typed-error
        /// path that replaced the old `expect` panic.
        #[test]
        fn vault_toml_encode_rejects_timestamp_out_of_range(
            created_at_ms in (i64::MAX as u64 + 1)..=u64::MAX,
        ) {
            let v = vault_toml::VaultToml {
                format_version: 1,
                suite_id: 1,
                vault_uuid: [0u8; 16],
                created_at_ms,
                kdf: vault_toml::KdfSection {
                    algorithm: "argon2id".to_string(),
                    version: "1.3".to_string(),
                    memory_kib: 8,
                    iterations: 1,
                    parallelism: 1,
                    salt: [0u8; 32],
                },
            };
            let err = vault_toml::encode(&v).unwrap_err();
            prop_assert!(matches!(err, vault_toml::VaultTomlError::TimestampOutOfRange(_)));
        }

        /// `open_with_password(create_vault(...)) ` recovers the same IBK and
        /// user UUID. Uses weak Argon2id params for speed.
        #[test]
        fn create_then_open_roundtrip_preserves_identity(seed: [u8; 32], pw_seed: [u8; 16]) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let pw = SecretBytes::new(pw_seed.to_vec());
            let v = create_vault(&pw, "X", 0, Argon2idParams::new(8, 1, 1), &mut rng).unwrap();
            let opened = open_with_password(
                &v.vault_toml_bytes, &v.identity_bundle_bytes, &pw,
            ).unwrap();
            prop_assert_eq!(opened.identity_block_key.expose(), v.identity_block_key.expose());
            prop_assert_eq!(opened.identity.user_uuid, v.identity.user_uuid);
        }
    }
}
