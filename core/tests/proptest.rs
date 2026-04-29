#![forbid(unsafe_code)]

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
        bundle, bundle_file, create_vault_unchecked, open_with_password, vault_toml,
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

        /// `open_with_password(create_vault_unchecked(...))` recovers the
        /// same IBK and user UUID. Uses sub-floor Argon2id params (only
        /// permitted via the unchecked path) for proptest speed.
        #[test]
        fn create_then_open_roundtrip_preserves_identity(seed: [u8; 32], pw_seed: [u8; 16]) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let pw = SecretBytes::new(pw_seed.to_vec());
            let v = create_vault_unchecked(&pw, "X", 0, Argon2idParams::new(8, 1, 1), &mut rng).unwrap();
            let opened = open_with_password(
                &v.vault_toml_bytes, &v.identity_bundle_bytes, &pw,
            ).unwrap();
            prop_assert_eq!(opened.identity_block_key.expose(), v.identity_block_key.expose());
            prop_assert_eq!(opened.identity.user_uuid, v.identity.user_uuid);
        }
    }
}

// ---------------------------------------------------------------------------
// Properties — vault module (record CBOR, recipient table, BlockFile
// round-trip, full encrypt/decrypt round-trip, and verify-before-decap
// fuzzing on the §6.4 signed range)
// ---------------------------------------------------------------------------
//
// Strategy budgeting mirrors the crypto-heavy block above: anything that
// triggers `IdentityBundle::generate` (Argon2id-light + ML-KEM-768 keygen +
// ML-DSA-65 keygen) runs at `cases = 8` or `cases = 16`. Pure CBOR / pure
// byte-shape properties run at the proptest default (256).
//
// `signed_message_bytes` (§6.4) is private to `vault::block`; the signed
// range covers `magic..=aead_tag` inclusive. The trailing signature suffix
// is fixed-size 3393 bytes:
//   author_fingerprint  16
//   sig_ed_len           2
//   sig_ed              64
//   sig_pq_len           2
//   sig_pq            3309
// → SIGNATURE_SUFFIX_LEN = 16 + 2 + 64 + 2 + 3309 = 3393. Property E uses
// `bytes.len() - 3393` as the signed-range upper bound.

mod vault {
    use std::collections::BTreeMap;

    use proptest::prelude::*;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    // Re-implement the small helpers from the outer scope — proptest
    // strategies live inside `mod vault` and can't see top-of-file free
    // functions without `super::`. Local copies keep the inner module
    // self-contained.

    fn vec_exact(len: usize) -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), len..=len)
    }

    fn arr16() -> impl Strategy<Value = [u8; 16]> {
        any::<[u8; 16]>()
    }

    fn arr32() -> impl Strategy<Value = [u8; 32]> {
        any::<[u8; 32]>()
    }

    use secretary_core::crypto::aead::AEAD_TAG_LEN;
    use secretary_core::crypto::kem::{
        self, HybridWrap, MlKem768Public, MlKem768Secret, BLOCK_CONTENT_KEY_LEN,
        ML_KEM_768_CT_LEN, X25519_PK_LEN,
    };
    use secretary_core::crypto::secret::Sensitive;
    use secretary_core::crypto::sig::{
        Ed25519Secret, MlDsa65Public, MlDsa65Secret, ED25519_SIG_LEN, ML_DSA_65_SIG_LEN,
    };
    use secretary_core::unlock::bundle::{self, IdentityBundle};
    use secretary_core::vault::block::{
        decode_block_file, decode_recipient_table, decrypt_block, encode_block_file,
        encode_recipient_table, encrypt_block, BlockError, BlockHeader, BlockPlaintext,
        RecipientPublicKeys, RecipientWrap, FILE_KIND_BLOCK,
    };
    use secretary_core::vault::conflict::merge_record;
    use secretary_core::vault::record::{self, Record, RecordField, RecordFieldValue};
    use secretary_core::version::{FORMAT_VERSION, MAGIC, SUITE_ID};

    /// Fixed-size signature suffix per §6.1: author_fp(16) + sig_ed_len(2) +
    /// sig_ed(`ED25519_SIG_LEN`=64) + sig_pq_len(2) + sig_pq(`ML_DSA_65_SIG_LEN`=3309)
    /// = 3393 bytes. The signed range (`magic..=aead_tag`) is therefore
    /// `bytes.len() - SIGNATURE_SUFFIX_LEN`.
    ///
    /// Computed from upstream constants so a future widening of either
    /// signature length breaks compile loudly rather than silently
    /// desynchronising the byte-flip strategy in property E.
    const SIGNATURE_SUFFIX_LEN: usize = 16 + 2 + ED25519_SIG_LEN + 2 + ML_DSA_65_SIG_LEN;

    // -----------------------------------------------------------------------
    // Strategies
    // -----------------------------------------------------------------------

    /// Strategy for `RecordFieldValue` — half Text, half Bytes.
    fn field_value_strategy() -> impl Strategy<Value = RecordFieldValue> {
        prop_oneof![
            prop::collection::vec(any::<char>(), 0..=64)
                .prop_map(|cs| RecordFieldValue::Text(cs.into_iter().collect())),
            prop::collection::vec(any::<u8>(), 0..=128).prop_map(RecordFieldValue::Bytes),
        ]
    }

    /// Strategy for one `RecordField`. Per-field `unknown` left empty —
    /// modelling forward-compat unknowns in proptest adds significant
    /// strategy complexity beyond Task 7's scope; the integration tests
    /// in `core/tests/vault.rs` and the fixed KATs cover that path.
    fn record_field_strategy() -> impl Strategy<Value = RecordField> {
        (field_value_strategy(), any::<u64>(), any::<[u8; 16]>()).prop_map(
            |(value, last_mod, device_uuid)| RecordField {
                value,
                last_mod,
                device_uuid,
                unknown: BTreeMap::new(),
            },
        )
    }

    /// Strategy for `Record`. `record_type` is drawn from a small fixed set
    /// plus a "future_unknown" string so the property exercises both the
    /// §6.3.1 standard types and the open-ended-string contract. Field
    /// names are short ASCII to keep the strategy tractable. Record-level
    /// `unknown` left empty — same rationale as `record_field_strategy`.
    fn record_strategy() -> impl Strategy<Value = Record> {
        let record_type = prop_oneof![
            Just("login".to_string()),
            Just("note".to_string()),
            Just("totp".to_string()),
            Just("future_unknown".to_string()),
        ];
        let field_name = prop_oneof![
            Just("username".to_string()),
            Just("password".to_string()),
            Just("seed".to_string()),
            Just("notes".to_string()),
        ];
        let fields_strategy = prop::collection::btree_map(field_name, record_field_strategy(), 0..=3);
        let tags_strategy = prop::collection::vec("[a-z]{1,8}", 0..=3);

        (
            any::<[u8; 16]>(),    // record_uuid
            record_type,          // record_type
            fields_strategy,      // fields
            tags_strategy,        // tags
            any::<u64>(),         // created_at_ms
            any::<u64>(),         // last_mod_ms
            any::<bool>(),        // tombstone
            any::<u64>(),         // tombstoned_at_ms (raw — canonicalised at use sites)
        )
            .prop_map(
                |(record_uuid, record_type, fields, tags, created, last, tombstone, tombstoned)| {
                    Record {
                        record_uuid,
                        record_type,
                        fields,
                        tags,
                        created_at_ms: created,
                        last_mod_ms: last,
                        tombstone,
                        tombstoned_at_ms: tombstoned,
                        unknown: BTreeMap::new(),
                    }
                },
            )
    }

    /// Strategy for an ad-hoc `RecipientWrap`. The four `HybridWrap`
    /// fields use the spec-pinned wire lengths; the underlying bytes are
    /// arbitrary (decode does not crypto-validate them). The fingerprint
    /// drives the §6.2 sort invariant we test on `decode_recipient_table`.
    fn recipient_wrap_strategy() -> impl Strategy<Value = RecipientWrap> {
        (
            any::<[u8; 16]>(),
            any::<[u8; X25519_PK_LEN]>(),
            vec_exact(ML_KEM_768_CT_LEN),
            any::<[u8; 24]>(),
            vec_exact(BLOCK_CONTENT_KEY_LEN + AEAD_TAG_LEN),
        )
            .prop_map(|(fp, ct_x, ct_pq, nonce_w, ct_w)| RecipientWrap {
                recipient_fingerprint: fp,
                wrap: HybridWrap {
                    ct_x,
                    ct_pq,
                    nonce_w,
                    ct_w,
                },
            })
    }

    /// Inputs to the plaintext (all primitive proptest types) so the
    /// crypto-heavy properties can derive a `BlockPlaintext` keyed to
    /// the header's `block_uuid` without the closure-over-uuid pattern
    /// proptest macros don't compose with.
    type PlaintextInputs = (String, Vec<Record>);

    fn plaintext_inputs_strategy() -> impl Strategy<Value = PlaintextInputs> {
        (
            "[a-z ]{0,32}",
            prop::collection::vec(record_strategy(), 0..=2),
        )
    }

    fn build_plaintext(block_uuid: [u8; 16], inputs: PlaintextInputs) -> BlockPlaintext {
        let (block_name, records) = inputs;
        BlockPlaintext {
            block_version: 1,
            block_uuid,
            block_name,
            schema_version: 1,
            records,
            unknown: BTreeMap::new(),
        }
    }

    /// Strategy for a minimal `BlockHeader`. Empty vector clock keeps the
    /// signed-range fuzzer's offset arithmetic simple — every test case
    /// puts the recipient table at the same offset.
    fn block_header_strategy() -> impl Strategy<Value = BlockHeader> {
        (
            any::<[u8; 16]>(), // vault_uuid
            any::<[u8; 16]>(), // block_uuid
            any::<u64>(),      // created_at_ms
            any::<u64>(),      // last_mod_ms
        )
            .prop_map(
                |(vault_uuid, block_uuid, created_at_ms, last_mod_ms)| BlockHeader {
                    magic: MAGIC,
                    format_version: FORMAT_VERSION,
                    suite_id: SUITE_ID,
                    file_kind: FILE_KIND_BLOCK,
                    vault_uuid,
                    block_uuid,
                    created_at_ms,
                    last_mod_ms,
                    vector_clock: Vec::new(),
                },
            )
    }

    // -----------------------------------------------------------------------
    // Helpers — identity + handles for the crypto-heavy properties
    // -----------------------------------------------------------------------

    struct VaultHandles {
        id: IdentityBundle,
        fp: [u8; 16],
        pk_bundle: Vec<u8>,
        pq_pk: MlKem768Public,
        ed_sk: Ed25519Secret,
        dsa_sk: MlDsa65Secret,
        dsa_pk: MlDsa65Public,
        x_sk: kem::X25519Secret,
        pq_sk: MlKem768Secret,
    }

    fn build_vault_handles(seed: [u8; 32], fp: [u8; 16]) -> VaultHandles {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let id = bundle::generate("X", 1_714_060_800_000, &mut rng);

        let mut pk_bundle = Vec::with_capacity(
            id.x25519_pk.len() + id.ml_kem_768_pk.len() + id.ed25519_pk.len() + id.ml_dsa_65_pk.len(),
        );
        pk_bundle.extend_from_slice(&id.x25519_pk);
        pk_bundle.extend_from_slice(&id.ml_kem_768_pk);
        pk_bundle.extend_from_slice(&id.ed25519_pk);
        pk_bundle.extend_from_slice(&id.ml_dsa_65_pk);

        let pq_pk = MlKem768Public::from_bytes(&id.ml_kem_768_pk).expect("ml-kem pk len");
        let ed_sk: Ed25519Secret = Sensitive::new(*id.ed25519_sk.expose());
        let dsa_sk = MlDsa65Secret::from_bytes(id.ml_dsa_65_sk.expose()).expect("ml-dsa sk len");
        let dsa_pk = MlDsa65Public::from_bytes(&id.ml_dsa_65_pk).expect("ml-dsa pk len");
        let x_sk: kem::X25519Secret = Sensitive::new(*id.x25519_sk.expose());
        let pq_sk = MlKem768Secret::from_bytes(id.ml_kem_768_sk.expose()).expect("ml-kem sk len");

        VaultHandles {
            id,
            fp,
            pk_bundle,
            pq_pk,
            ed_sk,
            dsa_sk,
            dsa_pk,
            x_sk,
            pq_sk,
        }
    }

    // -----------------------------------------------------------------------
    // Properties — pure CBOR / pure byte-shape (default cases)
    // -----------------------------------------------------------------------

    proptest! {
        /// Property A. Pure CBOR canonicalisation: `encode(decode(encode(r)))
        /// == encode(r)` and `decode(encode(r)) == r`. Pins the §6.3 record
        /// canonical-form invariant on arbitrary records, complementing the
        /// fixed KATs.
        #[test]
        fn record_canonical_cbor_bit_identical(r in record_strategy()) {
            let bytes_1 = record::encode(&r).expect("encode r");
            let parsed = record::decode(&bytes_1).expect("decode r");
            prop_assert_eq!(&parsed, &r, "decode(encode(r)) != r");
            let bytes_2 = record::encode(&parsed).expect("re-encode");
            prop_assert_eq!(&bytes_1, &bytes_2, "encode→decode→encode not bit-identical");
        }

        /// Property B. Pure byte-manipulation: encode_recipient_table
        /// sorts ascending by fingerprint and re-encoding the decoded
        /// table is bit-identical. Covers the §6.2 sort invariant under
        /// arbitrary fingerprint orderings (proptest will shrink toward
        /// the smallest disordering counterexample if the invariant breaks).
        #[test]
        fn block_recipient_table_sort_invariant(
            wraps in prop::collection::vec(recipient_wrap_strategy(), 1..=4)
                .prop_filter(
                    "duplicate fingerprints rejected by encode_recipient_table",
                    |ws| {
                        let mut fps: Vec<_> =
                            ws.iter().map(|w| w.recipient_fingerprint).collect();
                        fps.sort();
                        fps.windows(2).all(|p| p[0] != p[1])
                    },
                ),
        ) {
            let bytes_1 = encode_recipient_table(&wraps).expect("encode rt");
            let (decoded, rest) = decode_recipient_table(&bytes_1).expect("decode rt");
            prop_assert!(rest.is_empty(), "decode left trailing bytes");
            // Sorted ascending by fingerprint.
            for w in decoded.windows(2) {
                prop_assert!(
                    w[0].recipient_fingerprint < w[1].recipient_fingerprint,
                    "recipient table not sorted ascending"
                );
            }
            // Re-encoding the decoded table is bit-identical.
            let bytes_2 = encode_recipient_table(&decoded).expect("re-encode rt");
            prop_assert_eq!(bytes_1, bytes_2, "encode→decode→encode not bit-identical");
        }
    }

    // -----------------------------------------------------------------------
    // Properties — crypto-heavy (IdentityBundle keygen, reduced cases)
    // -----------------------------------------------------------------------

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(8))]

        /// Property C. Full BlockFile encode/decode is a fixed point on
        /// arbitrary block content. Generates a fresh IdentityBundle, builds
        /// a single-self-recipient block, and asserts:
        /// `decode(encode(b)) == b` AND `encode(decode(encode(b))) == encode(b)`.
        #[test]
        fn block_file_encode_decode_bit_identical(
            id_seed in arr32(),
            aead_seed in arr32(),
            fp in arr16(),
            header in block_header_strategy(),
            pt_inputs in plaintext_inputs_strategy(),
        ) {
            let h = build_vault_handles(id_seed, fp);
            let plaintext = build_plaintext(header.block_uuid, pt_inputs);

            let mut rng = ChaCha20Rng::from_seed(aead_seed);
            let recipients = [RecipientPublicKeys {
                fingerprint: h.fp,
                pk_bundle: &h.pk_bundle,
                x25519_pk: &h.id.x25519_pk,
                ml_kem_768_pk: &h.pq_pk,
            }];
            let block = encrypt_block(
                &mut rng,
                &header,
                &plaintext,
                &h.fp,
                &h.pk_bundle,
                &h.ed_sk,
                &h.dsa_sk,
                &recipients,
            ).expect("encrypt_block");

            let bytes_1 = encode_block_file(&block).expect("encode_block_file");
            let decoded = decode_block_file(&bytes_1).expect("decode_block_file");
            prop_assert_eq!(&decoded, &block, "decode(encode(b)) != b");
            let bytes_2 = encode_block_file(&decoded).expect("re-encode");
            prop_assert_eq!(bytes_1, bytes_2, "encode→decode→encode not bit-identical");
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        /// Property D. Full encrypt → decrypt round-trip recovers the
        /// plaintext on arbitrary input. Covers the §6.5 → §6.4 inverse
        /// path under the single-self-recipient configuration; multi-
        /// recipient is exercised by the integration tests.
        #[test]
        fn block_encrypt_decrypt_roundtrip_self(
            id_seed in arr32(),
            aead_seed in arr32(),
            fp in arr16(),
            header in block_header_strategy(),
            pt_inputs in plaintext_inputs_strategy(),
        ) {
            let h = build_vault_handles(id_seed, fp);
            let plaintext = build_plaintext(header.block_uuid, pt_inputs);

            let mut rng = ChaCha20Rng::from_seed(aead_seed);
            let recipients = [RecipientPublicKeys {
                fingerprint: h.fp,
                pk_bundle: &h.pk_bundle,
                x25519_pk: &h.id.x25519_pk,
                ml_kem_768_pk: &h.pq_pk,
            }];
            let block = encrypt_block(
                &mut rng,
                &header,
                &plaintext,
                &h.fp,
                &h.pk_bundle,
                &h.ed_sk,
                &h.dsa_sk,
                &recipients,
            ).expect("encrypt_block");

            let recovered = decrypt_block(
                &block,
                &h.fp,
                &h.pk_bundle,
                &h.id.ed25519_pk,
                &h.dsa_pk,
                &h.fp,
                &h.pk_bundle,
                &h.x_sk,
                &h.pq_sk,
            ).expect("decrypt_block");
            prop_assert_eq!(recovered, plaintext);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(8))]

        /// Property E. Verify-before-decap fuzzing. Flip a single byte
        /// anywhere inside the §6.4 signed range (`magic..=aead_tag`).
        /// The full `decode_block_file` → `decrypt_block` pipeline must
        /// reject the result with EITHER the §8 hybrid signature failure
        /// (`BlockError::Sig`) OR a structural decode error from the
        /// header / recipient-table / AEAD-section parser.
        ///
        /// What MUST NOT happen — pinning the security contract:
        ///
        /// 1. `Ok(_)` — silent acceptance of a forged file.
        /// 2. `BlockError::Aead(_)` — body AEAD-decrypt should never run
        ///    on a tampered file (§6.4 step 2 verifies first).
        /// 3. `BlockError::Kem(_)` — hybrid-decap should never run on a
        ///    tampered file (§6.4 step 4 runs after step 2).
        /// 4. `BlockError::AuthorFingerprintMismatch` — the
        ///    author_fingerprint field sits AFTER `aead_tag` in the
        ///    signature suffix, outside our flip range, so this cannot
        ///    fire from a flip in the signed range.
        /// 5. `BlockError::NotARecipient` — decap-side lookup, only
        ///    reached after the signature verifies.
        #[test]
        fn block_decrypt_rejects_corrupted_signed_range(
            id_seed in arr32(),
            aead_seed in arr32(),
            fp in arr16(),
            header in block_header_strategy(),
            pt_inputs in plaintext_inputs_strategy(),
            byte_idx_seed in any::<u32>(),
            xor_byte in 1u8..=255,
        ) {
            let h = build_vault_handles(id_seed, fp);
            let plaintext = build_plaintext(header.block_uuid, pt_inputs);

            let mut rng = ChaCha20Rng::from_seed(aead_seed);
            let recipients = [RecipientPublicKeys {
                fingerprint: h.fp,
                pk_bundle: &h.pk_bundle,
                x25519_pk: &h.id.x25519_pk,
                ml_kem_768_pk: &h.pq_pk,
            }];
            let block = encrypt_block(
                &mut rng,
                &header,
                &plaintext,
                &h.fp,
                &h.pk_bundle,
                &h.ed_sk,
                &h.dsa_sk,
                &recipients,
            ).expect("encrypt_block");

            let mut bytes = encode_block_file(&block).expect("encode_block_file");
            // Signed range is `magic..=aead_tag`, i.e. everything before
            // the fixed-size signature suffix. SIGNATURE_SUFFIX_LEN is the
            // §6.1 trailing block: author_fp + sig_ed_len + sig_ed +
            // sig_pq_len + sig_pq.
            let signed_len = bytes.len() - SIGNATURE_SUFFIX_LEN;
            prop_assert!(signed_len > 0, "encoded block too small");
            let i = (byte_idx_seed as usize) % signed_len;
            bytes[i] ^= xor_byte;

            let result = (|| -> Result<BlockPlaintext, BlockError> {
                let tampered = decode_block_file(&bytes)?;
                decrypt_block(
                    &tampered,
                    &h.fp,
                    &h.pk_bundle,
                    &h.id.ed25519_pk,
                    &h.dsa_pk,
                    &h.fp,
                    &h.pk_bundle,
                    &h.x_sk,
                    &h.pq_sk,
                )
            })();

            match result {
                Ok(_) => prop_assert!(
                    false,
                    "tampered byte at offset {} of {} (signed range) was silently accepted",
                    i, signed_len,
                ),
                Err(BlockError::Aead(e)) => prop_assert!(
                    false,
                    "verify-before-decap bypassed: AEAD ran on tampered byte at offset {}: {}",
                    i, e,
                ),
                Err(BlockError::Kem(e)) => prop_assert!(
                    false,
                    "verify-before-decap bypassed: KEM ran on tampered byte at offset {}: {}",
                    i, e,
                ),
                Err(BlockError::AuthorFingerprintMismatch { .. }) => prop_assert!(
                    false,
                    "AuthorFingerprintMismatch unreachable from flip in signed range at offset {}",
                    i,
                ),
                Err(BlockError::NotARecipient { .. }) => prop_assert!(
                    false,
                    "NotARecipient unreachable from flip in signed range at offset {}",
                    i,
                ),
                // Permitted: §8 signature verify failure OR any structural
                // decode rejection (BadMagic, UnsupportedFormatVersion,
                // UnsupportedSuiteId, WrongFileKind, Truncated,
                // RecipientsNotSorted, DuplicateRecipient, EmptyRecipientList,
                // RecipientCtPqWrongLength, RecipientCtWrongLength,
                // VectorClockNotSorted, VectorClockDuplicateDevice,
                // VectorClockCountMismatch, TooManyRecipients,
                // SigEdWrongLength, SigPqWrongLength, SigPqTooLong,
                // TrailingBytes, IntegerOverflow). All are valid responses
                // to a single-byte tamper inside the signed range.
                Err(_) => {}
            }
        }
    }

    // -----------------------------------------------------------------------
    // PR-C properties I, J, K — CRDT merge invariants on `merge_record`.
    //
    // The §11 spec claims commutativity, associativity, and idempotence
    // of the per-record merge. These three properties pin those claims
    // against the entire `MergedRecord` (i.e. bit-identical equality on
    // both `.merged` and `.collisions` for I and K; `.merged` only for J
    // — `.collisions` is per-step informational and does not survive
    // through an intermediate persisted record).
    //
    // Inputs share `record_uuid` (otherwise the merge precondition would
    // not hold) but everything else is drawn from the existing
    // `record_strategy()`. Default proptest case count (256) — these are
    // pure CBOR / map operations; no crypto keygen on the hot path.
    // -----------------------------------------------------------------------

    /// Canonicalize a Record into the form well-formed clients emit
    /// (the §11.5 invariants). `record_strategy()` generates raw data
    /// that may violate them; merging trivially canonicalises, so the
    /// CRDT proptests canonicalise inputs first to make commutativity
    /// / associativity / idempotence hold bit-identically.
    ///
    /// Invariants applied:
    ///
    /// - `tags` sorted lex and deduped (§11.1 — the merge always emits
    ///   tags in this canonical form on tie via set union).
    /// - `last_mod_ms ≥ max(field.last_mod for field in fields)` —
    ///   real clients bump the record-level `last_mod_ms` whenever
    ///   they touch any field, so per-field edits never out-pace the
    ///   record clock.
    /// - `tombstoned_at_ms ≤ last_mod_ms`; equality when
    ///   `tombstone == true` (§11.3 / §11.5). A currently-tombstoned
    ///   record was tombstoned at its most recent edit; a previously-
    ///   tombstoned-then-resurrected record carries a death clock
    ///   somewhere in `[0, last_mod_ms]`.
    /// - When `tombstone == true`: `fields` is cleared (§6.3 / §11.3).
    fn canonicalize_record(r: &mut Record) {
        r.tags.sort();
        r.tags.dedup();
        let max_field_lm = r.fields.values().map(|f| f.last_mod).max().unwrap_or(0);
        r.last_mod_ms = r.last_mod_ms.max(max_field_lm);
        if r.tombstone {
            r.fields.clear();
            r.tombstoned_at_ms = r.last_mod_ms;
        } else {
            r.tombstoned_at_ms = r.tombstoned_at_ms.min(r.last_mod_ms);
            // Drop fields that the §11.3 staleness filter would
            // remove on the next merge. Keeping them would violate
            // idempotence: `merge(a, a)` would canonicalise the
            // record by dropping them, producing `a' != a`. The
            // canonical form is "the record after one round of
            // self-merge" — tags sorted+deduped, fields above the
            // death clock, etc.
            if r.tombstoned_at_ms > 0 {
                let death = r.tombstoned_at_ms;
                r.fields.retain(|_, f| f.last_mod > death);
            }
        }
    }

    proptest! {
        /// Property I — `merge_record(a, b) == merge_record(b, a)` on
        /// the entire MergedRecord (merged + collisions).
        #[test]
        fn crdt_merge_record_commutativity(
            uuid in any::<[u8; 16]>(),
            a in record_strategy(),
            b in record_strategy(),
        ) {
            let mut a = a;
            let mut b = b;
            a.record_uuid = uuid;
            b.record_uuid = uuid;
            canonicalize_record(&mut a);
            canonicalize_record(&mut b);
            let ab = merge_record(&a, &b);
            let ba = merge_record(&b, &a);
            prop_assert_eq!(ab, ba);
        }

        /// Property J — associativity on the persisted record only:
        /// `merge_record(merge_record(a, b).merged, c).merged ==
        ///  merge_record(a, merge_record(b, c).merged).merged`.
        ///
        /// Per-step `collisions` lists are not preserved through an
        /// intermediate persisted record (the LWW winner replaces the
        /// loser in the intermediate `.merged`), so associativity is
        /// claimed on `.merged` alone — matching the spec's claim.
        #[test]
        fn crdt_merge_record_associativity(
            uuid in any::<[u8; 16]>(),
            a in record_strategy(),
            b in record_strategy(),
            c in record_strategy(),
        ) {
            let mut a = a;
            let mut b = b;
            let mut c = c;
            a.record_uuid = uuid;
            b.record_uuid = uuid;
            c.record_uuid = uuid;
            canonicalize_record(&mut a);
            canonicalize_record(&mut b);
            canonicalize_record(&mut c);
            let left = merge_record(&merge_record(&a, &b).merged, &c).merged;
            let right = merge_record(&a, &merge_record(&b, &c).merged).merged;
            prop_assert_eq!(left, right);
        }

        /// Property K — `merge_record(a, a) == MergedRecord { merged: a,
        /// collisions: [] }`. Idempotence on the full structure.
        #[test]
        fn crdt_merge_record_idempotence(a in record_strategy()) {
            let mut a = a;
            canonicalize_record(&mut a);
            let m = merge_record(&a, &a);
            prop_assert_eq!(&m.merged, &a);
            prop_assert!(m.collisions.is_empty());
        }

        /// Property L — `merge_record` produces a §11.5 well-formed
        /// output for **arbitrary** (non-canonicalised, possibly
        /// hostile) inputs, AND that output is a fixed point under
        /// self-merge.
        ///
        /// Properties I, J, K above pre-canonicalise inputs via
        /// `canonicalize_record`, so they certify CRDT correctness on
        /// the canonical sub-domain only. The defensive clamp in
        /// `merge_record` is supposed to canonicalise opportunistically
        /// — i.e., merging arbitrary inputs (including the malformed
        /// shapes a hostile sync peer might ship) must still produce a
        /// well-formed merged record. Pre-PR review #2 flagged that
        /// the proptest harness did not exercise this claim.
        ///
        /// Three invariants are asserted on the merged output, which
        /// the merge code is responsible for enforcing regardless of
        /// input well-formedness:
        ///
        /// * §11.5 / death-clock: `tombstoned_at_ms ≤ last_mod_ms`
        ///   always (the clamp + lattice join cannot exceed the
        ///   merged `last_mod_ms`, which is `max` of both sides').
        /// * §11.5 / tombstone equality: `tombstone == true ⇒
        ///   tombstoned_at_ms == last_mod_ms`.
        /// * §6.3 / §11.3: `tombstone == true ⇒ fields.is_empty()`.
        ///
        /// Plus the canonicalisation-fixed-point claim:
        ///
        /// * `merge_record(m, m) == MergedRecord { merged: m,
        ///   collisions: [] }` for `m = merge_record(a, b).merged` —
        ///   the merge output is its own self-merge.
        ///
        /// This last property is the strongest of the four: it
        /// implies the output is in canonical form (otherwise
        /// self-merge would canonicalise further), which transitively
        /// implies the §11.5 invariants the merge is responsible for.
        /// The first three are kept as separate assertions so a
        /// regression in any single invariant is reported precisely
        /// rather than as a generic equality mismatch. Other §11.5
        /// invariants (`tags` sorted+deduped, `last_mod_ms ≥
        /// max(field.last_mod)`) are write-path responsibilities and
        /// not enforced by the merge alone, so they are not asserted
        /// here.
        ///
        /// `record_uuid` is unified as in the other properties; no
        /// other input canonicalisation is applied.
        #[test]
        fn crdt_merge_record_well_formed_under_arbitrary_inputs(
            uuid in any::<[u8; 16]>(),
            a in record_strategy(),
            b in record_strategy(),
        ) {
            let mut a = a;
            let mut b = b;
            a.record_uuid = uuid;
            b.record_uuid = uuid;
            // Intentionally NO canonicalize_record() — feed raw inputs.

            let merged = merge_record(&a, &b).merged;

            // §11.5 invariant 1: tombstoned_at_ms ≤ last_mod_ms.
            prop_assert!(
                merged.tombstoned_at_ms <= merged.last_mod_ms,
                "§11.5 violated: merged.tombstoned_at_ms={} > last_mod_ms={}",
                merged.tombstoned_at_ms,
                merged.last_mod_ms
            );

            // §11.5 invariant 2: tombstone == true ⇒ tombstoned_at_ms == last_mod_ms.
            if merged.tombstone {
                prop_assert_eq!(
                    merged.tombstoned_at_ms, merged.last_mod_ms,
                    "§11.5 violated: tombstoned merged record has tombstoned_at_ms != last_mod_ms"
                );
                // §6.3 / §11.3: tombstoned merged record has empty fields.
                prop_assert!(
                    merged.fields.is_empty(),
                    "§11.3 violated: tombstoned merged record has {} fields",
                    merged.fields.len()
                );
            }

            // Canonicalisation-fixed-point: self-merge of the merged
            // output is a no-op. This implies the output is canonical;
            // a regression here would mean the merge's first round of
            // canonicalisation was incomplete (e.g., the clamp missed
            // a malformation, or a tombstone-tie outcome left
            // identity metadata in a non-canonical form).
            let self_merged = merge_record(&merged, &merged);
            prop_assert_eq!(&self_merged.merged, &merged);
            prop_assert!(self_merged.collisions.is_empty());
        }
    }
}

// ---------------------------------------------------------------------------
// PR-B properties F, G, H — manifest round-trip, tamper detection,
// verify-before-decrypt. Mirror block-layer properties (PR-A) for
// the §4.1 manifest envelope.
// ---------------------------------------------------------------------------
//
// Strategy budgeting mirrors `mod vault`: pure CBOR round-trip (Property F)
// runs at the proptest default of 256 cases; the crypto-heavy tamper +
// verify-before-decrypt properties (G, H) trigger ML-DSA-65 keygen and run
// at `cases = 8`. The hybrid keypair is generated once per test case from
// a proptest-supplied seed via `ChaCha20Rng::from_seed` — same pattern as
// the block-layer `build_vault_handles` helper above.
//
// `unknown` BTreeMaps on `Manifest` / `BlockEntry` / `TrashEntry` are left
// empty for the same reason they are left empty in `record_strategy` and
// `record_field_strategy`: modelling forward-compat unknowns adds
// significant strategy complexity and is the deferred enhancement noted in
// secretary_next_session.md Item 7. The fixed KATs in `core/src/vault/manifest.rs`
// `mod tests` and the integration tests in `core/tests/vault.rs` cover the
// unknown-key round-trip path.

mod manifest_props {
    use std::collections::BTreeMap;

    use proptest::prelude::*;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    use secretary_core::crypto::aead::{AeadKey, AeadNonce};
    use secretary_core::crypto::secret::Sensitive;
    use secretary_core::crypto::sig::{
        self, Ed25519Public, Ed25519Secret, MlDsa65Public, MlDsa65Secret,
    };
    use secretary_core::vault::manifest::{
        decode_manifest, decode_manifest_file, decrypt_manifest_body, encode_manifest,
        encode_manifest_file, sign_manifest, verify_manifest, BlockEntry, KdfParamsRef, Manifest,
        ManifestError, ManifestHeader, TrashEntry, VectorClockEntry,
    };
    use secretary_core::version::{FORMAT_VERSION, SUITE_ID};

    const UUID_LEN: usize = 16;
    const FINGERPRINT_LEN: usize = 32;
    const SALT_LEN: usize = 32;
    const MANIFEST_VERSION_V1: u8 = 1;

    // -----------------------------------------------------------------------
    // Strategies — manifest body
    // -----------------------------------------------------------------------

    fn arr16() -> impl Strategy<Value = [u8; UUID_LEN]> {
        any::<[u8; UUID_LEN]>()
    }

    fn arr32_fp() -> impl Strategy<Value = [u8; FINGERPRINT_LEN]> {
        any::<[u8; FINGERPRINT_LEN]>()
    }

    fn arr32_salt() -> impl Strategy<Value = [u8; SALT_LEN]> {
        any::<[u8; SALT_LEN]>()
    }

    /// Strategy for `VectorClockEntry`. `counter` is bounded to `0..=1000`
    /// rather than `any::<u64>()` because shrinking large u64s nicely is
    /// expensive and the shape we care about (per-device monotonic, sort
    /// invariant) is exercised at any range.
    fn vector_clock_entry_strategy() -> impl Strategy<Value = VectorClockEntry> {
        (arr16(), 0u64..=1000).prop_map(|(device_uuid, counter)| VectorClockEntry {
            device_uuid,
            counter,
        })
    }

    fn vector_clock_strategy() -> impl Strategy<Value = Vec<VectorClockEntry>> {
        prop::collection::vec(vector_clock_entry_strategy(), 0..=4)
            .prop_filter("duplicate device_uuid in vector clock", |vc| {
                let mut ids: Vec<[u8; UUID_LEN]> =
                    vc.iter().map(|e| e.device_uuid).collect();
                ids.sort();
                ids.windows(2).all(|p| p[0] != p[1])
            })
    }

    /// Strategy for `BlockEntry`. `block_name` is bounded ASCII; nested
    /// `vector_clock_summary` and `recipients` use the same dedup discipline
    /// as the top-level vector clock and the per-block recipients sort
    /// invariant.
    fn block_entry_strategy() -> impl Strategy<Value = BlockEntry> {
        (
            arr16(),                                                     // block_uuid
            "[a-zA-Z0-9_-]{0,20}",                                       // block_name
            arr32_fp(),                                                  // fingerprint
            prop::collection::vec(arr16(), 0..=3),                       // recipients
            vector_clock_strategy(),                                     // vector_clock_summary
            any::<u64>(),                                                // created_at_ms
            any::<u64>(),                                                // last_mod_ms
        )
            .prop_filter("duplicate recipient uuid", |(_, _, _, recip, _, _, _)| {
                let mut sorted = recip.clone();
                sorted.sort();
                sorted.windows(2).all(|p| p[0] != p[1])
            })
            .prop_map(
                |(
                    block_uuid,
                    block_name,
                    fingerprint,
                    recipients,
                    vector_clock_summary,
                    created_at_ms,
                    last_mod_ms,
                )| BlockEntry {
                    block_uuid,
                    block_name,
                    fingerprint,
                    recipients,
                    vector_clock_summary,
                    suite_id: SUITE_ID,
                    created_at_ms,
                    last_mod_ms,
                    unknown: BTreeMap::new(),
                },
            )
    }

    fn blocks_strategy() -> impl Strategy<Value = Vec<BlockEntry>> {
        prop::collection::vec(block_entry_strategy(), 0..=3).prop_filter(
            "duplicate block_uuid in blocks array",
            |bs| {
                let mut ids: Vec<[u8; UUID_LEN]> = bs.iter().map(|b| b.block_uuid).collect();
                ids.sort();
                ids.windows(2).all(|p| p[0] != p[1])
            },
        )
    }

    fn trash_entry_strategy() -> impl Strategy<Value = TrashEntry> {
        (arr16(), any::<u64>(), arr16()).prop_map(
            |(block_uuid, tombstoned_at_ms, tombstoned_by)| TrashEntry {
                block_uuid,
                tombstoned_at_ms,
                tombstoned_by,
                unknown: BTreeMap::new(),
            },
        )
    }

    fn trash_strategy() -> impl Strategy<Value = Vec<TrashEntry>> {
        prop::collection::vec(trash_entry_strategy(), 0..=2).prop_filter(
            "duplicate block_uuid in trash array",
            |ts| {
                let mut ids: Vec<[u8; UUID_LEN]> = ts.iter().map(|t| t.block_uuid).collect();
                ids.sort();
                ids.windows(2).all(|p| p[0] != p[1])
            },
        )
    }

    fn kdf_params_strategy() -> impl Strategy<Value = KdfParamsRef> {
        (any::<u32>(), any::<u32>(), any::<u32>(), arr32_salt()).prop_map(
            |(memory_kib, iterations, parallelism, salt)| KdfParamsRef {
                memory_kib,
                iterations,
                parallelism,
                salt,
            },
        )
    }

    fn manifest_strategy() -> impl Strategy<Value = Manifest> {
        (
            arr16(),                  // vault_uuid
            arr16(),                  // owner_user_uuid
            vector_clock_strategy(),  // vector_clock
            blocks_strategy(),        // blocks
            trash_strategy(),         // trash
            kdf_params_strategy(),    // kdf_params
        )
            .prop_map(
                |(vault_uuid, owner_user_uuid, vector_clock, blocks, trash, kdf_params)| {
                    Manifest {
                        manifest_version: MANIFEST_VERSION_V1,
                        vault_uuid,
                        format_version: FORMAT_VERSION,
                        suite_id: SUITE_ID,
                        owner_user_uuid,
                        vector_clock,
                        blocks,
                        trash,
                        kdf_params,
                        unknown: BTreeMap::new(),
                    }
                },
            )
    }

    // -----------------------------------------------------------------------
    // Helpers — keypair / IBK / nonce / header
    // -----------------------------------------------------------------------

    struct Keypair {
        sk_ed: Ed25519Secret,
        pk_ed: Ed25519Public,
        sk_pq: MlDsa65Secret,
        pk_pq: MlDsa65Public,
    }

    fn build_keypair(seed: [u8; 32]) -> Keypair {
        let mut ed_rng = ChaCha20Rng::from_seed(seed);
        // Derive the PQ-rng seed deterministically from the same input so a
        // single proptest seed parameter drives both halves; the offset
        // mirrors the manifest unit tests' fixture pattern (seed vs
        // seed+1).
        let mut pq_seed = seed;
        pq_seed[0] = pq_seed[0].wrapping_add(1);
        let mut pq_rng = ChaCha20Rng::from_seed(pq_seed);
        let (sk_ed, pk_ed) = sig::generate_ed25519(&mut ed_rng);
        let (sk_pq, pk_pq) = sig::generate_ml_dsa_65(&mut pq_rng);
        Keypair {
            sk_ed,
            pk_ed,
            sk_pq,
            pk_pq,
        }
    }

    fn build_ibk(byte: u8) -> AeadKey {
        Sensitive::new([byte; 32])
    }

    fn build_nonce(seed: u8) -> AeadNonce {
        let mut n = [0u8; 24];
        for (i, b) in n.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8);
        }
        n
    }

    fn build_header(m: &Manifest) -> ManifestHeader {
        ManifestHeader {
            vault_uuid: m.vault_uuid,
            created_at_ms: 1_714_060_800_000,
            last_mod_ms: 1_714_060_900_000,
        }
    }

    // -----------------------------------------------------------------------
    // Property F — manifest body round-trip (pure CBOR, default cases)
    // -----------------------------------------------------------------------

    proptest! {
        /// Property F. `decode_manifest(encode_manifest(m)) == m` for any
        /// well-formed [`Manifest`]. Catches encoder/decoder asymmetry that
        /// the fixed KATs in `core/src/vault/manifest.rs::tests` cannot
        /// catch by construction (they only pin pre-chosen inputs).
        ///
        /// All sort-discipline arrays (`vector_clock`, per-block
        /// `vector_clock_summary`, `blocks`, `trash`, per-block
        /// `recipients`) are generated *already sorted* by construction
        /// here — we use `prop_filter` to reject duplicates rather than
        /// shuffling — so `decode(encode(m)) == m` holds without the
        /// canonical-sort-then-compare dance the unit tests use for the
        /// hand-rolled non-canonical fixture.
        ///
        /// Strategies generate sorted-on-the-wire arrays as follows:
        /// every `Vec<VectorClockEntry>` enforces `device_uuid` uniqueness
        /// but DOES NOT pre-sort; `encode_manifest` sorts on output and
        /// `decode_manifest` returns the sorted form. So we sort `m`'s
        /// arrays before comparing — same trick as
        /// `roundtrip_populated_manifest`.
        #[test]
        fn manifest_roundtrip(m in manifest_strategy()) {
            let bytes = encode_manifest(&m).expect("encode_manifest");
            let parsed = decode_manifest(&bytes).expect("decode_manifest");

            // Sort `m`'s arrays in canonical order to match the decoded form.
            let mut m_sorted = m.clone();
            m_sorted
                .vector_clock
                .sort_by(|a, b| a.device_uuid.cmp(&b.device_uuid));
            m_sorted.blocks.sort_by(|a, b| a.block_uuid.cmp(&b.block_uuid));
            for blk in &mut m_sorted.blocks {
                blk.recipients.sort();
                blk.vector_clock_summary
                    .sort_by(|a, b| a.device_uuid.cmp(&b.device_uuid));
            }
            m_sorted.trash.sort_by(|a, b| a.block_uuid.cmp(&b.block_uuid));

            prop_assert_eq!(&parsed, &m_sorted);

            // Re-encode is bit-identical (canonical CBOR).
            let bytes_again = encode_manifest(&parsed).expect("re-encode");
            prop_assert_eq!(bytes, bytes_again, "encode→decode→encode not bit-identical");
        }
    }

    // -----------------------------------------------------------------------
    // Properties G, H — crypto-heavy (ML-DSA-65 keygen, reduced cases)
    // -----------------------------------------------------------------------

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(8))]

        /// Property G. Single-byte XOR-tamper anywhere in the encoded
        /// `ManifestFile` must be rejected by at least one of:
        ///
        /// 1. `decode_manifest_file` — structural / length validation.
        /// 2. `verify_manifest` — §8 hybrid signature verify.
        /// 3. `decrypt_manifest_body` — AEAD tag verify.
        ///
        /// Silent acceptance (the file decodes cleanly, the signature
        /// verifies, AND the AEAD body decrypts) is a security violation.
        /// Mirrors PR-A's block-layer Property E discipline.
        ///
        /// The §4.1 envelope has one byte region — `author_fingerprint`
        /// (16 bytes between `aead_tag` and `sig_ed_len`) — that is NOT
        /// inside the §8 signed range and NOT inside the AEAD AAD. A
        /// flip in that region is caught by the orchestrator's
        /// `VaultError::ManifestAuthorMismatch` cross-check at
        /// `open_vault`-time, not by any of the three file-level layers
        /// below. The property therefore checks four layers:
        ///   1. structural decode
        ///   2. §8 hybrid signature verify
        ///   3. AEAD body decrypt
        ///   4. `author_fingerprint` invariance vs the pre-tamper value
        /// Any layer rejecting the tampered bytes proves the property;
        /// silent acceptance across all four would be the violation.
        #[test]
        fn manifest_file_tamper_rejected(
            kp_seed in any::<[u8; 32]>(),
            m in manifest_strategy(),
            byte_idx_seed in any::<u32>(),
            xor_mask in 1u8..=255,
        ) {
            let kp = build_keypair(kp_seed);
            let ibk = build_ibk(0x00);
            let nonce = build_nonce(0x10);
            let author = [0xa5; 16];
            let header = build_header(&m);

            let file = sign_manifest(header, &m, &ibk, &nonce, author, &kp.sk_ed, &kp.sk_pq)
                .expect("sign_manifest");
            let mut bytes = encode_manifest_file(&file).expect("encode_manifest_file");
            prop_assert!(!bytes.is_empty(), "encoded manifest file empty");

            let i = (byte_idx_seed as usize) % bytes.len();
            bytes[i] ^= xor_mask;

            // Layer 1: structural decode. May fail; if so, property holds.
            let decoded = match decode_manifest_file(&bytes) {
                Ok(d) => d,
                Err(_) => return Ok(()),
            };

            // Layer 2: hybrid signature verify. May fail; if so, property holds.
            if verify_manifest(&decoded, &kp.pk_ed, &kp.pk_pq).is_err() {
                return Ok(());
            }

            // Layer 3: AEAD body decrypt. Must fail with AeadFailure if we
            // got this far AND the tamper landed in the signed range.
            let mut ct_with_tag =
                Vec::with_capacity(decoded.aead_ct.len() + decoded.aead_tag.len());
            ct_with_tag.extend_from_slice(&decoded.aead_ct);
            ct_with_tag.extend_from_slice(&decoded.aead_tag);
            let aead_result =
                decrypt_manifest_body(&decoded.header, &ct_with_tag, &ibk, &nonce);
            if aead_result.is_err() {
                return Ok(());
            }

            // Layer 4: orchestrator-level `author_fingerprint` cross-check.
            // The 16 author_fingerprint bytes sit between aead_tag and
            // sig_ed_len; they are outside the signed range and outside
            // the AEAD AAD. `open_vault` catches a tampered fingerprint
            // via `VaultError::ManifestAuthorMismatch` (mod.rs §4.3 step
            // 3). The property treats a deviation from the pre-tamper
            // fingerprint as a Layer 4 rejection.
            if decoded.author_fingerprint != file.author_fingerprint {
                return Ok(());
            }

            prop_assert!(
                false,
                "tampered byte at offset {} of {} silently accepted by all four layers; \
                 AEAD result: {:?}",
                i,
                bytes.len(),
                aead_result,
            );
        }

        /// Property H. Verify-before-decrypt: a `ManifestFile` with valid
        /// AEAD body but invalid §8 hybrid signature must be rejected by
        /// `verify_manifest` regardless of the body's decryptability.
        ///
        /// Construction: sign the body honestly (so AEAD is valid under
        /// the chosen IBK / nonce / header), then flip a byte in `sig_ed`
        /// to break the Ed25519 half. `verify_manifest` MUST return an
        /// error — the orchestrator pattern (Task 11 `open_vault`)
        /// enforces verify-then-decrypt; this property pins the verify
        /// half rejects independently.
        ///
        /// Mirrors PR-A's block-layer Property E. The orchestrator
        /// ordering itself is enforced separately (orchestrator unit
        /// tests, not proptest-tractable here).
        #[test]
        fn manifest_verify_rejects_invalid_signature(
            kp_seed in any::<[u8; 32]>(),
            m in manifest_strategy(),
            sig_byte_idx in 0usize..64,
            xor_mask in 1u8..=255,
        ) {
            let kp = build_keypair(kp_seed);
            let ibk = build_ibk(0x00);
            let nonce = build_nonce(0x20);
            let author = [0xa5; 16];
            let header = build_header(&m);

            let mut file = sign_manifest(
                header, &m, &ibk, &nonce, author, &kp.sk_ed, &kp.sk_pq,
            ).expect("sign_manifest");

            // Sanity: confirm the original verify passes — the AEAD body
            // is genuinely valid before we corrupt the signature.
            verify_manifest(&file, &kp.pk_ed, &kp.pk_pq).expect("baseline verify_manifest");

            // Corrupt the Ed25519 half of the hybrid signature.
            file.sig_ed[sig_byte_idx] ^= xor_mask;

            let r = verify_manifest(&file, &kp.pk_ed, &kp.pk_pq);
            prop_assert!(
                matches!(
                    r,
                    Err(ManifestError::Ed25519SignatureInvalid)
                        | Err(ManifestError::MlDsa65SignatureInvalid)
                ),
                "expected hybrid verify failure on sig_ed byte-flip at offset {}, got {:?}",
                sig_byte_idx, r,
            );
        }
    }
}
