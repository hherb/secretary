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
        Ed25519Secret, MlDsa65Public, MlDsa65Secret, ED25519_SIG_LEN,
    };
    use secretary_core::unlock::bundle::{self, IdentityBundle};
    use secretary_core::vault::block::{
        decode_block_file, decode_recipient_table, decrypt_block, encode_block_file,
        encode_recipient_table, encrypt_block, BlockError, BlockHeader, BlockPlaintext,
        RecipientPublicKeys, RecipientWrap, FILE_KIND_BLOCK,
    };
    use secretary_core::vault::record::{self, Record, RecordField, RecordFieldValue};
    use secretary_core::version::{FORMAT_VERSION, MAGIC, SUITE_ID};

    /// Fixed-size signature suffix per §6.1: author_fp(16) + sig_ed_len(2) +
    /// sig_ed(64) + sig_pq_len(2) + sig_pq(3309) = 3393 bytes. The signed
    /// range (`magic..=aead_tag`) is therefore `bytes.len() - 3393` bytes.
    const SIGNATURE_SUFFIX_LEN: usize = 16 + 2 + ED25519_SIG_LEN + 2 + 3309;

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
        )
            .prop_map(|(record_uuid, record_type, fields, tags, created, last, tombstone)| {
                Record {
                    record_uuid,
                    record_type,
                    fields,
                    tags,
                    created_at_ms: created,
                    last_mod_ms: last,
                    tombstone,
                    unknown: BTreeMap::new(),
                }
            })
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
}
