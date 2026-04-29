//! End-to-end coverage suite for PR-B follow-ups #3 and #4 — surfaced
//! by PR-A's parallel reviewers as missing-but-important block-layer
//! coverage.
//!
//! Three tests, each targeting a single contract:
//!
//! 1. [`vector_clock_duplicate_device_rejected`] — pins
//!    [`BlockError::VectorClockDuplicateDevice`] as the *dispositive*
//!    error for a header whose vector clock has two entries with the
//!    same `device_uuid`. The proptest at
//!    `core/tests/proptest.rs:981` lists this variant as one of many
//!    *permitted* outcomes for a single-byte tamper, but does not
//!    assert it actually fires. A regression that demoted the rejection
//!    into a generic "ok" path would slip through; this test is the
//!    dedicated tripwire.
//!
//! 2. [`vector_clock_count_truncated_rejected`] — pins the dispositive
//!    error for a header whose declared `vector_clock_count` exceeds
//!    the trailing-byte budget. Proves the §6.1 count field is bound
//!    against actual entry bytes at decode time. Note:
//!    [`BlockError::VectorClockCountMismatch`] (block.rs:779) is
//!    structurally unreachable from external bytes — it's a
//!    defence-in-depth check on an internal invariant (the loop body
//!    drives both sides of the equality). The user-facing rejection
//!    for "declared count exceeds available bytes" is
//!    [`BlockError::Truncated`], which is what we pin here.
//!
//! 3. [`block_plaintext_unknown_bag_round_trips`] — exercises the
//!    `BlockPlaintext::unknown` BTreeMap through a full
//!    encrypt → encode → decode → decrypt cycle, asserting the
//!    forward-compat unknown keys survive bit-identically. Today's
//!    block-cycle tests all use `BTreeMap::new()` for this field; the
//!    field is reserved for §6.3.2 forward-compat and must round-trip
//!    canonically.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

use secretary_core::crypto::kem::{self, MlKem768Public, MlKem768Secret};
use secretary_core::crypto::secret::Sensitive;
use secretary_core::crypto::sig::{Ed25519Secret, MlDsa65Public, MlDsa65Secret};
use secretary_core::unlock::bundle::{self, IdentityBundle};
use secretary_core::vault::block::{
    decode_block_file, decrypt_block, encode_block_file, encrypt_block, BlockError, BlockHeader,
    BlockPlaintext, RecipientPublicKeys, VectorClockEntry, BLOCK_UUID_LEN, FILE_KIND_BLOCK,
};
use secretary_core::vault::record::UnknownValue;
use secretary_core::version::{FORMAT_VERSION, MAGIC, SUITE_ID};

// ---------------------------------------------------------------------------
// Hand-built header bytes (§6.1 wire layout)
// ---------------------------------------------------------------------------

/// Build the §6.1 fixed header prefix (magic..last_mod_ms = 58 bytes)
/// followed by `vector_clock_count` (2 bytes). Caller appends the
/// per-entry bytes. We hand-build because [`encode_header`] sorts and
/// dedups before emission — so we cannot use the encoder to produce a
/// header with deliberately invalid vector-clock content.
fn header_prefix_with_count(count: u16) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(60);
    out.extend_from_slice(&MAGIC.to_be_bytes());
    out.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    out.extend_from_slice(&SUITE_ID.to_be_bytes());
    out.extend_from_slice(&FILE_KIND_BLOCK.to_be_bytes());
    out.extend_from_slice(&[0x11; 16]); // vault_uuid
    out.extend_from_slice(&[0x42; 16]); // block_uuid
    out.extend_from_slice(&1_714_060_800_000u64.to_be_bytes());
    out.extend_from_slice(&1_714_060_800_500u64.to_be_bytes());
    out.extend_from_slice(&count.to_be_bytes());
    out
}

// ---------------------------------------------------------------------------
// Test 1 — duplicate device_uuid in vector_clock_entries
// ---------------------------------------------------------------------------

#[test]
fn vector_clock_duplicate_device_rejected() {
    // Two vector_clock entries with IDENTICAL device_uuid. They are
    // already "sorted" (equal entries are non-strict-ascending), so the
    // decoder reaches the windows() walk that distinguishes Equal from
    // Less and emits VectorClockDuplicateDevice (block.rs:793).
    //
    // We hand-assemble because encode_header rejects duplicates before
    // emission (block.rs:671) — the encoder's own dedup check is a
    // separate gate that we cannot use here.
    let mut bytes = header_prefix_with_count(2);
    // Entry #1: device_uuid = 0x33.., counter = 1
    bytes.extend_from_slice(&[0x33; 16]);
    bytes.extend_from_slice(&1u64.to_be_bytes());
    // Entry #2: SAME device_uuid, different counter
    bytes.extend_from_slice(&[0x33; 16]);
    bytes.extend_from_slice(&7u64.to_be_bytes());

    let err = decode_block_file(&bytes)
        .expect_err("duplicate device_uuid in vector clock must be rejected");
    assert!(
        matches!(err, BlockError::VectorClockDuplicateDevice),
        "expected VectorClockDuplicateDevice, got {err:?}",
    );
}

// ---------------------------------------------------------------------------
// Test 2 — declared vector_clock_count exceeds trailing-byte budget
// ---------------------------------------------------------------------------

#[test]
fn vector_clock_count_truncated_rejected() {
    // Header declares 2 entries (48 bytes) but only 1 entry's worth of
    // bytes (24) follows. The decoder's truncation guard
    // (block.rs:758-764) trips before any per-entry parse: it computes
    // `needed = count * 24`, checks `available = bytes.len() - pos`,
    // and emits `Truncated { needed: 48, got: 24 }` when the budget
    // is short.
    //
    // The §6.1 invariant "declared count matches actual entries" is
    // also tracked by `BlockError::VectorClockCountMismatch`
    // (block.rs:779), but that variant is *defence-in-depth* on an
    // internal invariant (the loop body drives both sides of the
    // equality check) and cannot be reached from external bytes. The
    // dispositive external error is `Truncated`, which is what we pin.
    let mut bytes = header_prefix_with_count(2);
    bytes.extend_from_slice(&[0x33; 16]);
    bytes.extend_from_slice(&1u64.to_be_bytes());
    // Note: only ONE entry's bytes appended; declared count = 2.

    let err = decode_block_file(&bytes)
        .expect_err("declared vector_clock_count > available entries must be rejected");
    match err {
        BlockError::Truncated { needed, got } => {
            assert_eq!(needed, 48, "needed must equal 2 * VECTOR_CLOCK_ENTRY_LEN");
            assert_eq!(got, 24, "got must equal the single entry's bytes");
        }
        other => panic!(
            "expected Truncated {{ needed: 48, got: 24 }}, got {other:?}",
        ),
    }
}

// ---------------------------------------------------------------------------
// Test 3 — BlockPlaintext::unknown bag round-trips through full cycle
// ---------------------------------------------------------------------------

/// Bundle of decap- and verify-side handles derived from an
/// [`IdentityBundle`]. Mirrors the helper in `core/tests/vault.rs`,
/// kept local so this file is self-contained.
struct Handles {
    fp: [u8; 16],
    pk_bundle: Vec<u8>,
    pq_pk: MlKem768Public,
    ed_sk: Ed25519Secret,
    dsa_sk: MlDsa65Secret,
    dsa_pk: MlDsa65Public,
    x_sk: kem::X25519Secret,
    pq_sk: MlKem768Secret,
}

fn handles(id: &IdentityBundle, seed_byte: u8) -> Handles {
    let mut pk_bundle = Vec::with_capacity(
        id.x25519_pk.len() + id.ml_kem_768_pk.len() + id.ed25519_pk.len() + id.ml_dsa_65_pk.len(),
    );
    pk_bundle.extend_from_slice(&id.x25519_pk);
    pk_bundle.extend_from_slice(&id.ml_kem_768_pk);
    pk_bundle.extend_from_slice(&id.ed25519_pk);
    pk_bundle.extend_from_slice(&id.ml_dsa_65_pk);

    Handles {
        fp: [seed_byte; 16],
        pk_bundle,
        pq_pk: MlKem768Public::from_bytes(&id.ml_kem_768_pk).expect("ml-kem pk len"),
        ed_sk: Sensitive::new(*id.ed25519_sk.expose()),
        dsa_sk: MlDsa65Secret::from_bytes(id.ml_dsa_65_sk.expose()).expect("ml-dsa sk len"),
        dsa_pk: MlDsa65Public::from_bytes(&id.ml_dsa_65_pk).expect("ml-dsa pk len"),
        x_sk: Sensitive::new(*id.x25519_sk.expose()),
        pq_sk: MlKem768Secret::from_bytes(id.ml_kem_768_sk.expose()).expect("ml-kem sk len"),
    }
}

#[test]
fn block_plaintext_unknown_bag_round_trips() {
    // Forward-compat: the §6.3 plaintext keeps an `unknown` bag for
    // top-level CBOR keys not recognised by this version. Today's
    // block-cycle tests pass `BTreeMap::new()` here; this test pins
    // that the bag survives encrypt → encode → decode → decrypt with
    // bit-identical canonical-CBOR re-encoding for each value.

    // Two unknown values with diverse shapes:
    //   - "future_field_a" => CBOR array [1, 2]                 (3 bytes)
    //   - "future_field_b" => CBOR map { "k": 42 }              (5 bytes)
    let mut unknown: BTreeMap<String, UnknownValue> = BTreeMap::new();
    unknown.insert(
        "future_field_a".to_string(),
        UnknownValue::from_canonical_cbor(&[0x82, 0x01, 0x02]).expect("array unknown"),
    );
    unknown.insert(
        "future_field_b".to_string(),
        UnknownValue::from_canonical_cbor(&[0xa1, 0x61, 0x6b, 0x18, 0x2a]).expect("map unknown"),
    );

    // ---- Identity / handles -------------------------------------------
    let mut id_rng = ChaCha20Rng::from_seed([0xc0; 32]);
    let id = bundle::generate("Owner", 1_714_060_800_000, &mut id_rng);
    let h = handles(&id, 0xab);

    // ---- Header / plaintext -------------------------------------------
    let block_uuid: [u8; BLOCK_UUID_LEN] = [0x42; BLOCK_UUID_LEN];
    let header = BlockHeader {
        magic: MAGIC,
        format_version: FORMAT_VERSION,
        suite_id: SUITE_ID,
        file_kind: FILE_KIND_BLOCK,
        vault_uuid: [0x11; 16],
        block_uuid,
        created_at_ms: 1_714_060_800_000,
        last_mod_ms: 1_714_060_800_500,
        vector_clock: vec![VectorClockEntry {
            device_uuid: [0x33; 16],
            counter: 1,
        }],
    };
    let plaintext = BlockPlaintext {
        block_version: 1,
        block_uuid,
        block_name: "forward-compat".to_string(),
        schema_version: 1,
        records: Vec::new(),
        unknown: unknown.clone(),
    };

    // ---- Encrypt -> encode -> decode -> decrypt -----------------------
    let mut enc_rng = ChaCha20Rng::from_seed([0xc1; 32]);
    let recipients = [RecipientPublicKeys {
        fingerprint: h.fp,
        pk_bundle: &h.pk_bundle,
        x25519_pk: &id.x25519_pk,
        ml_kem_768_pk: &h.pq_pk,
    }];
    let block = encrypt_block(
        &mut enc_rng,
        &header,
        &plaintext,
        &h.fp,
        &h.pk_bundle,
        &h.ed_sk,
        &h.dsa_sk,
        &recipients,
    )
    .expect("encrypt_block");

    let bytes = encode_block_file(&block).expect("encode_block_file");
    let decoded = decode_block_file(&bytes).expect("decode_block_file");
    let recovered = decrypt_block(
        &decoded,
        &h.fp,
        &h.pk_bundle,
        &id.ed25519_pk,
        &h.dsa_pk,
        &h.fp,
        &h.pk_bundle,
        &h.x_sk,
        &h.pq_sk,
    )
    .expect("decrypt_block");

    // ---- Assertions: full structural + per-value byte equality --------
    // BlockPlaintext: PartialEq compares all fields including `unknown`.
    assert_eq!(recovered, plaintext, "BlockPlaintext round-trip failed");

    // Per-value canonical-CBOR equality: the unknown bag is meant to be
    // re-emitted byte-for-byte. PartialEq on UnknownValue compares the
    // wrapped Value structurally; pin the byte form too so a future
    // canonical-CBOR drift (e.g. integer encoding width changes) is
    // caught directly.
    assert_eq!(
        recovered.unknown.keys().collect::<Vec<_>>(),
        unknown.keys().collect::<Vec<_>>(),
        "unknown key set drifted across round-trip",
    );
    for (k, original) in &unknown {
        let got = recovered
            .unknown
            .get(k)
            .unwrap_or_else(|| panic!("missing unknown key {k:?} after round-trip"));
        let original_bytes = original.to_canonical_cbor().expect("encode original");
        let got_bytes = got.to_canonical_cbor().expect("encode recovered");
        assert_eq!(
            got_bytes, original_bytes,
            "unknown[{k:?}] not byte-identical after round-trip",
        );
    }
}
