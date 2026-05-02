//! Integration tests for [`secretary_core::vault::block`].
//!
//! Exercises the full §6.1 / §6.2 / §6.3 / §6.4 / §6.5 wire-format pipeline:
//!
//! - Round-trip equivalence: self-recipient, multi-recipient, records (mixed
//!   types and tombstones), and non-empty vector clocks.
//! - Recipient-table edge cases: empty list, sort-on-encode, reject-unsorted
//!   on decode, reject-duplicate, and not-a-recipient.
//! - Corruption: every byte field flipped at a known offset. Where the
//!   §6.5 step-7 block hybrid signature covers the field (the signed
//!   message is `magic..aead_tag` inclusive), the corruption surfaces as
//!   [`BlockError::Sig`] from the §6.4 step-7 verify, which intentionally
//!   gates all later (decap, AEAD) operations. The tests pin that contract
//!   directly: any tampering inside the signed area is rejected before any
//!   private-key operation runs.
//! - Wire-format strictness: truncation at every layer, trailing bytes,
//!   wrong-length signature fields, and unsorted vector clocks.
//!
//! All tests are deterministic ([`ChaCha20Rng`] with fixed seed bytes;
//! [`bundle::generate`] consumes the RNG to derive the four `(sk, pk)`
//! pairs). The Task-3/4/5 smoke tests inside `core/src/vault/block.rs`'s
//! `mod tests` are intentionally minimal; this file delivers the rest.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

mod common;

use secretary_core::crypto::aead::AEAD_TAG_LEN;
use secretary_core::crypto::kem::{self, MlKem768Public, MlKem768Secret};
use secretary_core::crypto::secret::Sensitive;
use secretary_core::crypto::sig::{
    Ed25519Secret, MlDsa65Public, MlDsa65Secret, SigError, ED25519_SIG_LEN,
};
use secretary_core::identity::fingerprint::Fingerprint;
use secretary_core::unlock::bundle::{self, IdentityBundle};
use secretary_core::vault::block::{
    decode_block_file, decrypt_block, encode_block_file, encrypt_block, BlockError, BlockFile,
    BlockHeader, BlockPlaintext, RecipientPublicKeys, VectorClockEntry, BLOCK_UUID_LEN,
    FILE_KIND_BLOCK, RECIPIENT_ENTRY_LEN,
};
use secretary_core::vault::record::{Record, RecordField, RecordFieldValue, RECORD_UUID_LEN};
use secretary_core::version::{FORMAT_VERSION, MAGIC, SUITE_ID};

// ---------------------------------------------------------------------------
// Wire-format byte offsets (deterministic, see header layout in §6.1)
// ---------------------------------------------------------------------------
//
// Empty `vector_clock` keeps the header at exactly 60 bytes:
//   magic           4   ..  4
//   format_version  2   ..  6
//   suite_id        2   ..  8
//   file_kind       2   .. 10
//   vault_uuid     16   .. 26
//   block_uuid     16   .. 42
//   created_at_ms   8   .. 50
//   last_mod_ms     8   .. 58
//   vc_count(=0)    2   .. 60
//
// One recipient pushes the recipient table to (2 + 1208) bytes, ending at
// 1270. The AEAD section follows immediately and runs to 1270 + 24 + 4 +
// aead_ct_len + 16. All offsets below assume an empty vector clock and
// exactly one recipient.

const OFF_MAGIC: usize = 0;
const OFF_FORMAT_VERSION: usize = 4;
const OFF_SUITE_ID: usize = 6;
const OFF_FILE_KIND: usize = 8;
const OFF_VAULT_UUID: usize = 10;
const OFF_BLOCK_UUID: usize = 26;
const HEADER_LEN_NO_VC: usize = 60;

const OFF_RECIPIENT_TABLE_START: usize = HEADER_LEN_NO_VC + 2; // 62
const OFF_RECIPIENT_FINGERPRINT: usize = OFF_RECIPIENT_TABLE_START; // 62
const OFF_RECIPIENT_CT_X: usize = OFF_RECIPIENT_TABLE_START + 16; // 78
// Recipient ct_pq starts at 78 + 32 = 110, runs 1088 bytes to 1198.
// Recipient nonce_w starts at 1198, runs 24 bytes to 1222.
// Recipient ct_w (32 + 16 = 48 bytes) runs 1222..1270.

const OFF_AEAD_NONCE: usize = OFF_RECIPIENT_TABLE_START + RECIPIENT_ENTRY_LEN; // 1270
const OFF_AEAD_CT_LEN: usize = OFF_AEAD_NONCE + 24; // 1294
const OFF_AEAD_CT: usize = OFF_AEAD_CT_LEN + 4; // 1298

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

/// Build a deterministic [`IdentityBundle`] from a 1-byte seed (broadcast
/// into the 32-byte ChaCha20 seed). Each test uses its own seed byte so
/// distinct identities do not overlap across tests.
fn make_identity(seed: u8) -> IdentityBundle {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    bundle::generate("Test", 1_714_060_800_000, &mut rng)
}

/// Ad-hoc concatenation of the four public keys to form an opaque
/// `pk_bundle` byte string. Mirrors the smoke tests in
/// `core/src/vault/block.rs`. [`kem::encap`] / [`kem::decap`] treat the
/// bundle opaquely (HKDF-bound only), so any deterministic byte string
/// round-trips. Replace with `ContactCard::pk_bundle_bytes()` once that
/// helper lands (deferred at Task 4).
fn pk_bundle_for(id: &IdentityBundle) -> Vec<u8> {
    let mut v = Vec::with_capacity(
        id.x25519_pk.len() + id.ml_kem_768_pk.len() + id.ed25519_pk.len() + id.ml_dsa_65_pk.len(),
    );
    v.extend_from_slice(&id.x25519_pk);
    v.extend_from_slice(&id.ml_kem_768_pk);
    v.extend_from_slice(&id.ed25519_pk);
    v.extend_from_slice(&id.ml_dsa_65_pk);
    v
}

/// Build a minimal valid [`BlockHeader`] with empty vector clock.
fn make_header(vault_uuid: [u8; 16], block_uuid: [u8; 16]) -> BlockHeader {
    BlockHeader {
        magic: MAGIC,
        format_version: FORMAT_VERSION,
        suite_id: SUITE_ID,
        file_kind: FILE_KIND_BLOCK,
        vault_uuid,
        block_uuid,
        created_at_ms: 1_714_060_800_000,
        last_mod_ms: 1_714_060_800_500,
        vector_clock: Vec::new(),
    }
}

/// Build an empty-records [`BlockPlaintext`].
fn make_empty_plaintext(block_uuid: [u8; 16]) -> BlockPlaintext {
    BlockPlaintext {
        block_version: 1,
        block_uuid,
        block_name: "test".to_string(),
        schema_version: 1,
        records: Vec::new(),
        unknown: BTreeMap::new(),
    }
}

/// Bundle of decap- and verify-side handles derived from an
/// [`IdentityBundle`]. Avoids re-doing the conversions in every test.
struct Handles {
    fp: Fingerprint,
    pk_bundle: Vec<u8>,
    pq_pk: MlKem768Public,
    ed_sk: Ed25519Secret,
    dsa_sk: MlDsa65Secret,
    dsa_pk: MlDsa65Public,
    x_sk: kem::X25519Secret,
    pq_sk: MlKem768Secret,
}

/// Materialise the typed key handles from an [`IdentityBundle`]. The
/// fingerprint is a deterministic 16-byte handle keyed by `seed_byte`
/// (a real fingerprint requires the canonical-CBOR signed contact card
/// which Task 6 does not depend on; [`encrypt_block`] / [`decrypt_block`]
/// treat the fingerprint as opaque).
fn handles(id: &IdentityBundle, seed_byte: u8) -> Handles {
    let pk_bundle = pk_bundle_for(id);
    let pq_pk = MlKem768Public::from_bytes(&id.ml_kem_768_pk).expect("ml-kem pk len");
    let ed_sk: Ed25519Secret = Sensitive::new(*id.ed25519_sk.expose());
    let dsa_sk = MlDsa65Secret::from_bytes(id.ml_dsa_65_sk.expose()).expect("ml-dsa sk len");
    let dsa_pk = MlDsa65Public::from_bytes(&id.ml_dsa_65_pk).expect("ml-dsa pk len");
    let x_sk: kem::X25519Secret = Sensitive::new(*id.x25519_sk.expose());
    let pq_sk = MlKem768Secret::from_bytes(id.ml_kem_768_sk.expose()).expect("ml-kem sk len");
    Handles {
        fp: [seed_byte; 16],
        pk_bundle,
        pq_pk,
        ed_sk,
        dsa_sk,
        dsa_pk,
        x_sk,
        pq_sk,
    }
}

/// Encrypt a block with the given identity as the sole recipient and the
/// caller-supplied AEAD-RNG seed.
fn encrypt_self(
    h: &Handles,
    id: &IdentityBundle,
    header: &BlockHeader,
    plaintext: &BlockPlaintext,
    rng_seed: u8,
) -> BlockFile {
    let mut rng = ChaCha20Rng::from_seed([rng_seed; 32]);
    let recipients = [RecipientPublicKeys {
        fingerprint: h.fp,
        pk_bundle: &h.pk_bundle,
        x25519_pk: &id.x25519_pk,
        ml_kem_768_pk: &h.pq_pk,
    }];
    encrypt_block(
        &mut rng,
        header,
        plaintext,
        &h.fp,
        &h.pk_bundle,
        &h.ed_sk,
        &h.dsa_sk,
        &recipients,
    )
    .expect("encrypt_block")
}

/// Run the standard self-recipient decrypt path against `block`, using
/// the same identity for sender and reader.
fn decrypt_self(h: &Handles, id: &IdentityBundle, block: &BlockFile) -> Result<BlockPlaintext, BlockError> {
    decrypt_block(
        block,
        &h.fp,
        &h.pk_bundle,
        &id.ed25519_pk,
        &h.dsa_pk,
        &h.fp,
        &h.pk_bundle,
        &h.x_sk,
        &h.pq_sk,
    )
}

// ---------------------------------------------------------------------------
// Round-trip / happy paths
// ---------------------------------------------------------------------------

#[test]
fn block_file_round_trips_self_recipient() {
    let id = make_identity(0x10);
    let h = handles(&id, 0xab);
    let block_uuid = [0x42; BLOCK_UUID_LEN];
    let header = make_header([0x11; 16], block_uuid);
    let plaintext = make_empty_plaintext(block_uuid);

    let block = encrypt_self(&h, &id, &header, &plaintext, 0x22);

    // encode → decode → bit-identical
    let bytes = encode_block_file(&block).expect("encode_block_file");
    let decoded = decode_block_file(&bytes).expect("decode_block_file");
    assert_eq!(decoded, block);
    let re_encoded = encode_block_file(&decoded).expect("re-encode");
    assert_eq!(re_encoded, bytes, "encode→decode→encode must be a fixed point");

    // decrypt round-trips the plaintext.
    let recovered = decrypt_self(&h, &id, &decoded).expect("decrypt_block");
    assert_eq!(recovered, plaintext);
}

#[test]
fn block_file_round_trips_multi_recipient() {
    // Three distinct identities — owner + 2 additional recipients.
    let owner = make_identity(0xAA);
    let alice = make_identity(0xBB);
    let bob = make_identity(0xCC);

    let owner_h = handles(&owner, 0x01);
    let alice_h = handles(&alice, 0x02);
    let bob_h = handles(&bob, 0x03);

    let block_uuid = [0x55; BLOCK_UUID_LEN];
    let header = make_header([0x77; 16], block_uuid);
    let plaintext = BlockPlaintext {
        block_version: 1,
        block_uuid,
        block_name: "shared".to_string(),
        schema_version: 1,
        records: Vec::new(),
        unknown: BTreeMap::new(),
    };

    let recipients = [
        RecipientPublicKeys {
            fingerprint: owner_h.fp,
            pk_bundle: &owner_h.pk_bundle,
            x25519_pk: &owner.x25519_pk,
            ml_kem_768_pk: &owner_h.pq_pk,
        },
        RecipientPublicKeys {
            fingerprint: alice_h.fp,
            pk_bundle: &alice_h.pk_bundle,
            x25519_pk: &alice.x25519_pk,
            ml_kem_768_pk: &alice_h.pq_pk,
        },
        RecipientPublicKeys {
            fingerprint: bob_h.fp,
            pk_bundle: &bob_h.pk_bundle,
            x25519_pk: &bob.x25519_pk,
            ml_kem_768_pk: &bob_h.pq_pk,
        },
    ];

    let mut rng = ChaCha20Rng::from_seed([0x99; 32]);
    let block = encrypt_block(
        &mut rng,
        &header,
        &plaintext,
        &owner_h.fp,
        &owner_h.pk_bundle,
        &owner_h.ed_sk,
        &owner_h.dsa_sk,
        &recipients,
    )
    .expect("encrypt_block multi-recipient");

    assert_eq!(block.recipients.len(), 3);

    // encode → decode round-trip is bit-identical.
    let bytes = encode_block_file(&block).expect("encode_block_file");
    let decoded = decode_block_file(&bytes).expect("decode_block_file");
    assert_eq!(decoded, block);

    // Each of the three recipients (including the author/owner) decrypts and
    // recovers the same plaintext. decrypt_block needs the *sender* keys for
    // signature verify and the *reader* keys for the lookup + decap.
    for (label, reader_h) in [("owner", &owner_h), ("alice", &alice_h), ("bob", &bob_h)] {
        let recovered = decrypt_block(
            &decoded,
            &owner_h.fp,
            &owner_h.pk_bundle,
            &owner.ed25519_pk,
            &owner_h.dsa_pk,
            &reader_h.fp,
            &reader_h.pk_bundle,
            &reader_h.x_sk,
            &reader_h.pq_sk,
        )
        .unwrap_or_else(|e| panic!("{label} decrypt failed: {e:?}"));
        assert_eq!(recovered, plaintext, "{label} plaintext mismatch");
    }
}

#[test]
fn block_file_round_trips_with_records() {
    let id = make_identity(0x20);
    let h = handles(&id, 0xab);
    let block_uuid = [0x42; BLOCK_UUID_LEN];
    let header = make_header([0x11; 16], block_uuid);

    // Record 1: text-typed field with unicode content, type "login".
    let mut fields_login = BTreeMap::new();
    fields_login.insert(
        "username".to_string(),
        RecordField {
            value: RecordFieldValue::Text("éloïse-日本語-✓".into()),
            last_mod: 1_714_060_800_000,
            device_uuid: [0x01; RECORD_UUID_LEN],
            unknown: BTreeMap::new(),
        },
    );

    // Record 2: bytes-typed field, custom record_type.
    let mut fields_totp = BTreeMap::new();
    fields_totp.insert(
        "seed".to_string(),
        RecordField {
            value: RecordFieldValue::Bytes(b"\x00\x01\x02\x03\xff\xfe\xfd".to_vec().into()),
            last_mod: 1_714_060_800_100,
            device_uuid: [0x02; RECORD_UUID_LEN],
            unknown: BTreeMap::new(),
        },
    );

    // Record 3: tombstoned, no fields, type "note".
    let plaintext = BlockPlaintext {
        block_version: 1,
        block_uuid,
        block_name: "mixed".to_string(),
        schema_version: 1,
        records: vec![
            Record {
                record_uuid: [0x10; RECORD_UUID_LEN],
                record_type: "login".to_string(),
                fields: fields_login,
                tags: vec!["personal".to_string()],
                created_at_ms: 1_714_060_800_000,
                last_mod_ms: 1_714_060_800_001,
                tombstone: false,
                tombstoned_at_ms: 0,
                unknown: BTreeMap::new(),
            },
            Record {
                record_uuid: [0x20; RECORD_UUID_LEN],
                record_type: "totp".to_string(),
                fields: fields_totp,
                tags: Vec::new(),
                created_at_ms: 1_714_060_800_100,
                last_mod_ms: 1_714_060_800_101,
                tombstone: false,
                tombstoned_at_ms: 0,
                unknown: BTreeMap::new(),
            },
            Record {
                record_uuid: [0x30; RECORD_UUID_LEN],
                record_type: "note".to_string(),
                fields: BTreeMap::new(),
                tags: Vec::new(),
                created_at_ms: 1_714_060_800_200,
                last_mod_ms: 1_714_060_800_300,
                tombstone: true,
                // §11.5 invariant: tombstone == true ⇒ tombstoned_at_ms ==
                // last_mod_ms. The encoded record now exercises a
                // non-zero tombstoned_at_ms key on the wire (the absent-
                // when-zero path is covered by the `tombstone: false`
                // record above).
                tombstoned_at_ms: 1_714_060_800_300,
                unknown: BTreeMap::new(),
            },
        ],
        unknown: BTreeMap::new(),
    };

    let block = encrypt_self(&h, &id, &header, &plaintext, 0x33);

    let bytes = encode_block_file(&block).expect("encode_block_file");
    let decoded = decode_block_file(&bytes).expect("decode_block_file");
    assert_eq!(decoded, block);
    assert_eq!(encode_block_file(&decoded).expect("re-encode"), bytes);

    let recovered = decrypt_self(&h, &id, &decoded).expect("decrypt_block");
    assert_eq!(recovered, plaintext);
    assert_eq!(recovered.records.len(), 3);
    assert!(recovered.records[2].tombstone);
}

#[test]
fn block_file_round_trips_with_vector_clock() {
    let id = make_identity(0x30);
    let h = handles(&id, 0xab);
    let block_uuid = [0x42; BLOCK_UUID_LEN];

    // Build vector-clock entries in *unsorted* order — the encoder is
    // contracted to sort them before emission, so the on-disk bytes will
    // be ascending by device_uuid.
    let mut header = make_header([0x11; 16], block_uuid);
    header.vector_clock = vec![
        VectorClockEntry {
            device_uuid: [0xff; 16],
            counter: 1,
        },
        VectorClockEntry {
            device_uuid: [0x10; 16],
            counter: 9_876_543_210,
        },
        VectorClockEntry {
            device_uuid: [0x80; 16],
            counter: 0,
        },
    ];
    let plaintext = make_empty_plaintext(block_uuid);

    let block = encrypt_self(&h, &id, &header, &plaintext, 0x44);
    let bytes = encode_block_file(&block).expect("encode_block_file");

    // Verify the on-disk vector_clock bytes are sorted ascending. Vector
    // clock starts at byte 60 (vc_count u16); entries follow at byte 62.
    let vc_count = u16::from_be_bytes([bytes[58], bytes[59]]);
    assert_eq!(vc_count, 3, "vc_count u16 BE at offset 58");
    let mut prev = [0u8; 16];
    let mut first = true;
    for i in 0..3 {
        let off = 60 + i * 24;
        let mut device = [0u8; 16];
        device.copy_from_slice(&bytes[off..off + 16]);
        if !first {
            assert!(prev < device, "vector clock entries must be ascending");
        }
        prev = device;
        first = false;
    }

    let decoded = decode_block_file(&bytes).expect("decode_block_file");
    // The decoded block matches `block` (whose vector_clock the encoder
    // sorted on the spot for AAD/sig consistency, leaving block.recipients
    // sorted; encode_block_file sorts vc anew here too).
    assert_eq!(decoded.header.vector_clock.len(), 3);
    let recovered = decrypt_self(&h, &id, &decoded).expect("decrypt_block");
    assert_eq!(recovered, plaintext);
}

// ---------------------------------------------------------------------------
// Recipient-table edge cases
// ---------------------------------------------------------------------------

#[test]
fn encrypt_block_rejects_empty_recipients() {
    let id = make_identity(0x40);
    let h = handles(&id, 0xab);
    let block_uuid = [0x42; BLOCK_UUID_LEN];
    let header = make_header([0x11; 16], block_uuid);
    let plaintext = make_empty_plaintext(block_uuid);

    let mut rng = ChaCha20Rng::from_seed([0x55; 32]);
    let recipients: [RecipientPublicKeys<'_>; 0] = [];
    let err = encrypt_block(
        &mut rng,
        &header,
        &plaintext,
        &h.fp,
        &h.pk_bundle,
        &h.ed_sk,
        &h.dsa_sk,
        &recipients,
    )
    .expect_err("empty recipient list must be rejected");
    assert!(matches!(err, BlockError::EmptyRecipientList));
}

#[test]
fn encrypt_block_sorts_recipients_in_output() {
    // Pass recipients in DESCENDING fingerprint order; assert the resulting
    // BlockFile.recipients is ASCENDING.
    let owner = make_identity(0x50);
    let alice = make_identity(0x51);
    let bob = make_identity(0x52);

    let owner_h = handles(&owner, 0x10);
    let alice_h = handles(&alice, 0x20);
    let bob_h = handles(&bob, 0x30);
    // Fingerprints: 0x10.., 0x20.., 0x30...

    let block_uuid = [0x42; BLOCK_UUID_LEN];
    let header = make_header([0x11; 16], block_uuid);
    let plaintext = make_empty_plaintext(block_uuid);

    // Reverse order on input: bob (0x30) first, then alice (0x20), then owner (0x10).
    let recipients = [
        RecipientPublicKeys {
            fingerprint: bob_h.fp,
            pk_bundle: &bob_h.pk_bundle,
            x25519_pk: &bob.x25519_pk,
            ml_kem_768_pk: &bob_h.pq_pk,
        },
        RecipientPublicKeys {
            fingerprint: alice_h.fp,
            pk_bundle: &alice_h.pk_bundle,
            x25519_pk: &alice.x25519_pk,
            ml_kem_768_pk: &alice_h.pq_pk,
        },
        RecipientPublicKeys {
            fingerprint: owner_h.fp,
            pk_bundle: &owner_h.pk_bundle,
            x25519_pk: &owner.x25519_pk,
            ml_kem_768_pk: &owner_h.pq_pk,
        },
    ];
    let mut rng = ChaCha20Rng::from_seed([0x66; 32]);
    let block = encrypt_block(
        &mut rng,
        &header,
        &plaintext,
        &owner_h.fp,
        &owner_h.pk_bundle,
        &owner_h.ed_sk,
        &owner_h.dsa_sk,
        &recipients,
    )
    .expect("encrypt_block");

    assert_eq!(block.recipients.len(), 3);
    assert_eq!(block.recipients[0].recipient_fingerprint, owner_h.fp);
    assert_eq!(block.recipients[1].recipient_fingerprint, alice_h.fp);
    assert_eq!(block.recipients[2].recipient_fingerprint, bob_h.fp);
}

#[test]
fn decode_recipient_table_rejects_unsorted() {
    // Encode normally, then swap the two recipient entries on disk so the
    // recipient table is descending (invalid). Decode must reject.
    let owner = make_identity(0x60);
    let alice = make_identity(0x61);
    let owner_h = handles(&owner, 0x10);
    let alice_h = handles(&alice, 0x20);

    let block_uuid = [0x42; BLOCK_UUID_LEN];
    let header = make_header([0x11; 16], block_uuid);
    let plaintext = make_empty_plaintext(block_uuid);

    let mut rng = ChaCha20Rng::from_seed([0x77; 32]);
    let recipients = [
        RecipientPublicKeys {
            fingerprint: owner_h.fp,
            pk_bundle: &owner_h.pk_bundle,
            x25519_pk: &owner.x25519_pk,
            ml_kem_768_pk: &owner_h.pq_pk,
        },
        RecipientPublicKeys {
            fingerprint: alice_h.fp,
            pk_bundle: &alice_h.pk_bundle,
            x25519_pk: &alice.x25519_pk,
            ml_kem_768_pk: &alice_h.pq_pk,
        },
    ];
    let block = encrypt_block(
        &mut rng,
        &header,
        &plaintext,
        &owner_h.fp,
        &owner_h.pk_bundle,
        &owner_h.ed_sk,
        &owner_h.dsa_sk,
        &recipients,
    )
    .expect("encrypt_block");

    let mut bytes = encode_block_file(&block).expect("encode_block_file");
    // Swap the two 1208-byte recipient entries. Recipient table starts at
    // offset 62 (HEADER_LEN_NO_VC + 2). Two entries: [62..1270) and
    // [1270..2478).
    let entry0_start = OFF_RECIPIENT_TABLE_START;
    let entry1_start = entry0_start + RECIPIENT_ENTRY_LEN;
    let entry1_end = entry1_start + RECIPIENT_ENTRY_LEN;
    let entry0 = bytes[entry0_start..entry1_start].to_vec();
    let entry1 = bytes[entry1_start..entry1_end].to_vec();
    bytes[entry0_start..entry1_start].copy_from_slice(&entry1);
    bytes[entry1_start..entry1_end].copy_from_slice(&entry0);

    let err = decode_block_file(&bytes).expect_err("descending recipients must be rejected");
    assert!(
        matches!(err, BlockError::RecipientsNotSorted),
        "expected RecipientsNotSorted, got {err:?}",
    );
}

#[test]
fn decode_recipient_table_rejects_duplicate() {
    // Encode normally, then overwrite the second recipient entry with a
    // copy of the first. After this the recipient_count claims 2 entries
    // but they share a fingerprint.
    let owner = make_identity(0x70);
    let alice = make_identity(0x71);
    let owner_h = handles(&owner, 0x10);
    let alice_h = handles(&alice, 0x20);

    let block_uuid = [0x42; BLOCK_UUID_LEN];
    let header = make_header([0x11; 16], block_uuid);
    let plaintext = make_empty_plaintext(block_uuid);
    let mut rng = ChaCha20Rng::from_seed([0x88; 32]);
    let recipients = [
        RecipientPublicKeys {
            fingerprint: owner_h.fp,
            pk_bundle: &owner_h.pk_bundle,
            x25519_pk: &owner.x25519_pk,
            ml_kem_768_pk: &owner_h.pq_pk,
        },
        RecipientPublicKeys {
            fingerprint: alice_h.fp,
            pk_bundle: &alice_h.pk_bundle,
            x25519_pk: &alice.x25519_pk,
            ml_kem_768_pk: &alice_h.pq_pk,
        },
    ];
    let block = encrypt_block(
        &mut rng,
        &header,
        &plaintext,
        &owner_h.fp,
        &owner_h.pk_bundle,
        &owner_h.ed_sk,
        &owner_h.dsa_sk,
        &recipients,
    )
    .expect("encrypt_block");

    let mut bytes = encode_block_file(&block).expect("encode_block_file");
    let entry0_start = OFF_RECIPIENT_TABLE_START;
    let entry1_start = entry0_start + RECIPIENT_ENTRY_LEN;
    let entry1_end = entry1_start + RECIPIENT_ENTRY_LEN;
    let entry0 = bytes[entry0_start..entry1_start].to_vec();
    bytes[entry1_start..entry1_end].copy_from_slice(&entry0);

    let err = decode_block_file(&bytes).expect_err("duplicate recipients must be rejected");
    match err {
        BlockError::DuplicateRecipient { fingerprint } => {
            assert_eq!(fingerprint, owner_h.fp);
        }
        other => panic!("expected DuplicateRecipient, got {other:?}"),
    }
}

#[test]
fn decrypt_block_rejects_non_recipient() {
    let owner = make_identity(0x80);
    let other = make_identity(0x81);
    let owner_h = handles(&owner, 0xaa);
    let other_h = handles(&other, 0xbb);

    let block_uuid = [0x42; BLOCK_UUID_LEN];
    let header = make_header([0x11; 16], block_uuid);
    let plaintext = make_empty_plaintext(block_uuid);

    // Block addressed only to the owner.
    let block = encrypt_self(&owner_h, &owner, &header, &plaintext, 0x55);

    // Other party tries to read it: fails as NotARecipient with the
    // *reader's* fingerprint (not the on-disk owner's).
    let err = decrypt_block(
        &block,
        &owner_h.fp,
        &owner_h.pk_bundle,
        &owner.ed25519_pk,
        &owner_h.dsa_pk,
        &other_h.fp,
        &other_h.pk_bundle,
        &other_h.x_sk,
        &other_h.pq_sk,
    )
    .expect_err("non-recipient must be rejected");
    match err {
        BlockError::NotARecipient { fingerprint } => {
            assert_eq!(fingerprint, other_h.fp);
        }
        other => panic!("expected NotARecipient, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Corruption — every byte field flipped
//
// The §6.5 step-7 block hybrid signature covers `magic..aead_tag` inclusive.
// `decrypt_block` verifies that signature BEFORE any decap or AEAD-decrypt
// operation runs (the §6.4 step-7 ordering). So any tampering inside the
// signed area surfaces as `BlockError::Sig(_)`, gating decap / AEAD entirely.
// This is a security feature, not a test artefact: a forged block must
// never trigger a private-key operation.
//
// Each test below builds its own valid block, encodes it, flips a single
// byte at a known offset, and pins the resulting error. Where the flipped
// field is *outside* the signed area (author_fingerprint, sig_ed, sig_pq)
// the orchestrator surfaces the field-specific error variant directly.
// ---------------------------------------------------------------------------

/// Helper: build a corruption-test fixture (identity + handles + valid
/// encoded `BlockFile` bytes), so each test stays focused on the flip.
fn corrupt_fixture(seed: u8) -> (IdentityBundle, Handles, Vec<u8>) {
    let id = make_identity(seed);
    let h = handles(&id, 0xab);
    let block_uuid = [0x42; BLOCK_UUID_LEN];
    let header = make_header([0x11; 16], block_uuid);
    let plaintext = make_empty_plaintext(block_uuid);
    let block = encrypt_self(&h, &id, &header, &plaintext, seed.wrapping_add(1));
    let bytes = encode_block_file(&block).expect("encode_block_file");
    (id, h, bytes)
}

#[test]
fn corruption_magic_bytes_rejected() {
    let (_, _, mut bytes) = corrupt_fixture(0x90);
    bytes[OFF_MAGIC] ^= 0xFF;
    let err = decode_block_file(&bytes).expect_err("bad magic must be rejected");
    assert!(matches!(err, BlockError::BadMagic { .. }), "got {err:?}");
}

#[test]
fn corruption_format_version_rejected() {
    let (_, _, mut bytes) = corrupt_fixture(0x91);
    // Flip the high byte so the resulting u16 cannot equal FORMAT_VERSION (1).
    bytes[OFF_FORMAT_VERSION] ^= 0xFF;
    let err = decode_block_file(&bytes).expect_err("bad format version must be rejected");
    assert!(
        matches!(err, BlockError::UnsupportedFormatVersion { .. }),
        "got {err:?}",
    );
}

#[test]
fn corruption_suite_id_rejected() {
    let (_, _, mut bytes) = corrupt_fixture(0x92);
    bytes[OFF_SUITE_ID] ^= 0xFF;
    let err = decode_block_file(&bytes).expect_err("bad suite id must be rejected");
    assert!(
        matches!(err, BlockError::UnsupportedSuiteId { .. }),
        "got {err:?}",
    );
}

#[test]
fn corruption_file_kind_rejected() {
    let (_, _, mut bytes) = corrupt_fixture(0x93);
    bytes[OFF_FILE_KIND] ^= 0xFF;
    let err = decode_block_file(&bytes).expect_err("bad file kind must be rejected");
    match err {
        BlockError::WrongFileKind { expected, .. } => {
            assert_eq!(expected, FILE_KIND_BLOCK);
        }
        other => panic!("expected WrongFileKind, got {other:?}"),
    }
}

#[test]
fn corruption_vault_uuid_passes_decode_but_sig_fails_decrypt() {
    // vault_uuid is part of the signed message (`magic..aead_tag`), so
    // tampering with it falsifies the signature. decode_block_file does
    // NOT validate vault_uuid contents (it's a u128 field with no header-
    // level constraints), so decode succeeds and decrypt fails at sig
    // verify, BEFORE any decap or AEAD work.
    let (id, h, mut bytes) = corrupt_fixture(0x94);
    bytes[OFF_VAULT_UUID] ^= 0xFF;
    let block = decode_block_file(&bytes).expect("decode succeeds — no per-field validation");
    let err = decrypt_self(&h, &id, &block).expect_err("sig verify must fail");
    assert!(matches!(err, BlockError::Sig(_)), "got {err:?}");
}

#[test]
fn corruption_block_uuid_in_header_passes_decode_but_sig_fails_decrypt() {
    // Same shape as vault_uuid: the header's block_uuid lives inside the
    // signed message, so a flip there fails sig verify before decap or
    // AEAD-decrypt can run. The §6.4 step-9 plaintext-vs-header cross-check
    // is therefore unreachable via this corruption path; it is only
    // exercisable by a deliberately mis-encoded plaintext (test #33 below
    // is left as a future-work TODO).
    let (id, h, mut bytes) = corrupt_fixture(0x95);
    bytes[OFF_BLOCK_UUID] ^= 0xFF;
    let block = decode_block_file(&bytes).expect("decode succeeds");
    let err = decrypt_self(&h, &id, &block).expect_err("sig verify must fail");
    assert!(matches!(err, BlockError::Sig(_)), "got {err:?}");
}

#[test]
fn corruption_aead_nonce_rejected_on_decrypt() {
    // aead_nonce is signed; flipping it fails sig verify before AEAD-decrypt.
    let (id, h, mut bytes) = corrupt_fixture(0x96);
    bytes[OFF_AEAD_NONCE] ^= 0xFF;
    let block = decode_block_file(&bytes).expect("decode succeeds");
    let err = decrypt_self(&h, &id, &block).expect_err("decrypt must fail");
    assert!(matches!(err, BlockError::Sig(_)), "got {err:?}");
}

#[test]
fn corruption_aead_ct_len_inflated_truncates() {
    // Inflate aead_ct_len so it claims more bytes than the file actually
    // contains. decode_aead_section catches this at parse time as
    // BlockError::Truncated (no signature work needed).
    let (_, _, mut bytes) = corrupt_fixture(0x97);
    // Replace the u32 BE length prefix with 0xFFFF_FFFF (bigger than the
    // file). Catch any silent bound-violation by the truncation check.
    bytes[OFF_AEAD_CT_LEN..OFF_AEAD_CT_LEN + 4].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
    let err = decode_block_file(&bytes).expect_err("inflated aead_ct_len must truncate");
    assert!(matches!(err, BlockError::Truncated { .. }), "got {err:?}");
}

#[test]
fn corruption_aead_ct_byte_flipped_sig_fails() {
    // aead_ct is signed; flipping a byte fails sig verify before AEAD-decrypt.
    let (id, h, mut bytes) = corrupt_fixture(0x98);
    bytes[OFF_AEAD_CT] ^= 0xFF;
    let block = decode_block_file(&bytes).expect("decode succeeds");
    let err = decrypt_self(&h, &id, &block).expect_err("decrypt must fail");
    assert!(matches!(err, BlockError::Sig(_)), "got {err:?}");
}

#[test]
fn corruption_aead_tag_rejected_on_decrypt() {
    // aead_tag is signed; flipping a byte fails sig verify before AEAD.
    // To find the tag offset we need the actual aead_ct_len from this
    // particular block (depends on the canonical-CBOR plaintext size).
    let (id, h, mut bytes) = corrupt_fixture(0x99);
    let aead_ct_len = u32::from_be_bytes([
        bytes[OFF_AEAD_CT_LEN],
        bytes[OFF_AEAD_CT_LEN + 1],
        bytes[OFF_AEAD_CT_LEN + 2],
        bytes[OFF_AEAD_CT_LEN + 3],
    ]) as usize;
    let off_aead_tag = OFF_AEAD_CT + aead_ct_len;
    bytes[off_aead_tag] ^= 0xFF;
    let block = decode_block_file(&bytes).expect("decode succeeds");
    let err = decrypt_self(&h, &id, &block).expect_err("decrypt must fail");
    assert!(matches!(err, BlockError::Sig(_)), "got {err:?}");
}

#[test]
fn corruption_recipient_fingerprint_in_table_sig_fails_decrypt() {
    // Recipient table is part of the signed message; flipping a fingerprint
    // byte fails sig verify before any reader-lookup or decap can run.
    // The "lookup miss with reader's own fingerprint" path is exercised by
    // `decrypt_block_rejects_non_recipient` above, which constructs a real
    // (signed) block addressed to someone else.
    let (id, h, mut bytes) = corrupt_fixture(0x9A);
    bytes[OFF_RECIPIENT_FINGERPRINT] ^= 0xFF;
    let block = decode_block_file(&bytes).expect("decode succeeds");
    let err = decrypt_self(&h, &id, &block).expect_err("decrypt must fail");
    assert!(matches!(err, BlockError::Sig(_)), "got {err:?}");
}

#[test]
fn corruption_recipient_ct_x_sig_fails_decrypt() {
    // Same posture as recipient_fingerprint: ct_x is signed, so a flip
    // fails sig verify before hybrid-decap. The decap-failure-mode path
    // (KemError::AeadFailure) is exercised by the kem-module unit tests,
    // not via the block orchestrator's pre-verify gate.
    let (id, h, mut bytes) = corrupt_fixture(0x9B);
    bytes[OFF_RECIPIENT_CT_X] ^= 0xFF;
    let block = decode_block_file(&bytes).expect("decode succeeds");
    let err = decrypt_self(&h, &id, &block).expect_err("decrypt must fail");
    assert!(matches!(err, BlockError::Sig(_)), "got {err:?}");
}

#[test]
fn corruption_author_fingerprint_rejected_at_check() {
    // author_fingerprint sits AFTER aead_tag — outside the signed message
    // (`magic..aead_tag`). decode_block_file accepts it; decrypt_block step 1
    // catches the mismatch as AuthorFingerprintMismatch BEFORE any sig or
    // decap work runs.
    let (id, h, mut bytes) = corrupt_fixture(0x9C);
    let aead_ct_len = u32::from_be_bytes([
        bytes[OFF_AEAD_CT_LEN],
        bytes[OFF_AEAD_CT_LEN + 1],
        bytes[OFF_AEAD_CT_LEN + 2],
        bytes[OFF_AEAD_CT_LEN + 3],
    ]) as usize;
    let off_author_fp = OFF_AEAD_CT + aead_ct_len + AEAD_TAG_LEN;
    let original_byte = bytes[off_author_fp];
    bytes[off_author_fp] ^= 0xFF;
    let block = decode_block_file(&bytes).expect("decode succeeds");
    let err = decrypt_self(&h, &id, &block).expect_err("author mismatch must be rejected");
    match err {
        BlockError::AuthorFingerprintMismatch { expected, found } => {
            assert_eq!(expected, h.fp);
            assert_eq!(found[0], original_byte ^ 0xFF);
        }
        other => panic!("expected AuthorFingerprintMismatch, got {other:?}"),
    }
}

#[test]
fn corruption_sig_ed_byte_flipped_verify_fails() {
    // sig_ed is the trailing-suffix Ed25519 half. Flipping a byte fails
    // the Ed25519 verify; ML-DSA-65 is unaffected.
    let (id, h, mut bytes) = corrupt_fixture(0x9D);
    let aead_ct_len = u32::from_be_bytes([
        bytes[OFF_AEAD_CT_LEN],
        bytes[OFF_AEAD_CT_LEN + 1],
        bytes[OFF_AEAD_CT_LEN + 2],
        bytes[OFF_AEAD_CT_LEN + 3],
    ]) as usize;
    // Suffix layout after aead_tag: author_fingerprint(16) || sig_ed_len(2)
    // || sig_ed(64) || sig_pq_len(2) || sig_pq(3309).
    let off_sig_ed = OFF_AEAD_CT + aead_ct_len + AEAD_TAG_LEN + 16 + 2;
    bytes[off_sig_ed] ^= 0xFF;
    let block = decode_block_file(&bytes).expect("decode succeeds");
    let err = decrypt_self(&h, &id, &block).expect_err("ed25519 verify must fail");
    assert!(
        matches!(err, BlockError::Sig(SigError::Ed25519VerifyFailed)),
        "got {err:?}",
    );
}

#[test]
fn corruption_sig_pq_byte_flipped_verify_fails() {
    let (id, h, mut bytes) = corrupt_fixture(0x9E);
    let aead_ct_len = u32::from_be_bytes([
        bytes[OFF_AEAD_CT_LEN],
        bytes[OFF_AEAD_CT_LEN + 1],
        bytes[OFF_AEAD_CT_LEN + 2],
        bytes[OFF_AEAD_CT_LEN + 3],
    ]) as usize;
    // Suffix layout: aead_tag.end || author_fingerprint(16) ||
    // sig_ed_len(2) || sig_ed(64) || sig_pq_len(2) || sig_pq(3309).
    let off_sig_pq = OFF_AEAD_CT + aead_ct_len + AEAD_TAG_LEN + 16 + 2 + ED25519_SIG_LEN + 2;
    bytes[off_sig_pq] ^= 0xFF;
    let block = decode_block_file(&bytes).expect("decode succeeds");
    let err = decrypt_self(&h, &id, &block).expect_err("ml-dsa-65 verify must fail");
    assert!(
        matches!(err, BlockError::Sig(SigError::MlDsa65VerifyFailed)),
        "got {err:?}",
    );
}

// ---------------------------------------------------------------------------
// Wire-format / decoder strictness
// ---------------------------------------------------------------------------

#[test]
fn decode_rejects_truncated_at_header() {
    let (_, _, bytes) = corrupt_fixture(0xA0);
    // First 30 bytes — short of the 60-byte header prefix even before the
    // vector clock has a chance to be parsed.
    let truncated = &bytes[..30];
    let err = decode_block_file(truncated).expect_err("truncated header must be rejected");
    assert!(matches!(err, BlockError::Truncated { .. }), "got {err:?}");
}

#[test]
fn decode_rejects_truncated_at_recipient_table() {
    let (_, _, bytes) = corrupt_fixture(0xA1);
    // Cut mid-recipient-entry: keep header + recipient_count + 100 bytes
    // of the entry. The entry is supposed to be 1208 bytes, so the next
    // read inside `decode_recipient` finds < 1208 bytes available.
    let truncated = &bytes[..OFF_RECIPIENT_TABLE_START + 100];
    let err = decode_block_file(truncated).expect_err("truncated recipient table must be rejected");
    assert!(matches!(err, BlockError::Truncated { .. }), "got {err:?}");
}

#[test]
fn decode_rejects_truncated_at_aead_section() {
    let (_, _, bytes) = corrupt_fixture(0xA2);
    let aead_ct_len = u32::from_be_bytes([
        bytes[OFF_AEAD_CT_LEN],
        bytes[OFF_AEAD_CT_LEN + 1],
        bytes[OFF_AEAD_CT_LEN + 2],
        bytes[OFF_AEAD_CT_LEN + 3],
    ]) as usize;
    // Cut a few bytes before the end of aead_ct (so the tag never reads).
    let cut_at = OFF_AEAD_CT + aead_ct_len - 4;
    let truncated = &bytes[..cut_at];
    let err = decode_block_file(truncated).expect_err("truncated aead must be rejected");
    assert!(matches!(err, BlockError::Truncated { .. }), "got {err:?}");
}

#[test]
fn decode_rejects_truncated_at_signature_suffix() {
    let (_, _, bytes) = corrupt_fixture(0xA3);
    // Cut just before sig_pq finishes — keep everything through sig_pq's
    // first half and then drop. The earlier wire-format check is on
    // sig_pq_len, which is what `decode_signature_suffix` evaluates first;
    // we want to land on the post-length truncation check, so we keep the
    // length prefix intact and cut the bytes themselves.
    let cut_at = bytes.len() - 200;
    let truncated = &bytes[..cut_at];
    let err = decode_block_file(truncated).expect_err("truncated signature must be rejected");
    assert!(matches!(err, BlockError::Truncated { .. }), "got {err:?}");
}

#[test]
fn decode_rejects_trailing_bytes() {
    let (_, _, bytes) = corrupt_fixture(0xA4);
    let mut extended = bytes.clone();
    extended.push(0xCA); // one extra byte after the §6.1 fixed-length suffix
    let err = decode_block_file(&extended).expect_err("trailing bytes must be rejected");
    match err {
        BlockError::TrailingBytes { count } => assert_eq!(count, 1),
        other => panic!("expected TrailingBytes {{ count: 1 }}, got {other:?}"),
    }
}

#[test]
fn decode_rejects_sig_ed_wrong_length() {
    // Mutate the sig_ed_len u16 BE to 65 (instead of 64). The decoder
    // checks the declared length BEFORE reading the bytes, so it will
    // surface SigEdWrongLength { found: 65 } and never look at the bytes
    // themselves.
    let (_, _, mut bytes) = corrupt_fixture(0xA5);
    let aead_ct_len = u32::from_be_bytes([
        bytes[OFF_AEAD_CT_LEN],
        bytes[OFF_AEAD_CT_LEN + 1],
        bytes[OFF_AEAD_CT_LEN + 2],
        bytes[OFF_AEAD_CT_LEN + 3],
    ]) as usize;
    let off_sig_ed_len = OFF_AEAD_CT + aead_ct_len + AEAD_TAG_LEN + 16; // after author_fp(16)
    bytes[off_sig_ed_len..off_sig_ed_len + 2].copy_from_slice(&65u16.to_be_bytes());
    let err = decode_block_file(&bytes).expect_err("sig_ed_len != 64 must be rejected");
    match err {
        BlockError::SigEdWrongLength { found } => assert_eq!(found, 65),
        other => panic!("expected SigEdWrongLength {{ found: 65 }}, got {other:?}"),
    }
}

#[test]
fn decode_rejects_sig_pq_wrong_length() {
    // Mutate sig_pq_len u16 BE to 3308 (instead of 3309). The decoder pins
    // the expected value at ML_DSA_65_SIG_LEN (3309) and surfaces
    // SigPqWrongLength { found } before reading the bytes. (Symmetry with
    // SigEdWrongLength was the point of the Task-5 fix `1e85e2b`.)
    let (_, _, mut bytes) = corrupt_fixture(0xA6);
    let aead_ct_len = u32::from_be_bytes([
        bytes[OFF_AEAD_CT_LEN],
        bytes[OFF_AEAD_CT_LEN + 1],
        bytes[OFF_AEAD_CT_LEN + 2],
        bytes[OFF_AEAD_CT_LEN + 3],
    ]) as usize;
    let off_sig_pq_len =
        OFF_AEAD_CT + aead_ct_len + AEAD_TAG_LEN + 16 + 2 + ED25519_SIG_LEN; // after sig_ed
    bytes[off_sig_pq_len..off_sig_pq_len + 2].copy_from_slice(&3308u16.to_be_bytes());
    let err = decode_block_file(&bytes).expect_err("sig_pq_len != 3309 must be rejected");
    match err {
        BlockError::SigPqWrongLength { found } => assert_eq!(found, 3308),
        other => panic!("expected SigPqWrongLength {{ found: 3308 }}, got {other:?}"),
    }
}

#[test]
fn decode_rejects_vector_clock_unsorted() {
    // Build a header by hand with two vector_clock entries in DESCENDING
    // device_uuid order. We cannot use `encode_header` (it sorts before
    // emission), so we hand-assemble the 60 + 2 + 2*24 bytes directly.
    let mut header_bytes: Vec<u8> = Vec::with_capacity(60 + 48);
    header_bytes.extend_from_slice(&MAGIC.to_be_bytes());
    header_bytes.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    header_bytes.extend_from_slice(&SUITE_ID.to_be_bytes());
    header_bytes.extend_from_slice(&FILE_KIND_BLOCK.to_be_bytes());
    header_bytes.extend_from_slice(&[0x11; 16]); // vault_uuid
    header_bytes.extend_from_slice(&[0x42; 16]); // block_uuid
    header_bytes.extend_from_slice(&1_714_060_800_000u64.to_be_bytes());
    header_bytes.extend_from_slice(&1_714_060_800_500u64.to_be_bytes());
    // 2 entries, descending: device_uuid 0xFF.. (counter 7) then 0x10..
    // (counter 1). decode_header reads them in order then sees out-of-order.
    header_bytes.extend_from_slice(&2u16.to_be_bytes());
    header_bytes.extend_from_slice(&[0xFF; 16]);
    header_bytes.extend_from_slice(&7u64.to_be_bytes());
    header_bytes.extend_from_slice(&[0x10; 16]);
    header_bytes.extend_from_slice(&1u64.to_be_bytes());
    // decode_header is the gate; we don't need to append the rest of the
    // file because this fails before recipient_table parsing.
    let err =
        decode_block_file(&header_bytes).expect_err("descending vector clock must be rejected");
    assert!(matches!(err, BlockError::VectorClockNotSorted), "got {err:?}");
}

// ---------------------------------------------------------------------------
// Block-uuid header-vs-plaintext cross-check
// ---------------------------------------------------------------------------
//
// TODO: a dedicated test for [`BlockError::BlockUuidMismatch`] requires
// either (a) a path that calls `encode_plaintext` with a deliberately
// different `block_uuid` than the header before AEAD-encrypting, or (b)
// orchestrator-level test fixtures (envisaged in PR-B's higher-level
// vault wrappers). Today the cross-check is exercised manually by the
// `smoke_block_header_and_plaintext_roundtrip` test in
// `core/src/vault/block.rs` (which asserts the invariant directly rather
// than going through `decrypt_block`). Revisit once PR-B's full
// orchestrators land, at which point flipping the plaintext block_uuid
// becomes a one-liner via the higher-level builder.

// ---------------------------------------------------------------------------
// §15 Block KAT — the spec-doc cross-language conformance contract
// ---------------------------------------------------------------------------
//
// Pins the on-disk byte sequence of one fully-specified `BlockFile` against
// `core/tests/data/block_kat.json`. Inputs (RNG seeds, identity, records)
// are loaded from JSON; the test rebuilds the block deterministically and
// asserts encode-bytes match the JSON's `expected.block_file` byte-for-byte.
// The companion `core/tests/python/conformance.py` script proves the same
// bytes can be parsed by a clean-room reader using only `vault-format.md`
// and `crypto-design.md`.
//
// To regenerate after a deliberate spec/format change: rerun
// `cargo test --test vault -p secretary-core block_kat_bootstrap_dump --
// --ignored --nocapture` and paste the printed `block_file` hex (and the
// `size_bytes` sentinel) into `block_kat.json`. Every other field in the
// JSON is a *human-authored* input; only the `expected` block is generated
// output.

/// Build a [`BlockFile`] deterministically from a [`common::BlockKatVector`]
/// — the closed-loop generator that pins the KAT bytes. Used by both the
/// assertion test and the bootstrap dumper.
fn build_block_from_kat(v: &common::BlockKatVector) -> (BlockFile, IdentityBundle) {
    use secretary_core::vault::record::{
        Record as RecRecord, RecordField as RecField, RecordFieldValue as RecValue,
    };

    let mut id_rng = ChaCha20Rng::from_seed(v.inputs.identity_seed);
    let id = bundle::generate(&v.inputs.display_name, v.inputs.created_at_ms, &mut id_rng);

    let pk_bundle = pk_bundle_for(&id);
    let pq_pk = MlKem768Public::from_bytes(&id.ml_kem_768_pk).expect("ml-kem pk len");
    let ed_sk: Ed25519Secret = Sensitive::new(*id.ed25519_sk.expose());
    let dsa_sk = MlDsa65Secret::from_bytes(id.ml_dsa_65_sk.expose()).expect("ml-dsa sk len");

    // Build the header (vector_clock entries are emitted in input order;
    // encoder sorts ascending by device_uuid before writing bytes).
    let header = BlockHeader {
        magic: MAGIC,
        format_version: FORMAT_VERSION,
        suite_id: SUITE_ID,
        file_kind: FILE_KIND_BLOCK,
        vault_uuid: v.inputs.vault_uuid,
        block_uuid: v.inputs.block_uuid,
        created_at_ms: v.inputs.created_at_ms,
        last_mod_ms: v.inputs.last_mod_ms,
        vector_clock: v
            .inputs
            .vector_clock
            .iter()
            .map(|e| VectorClockEntry {
                device_uuid: e.device_uuid,
                counter: e.counter,
            })
            .collect(),
    };

    // Build records from the JSON spec. Each field's `value_type` selects
    // between the text and bytes payloads; missing companion fields are a
    // KAT shape error.
    let mut records: Vec<RecRecord> = Vec::with_capacity(v.inputs.records.len());
    for r in &v.inputs.records {
        let mut fields: BTreeMap<String, RecField> = BTreeMap::new();
        for f in &r.fields {
            let value = match f.value_type.as_str() {
                "text" => RecValue::Text(
                    f.value_text
                        .clone()
                        .expect("KAT: value_type=text requires value_text")
                        .into(),
                ),
                "bytes" => {
                    let hex_str = f
                        .value_hex
                        .as_ref()
                        .expect("KAT: value_type=bytes requires value_hex");
                    RecValue::Bytes(
                        common::hex(hex_str).expect("KAT: value_hex must be hex").into(),
                    )
                }
                other => panic!("KAT: unknown value_type {other:?}"),
            };
            fields.insert(
                f.name.clone(),
                RecField {
                    value,
                    last_mod: f.last_mod,
                    device_uuid: f.device_uuid,
                    unknown: BTreeMap::new(),
                },
            );
        }
        records.push(RecRecord {
            record_uuid: r.record_uuid,
            record_type: r.record_type.clone(),
            fields,
            tags: r.tags.clone(),
            created_at_ms: r.created_at_ms,
            last_mod_ms: r.last_mod_ms,
            tombstone: r.tombstone,
            tombstoned_at_ms: r.tombstoned_at_ms,
            unknown: BTreeMap::new(),
        });
    }

    let plaintext = BlockPlaintext {
        block_version: v.inputs.block_version,
        block_uuid: v.inputs.block_uuid,
        block_name: v.inputs.block_name.clone(),
        schema_version: v.inputs.schema_version,
        records,
        unknown: BTreeMap::new(),
    };

    // Single self-recipient: author_fingerprint pinned by the JSON.
    let recipients = [RecipientPublicKeys {
        fingerprint: v.inputs.author_fingerprint,
        pk_bundle: &pk_bundle,
        x25519_pk: &id.x25519_pk,
        ml_kem_768_pk: &pq_pk,
    }];

    let mut enc_rng = ChaCha20Rng::from_seed(v.inputs.encrypt_seed);
    let block = encrypt_block(
        &mut enc_rng,
        &header,
        &plaintext,
        &v.inputs.author_fingerprint,
        &pk_bundle,
        &ed_sk,
        &dsa_sk,
        &recipients,
    )
    .expect("encrypt_block");

    (block, id)
}

#[test]
fn block_kat_self_recipient_one_record() {
    let kat: common::BlockKat = common::load_kat("block_kat.json");
    assert_eq!(kat.version, 1, "block_kat.json version must be 1");
    assert!(!kat.vectors.is_empty(), "block_kat.json: no vectors");

    let v = kat
        .vectors
        .iter()
        .find(|v| v.name == "self_recipient_one_record")
        .expect("block_kat.json: missing self_recipient_one_record vector");

    let (block, id) = build_block_from_kat(v);

    // 1. Encoded bytes match the pinned hex byte-for-byte.
    let bytes = encode_block_file(&block).expect("encode_block_file");
    assert_eq!(
        bytes, v.expected.block_file,
        "encoded block_file bytes mismatch — regenerate KAT via \
         `cargo test --test vault block_kat_bootstrap_dump -- --ignored --nocapture` \
         after a deliberate format change",
    );
    assert_eq!(bytes.len(), v.expected.size_bytes, "size_bytes sentinel");

    // 2. Decode round-trips exactly.
    let decoded = decode_block_file(&bytes).expect("decode_block_file");
    assert_eq!(decoded, block, "decode→re-encode fixed point");
    assert_eq!(decoded.recipients.len(), v.expected.recipients_count);

    // 3. Decrypt recovers the plaintext and matches expected shape.
    // pk_bundle is the same byte string used at encrypt time; the
    // ml-kem PK handle is rebuilt for the decap path below.
    let pk_bundle = pk_bundle_for(&id);
    let dsa_pk = MlDsa65Public::from_bytes(&id.ml_dsa_65_pk).expect("ml-dsa pk len");
    let x_sk: kem::X25519Secret = Sensitive::new(*id.x25519_sk.expose());
    let pq_sk = MlKem768Secret::from_bytes(id.ml_kem_768_sk.expose()).expect("ml-kem sk len");
    let plaintext = decrypt_block(
        &decoded,
        &v.inputs.author_fingerprint,
        &pk_bundle,
        &id.ed25519_pk,
        &dsa_pk,
        &v.inputs.author_fingerprint,
        &pk_bundle,
        &x_sk,
        &pq_sk,
    )
    .expect("decrypt_block");

    assert_eq!(plaintext.records.len(), v.expected.records_count);
    assert_eq!(plaintext.records[0].record_type, v.expected.first_record_type);
    assert_eq!(plaintext.block_uuid, v.inputs.block_uuid);
    assert_eq!(plaintext.block_name, v.inputs.block_name);
}

/// Bootstrap helper: regenerates the `expected.block_file` hex sentinel
/// for `block_kat.json`. Ignored by default — the assertion test above is
/// the regression-locking gate, this helper just prints captured bytes.
///
/// Run with:
///
/// ```text
/// cargo test --test vault -p secretary-core block_kat_bootstrap_dump \
///     -- --ignored --nocapture
/// ```
///
/// Then paste `block_file` and `size_bytes` into the JSON's `expected`
/// block. All other JSON fields are human-authored inputs and must match
/// the values used here in [`bootstrap_inputs`].
#[test]
#[ignore = "bootstrap helper; run manually to regenerate block_kat.json"]
fn block_kat_bootstrap_dump() {
    // Inputs are pinned in code so the dumper is hermetic and the JSON
    // can be regenerated after a deliberate format change without first
    // editing the JSON itself.
    let v = bootstrap_inputs();
    let (block, _id) = build_block_from_kat(&v);
    let bytes = encode_block_file(&block).expect("encode_block_file");

    eprintln!("---- BEGIN block_kat.json expected.* values ----");
    eprintln!("size_bytes:       {}", bytes.len());
    eprintln!("recipients_count: {}", block.recipients.len());
    eprintln!("block_file (hex, {} bytes):", bytes.len());
    eprintln!("{}", hex_encode(&bytes));
    eprintln!("---- END ----");
}

/// Inputs hard-pinned for the `self_recipient_one_record` vector. Keep in
/// sync with the same fields in `core/tests/data/block_kat.json`. This
/// dumper is hermetic (pinned in code); drift detection comes from the
/// assertion test [`block_kat_self_recipient_one_record`], which loads
/// the JSON and asserts the encoded bytes match — any mismatch between
/// these inputs and the JSON's `expected.block_file` fails that test.
fn bootstrap_inputs() -> common::BlockKatVector {
    common::BlockKatVector {
        name: "self_recipient_one_record".to_string(),
        description: "Single self-addressed block with one login record. Pins \
            the encoded BlockFile byte sequence."
            .to_string(),
        inputs: common::BlockKatInputs {
            identity_seed: [0xC0; 32],
            encrypt_seed: [0xC1; 32],
            vault_uuid: [
                0x76, 0x61, 0x75, 0x6c, 0x74, 0x2d, 0x75, 0x75, 0x69, 0x64, 0x2d, 0x6b, 0x61, 0x74,
                0x2d, 0x31,
            ],
            block_uuid: [
                0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x2d, 0x75, 0x75, 0x69, 0x64, 0x2d, 0x6b, 0x61, 0x74,
                0x2d, 0x31,
            ],
            author_fingerprint: [
                0x66, 0x70, 0x2d, 0x73, 0x65, 0x6c, 0x66, 0x2d, 0x6b, 0x61, 0x74, 0x2d, 0x76, 0x30,
                0x30, 0x31,
            ],
            created_at_ms: 1_714_060_800_000,
            last_mod_ms: 1_714_060_800_500,
            display_name: "Block KAT Identity".to_string(),
            vector_clock: vec![common::BlockKatVectorClockEntry {
                device_uuid: [
                    0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x2d, 0x75, 0x75, 0x69, 0x64, 0x2d, 0x6b,
                    0x61, 0x74, 0x31,
                ],
                counter: 1,
            }],
            block_name: "Banking".to_string(),
            block_version: 1,
            schema_version: 1,
            records: vec![common::BlockKatRecord {
                record_uuid: [
                    0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x2d, 0x75, 0x75, 0x69, 0x64, 0x2d, 0x6b,
                    0x61, 0x74, 0x31,
                ],
                record_type: "login".to_string(),
                fields: vec![
                    common::BlockKatField {
                        name: "username".to_string(),
                        value_type: "text".to_string(),
                        value_text: Some("alice".to_string()),
                        value_hex: None,
                        last_mod: 1_714_060_800_000,
                        device_uuid: [
                            0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x2d, 0x75, 0x75, 0x69, 0x64, 0x2d,
                            0x6b, 0x61, 0x74, 0x31,
                        ],
                    },
                    common::BlockKatField {
                        name: "totp_seed".to_string(),
                        value_type: "bytes".to_string(),
                        value_text: None,
                        value_hex: Some("00010203fffefdfc".to_string()),
                        last_mod: 1_714_060_800_000,
                        device_uuid: [
                            0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x2d, 0x75, 0x75, 0x69, 0x64, 0x2d,
                            0x6b, 0x61, 0x74, 0x31,
                        ],
                    },
                ],
                tags: vec!["personal".to_string()],
                created_at_ms: 1_714_060_800_000,
                last_mod_ms: 1_714_060_800_000,
                tombstone: false,
                tombstoned_at_ms: 0,
            }],
        },
        // expected.* is filled in by the dumper; placeholders here.
        expected: common::BlockKatExpected {
            block_file: Vec::new(),
            size_bytes: 0,
            recipients_count: 1,
            records_count: 1,
            first_record_type: "login".to_string(),
        },
    }
}

/// Lowercase hex encoder (the `hex` crate is not a dev-dep here; copying
/// bytes through `format!` per byte avoids pulling one in for one call
/// site).
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}
