//! Manifest layer unit tests.
//!
//! Moved verbatim out of the pre-split `manifest.rs`; `mod.rs` holds the
//! module map. `use super::*` became an explicit `crate::vault::manifest::*`
//! glob plus the imports the pre-split file's own `use` lines used to supply
//! through that glob.

use std::collections::BTreeMap;

use ciborium::Value;

use crate::crypto::aead::{AeadKey, AeadNonce, AEAD_TAG_LEN};
use crate::crypto::secret::Sensitive;
use crate::crypto::sig::{
    self, Ed25519Public, Ed25519Secret, MlDsa65Public, MlDsa65Secret, MlDsa65Sig, ED25519_SIG_LEN,
    ML_DSA_65_SIG_LEN,
};
use crate::identity::fingerprint::Fingerprint;
use crate::vault::canonical::{encode_canonical_map, CanonicalError};
use crate::vault::record::UnknownValue;
use crate::version::{FILE_KIND_MANIFEST, MAGIC};

use crate::vault::manifest::encode::{
    kdf_params_to_value, manifest_to_entries, trash_entry_to_value, unknown_value_inner,
};
use crate::vault::manifest::*;

fn dummy_kdf_params() -> KdfParamsRef {
    KdfParamsRef {
        memory_kib: 262_144,
        iterations: 3,
        parallelism: 1,
        salt: [0x11; SALT_LEN],
    }
}

fn minimal_manifest() -> Manifest {
    Manifest {
        manifest_version: MANIFEST_VERSION_V1,
        vault_uuid: [0x01; UUID_LEN],
        format_version: FORMAT_VERSION_V1,
        suite_id: SUITE_ID_V1,
        owner_user_uuid: [0x02; UUID_LEN],
        vector_clock: Vec::new(),
        blocks: Vec::new(),
        trash: Vec::new(),
        kdf_params: dummy_kdf_params(),
        unknown: BTreeMap::new(),
    }
}

fn populated_manifest() -> Manifest {
    let vc = vec![
        VectorClockEntry {
            device_uuid: [0xaa; UUID_LEN],
            counter: 7,
        },
        VectorClockEntry {
            device_uuid: [0x55; UUID_LEN],
            counter: 3,
        },
    ];
    let block_a = BlockEntry {
        block_uuid: [0xb1; UUID_LEN],
        block_name: "logins".to_string(),
        fingerprint: [0xff; BLOCK_FINGERPRINT_LEN],
        recipients: vec![[0xc1; UUID_LEN], [0xc2; UUID_LEN]],
        vector_clock_summary: vec![
            VectorClockEntry {
                device_uuid: [0xaa; UUID_LEN],
                counter: 4,
            },
            VectorClockEntry {
                device_uuid: [0x55; UUID_LEN],
                counter: 2,
            },
        ],
        suite_id: SUITE_ID_V1,
        created_at_ms: 1_714_060_800_000,
        last_mod_ms: 1_714_060_800_010,
        unknown: BTreeMap::new(),
    };
    let block_b = BlockEntry {
        block_uuid: [0xa2; UUID_LEN],
        block_name: "notes".to_string(),
        fingerprint: [0xee; BLOCK_FINGERPRINT_LEN],
        recipients: vec![[0xc1; UUID_LEN], [0xc3; UUID_LEN]],
        vector_clock_summary: vec![
            VectorClockEntry {
                device_uuid: [0x55; UUID_LEN],
                counter: 1,
            },
            VectorClockEntry {
                device_uuid: [0xaa; UUID_LEN],
                counter: 5,
            },
        ],
        suite_id: SUITE_ID_V1,
        created_at_ms: 1_714_060_800_001,
        last_mod_ms: 1_714_060_800_011,
        unknown: BTreeMap::new(),
    };
    let trash = vec![TrashEntry {
        block_uuid: [0xde; UUID_LEN],
        tombstoned_at_ms: 1_714_060_900_000,
        tombstoned_by: [0xaa; UUID_LEN],
        fingerprint: Some([0xcd; BLOCK_FINGERPRINT_LEN]),
        purged_at_ms: None,
        unknown: BTreeMap::new(),
    }];
    Manifest {
        manifest_version: MANIFEST_VERSION_V1,
        vault_uuid: [0x42; UUID_LEN],
        format_version: FORMAT_VERSION_V1,
        suite_id: SUITE_ID_V1,
        owner_user_uuid: [0x99; UUID_LEN],
        vector_clock: vc,
        blocks: vec![block_a, block_b],
        trash,
        kdf_params: KdfParamsRef {
            memory_kib: 524_288,
            iterations: 4,
            parallelism: 2,
            salt: [0x22; SALT_LEN],
        },
        unknown: BTreeMap::new(),
    }
}

// ---- TrashEntry content-commitment round-trip (#293) -----------------

#[test]
fn trash_entry_fingerprint_some_round_trips() {
    // A TrashEntry carrying a content commitment must survive a full
    // encode → decode cycle with the fingerprint intact (#293).
    let mut m = populated_manifest();
    m.trash[0].fingerprint = Some([0x7a; BLOCK_FINGERPRINT_LEN]);
    let bytes = encode_manifest(&m).unwrap();
    let decoded = decode_manifest(bytes.expose()).unwrap();
    assert_eq!(
        decoded.trash[0].fingerprint,
        Some([0x7a; BLOCK_FINGERPRINT_LEN]),
        "Some(fingerprint) must round-trip"
    );
    // The typed key must NOT leak into the forward-compat `unknown` map.
    assert!(
        decoded.trash[0].unknown.is_empty(),
        "fingerprint must decode as a typed field, not into unknown"
    );
}

#[test]
fn trash_entry_fingerprint_none_omits_key() {
    // A legacy-shaped entry (no commitment) must encode WITHOUT the
    // "fingerprint" key and decode back to None — byte-compatible with
    // pre-#293 manifests.
    let mut m = populated_manifest();
    m.trash[0].fingerprint = None;
    let bytes = encode_manifest(&m).unwrap();
    // The "fingerprint" key must be byte-absent from the TrashEntry
    // encoding (legacy-byte-identical — the frozen-v1 no-format-bump
    // guarantee). We encode the trash entry in isolation so the check is
    // scoped to TrashEntry bytes only (BlockEntry.fingerprint is always
    // present and would otherwise be a false positive).
    let entry_value = trash_entry_to_value(&m.trash[0]).unwrap();
    let mut entry_bytes = Vec::new();
    ciborium::ser::into_writer(&entry_value, &mut entry_bytes).unwrap();
    assert!(
        !String::from_utf8_lossy(&entry_bytes).contains("fingerprint"),
        "None must not emit the fingerprint key"
    );
    let decoded = decode_manifest(bytes.expose()).unwrap();
    assert_eq!(decoded.trash[0].fingerprint, None, "None must round-trip");
}

// ---- TrashEntry.purged_at_ms round-trip (#399) ------------------------

#[test]
fn trash_entry_purged_at_ms_some_round_trips() {
    // A TrashEntry marked as purged must survive a full encode → decode
    // cycle with purged_at_ms intact (#399).
    let mut m = populated_manifest();
    m.trash[0].purged_at_ms = Some(1_724_000_000_123);
    let bytes = encode_manifest(&m).unwrap();
    let decoded = decode_manifest(bytes.expose()).unwrap();
    assert_eq!(
        decoded.trash[0].purged_at_ms,
        Some(1_724_000_000_123),
        "Some(purged_at_ms) must round-trip"
    );
    // The typed key must NOT leak into the forward-compat `unknown` map.
    assert!(
        decoded.trash[0].unknown.is_empty(),
        "purged_at_ms must decode as a typed field, not into unknown"
    );
}

#[test]
fn trash_entry_purged_at_ms_none_roundtrips_byte_identical() {
    // A still-restorable trash entry (not purged) must encode WITHOUT
    // the "purged_at_ms" key and decode back to None — byte-compatible
    // with pre-#399 manifests (frozen-v1 no-format-bump guarantee).
    let mut m = populated_manifest();
    m.trash[0].purged_at_ms = None;
    let entry_value = trash_entry_to_value(&m.trash[0]).unwrap();
    let mut entry_bytes = Vec::new();
    ciborium::ser::into_writer(&entry_value, &mut entry_bytes).unwrap();
    assert!(
        !String::from_utf8_lossy(&entry_bytes).contains("purged_at_ms"),
        "None must not emit the purged_at_ms key"
    );

    let bytes = encode_manifest(&m).unwrap();
    let decoded = decode_manifest(bytes.expose()).unwrap();
    assert_eq!(decoded.trash[0].purged_at_ms, None, "None must round-trip");

    // Absent key, not explicit null: re-encoding the decoded entry
    // reproduces byte-identical bytes to the pre-purge entry.
    let re_entry_value = trash_entry_to_value(&decoded.trash[0]).unwrap();
    let mut re_entry_bytes = Vec::new();
    ciborium::ser::into_writer(&re_entry_value, &mut re_entry_bytes).unwrap();
    assert_eq!(
        entry_bytes, re_entry_bytes,
        "None must re-encode byte-identically (no explicit null)"
    );
}

// ---- Round-trip ------------------------------------------------------

#[test]
fn roundtrip_minimal_manifest() {
    let m = minimal_manifest();
    let bytes = encode_manifest(&m).expect("encode minimal");
    let parsed = decode_manifest(bytes.expose()).expect("decode minimal");
    assert_eq!(parsed, m);
    let bytes_again = encode_manifest(&parsed).expect("re-encode minimal");
    assert_eq!(bytes, bytes_again, "encode is deterministic");
}

#[test]
fn roundtrip_populated_manifest() {
    let m = populated_manifest();
    let bytes = encode_manifest(&m).expect("encode populated");
    let parsed = decode_manifest(bytes.expose()).expect("decode populated");
    // We can't compare `parsed == m` directly because the input
    // vector_clock and recipients arrays were built in non-canonical
    // order. After encode-then-decode they come back sorted. So we
    // sort `m`'s arrays the same way before comparing.
    let mut m_sorted = m.clone();
    m_sorted.vector_clock.sort_by_key(|a| a.device_uuid);
    m_sorted.blocks.sort_by_key(|a| a.block_uuid);
    for blk in &mut m_sorted.blocks {
        blk.recipients.sort();
        blk.vector_clock_summary.sort_by_key(|a| a.device_uuid);
    }
    m_sorted.trash.sort_by_key(|a| a.block_uuid);
    assert_eq!(parsed, m_sorted);

    let bytes_again = encode_manifest(&parsed).expect("re-encode populated");
    assert_eq!(bytes, bytes_again, "round-trip is bit-identical");
}

// ---- Encoding sorts arrays on output ---------------------------------

/// Re-parse encoded bytes to a `ciborium::Value` map for raw
/// inspection of array order.
fn parse_to_value_map(bytes: &[u8]) -> Vec<(Value, Value)> {
    match ciborium::de::from_reader(bytes).expect("ciborium parse") {
        Value::Map(m) => m,
        _ => panic!("manifest is not a map"),
    }
}

fn find_array<'a>(map: &'a [(Value, Value)], key: &str) -> &'a [Value] {
    for (k, v) in map {
        if let Value::Text(s) = k {
            if s == key {
                return match v {
                    Value::Array(a) => a.as_slice(),
                    _ => panic!("{key} is not an array"),
                };
            }
        }
    }
    panic!("key {key} not present in manifest map");
}

fn entry_bytes_field(entry: &Value, key: &str) -> Vec<u8> {
    match entry {
        Value::Map(m) => {
            for (k, v) in m {
                if let Value::Text(s) = k {
                    if s == key {
                        return match v {
                            Value::Bytes(b) => b.clone(),
                            _ => panic!("{key} is not bytes"),
                        };
                    }
                }
            }
            panic!("entry missing key {key}");
        }
        _ => panic!("entry is not a map"),
    }
}

#[test]
fn encoding_sorts_arrays_on_output() {
    let m = populated_manifest();
    let bytes = encode_manifest(&m).expect("encode");
    let map = parse_to_value_map(bytes.expose());

    // vector_clock sorted ascending by device_uuid.
    let vc = find_array(&map, KEY_VECTOR_CLOCK);
    let device_ids: Vec<Vec<u8>> = vc
        .iter()
        .map(|e| entry_bytes_field(e, KEY_DEVICE_UUID))
        .collect();
    assert_eq!(
        device_ids,
        vec![vec![0x55; UUID_LEN], vec![0xaa; UUID_LEN]],
        "vector_clock sorted by device_uuid lex"
    );

    // blocks sorted ascending by block_uuid.
    let blocks = find_array(&map, KEY_BLOCKS);
    let block_ids: Vec<Vec<u8>> = blocks
        .iter()
        .map(|b| entry_bytes_field(b, KEY_BLOCK_UUID))
        .collect();
    assert_eq!(
        block_ids,
        vec![vec![0xa2; UUID_LEN], vec![0xb1; UUID_LEN]],
        "blocks sorted by block_uuid lex"
    );

    // Inner vector_clock_summary on each block is also sorted.
    for blk in blocks {
        let inner_vc = match blk {
            Value::Map(entries) => entries
                .iter()
                .find_map(|(k, v)| match k {
                    Value::Text(s) if s == KEY_VECTOR_CLOCK_SUMMARY => match v {
                        Value::Array(a) => Some(a.as_slice()),
                        _ => None,
                    },
                    _ => None,
                })
                .expect("vector_clock_summary present"),
            _ => panic!("block entry not a map"),
        };
        let ids: Vec<Vec<u8>> = inner_vc
            .iter()
            .map(|e| entry_bytes_field(e, KEY_DEVICE_UUID))
            .collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted, "vector_clock_summary sorted on output");
    }

    // trash array — only one entry, but check the key is present.
    let trash = find_array(&map, KEY_TRASH);
    assert_eq!(trash.len(), 1, "trash has one entry");
}

// ---- Forward-compat round-trip ---------------------------------------

#[test]
fn forward_compat_unknown_top_level_key_round_trips() {
    let mut m = minimal_manifest();
    // CBOR for a tiny array `[1, 2]`: 0x82 0x01 0x02.
    m.unknown.insert(
        "future_field".into(),
        UnknownValue::from_canonical_cbor(&[0x82, 0x01, 0x02])
            .expect("UnknownValue from canonical bytes"),
    );
    let bytes = encode_manifest(&m).expect("encode with unknown");
    let parsed = decode_manifest(bytes.expose()).expect("decode with unknown");
    assert!(
        parsed.unknown.contains_key("future_field"),
        "unknown top-level key preserved on decode"
    );
    let bytes_again = encode_manifest(&parsed).expect("re-encode");
    assert_eq!(
        bytes, bytes_again,
        "unknown top-level key round-trips bit-identically"
    );
}

// `encode_manifest_wipes_unknown_value_inners_intermediate_parse` stood
// here until the #560 review. It pinned `unknown_value_inner`'s
// `SecretValueTree` wrap — and that wrap is gone, because it covered no
// early-return window and forced a deep clone of decrypted forward-compat
// content to get the value back out of a type with no consuming accessor.
// See that function's doc for the full reasoning and for what replaced it
// (a `SecretBytes` wrap on `bytes`, which DOES have a window). The test is
// retired with the wrap it pinned rather than repointed: the replacement
// is not counter-observable, which is the #558 class, and writing a test
// that asserts nothing about it would be worse than admitting the gap.

// ---- Decode wipes its parsed tree (#547 Task 7b) ----------------------

/// THE test #547 Task 7b's brief asks for: drive an early-return path
/// through `decode_manifest` and prove `SecretValueTree::drop` actually
/// fires, mirroring `record::decode`'s
/// `decode_wipes_its_parsed_tree_on_an_early_return` and
/// `block::decode_plaintext`'s
/// `decode_plaintext_wipes_its_parsed_tree_on_an_early_return`.
///
/// That second citation was FALSE when first written and is corrected
/// rather than dropped: no such block test existed, `block.rs` had zero
/// `wipe_calls()` assertions of any kind, and open issue #557 said so
/// outright — so this comment told a reader the opposite of the tracker.
/// The block test was written during the #560 review; the claim is true
/// now because the code changed, not because the wording softened.
///
/// `manifest_version` — the FIRST entry `manifest_to_entries` emits —
/// is corrupted to the wrong CBOR type, so `parse_manifest_map`'s very
/// first `take_u8(KEY_MANIFEST_VERSION)` call fails and the `?`
/// propagates all the way back to `decode_manifest` before the
/// `blocks` array entry — carrying a structurally valid `block_name`
/// ("logins"), the user-visible plaintext this whole task exists to
/// cover — is ever examined. Wiping here proves not-yet-examined
/// content is covered too, not just already-consumed content.
///
/// **Updated to `before + 2` by Task 2 (#561), and re-tightened to an
/// exact count in review.** `decode_manifest` now parses through
/// `crate::cbor::from_secret_reader` instead of plain
/// `ciborium::de::from_reader`; that call's own `CborScratch` wipes
/// unconditionally when it drops at the end of `from_secret_reader`,
/// before `parse_manifest_map` even runs — so a first pass at this
/// update left the assertion as `> before`, which the added scratch
/// wipe alone satisfies regardless of whether the early-return path
/// wipes anything. Proven by mutation: wrapping
/// `SecretValueTree::new(parsed)` in `ManuallyDrop` inside
/// `decode_manifest` (killing that `Drop`) left the `> before` form of
/// this test PASSING — only the happy-path exact-count test below
/// failed. `before + 2` is exact: 1 scratch wipe (`from_secret_reader`,
/// unconditional) + 1 `SecretValueTree::drop` on the early return this
/// test exists to pin — the second of the two is what the mutation
/// above proved this assertion was no longer covering.
#[test]
fn decode_manifest_wipes_its_parsed_tree_on_an_early_return() {
    let m = populated_manifest();
    let mut entries = manifest_to_entries(&m).expect("encode entries");
    let version_idx = entries
        .iter()
        .position(|(k, _)| matches!(k, Value::Text(s) if s == KEY_MANIFEST_VERSION))
        .expect("manifest_version entry present");
    entries[version_idx].1 = Value::Text("not-a-u8".to_string());

    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&Value::Map(entries), &mut bytes).expect("serialize");

    let before = crate::cbor::wipe_calls();
    let err = decode_manifest(&bytes).expect_err("wrong-typed manifest_version must be rejected");
    assert!(
        matches!(
            err,
            ManifestError::WrongType {
                field: KEY_MANIFEST_VERSION,
                expected: "unsigned integer",
            }
        ),
        "expected WrongType {{ field: manifest_version, expected: unsigned integer }}, got {err:?}"
    );
    assert_eq!(
        crate::cbor::wipe_calls(),
        before + 2,
        "expected exactly 2 wipes (from_secret_reader's scratch wipe, \
         plus SecretValueTree::drop on the early return out of \
         parse_manifest_map) — decode_manifest's wrap is gone, or no \
         longer covers this path (#561)"
    );
}

/// `decode_manifest` must parse through `cbor::from_secret_reader`,
/// whose scratch buffer holds a copy of every decrypted plaintext value
/// in the input — including every `block_name` (#561). Pinning the
/// COMPOSITION on the HAPPY path, complementing the early-return test
/// above: `scratch.rs`'s own tests prove the wipe fires, this one
/// proves this path uses it.
#[test]
fn decode_manifest_wipes_the_parser_scratch_buffer() {
    let m = populated_manifest();
    let bytes = encode_manifest(&m).expect("encode");

    let before = crate::cbor::wipe_calls();
    let decoded = decode_manifest(bytes.expose()).expect("decode");
    let after = crate::cbor::wipe_calls();

    assert_eq!(decoded.vault_uuid, m.vault_uuid);
    // Two wipes: one scratch wipe from `from_secret_reader`'s own
    // `CborScratch::drop` (fires unconditionally at the end of that
    // call), and one tree wipe from `SecretValueTree::drop` at the end
    // of `decode_manifest`. `populated_manifest()` deliberately carries
    // NO forward-compat `unknown` entries at any level (manifest,
    // block-entry, or trash-entry — all three are `BTreeMap::new()`),
    // so `parse_manifest_map`'s `value_to_unknown` — which, like
    // `block.rs`'s function of the same name, re-encodes and re-parses
    // through `UnknownValue::from_canonical_cbor`, itself now routed
    // through `from_secret_reader` — is never called on this fixture.
    // `block::decode_plaintext_wipes_the_parser_scratch_buffer`'s own
    // comment documents what happens when it IS: one extra wipe per
    // unknown value. Do not copy this fixture's "2" onto a manifest
    // that carries any `unknown` entry without re-deriving the count.
    //
    // DERIVED from the fixture rather than hardcoded (#575 review) —
    // same reasoning as `block::decode_plaintext_wipes_the_parser_
    // scratch_buffer`. `populated_manifest()` carries no `unknown`
    // entries at any of the three levels today; if one is ever added,
    // `value_to_unknown` re-parses it and this count follows
    // automatically instead of redding a security test for an
    // unrelated fixture change.
    let expected = 2 + m.unknown.len();
    assert_eq!(
        m.unknown.len(),
        0,
        "fixture guard: populated_manifest() is expected to carry no \
         top-level unknowns; `expected` tracks it if that changes"
    );
    assert_eq!(
        after - before,
        expected,
        "expected exactly {expected} wipes on the decode_manifest path"
    );
}

/// `unknown_value_inner` must parse through `cbor::from_secret_reader`
/// (#561): its input is a re-encode of a forward-compat unknown
/// subtree, plaintext this version cannot interpret but must still not
/// leave staged in `ciborium`'s own frame. Called directly rather than
/// through `encode_manifest`, matching the file's existing convention
/// of testing this private helper in isolation (see the retired-test
/// comment above this section) — an end-to-end `encode_manifest` call
/// would also exercise `value_to_unknown` on the decode side, which
/// wipes independently and would muddy this function's own count.
#[test]
fn unknown_value_inner_wipes_the_parser_scratch_buffer() {
    // CBOR for a tiny array `[1, 2]`: 0x82 0x01 0x02.
    let uv = UnknownValue::from_canonical_cbor(&[0x82, 0x01, 0x02])
        .expect("UnknownValue from canonical bytes");

    let before = crate::cbor::wipe_calls();
    let v = unknown_value_inner(&uv).expect("unknown_value_inner");
    let after = crate::cbor::wipe_calls();

    assert_eq!(
        v,
        Value::Array(vec![Value::Integer(1.into()), Value::Integer(2.into())])
    );
    // One wipe: `unknown_value_inner` calls `from_secret_reader` exactly
    // once and returns the raw parsed `Value` with no further wrap
    // (see the function's own doc for why the `SecretValueTree` wrap
    // that used to sit here was removed — it covered no early-return
    // window since `Ok(v)` is the very next line).
    assert_eq!(
        after - before,
        1,
        "expected exactly 1 wipe on the unknown_value_inner path"
    );
}

// ---- Negative paths --------------------------------------------------

/// Build a top-level manifest CBOR map by hand. Useful for negative
/// tests where we want to mutate one key away from canonical.
fn build_manifest_map_with_overrides(
    manifest_version: Option<u8>,
    vault_uuid_present: bool,
) -> Vec<u8> {
    let mut entries: Vec<(Value, Value)> = Vec::new();
    if let Some(mv) = manifest_version {
        entries.push((
            Value::Text(KEY_MANIFEST_VERSION.into()),
            Value::Integer(u64::from(mv).into()),
        ));
    }
    if vault_uuid_present {
        entries.push((
            Value::Text(KEY_VAULT_UUID.into()),
            Value::Bytes([0x01; UUID_LEN].to_vec()),
        ));
    }
    entries.push((
        Value::Text(KEY_FORMAT_VERSION.into()),
        Value::Integer(u64::from(FORMAT_VERSION_V1).into()),
    ));
    entries.push((
        Value::Text(KEY_SUITE_ID.into()),
        Value::Integer(u64::from(SUITE_ID_V1).into()),
    ));
    entries.push((
        Value::Text(KEY_OWNER_USER_UUID.into()),
        Value::Bytes([0x02; UUID_LEN].to_vec()),
    ));
    entries.push((
        Value::Text(KEY_VECTOR_CLOCK.into()),
        Value::Array(Vec::new()),
    ));
    entries.push((Value::Text(KEY_BLOCKS.into()), Value::Array(Vec::new())));
    entries.push((Value::Text(KEY_TRASH.into()), Value::Array(Vec::new())));
    entries.push((
        Value::Text(KEY_KDF_PARAMS.into()),
        kdf_params_to_value(&dummy_kdf_params()).expect("kdf_params"),
    ));
    encode_canonical_map(&entries).expect("encode_canonical_map")
}

#[test]
fn rejects_unsupported_manifest_version() {
    let bytes = build_manifest_map_with_overrides(Some(2), true);
    let err = decode_manifest(&bytes).expect_err("manifest_version=2 must reject");
    assert!(
        matches!(err, ManifestError::UnsupportedManifestVersion(2)),
        "expected UnsupportedManifestVersion(2), got {err:?}"
    );
}

#[test]
fn rejects_duplicate_device_uuid_in_vector_clock() {
    // Hand-build a manifest with two vector_clock entries sharing the
    // same device_uuid. We can NOT rely on encode_manifest to produce
    // duplicates (the input already needs to have them and the encode
    // path doesn't dedupe — but the canonical sort doesn't either).
    // The simplest path: just build the duplicate input, then invoke
    // encode_manifest and decode it.
    let dupe_dev = [0x33; UUID_LEN];
    let m = Manifest {
        manifest_version: MANIFEST_VERSION_V1,
        vault_uuid: [0x01; UUID_LEN],
        format_version: FORMAT_VERSION_V1,
        suite_id: SUITE_ID_V1,
        owner_user_uuid: [0x02; UUID_LEN],
        vector_clock: vec![
            VectorClockEntry {
                device_uuid: dupe_dev,
                counter: 1,
            },
            VectorClockEntry {
                device_uuid: dupe_dev,
                counter: 2,
            },
        ],
        blocks: Vec::new(),
        trash: Vec::new(),
        kdf_params: dummy_kdf_params(),
        unknown: BTreeMap::new(),
    };
    let bytes = encode_manifest(&m).expect("encode duplicates");
    let err = decode_manifest(bytes.expose())
        .expect_err("duplicate device_uuid must be rejected on decode");
    assert!(
        matches!(err, ManifestError::VectorClockDuplicateDevice),
        "expected VectorClockDuplicateDevice, got {err:?}"
    );
}

#[test]
fn rejects_duplicate_block_uuid() {
    let dupe = [0x77; UUID_LEN];
    let make_block = |suffix: u8| BlockEntry {
        block_uuid: dupe,
        block_name: format!("blk-{suffix}"),
        fingerprint: [suffix; BLOCK_FINGERPRINT_LEN],
        recipients: vec![[0xc1; UUID_LEN]],
        vector_clock_summary: Vec::new(),
        suite_id: SUITE_ID_V1,
        created_at_ms: 1,
        last_mod_ms: 2,
        unknown: BTreeMap::new(),
    };
    let m = Manifest {
        manifest_version: MANIFEST_VERSION_V1,
        vault_uuid: [0x01; UUID_LEN],
        format_version: FORMAT_VERSION_V1,
        suite_id: SUITE_ID_V1,
        owner_user_uuid: [0x02; UUID_LEN],
        vector_clock: Vec::new(),
        blocks: vec![make_block(1), make_block(2)],
        trash: Vec::new(),
        kdf_params: dummy_kdf_params(),
        unknown: BTreeMap::new(),
    };
    let bytes = encode_manifest(&m).expect("encode duplicates");
    let err = decode_manifest(bytes.expose())
        .expect_err("duplicate block_uuid must be rejected on decode");
    assert!(
        matches!(err, ManifestError::DuplicateBlockUuid),
        "expected DuplicateBlockUuid, got {err:?}"
    );
}

#[test]
fn rejects_duplicate_trash_uuid() {
    // The manifest carries the most-recent tombstone per block_uuid only
    // (vault-format §7), so two trash entries sharing a block_uuid are
    // nonsensical — a sign of corruption or attack — and rejected on
    // decode, mirroring the `blocks` duplicate rule.
    let dupe = [0x88; UUID_LEN];
    let make_trash = |suffix: u8| TrashEntry {
        block_uuid: dupe,
        tombstoned_at_ms: u64::from(suffix),
        tombstoned_by: [0xd1; UUID_LEN],
        fingerprint: Some([suffix; BLOCK_FINGERPRINT_LEN]),
        purged_at_ms: None,
        unknown: BTreeMap::new(),
    };
    let m = Manifest {
        manifest_version: MANIFEST_VERSION_V1,
        vault_uuid: [0x01; UUID_LEN],
        format_version: FORMAT_VERSION_V1,
        suite_id: SUITE_ID_V1,
        owner_user_uuid: [0x02; UUID_LEN],
        vector_clock: Vec::new(),
        blocks: Vec::new(),
        trash: vec![make_trash(1), make_trash(2)],
        kdf_params: dummy_kdf_params(),
        unknown: BTreeMap::new(),
    };
    let bytes = encode_manifest(&m).expect("encode duplicates");
    let err = decode_manifest(bytes.expose())
        .expect_err("duplicate trash block_uuid must be rejected on decode");
    assert!(
        matches!(err, ManifestError::DuplicateTrashUuid),
        "expected DuplicateTrashUuid, got {err:?}"
    );
}

#[test]
fn rejects_non_map_top_level() {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&Value::Array(Vec::new()), &mut buf).expect("encode array");
    let err = decode_manifest(&buf).expect_err("array top-level must reject");
    assert!(
        matches!(err, ManifestError::NotAMap),
        "expected NotAMap, got {err:?}"
    );
}

#[test]
fn rejects_float_in_unknown_value() {
    // Build a manifest map with an unknown top-level key whose value
    // is a CBOR float. The float-rejection walker fires up front in
    // decode_manifest before the unknown bag is even populated.
    let entries: Vec<(Value, Value)> = vec![
        (
            Value::Text(KEY_MANIFEST_VERSION.into()),
            Value::Integer(u64::from(MANIFEST_VERSION_V1).into()),
        ),
        (
            Value::Text(KEY_VAULT_UUID.into()),
            Value::Bytes([0x01; UUID_LEN].to_vec()),
        ),
        (
            Value::Text(KEY_FORMAT_VERSION.into()),
            Value::Integer(u64::from(FORMAT_VERSION_V1).into()),
        ),
        (
            Value::Text(KEY_SUITE_ID.into()),
            Value::Integer(u64::from(SUITE_ID_V1).into()),
        ),
        (
            Value::Text(KEY_OWNER_USER_UUID.into()),
            Value::Bytes([0x02; UUID_LEN].to_vec()),
        ),
        (
            Value::Text(KEY_VECTOR_CLOCK.into()),
            Value::Array(Vec::new()),
        ),
        (Value::Text(KEY_BLOCKS.into()), Value::Array(Vec::new())),
        (Value::Text(KEY_TRASH.into()), Value::Array(Vec::new())),
        (
            Value::Text(KEY_KDF_PARAMS.into()),
            kdf_params_to_value(&dummy_kdf_params()).expect("kdf_params"),
        ),
        // Float lives inside an unknown forward-compat key.
        (Value::Text("future_floaty".into()), Value::Float(1.5)),
    ];
    let bytes = encode_canonical_map(&entries).expect("encode_canonical_map");

    let err = decode_manifest(&bytes).expect_err("float must be rejected");
    assert!(
        matches!(
            err,
            ManifestError::Canonical(CanonicalError::FloatRejected { .. })
        ),
        "expected Canonical(FloatRejected), got {err:?}"
    );
}

#[test]
fn rejects_missing_required_field_vault_uuid() {
    let bytes = build_manifest_map_with_overrides(Some(MANIFEST_VERSION_V1), false);
    let err = decode_manifest(&bytes).expect_err("missing vault_uuid must reject");
    assert!(
        matches!(
            err,
            ManifestError::MissingField {
                field: KEY_VAULT_UUID
            }
        ),
        "expected MissingField {{ field: \"vault_uuid\" }}, got {err:?}"
    );
}

// (Group B) Hand-crafted decode negatives — pin every typed
// ManifestError variant that's reachable from real input but lacked a
// dedicated negative. Mirrors the style of the
// `rejects_unsupported_manifest_version` / `rejects_duplicate_*` tests
// above. Catches the regression where a refactor of `decode_manifest`
// collapses a typed variant into a generic CBOR error.

/// Regression: ensures `decode_manifest` rejects a top-level map whose
/// keys aren't all text strings. §4.2 fixes every map key as `tstr`.
#[test]
fn rejects_non_text_map_key() {
    // Build a hand-crafted top-level map with one integer key
    // alongside the text-string keys. The integer key fires
    // `take_text_key` → `NonTextKey` before any field-specific
    // dispatch.
    let entries: Vec<(Value, Value)> = vec![
        (
            Value::Text(KEY_MANIFEST_VERSION.into()),
            Value::Integer(u64::from(MANIFEST_VERSION_V1).into()),
        ),
        (
            Value::Text(KEY_VAULT_UUID.into()),
            Value::Bytes([0x01; UUID_LEN].to_vec()),
        ),
        (
            Value::Text(KEY_FORMAT_VERSION.into()),
            Value::Integer(u64::from(FORMAT_VERSION_V1).into()),
        ),
        (
            Value::Text(KEY_SUITE_ID.into()),
            Value::Integer(u64::from(SUITE_ID_V1).into()),
        ),
        (
            Value::Text(KEY_OWNER_USER_UUID.into()),
            Value::Bytes([0x02; UUID_LEN].to_vec()),
        ),
        (
            Value::Text(KEY_VECTOR_CLOCK.into()),
            Value::Array(Vec::new()),
        ),
        (Value::Text(KEY_BLOCKS.into()), Value::Array(Vec::new())),
        (Value::Text(KEY_TRASH.into()), Value::Array(Vec::new())),
        (
            Value::Text(KEY_KDF_PARAMS.into()),
            kdf_params_to_value(&dummy_kdf_params()).expect("kdf_params"),
        ),
        // Integer key — illegal under §4.2 ("all map keys are tstr").
        (Value::Integer(0u64.into()), Value::Integer(0u64.into())),
    ];
    let bytes = encode_canonical_map(&entries).expect("encode_canonical_map");

    let err = decode_manifest(&bytes).expect_err("integer map key must reject");
    assert!(
        matches!(err, ManifestError::NonTextKey),
        "expected NonTextKey, got {err:?}"
    );
}

/// `parse_manifest_map` is the last of four decoders without a
/// duplicate-key check; the other three reject and this one silently
/// last-wins (#568). Defence in depth, not a live hole: the manifest
/// body is covered by the hybrid signature (Ed25519 AND ML-DSA-65),
/// computed over the on-disk AEAD ciphertext — an attacker without the
/// owner's signing keys cannot forge a duplicate-key manifest that
/// still verifies. Unlike `block::decode_plaintext` / `record::decode`,
/// `decode_manifest` has no independent re-encode-and-compare
/// canonicality backstop of its own (#572) — before this fix the
/// signature was the *only* defence a duplicate key ran into, not a
/// second layer over an existing one.
#[test]
fn a_manifest_with_a_repeated_key_is_rejected() {
    let m = populated_manifest();
    let bytes = encode_manifest(&m).expect("encode");

    let entries = match ciborium::de::from_reader::<Value, _>(bytes.expose()).expect("parse") {
        Value::Map(m) => m,
        other => panic!("expected a map, got {other:?}"),
    };

    // EVERY known key, not just whichever sorts first. The check is now
    // per-`Option`-slot — nine independent `if slot.is_some()` arms
    // rather than the single shared `BTreeSet` lookup the first version
    // used — so a test that duplicates only `entries[0]` pins exactly
    // one of the nine and leaves eight deletable with the suite green.
    // That is the "nothing would notice if it were removed" failure this
    // whole slice exists to close, so the sweep is the point (#575
    // review). Mutation-verified: neutering any single arm reds this
    // test.
    assert_eq!(
        entries.len(),
        9,
        "populated_manifest() is expected to emit all nine known keys              and no unknowns; the sweep below covers whatever it emits, but              a change here means the arm census moved"
    );

    for i in 0..entries.len() {
        let repeated = match &entries[i].0 {
            Value::Text(s) => s.clone(),
            other => panic!("non-text manifest key: {other:?}"),
        };

        // Re-parse, duplicate entry `i`, re-encode. Non-canonical by
        // construction (irrelevant here — `decode_manifest` has no
        // re-encode-and-compare canonicality check of its own, #572 —
        // but the duplicate-key check must still be the thing that
        // fires, not some other decode failure downstream).
        let mut doubled_entries = entries.clone();
        doubled_entries.push(entries[i].clone());
        let mut doubled = Vec::new();
        ciborium::ser::into_writer(&Value::Map(doubled_entries), &mut doubled).expect("re-encode");

        let err = decode_manifest(&doubled).expect_err("a repeated key must be rejected");
        match err {
            ManifestError::DuplicateKey { field, .. } => assert_eq!(
                field, repeated,
                "DuplicateKey must name the key that was actually repeated"
            ),
            other => panic!("expected DuplicateKey for {repeated}, got {other:?}"),
        }
    }
}

/// The unknown-key arm has its own duplicate check — `BTreeMap::insert`'s
/// previous-value return, not an `Option` slot — so it needs its own
/// test (#575 review). `field` is the literal `"<unknown>"`: the
/// repeated key here is attacker-influenced forward-compat text from
/// inside the encrypted manifest, and carrying it would be exactly the
/// #474 leak class.
#[test]
fn a_manifest_with_a_repeated_unknown_key_is_rejected() {
    let mut m = populated_manifest();
    m.unknown.insert(
        "future_field".to_string(),
        UnknownValue::from_canonical_cbor(&[0x01]).expect("UnknownValue"),
    );
    let bytes = encode_manifest(&m).expect("encode");

    let mut entries = match ciborium::de::from_reader::<Value, _>(bytes.expose()).expect("parse") {
        Value::Map(m) => m,
        other => panic!("expected a map, got {other:?}"),
    };
    let unknown_entry = entries
        .iter()
        .find(|(k, _)| matches!(k, Value::Text(s) if s == "future_field"))
        .expect("the unknown key must be on the wire")
        .clone();
    entries.push(unknown_entry);
    let mut doubled = Vec::new();
    ciborium::ser::into_writer(&Value::Map(entries), &mut doubled).expect("re-encode");

    let err = decode_manifest(&doubled).expect_err("a repeated unknown key must be rejected");
    assert!(
        matches!(
            err,
            ManifestError::DuplicateKey {
                field: "<unknown>",
                index: _
            }
        ),
        "expected DuplicateKey {{ field: \"<unknown>\" }}, got {err:?}"
    );
}

/// Regression: ensures `decode_manifest` rejects a known field with the
/// wrong CBOR type. Field is `vault_uuid` (declared as `bstr 16`); we
/// hand-encode it as a text string so `take_fixed_bytes` fires the
/// `WrongType { expected: "byte string" }` arm.
#[test]
fn rejects_wrong_type_for_vault_uuid() {
    let entries: Vec<(Value, Value)> = vec![
        (
            Value::Text(KEY_MANIFEST_VERSION.into()),
            Value::Integer(u64::from(MANIFEST_VERSION_V1).into()),
        ),
        // vault_uuid declared as text — wrong type.
        (
            Value::Text(KEY_VAULT_UUID.into()),
            Value::Text("01010101-0101-0101-0101-010101010101".into()),
        ),
        (
            Value::Text(KEY_FORMAT_VERSION.into()),
            Value::Integer(u64::from(FORMAT_VERSION_V1).into()),
        ),
        (
            Value::Text(KEY_SUITE_ID.into()),
            Value::Integer(u64::from(SUITE_ID_V1).into()),
        ),
        (
            Value::Text(KEY_OWNER_USER_UUID.into()),
            Value::Bytes([0x02; UUID_LEN].to_vec()),
        ),
        (
            Value::Text(KEY_VECTOR_CLOCK.into()),
            Value::Array(Vec::new()),
        ),
        (Value::Text(KEY_BLOCKS.into()), Value::Array(Vec::new())),
        (Value::Text(KEY_TRASH.into()), Value::Array(Vec::new())),
        (
            Value::Text(KEY_KDF_PARAMS.into()),
            kdf_params_to_value(&dummy_kdf_params()).expect("kdf_params"),
        ),
    ];
    let bytes = encode_canonical_map(&entries).expect("encode_canonical_map");

    let err = decode_manifest(&bytes).expect_err("text vault_uuid must reject");
    assert!(
        matches!(
            err,
            ManifestError::WrongType {
                field: KEY_VAULT_UUID,
                expected: "byte string",
            }
        ),
        "expected WrongType {{ field: vault_uuid, expected: byte string }}, got {err:?}"
    );
}

/// Regression: ensures `decode_manifest` rejects a fixed-length `bstr`
/// field whose byte count is wrong. `vault_uuid` is `bstr 16`; here we
/// supply 15 bytes so `take_fixed_bytes::<16>` fails its
/// `<[u8; N]>::try_from` conversion (#547 Task 7b: was `Vec::try_into`
/// before the borrow conversion — same failure, different spelling).
#[test]
fn rejects_invalid_byte_length_for_vault_uuid() {
    let entries: Vec<(Value, Value)> = vec![
        (
            Value::Text(KEY_MANIFEST_VERSION.into()),
            Value::Integer(u64::from(MANIFEST_VERSION_V1).into()),
        ),
        // 15 bytes — short by one of the §4.2 declared 16.
        (
            Value::Text(KEY_VAULT_UUID.into()),
            Value::Bytes(vec![0x01; UUID_LEN - 1]),
        ),
        (
            Value::Text(KEY_FORMAT_VERSION.into()),
            Value::Integer(u64::from(FORMAT_VERSION_V1).into()),
        ),
        (
            Value::Text(KEY_SUITE_ID.into()),
            Value::Integer(u64::from(SUITE_ID_V1).into()),
        ),
        (
            Value::Text(KEY_OWNER_USER_UUID.into()),
            Value::Bytes([0x02; UUID_LEN].to_vec()),
        ),
        (
            Value::Text(KEY_VECTOR_CLOCK.into()),
            Value::Array(Vec::new()),
        ),
        (Value::Text(KEY_BLOCKS.into()), Value::Array(Vec::new())),
        (Value::Text(KEY_TRASH.into()), Value::Array(Vec::new())),
        (
            Value::Text(KEY_KDF_PARAMS.into()),
            kdf_params_to_value(&dummy_kdf_params()).expect("kdf_params"),
        ),
    ];
    let bytes = encode_canonical_map(&entries).expect("encode_canonical_map");

    let err = decode_manifest(&bytes).expect_err("15-byte vault_uuid must reject");
    assert!(
        matches!(
            err,
            ManifestError::InvalidByteLength {
                field: KEY_VAULT_UUID,
                expected: UUID_LEN,
                length: 15,
            }
        ),
        "expected InvalidByteLength {{ field: vault_uuid, expected: 16, length: 15 }}, got {err:?}"
    );
}

/// Regression: ensures `decode_manifest` rejects an integer field that
/// exceeds its declared range. `manifest_version` is declared `u8`;
/// here we encode a CBOR negative integer (major type 1) so
/// `take_u8`'s `0..=u8::MAX` range check fires `IntegerOutOfRange`.
#[test]
fn rejects_integer_out_of_range_for_manifest_version() {
    let entries: Vec<(Value, Value)> = vec![
        // -1 — outside [0, 255]. ciborium represents this as
        // major-type-1 integer; `take_integer_i128` returns -1 and
        // `take_u8`'s contains check fails.
        (
            Value::Text(KEY_MANIFEST_VERSION.into()),
            Value::Integer(ciborium::value::Integer::from(-1i64)),
        ),
        (
            Value::Text(KEY_VAULT_UUID.into()),
            Value::Bytes([0x01; UUID_LEN].to_vec()),
        ),
        (
            Value::Text(KEY_FORMAT_VERSION.into()),
            Value::Integer(u64::from(FORMAT_VERSION_V1).into()),
        ),
        (
            Value::Text(KEY_SUITE_ID.into()),
            Value::Integer(u64::from(SUITE_ID_V1).into()),
        ),
        (
            Value::Text(KEY_OWNER_USER_UUID.into()),
            Value::Bytes([0x02; UUID_LEN].to_vec()),
        ),
        (
            Value::Text(KEY_VECTOR_CLOCK.into()),
            Value::Array(Vec::new()),
        ),
        (Value::Text(KEY_BLOCKS.into()), Value::Array(Vec::new())),
        (Value::Text(KEY_TRASH.into()), Value::Array(Vec::new())),
        (
            Value::Text(KEY_KDF_PARAMS.into()),
            kdf_params_to_value(&dummy_kdf_params()).expect("kdf_params"),
        ),
    ];
    let bytes = encode_canonical_map(&entries).expect("encode_canonical_map");

    let err = decode_manifest(&bytes).expect_err("negative manifest_version must reject");
    assert!(
        matches!(
            err,
            ManifestError::IntegerOutOfRange {
                field: KEY_MANIFEST_VERSION,
                value: -1,
            }
        ),
        "expected IntegerOutOfRange {{ field: manifest_version, value: -1 }}, got {err:?}"
    );
}

/// Regression: ensures `decode_manifest` surfaces a typed `CborDecode`
/// error (with a classified [`CborFault`] payload, #474) when `ciborium`
/// itself can't parse the input bytes. Pins that the
/// `ciborium::de::Error → ManifestError` adaptation at the top of
/// `decode_manifest` is wired correctly — without this, a parse error
/// inside the manifest layer could collapse into a panic or a different
/// error variant on a future refactor.
#[test]
fn rejects_cbor_garbage() {
    // 16 bytes of 0xff — not a valid CBOR head byte for any major
    // type that decodes to a complete value (0xff is the indefinite-
    // length break, illegal at the top level).
    let bytes = [0xffu8; 16];
    let err = decode_manifest(&bytes).expect_err("garbage bytes must fail to parse");
    // CborDecode carries a data-free CborFault (not the upstream ciborium
    // message, #474), so a wildcard match is still the right granularity
    // here — this test pins the variant, not the classification.
    assert!(
        matches!(err, ManifestError::CborDecode(_)),
        "expected CborDecode(_), got {err:?}"
    );
}

// ---- Binary header encode/decode (§4.1) ------------------------------
//
// The header is the 42-byte AAD prefix that wraps the AEAD body. Every
// negative test below pins one §4.1 invariant; the round-trip and
// tamper tests pin the AAD-binding property (a tampered header
// invalidates the Poly1305 tag).

/// Pinned 32-byte test IBK. The `Sensitive` wrapper zeroizes on drop,
/// so each test gets a fresh instance — we don't share one across
/// tests. Same fixture style as PR-A's block.rs tests.
fn test_ibk(byte: u8) -> AeadKey {
    Sensitive::new([byte; 32])
}

fn test_nonce() -> AeadNonce {
    // Deterministic 24-byte nonce for fixture stability. NOT
    // representative of production: real callers must source nonces
    // from `crypto::rand` (or pinned KAT inputs in tests).
    let mut n = [0u8; 24];
    for (i, b) in n.iter_mut().enumerate() {
        *b = i as u8;
    }
    n
}

fn fixed_manifest_header() -> ManifestHeader {
    ManifestHeader {
        vault_uuid: [0x42; UUID_LEN],
        created_at_ms: 1_714_060_800_000,
        last_mod_ms: 1_714_060_900_000,
    }
}

#[test]
fn header_encode_round_trips() {
    let h = fixed_manifest_header();
    let bytes = h.encode();
    assert_eq!(
        bytes.len(),
        MANIFEST_HEADER_LEN,
        "encoded header is 42 bytes"
    );
    assert_eq!(bytes.len(), 42, "MANIFEST_HEADER_LEN spec value");

    // Pin the constant prefix. magic = "SECR" big-endian.
    assert_eq!(&bytes[0..4], b"SECR");
    // format_version 0x0001
    assert_eq!(&bytes[4..6], &[0x00, 0x01]);
    // suite_id 0x0001
    assert_eq!(&bytes[6..8], &[0x00, 0x01]);
    // file_kind 0x0002 (manifest)
    assert_eq!(&bytes[8..10], &[0x00, 0x02]);

    let (decoded, tail) = ManifestHeader::decode(&bytes).expect("decode round-trip");
    assert!(tail.is_empty(), "exact-length input leaves no tail");
    assert_eq!(decoded, h, "header round-trips");
}

#[test]
fn header_decode_returns_tail() {
    // Decoder leaves any post-header bytes as the returned tail so a
    // future ManifestFile decoder (Task 7) can keep parsing.
    let h = fixed_manifest_header();
    let mut buf = h.encode().to_vec();
    buf.extend_from_slice(&[0xab, 0xcd, 0xef]);
    let (decoded, tail) = ManifestHeader::decode(&buf).expect("decode with trailer");
    assert_eq!(decoded, h);
    assert_eq!(tail, &[0xab, 0xcd, 0xef]);
}

#[test]
fn header_decode_rejects_bad_magic() {
    let mut bytes = [0u8; MANIFEST_HEADER_LEN];
    // First 4 bytes deliberately wrong; rest doesn't matter — magic
    // is checked first.
    let err = ManifestHeader::decode(&bytes).expect_err("bad magic must reject");
    assert!(
        matches!(err, ManifestError::BadMagic { expected, got }
            if expected == MAGIC && got == 0),
        "expected BadMagic with expected=MAGIC and got=0, got {err:?}"
    );
    // Also try a non-zero wrong magic to make sure the comparison is
    // structural, not just zero-vs-nonzero.
    bytes[0..4].copy_from_slice(&0xdead_beef_u32.to_be_bytes());
    let err = ManifestHeader::decode(&bytes).expect_err("bad magic must reject");
    assert!(
        matches!(err, ManifestError::BadMagic { expected, got }
            if expected == MAGIC && got == 0xdead_beef),
        "expected BadMagic with got=0xdeadbeef, got {err:?}"
    );
}

#[test]
fn header_decode_rejects_wrong_format_version() {
    let mut bytes = fixed_manifest_header().encode();
    // format_version lives at offset 4..6 (after magic).
    bytes[4..6].copy_from_slice(&0x0002_u16.to_be_bytes());
    let err = ManifestHeader::decode(&bytes).expect_err("non-v1 format_version must reject");
    assert!(
        matches!(err, ManifestError::UnsupportedFormatVersion(2)),
        "expected UnsupportedFormatVersion(2), got {err:?}"
    );
}

#[test]
fn header_decode_rejects_wrong_suite_id() {
    let mut bytes = fixed_manifest_header().encode();
    // suite_id lives at offset 6..8.
    bytes[6..8].copy_from_slice(&0x0099_u16.to_be_bytes());
    let err = ManifestHeader::decode(&bytes).expect_err("non-v1 suite_id must reject");
    assert!(
        matches!(err, ManifestError::UnsupportedSuiteId(0x99)),
        "expected UnsupportedSuiteId(0x99), got {err:?}"
    );
}

#[test]
fn header_decode_rejects_wrong_file_kind() {
    let mut bytes = fixed_manifest_header().encode();
    // file_kind lives at offset 8..10. 0x0001 is the identity-bundle
    // file kind; rejecting it here pins the §4.1 cross-file-kind
    // anti-substitution check at the binary layer (the AEAD AAD also
    // catches it later, but we'd rather fail with a typed error than
    // a generic AEAD failure when the file-kind alone is enough to
    // disambiguate).
    bytes[8..10].copy_from_slice(&0x0001_u16.to_be_bytes());
    let err = ManifestHeader::decode(&bytes).expect_err("non-manifest file_kind must reject");
    assert!(
        matches!(
            err,
            ManifestError::UnsupportedFileKind {
                expected: FILE_KIND_MANIFEST,
                got: 0x0001
            }
        ),
        "expected UnsupportedFileKind {{ expected: 0x0002, got: 0x0001 }}, got {err:?}"
    );
}

#[test]
fn header_decode_rejects_truncation() {
    // 41 bytes — one short of the §4.1 header length.
    let bytes = [0u8; MANIFEST_HEADER_LEN - 1];
    let err = ManifestHeader::decode(&bytes).expect_err("41 bytes must reject as truncated");
    assert!(
        matches!(
            err,
            ManifestError::HeaderTruncated {
                need: MANIFEST_HEADER_LEN,
                got: 41
            }
        ),
        "expected HeaderTruncated {{ need: 42, got: 41 }}, got {err:?}"
    );

    // Also: empty input.
    let err = ManifestHeader::decode(&[]).expect_err("empty input must reject as truncated");
    assert!(
        matches!(
            err,
            ManifestError::HeaderTruncated {
                need: MANIFEST_HEADER_LEN,
                got: 0
            }
        ),
        "expected HeaderTruncated with got=0, got {err:?}"
    );
}

// ---- AEAD body encrypt/decrypt round-trip ---------------------------

#[test]
fn encrypt_decrypt_body_round_trip() {
    let m = populated_manifest();
    let manifest_bytes = encode_manifest(&m).expect("encode manifest body");
    let header = fixed_manifest_header();
    let ibk = test_ibk(0x00);
    let nonce = test_nonce();

    let ct_with_tag =
        encrypt_manifest_body(&header, &manifest_bytes, &ibk, &nonce).expect("encrypt body");
    // The tag is appended to the ciphertext per crypto::aead's contract.
    assert_eq!(
        ct_with_tag.len(),
        manifest_bytes.len() + AEAD_TAG_LEN,
        "ct||tag length is plaintext+16"
    );

    let ibk2 = test_ibk(0x00);
    let recovered =
        decrypt_manifest_body(&header, &ct_with_tag, &ibk2, &nonce).expect("decrypt body");

    // populated_manifest's input arrays are non-canonical-order; the
    // decoded copy is in canonical order. Use the same sort-then-compare
    // discipline as the existing `roundtrip_populated_manifest` test.
    let mut m_sorted = m.clone();
    m_sorted.vector_clock.sort_by_key(|a| a.device_uuid);
    m_sorted.blocks.sort_by_key(|a| a.block_uuid);
    for blk in &mut m_sorted.blocks {
        blk.recipients.sort();
        blk.vector_clock_summary.sort_by_key(|a| a.device_uuid);
    }
    m_sorted.trash.sort_by_key(|a| a.block_uuid);
    assert_eq!(recovered, m_sorted, "decrypted manifest matches original");
}

#[test]
fn tamper_header_breaks_aead() {
    // Central §4.1 spec property: the header is bound into the AEAD
    // tag via AAD, so a single-byte flip in the header invalidates
    // the tag on decrypt.
    let m = minimal_manifest();
    let manifest_bytes = encode_manifest(&m).expect("encode");
    let header = fixed_manifest_header();
    let ibk = test_ibk(0x00);
    let nonce = test_nonce();
    let ct_with_tag =
        encrypt_manifest_body(&header, &manifest_bytes, &ibk, &nonce).expect("encrypt");

    // Tamper #1: flip a byte in vault_uuid.
    let mut tampered = header;
    tampered.vault_uuid[0] ^= 0xff;
    let err = decrypt_manifest_body(&tampered, &ct_with_tag, &ibk, &nonce)
        .expect_err("tampered header must fail AEAD");
    assert!(
        matches!(err, ManifestError::AeadFailure),
        "expected AeadFailure (tampered vault_uuid), got {err:?}"
    );

    // Tamper #2: change last_mod_ms.
    let tampered = ManifestHeader {
        last_mod_ms: header.last_mod_ms.wrapping_add(1),
        ..header
    };
    let err = decrypt_manifest_body(&tampered, &ct_with_tag, &ibk, &nonce)
        .expect_err("tampered last_mod_ms must fail AEAD");
    assert!(
        matches!(err, ManifestError::AeadFailure),
        "expected AeadFailure (tampered last_mod_ms), got {err:?}"
    );
}

#[test]
fn tamper_ct_breaks_aead() {
    let m = minimal_manifest();
    let manifest_bytes = encode_manifest(&m).expect("encode");
    let header = fixed_manifest_header();
    let ibk = test_ibk(0x00);
    let nonce = test_nonce();
    let mut ct_with_tag =
        encrypt_manifest_body(&header, &manifest_bytes, &ibk, &nonce).expect("encrypt");

    // Flip a byte deep inside the ciphertext (not the tag region).
    // `manifest_bytes.len()` would be the start of the tag; pick
    // somewhere safely before that.
    ct_with_tag[2] ^= 0xff;
    let err = decrypt_manifest_body(&header, &ct_with_tag, &ibk, &nonce)
        .expect_err("tampered ct must fail AEAD");
    assert!(
        matches!(err, ManifestError::AeadFailure),
        "expected AeadFailure on flipped ciphertext byte, got {err:?}"
    );
}

#[test]
fn wrong_ibk_breaks_aead() {
    let m = minimal_manifest();
    let manifest_bytes = encode_manifest(&m).expect("encode");
    let header = fixed_manifest_header();
    let ibk = test_ibk(0x00);
    let nonce = test_nonce();
    let ct_with_tag =
        encrypt_manifest_body(&header, &manifest_bytes, &ibk, &nonce).expect("encrypt");

    let wrong_ibk = test_ibk(0xff);
    let err = decrypt_manifest_body(&header, &ct_with_tag, &wrong_ibk, &nonce)
        .expect_err("wrong IBK must fail AEAD");
    assert!(
        matches!(err, ManifestError::AeadFailure),
        "expected AeadFailure under wrong IBK, got {err:?}"
    );
}

// ---- ManifestFile envelope encode/decode (§4.1) ----------------------

/// Build a deterministic, fully-populated `ManifestFile` for the
/// envelope-level tests: pinned header, pinned AEAD ciphertext and
/// tag, pinned author fingerprint, and a length-correct (but
/// fake-content) ML-DSA-65 signature. The "fake content" makes the
/// envelope tests truly orthogonal to signature verification — the
/// signature is just bytes here. The sign/verify tests below use
/// real `sign_manifest` output.
fn fixture_manifest_file() -> ManifestFile {
    ManifestFile {
        header: fixed_manifest_header(),
        aead_nonce: test_nonce(),
        aead_ct: vec![0x77; 32],
        aead_tag: [0x88; AEAD_TAG_LEN],
        author_fingerprint: [0xa5; 16],
        sig_ed: [0x44; ED25519_SIG_LEN],
        sig_pq: MlDsa65Sig::from_bytes(&vec![0x55; ML_DSA_65_SIG_LEN])
            .expect("ML-DSA-65 sig bytes"),
    }
}

#[test]
fn manifest_file_encode_decode_round_trip() {
    let file = fixture_manifest_file();
    let bytes = encode_manifest_file(&file).expect("encode_manifest_file");
    let decoded = decode_manifest_file(&bytes).expect("decode_manifest_file");
    assert_eq!(decoded, file, "ManifestFile round-trips bit-identically");
    let bytes_again = encode_manifest_file(&decoded).expect("re-encode_manifest_file");
    assert_eq!(bytes, bytes_again, "encode is deterministic");
}

#[test]
fn encode_decode_pinned_byte_layout() {
    // Spec arithmetic for §4.1:
    //   header(42) + aead_nonce(24) + aead_ct_len(4) + aead_ct(N)
    //   + aead_tag(16) + author_fingerprint(16) + sig_ed_len(2)
    //   + sig_ed(64) + sig_pq_len(2) + sig_pq(3309)
    let file = fixture_manifest_file();
    let bytes = encode_manifest_file(&file).expect("encode");
    let ct_len = file.aead_ct.len();
    let expected = 42 + 24 + 4 + ct_len + 16 + 16 + 2 + 64 + 2 + 3309;
    assert_eq!(
        bytes.len(),
        expected,
        "encoded length matches §4.1 spec arithmetic"
    );

    // Spot-check: sig_ed_len at offset (42+24+4+ct_len+16+16) = 64.
    let sig_ed_len_offset = 42 + 24 + 4 + ct_len + 16 + 16;
    let sig_ed_len_bytes = [bytes[sig_ed_len_offset], bytes[sig_ed_len_offset + 1]];
    assert_eq!(
        u16::from_be_bytes(sig_ed_len_bytes),
        64,
        "sig_ed_len encodes 64 at the spec offset"
    );

    // Spot-check: aead_ct_len is u32 BE at offset 42+24=66.
    let ct_len_offset = 42 + 24;
    let ct_len_bytes = [
        bytes[ct_len_offset],
        bytes[ct_len_offset + 1],
        bytes[ct_len_offset + 2],
        bytes[ct_len_offset + 3],
    ];
    assert_eq!(
        u32::from_be_bytes(ct_len_bytes) as usize,
        ct_len,
        "aead_ct_len encodes the actual aead_ct length"
    );

    // Spot-check: sig_pq_len at offset (sig_ed_len_offset+2+64) = 3309.
    let sig_pq_len_offset = sig_ed_len_offset + 2 + 64;
    let sig_pq_len_bytes = [bytes[sig_pq_len_offset], bytes[sig_pq_len_offset + 1]];
    assert_eq!(
        u16::from_be_bytes(sig_pq_len_bytes),
        3309,
        "sig_pq_len encodes 3309 at the spec offset"
    );
}

#[test]
fn decode_rejects_sig_ed_wrong_length() {
    let file = fixture_manifest_file();
    let mut bytes = encode_manifest_file(&file).expect("encode");
    let ct_len = file.aead_ct.len();
    // sig_ed_len lives at offset (42+24+4+ct_len+16+16); flip it from
    // 64 to 63.
    let off = 42 + 24 + 4 + ct_len + 16 + 16;
    bytes[off..off + 2].copy_from_slice(&63u16.to_be_bytes());
    let err = decode_manifest_file(&bytes).expect_err("sig_ed_len=63 must reject");
    assert!(
        matches!(
            err,
            ManifestError::SigEdWrongLength {
                expected: 64,
                got: 63
            }
        ),
        "expected SigEdWrongLength {{ expected: 64, got: 63 }}, got {err:?}"
    );
}

#[test]
fn decode_rejects_sig_pq_wrong_length() {
    let file = fixture_manifest_file();
    let mut bytes = encode_manifest_file(&file).expect("encode");
    let ct_len = file.aead_ct.len();
    // sig_pq_len lives at offset (42+24+4+ct_len+16+16+2+64).
    let off = 42 + 24 + 4 + ct_len + 16 + 16 + 2 + 64;
    bytes[off..off + 2].copy_from_slice(&3308u16.to_be_bytes());
    let err = decode_manifest_file(&bytes).expect_err("sig_pq_len=3308 must reject");
    assert!(
        matches!(
            err,
            ManifestError::SigPqWrongLength {
                expected: 3309,
                got: 3308
            }
        ),
        "expected SigPqWrongLength {{ expected: 3309, got: 3308 }}, got {err:?}"
    );
}

#[test]
fn decode_rejects_aead_ct_len_overflow() {
    // Encode a valid file, then bump aead_ct_len past the available
    // remaining body. Decoder must surface AeadCtLenMismatch (or, if
    // the declared length pushes the suffix-reservation impossible,
    // SectionTruncated at "aead_ct"). We pin the AeadCtLenMismatch
    // case here: declared = ct_len + 100, plenty of fixed-suffix
    // bytes still present.
    let file = fixture_manifest_file();
    let mut bytes = encode_manifest_file(&file).expect("encode");
    let original_ct_len = file.aead_ct.len() as u32;
    // aead_ct_len lives at offset 42+24=66.
    let off = 42 + 24;
    let bumped = original_ct_len + 100;
    bytes[off..off + 4].copy_from_slice(&bumped.to_be_bytes());
    let err = decode_manifest_file(&bytes).expect_err("oversized aead_ct_len must reject");
    assert!(
        matches!(
            err,
            ManifestError::AeadCtLenMismatch {
                declared,
                remaining,
            } if declared == bumped && remaining == original_ct_len as usize
        ),
        "expected AeadCtLenMismatch, got {err:?}"
    );
}

#[test]
fn decode_rejects_trailing_bytes() {
    let file = fixture_manifest_file();
    let mut bytes = encode_manifest_file(&file).expect("encode");
    bytes.push(0x99);
    let err = decode_manifest_file(&bytes).expect_err("trailing junk byte must reject");
    assert!(
        matches!(err, ManifestError::TrailingBytes(1)),
        "expected TrailingBytes(1), got {err:?}"
    );
}

#[test]
fn decode_rejects_truncation_at_header() {
    // 41 bytes — one short of the §4.1 header.
    let bytes = [0u8; MANIFEST_HEADER_LEN - 1];
    let err = decode_manifest_file(&bytes).expect_err("41 bytes must reject as truncated");
    assert!(
        matches!(
            err,
            ManifestError::HeaderTruncated {
                need: MANIFEST_HEADER_LEN,
                got: 41
            }
        ),
        "expected HeaderTruncated, got {err:?}"
    );
}

#[test]
fn decode_rejects_truncation_at_aead_section() {
    // Header (42) plus 23 of the 24 nonce bytes.
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&fixed_manifest_header().encode());
    bytes.extend_from_slice(&[0u8; 23]);
    let err =
        decode_manifest_file(&bytes).expect_err("header + 23 bytes must reject as nonce-truncated");
    assert!(
        matches!(
            err,
            ManifestError::SectionTruncated {
                section: "aead_nonce",
                need: 24,
                got: 23
            }
        ),
        "expected SectionTruncated at aead_nonce, got {err:?}"
    );
}

#[test]
fn decode_rejects_truncation_at_signature_suffix() {
    // Header (42) + nonce (24) + aead_ct_len (4) + nothing else —
    // the fixed-size suffix needs 16 (tag) + 16 (fp) + 2 + 64 + 2 +
    // 3309 = 3409 bytes; we provide 0 so the decoder should reject
    // truncated at the aead_ct boundary.
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&fixed_manifest_header().encode());
    bytes.extend_from_slice(&[0u8; 24]); // nonce
    bytes.extend_from_slice(&0u32.to_be_bytes()); // aead_ct_len = 0
                                                  // No more bytes — the fixed suffix-after-ct (3409) is missing.
    let err = decode_manifest_file(&bytes).expect_err("missing signature suffix must reject");
    assert!(
        matches!(
            err,
            ManifestError::SectionTruncated {
                section: "aead_ct",
                need,
                got: 0,
            } if need == AEAD_TAG_LEN + 16 + 2 + 64 + 2 + ML_DSA_65_SIG_LEN
        ),
        "expected SectionTruncated at aead_ct (need=fixed-suffix, got=0), got {err:?}"
    );
}

// ---- Sign / verify (§4.1 / §8) ---------------------------------------

/// Build a fresh hybrid keypair from a pinned ChaCha20Rng seed.
/// Same pattern as block.rs's signing-key fixtures.
fn fixture_hybrid_keypair(
    seed: u8,
) -> (Ed25519Secret, Ed25519Public, MlDsa65Secret, MlDsa65Public) {
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    let mut ed_rng = ChaCha20Rng::from_seed([seed; 32]);
    let mut pq_rng = ChaCha20Rng::from_seed([seed.wrapping_add(1); 32]);
    let (sk_ed, pk_ed) = sig::generate_ed25519(&mut ed_rng);
    let (sk_pq, pk_pq) = sig::generate_ml_dsa_65(&mut pq_rng);
    (sk_ed, pk_ed, sk_pq, pk_pq)
}

#[test]
fn sign_then_verify_round_trips() {
    let body = populated_manifest();
    let header = fixed_manifest_header();
    let ibk = test_ibk(0x00);
    let nonce = test_nonce();
    let author: Fingerprint = [0xa5; 16];
    let (sk_ed, pk_ed, sk_pq, pk_pq) = fixture_hybrid_keypair(0x10);

    let file =
        sign_manifest(header, &body, &ibk, &nonce, author, &sk_ed, &sk_pq).expect("sign_manifest");
    verify_manifest(&file, &pk_ed, &pk_pq).expect("verify_manifest");
}

#[test]
fn verify_rejects_tampered_aead_ct() {
    let body = minimal_manifest();
    let header = fixed_manifest_header();
    let ibk = test_ibk(0x00);
    let nonce = test_nonce();
    let author: Fingerprint = [0xa5; 16];
    let (sk_ed, pk_ed, sk_pq, pk_pq) = fixture_hybrid_keypair(0x20);

    let mut file =
        sign_manifest(header, &body, &ibk, &nonce, author, &sk_ed, &sk_pq).expect("sign_manifest");
    // Flip a byte deep inside the ciphertext.
    if file.aead_ct.is_empty() {
        // minimal_manifest's CBOR is non-empty in practice, but guard
        // against a future trim.
        file.aead_ct.push(0x00);
    }
    file.aead_ct[0] ^= 0xff;
    let err =
        verify_manifest(&file, &pk_ed, &pk_pq).expect_err("tampered aead_ct must fail verify");
    assert!(
        matches!(
            err,
            ManifestError::Ed25519SignatureInvalid | ManifestError::MlDsa65SignatureInvalid
        ),
        "expected hybrid verify failure, got {err:?}"
    );
}

#[test]
fn verify_rejects_tampered_header() {
    let body = minimal_manifest();
    let header = fixed_manifest_header();
    let ibk = test_ibk(0x00);
    let nonce = test_nonce();
    let author: Fingerprint = [0xa5; 16];
    let (sk_ed, pk_ed, sk_pq, pk_pq) = fixture_hybrid_keypair(0x30);

    let mut file =
        sign_manifest(header, &body, &ibk, &nonce, author, &sk_ed, &sk_pq).expect("sign_manifest");
    // Mutate last_mod_ms — the header is part of the signed bytes.
    file.header.last_mod_ms = file.header.last_mod_ms.wrapping_add(1);
    let err = verify_manifest(&file, &pk_ed, &pk_pq).expect_err("tampered header must fail verify");
    assert!(
        matches!(
            err,
            ManifestError::Ed25519SignatureInvalid | ManifestError::MlDsa65SignatureInvalid
        ),
        "expected hybrid verify failure on header tamper, got {err:?}"
    );
}

#[test]
fn verify_rejects_wrong_pk() {
    let body = minimal_manifest();
    let header = fixed_manifest_header();
    let ibk = test_ibk(0x00);
    let nonce = test_nonce();
    let author: Fingerprint = [0xa5; 16];
    let (sk_ed, _pk_ed, sk_pq, _pk_pq) = fixture_hybrid_keypair(0x40);
    let (_sk_ed2, pk_ed2, _sk_pq2, pk_pq2) = fixture_hybrid_keypair(0x50);

    let file =
        sign_manifest(header, &body, &ibk, &nonce, author, &sk_ed, &sk_pq).expect("sign_manifest");
    // Verify with a *different* keypair's public keys.
    let err = verify_manifest(&file, &pk_ed2, &pk_pq2).expect_err("wrong pk must fail verify");
    assert!(
        matches!(
            err,
            ManifestError::Ed25519SignatureInvalid | ManifestError::MlDsa65SignatureInvalid
        ),
        "expected hybrid verify failure under wrong pk, got {err:?}"
    );
}

// (Group C) Pin the §8 signed-range invariants for the two regions
// exercised only stochastically by proptest property G:
// `aead_nonce` (24 bytes) and `aead_tag` (16 bytes). Both are inside
// the §8 signed-message range (magic..aead_tag inclusive — see
// `signed_message_bytes`), so a deterministic single-byte flip MUST
// fail signature verification. Companion to the existing
// `verify_rejects_tampered_aead_ct` / `verify_rejects_tampered_header`
// tests; this closes the §8 coverage to all four mutable regions.

/// Regression: ensures `aead_nonce` is inside the §8 signed range.
/// If a future signed_message_bytes refactor accidentally drops the
/// nonce from the signed prefix, this test catches it (verify would
/// suddenly accept a flipped-nonce file).
#[test]
fn tamper_aead_nonce_breaks_signature() {
    let body = minimal_manifest();
    let header = fixed_manifest_header();
    let ibk = test_ibk(0x00);
    let nonce = test_nonce();
    let author: Fingerprint = [0xa5; 16];
    let (sk_ed, pk_ed, sk_pq, pk_pq) = fixture_hybrid_keypair(0x70);

    let mut file =
        sign_manifest(header, &body, &ibk, &nonce, author, &sk_ed, &sk_pq).expect("sign_manifest");
    // Flip a byte in the nonce. Pick the middle to avoid any
    // boundary-mistake regressions where the signed slice off-by-ones
    // either edge.
    file.aead_nonce[12] ^= 0x01;
    let err =
        verify_manifest(&file, &pk_ed, &pk_pq).expect_err("tampered aead_nonce must fail verify");
    assert!(
        matches!(
            err,
            ManifestError::Ed25519SignatureInvalid | ManifestError::MlDsa65SignatureInvalid
        ),
        "expected hybrid verify failure on aead_nonce tamper, got {err:?}"
    );
}

/// Regression: ensures `aead_tag` is inside the §8 signed range.
/// If a future signed_message_bytes refactor accidentally truncates
/// the signed prefix at aead_ct (excluding the tag), this test
/// catches it. The §8 spec range is "magic..aead_tag inclusive" —
/// a flipped tag byte must still fail the signature even though
/// AEAD verification (which would also catch it) is sequenced AFTER
/// the verify per the verify-before-decrypt discipline.
#[test]
fn tamper_aead_tag_breaks_signature() {
    let body = minimal_manifest();
    let header = fixed_manifest_header();
    let ibk = test_ibk(0x00);
    let nonce = test_nonce();
    let author: Fingerprint = [0xa5; 16];
    let (sk_ed, pk_ed, sk_pq, pk_pq) = fixture_hybrid_keypair(0x80);

    let mut file =
        sign_manifest(header, &body, &ibk, &nonce, author, &sk_ed, &sk_pq).expect("sign_manifest");
    // Flip a byte in the AEAD tag. Tag is fixed-size (16 bytes), so
    // any index 0..AEAD_TAG_LEN works; pick the first.
    file.aead_tag[0] ^= 0x01;
    let err =
        verify_manifest(&file, &pk_ed, &pk_pq).expect_err("tampered aead_tag must fail verify");
    assert!(
        matches!(
            err,
            ManifestError::Ed25519SignatureInvalid | ManifestError::MlDsa65SignatureInvalid
        ),
        "expected hybrid verify failure on aead_tag tamper, got {err:?}"
    );
}

#[test]
fn sign_then_decrypt_round_trips() {
    // Full pipeline: sign → verify → decrypt → compare body.
    let body = populated_manifest();
    let header = fixed_manifest_header();
    let ibk = test_ibk(0x00);
    let nonce = test_nonce();
    let author: Fingerprint = [0xa5; 16];
    let (sk_ed, pk_ed, sk_pq, pk_pq) = fixture_hybrid_keypair(0x60);

    let file =
        sign_manifest(header, &body, &ibk, &nonce, author, &sk_ed, &sk_pq).expect("sign_manifest");

    // Verify before decrypt — orchestrator-style sequencing.
    verify_manifest(&file, &pk_ed, &pk_pq).expect("verify_manifest");

    // Reconstruct ct_with_tag = aead_ct ++ aead_tag for the AEAD API.
    let mut ct_with_tag = Vec::with_capacity(file.aead_ct.len() + AEAD_TAG_LEN);
    ct_with_tag.extend_from_slice(&file.aead_ct);
    ct_with_tag.extend_from_slice(&file.aead_tag);
    let recovered = decrypt_manifest_body(&file.header, &ct_with_tag, &ibk, &nonce)
        .expect("decrypt_manifest_body");

    // populated_manifest's input arrays are non-canonical-order; the
    // decoded copy is in canonical order. Use the same sort-then-compare
    // discipline as the existing `roundtrip_populated_manifest` test.
    let mut body_sorted = body.clone();
    body_sorted.vector_clock.sort_by_key(|a| a.device_uuid);
    body_sorted.blocks.sort_by_key(|a| a.block_uuid);
    for blk in &mut body_sorted.blocks {
        blk.recipients.sort();
        blk.vector_clock_summary.sort_by_key(|a| a.device_uuid);
    }
    body_sorted.trash.sort_by_key(|a| a.block_uuid);
    assert_eq!(
        recovered, body_sorted,
        "decrypted manifest matches original"
    );
}

// ---- §10 rollback resistance --------------------------------------

/// Tiny construction shorthand for the rollback test matrix.
fn vc(uuid_byte: u8, counter: u64) -> VectorClockEntry {
    VectorClockEntry {
        device_uuid: [uuid_byte; 16],
        counter,
    }
}

// (9) Spec-discipline lodestone: `is_rollback` must be defined on
//     the *logical* clock (a map from device_uuid → counter), not on
//     the slice. A consumer that confuses ordering with semantics
//     will silently mis-classify reorderings of the very same clock.
//     Pin two pairs that differ only in slice order.
#[test]
fn order_independence() {
    let local_a = vec![vc(0x01, 5), vc(0x02, 3), vc(0x03, 7)];
    let local_b = vec![vc(0x03, 7), vc(0x01, 5), vc(0x02, 3)];

    let incoming_a = vec![vc(0x01, 4), vc(0x02, 3), vc(0x03, 7)];
    let incoming_b = vec![vc(0x02, 3), vc(0x03, 7), vc(0x01, 4)];

    // Same logical clocks; differing slice orders. The boolean
    // verdict must not move with the order.
    assert_eq!(
        is_rollback(&local_a, &incoming_a),
        is_rollback(&local_b, &incoming_b),
        "is_rollback must be order-independent in both arguments"
    );

    // And likewise for the equal-clocks case in both directions.
    let eq_a = vec![vc(0x01, 5), vc(0x02, 3)];
    let eq_b = vec![vc(0x02, 3), vc(0x01, 5)];
    assert_eq!(
        is_rollback(&eq_a, &eq_b),
        is_rollback(&eq_b, &eq_a),
        "equal logical clocks reordered must compare identically"
    );
}

#[test]
fn equal_clocks_not_rollback() {
    let clock = vec![vc(0x01, 5), vc(0x02, 3)];
    assert!(
        !is_rollback(&clock, &clock),
        "identical clocks are not a rollback"
    );
}

#[test]
fn incoming_dominates_not_rollback() {
    let local = vec![vc(0x01, 5), vc(0x02, 3)];
    let incoming = vec![vc(0x01, 6), vc(0x02, 3)]; // ≥ everywhere, > on D1
    assert!(
        !is_rollback(&local, &incoming),
        "incoming strictly dominates local — accept, not rollback"
    );
}

#[test]
fn incoming_strictly_dominated_is_rollback() {
    let local = vec![vc(0x01, 5), vc(0x02, 3)];
    let incoming = vec![vc(0x01, 4), vc(0x02, 3)]; // ≤ everywhere, < on D1
    assert!(
        is_rollback(&local, &incoming),
        "incoming strictly dominated by local — rollback"
    );
}

#[test]
fn incoming_introduces_new_device_not_rollback() {
    let local = vec![vc(0x01, 5)];
    // incoming carries D1 unchanged AND introduces D2 with counter > 0.
    // That's "incoming dominates" (D2's counter is implicitly 0 in local).
    let incoming = vec![vc(0x01, 5), vc(0x02, 1)];
    assert!(
        !is_rollback(&local, &incoming),
        "incoming introducing a new device dominates — not a rollback"
    );
}

#[test]
fn local_introduces_device_incoming_lacks_is_rollback() {
    // local has D1 and D2; incoming has only D1 at the same counter.
    // D2 in incoming is implicitly 0, so any_strictly_less fires.
    // No counter in incoming is strictly more → rollback.
    let local = vec![vc(0x01, 5), vc(0x02, 2)];
    let incoming = vec![vc(0x01, 5)];
    assert!(
        is_rollback(&local, &incoming),
        "incoming missing a device that local has at counter > 0 — rollback"
    );
}

#[test]
fn concurrent_not_rollback() {
    // D1 higher in incoming, D2 higher in local → concurrent.
    let local = vec![vc(0x01, 5), vc(0x02, 4)];
    let incoming = vec![vc(0x01, 6), vc(0x02, 3)];
    assert!(
        !is_rollback(&local, &incoming),
        "concurrent clocks are not a rollback per se — caller will merge"
    );
}

#[test]
fn empty_incoming_against_nonempty_local_is_rollback() {
    let local = vec![vc(0x01, 1)];
    let incoming: Vec<VectorClockEntry> = Vec::new();
    assert!(
        is_rollback(&local, &incoming),
        "empty incoming against local with counter > 0 — rollback"
    );
}

#[test]
fn empty_local_against_any_incoming_not_rollback() {
    let local: Vec<VectorClockEntry> = Vec::new();
    let incoming = vec![vc(0x01, 5), vc(0x02, 3)];
    assert!(
        !is_rollback(&local, &incoming),
        "empty local — any incoming dominates (or is also empty)"
    );

    // And the both-empty edge: equal, not a rollback.
    let empty: Vec<VectorClockEntry> = Vec::new();
    assert!(
        !is_rollback(&empty, &empty),
        "both empty — equal, not a rollback"
    );
}
