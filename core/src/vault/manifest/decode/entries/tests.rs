//! Unit tests for the manifest per-array / per-entry parsers (§4.2).
//!
//! Moved verbatim out of the pre-split `manifest/tests.rs` (#564); shared
//! fixtures live in [`crate::vault::manifest::test_support`].
//!
//! Each test below pins one array parser's duplicate-key rejection.
//!
//! **The three duplicate-VALUE tests build their bodies by surgery, not
//! by the encoder (#600).** They used to hand `encode_manifest` a
//! `Manifest` carrying the repeat, which worked only while the encoder
//! declined to enforce §4.2's writer half — the defect #600 closed. They
//! now encode a CONFORMANT manifest and plant the repeat in the bytes
//! with [`copy_entry_field`], which is how such a body would actually
//! reach a reader: off a disk or a peer, never out of this crate's own
//! encoder.

use crate::vault::manifest::test_support::{
    copy_entry_field, dummy_kdf_params, expect_rejected, unexpected, BodyArray,
};
use crate::vault::manifest::{
    decode_manifest, encode_manifest, Manifest, FORMAT_VERSION_V1, MANIFEST_VERSION_V1, SUITE_ID_V1,
};

use super::*;

// `BTreeMap` used to reach this module through `use super::*`, because the
// parser above declared its `unknown` bag as a bare
// `BTreeMap<String, UnknownValue>`. #589 moved that behind
// `slot::UnknownBag`, so the parent no longer imports it and this module,
// which still builds expected bags by hand, imports it directly.
use std::collections::BTreeMap;

#[test]
fn rejects_duplicate_device_uuid_in_vector_clock() {
    // Two DISTINCT vector_clock entries, encoded conformantly, then the
    // repeat planted in the bytes: `encode_manifest` refuses to emit one
    // itself (#600), and a fixture only a non-conformant writer could
    // produce is the wrong fixture for a reader test anyway.
    let m = Manifest {
        manifest_version: MANIFEST_VERSION_V1,
        vault_uuid: [0x01; UUID_LEN],
        format_version: FORMAT_VERSION_V1,
        suite_id: SUITE_ID_V1,
        owner_user_uuid: [0x02; UUID_LEN],
        vector_clock: vec![
            VectorClockEntry {
                device_uuid: [0x33; UUID_LEN],
                counter: 1,
            },
            VectorClockEntry {
                device_uuid: [0x34; UUID_LEN],
                counter: 2,
            },
        ],
        blocks: Vec::new(),
        trash: Vec::new(),
        kdf_params: dummy_kdf_params(),
        unknown: BTreeMap::new(),
    };
    let conformant = encode_manifest(&m).expect("the distinct manifest encodes");
    let bytes = copy_entry_field(
        conformant.expose(),
        BodyArray::Top("vector_clock"),
        0,
        1,
        "device_uuid",
    );
    let err = expect_rejected(
        decode_manifest(&bytes),
        "duplicate device_uuid must be rejected on decode",
    );
    assert!(
        matches!(err, ManifestError::VectorClockDuplicateDevice),
        "expected VectorClockDuplicateDevice, got {err:?}"
    );
}

#[test]
fn rejects_duplicate_block_uuid() {
    // Distinct on the wire, repeated by surgery -- see the module doc.
    let make_block = |suffix: u8| BlockEntry {
        block_uuid: [0x76 + suffix; UUID_LEN],
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
    let conformant = encode_manifest(&m).expect("the distinct manifest encodes");
    let bytes = copy_entry_field(
        conformant.expose(),
        BodyArray::Top("blocks"),
        0,
        1,
        "block_uuid",
    );
    let err = expect_rejected(
        decode_manifest(&bytes),
        "duplicate block_uuid must be rejected on decode",
    );
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
    // Distinct on the wire, repeated by surgery -- see the module doc.
    let make_trash = |suffix: u8| TrashEntry {
        block_uuid: [0x87 + suffix; UUID_LEN],
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
    let conformant = encode_manifest(&m).expect("the distinct manifest encodes");
    let bytes = copy_entry_field(
        conformant.expose(),
        BodyArray::Top("trash"),
        0,
        1,
        "block_uuid",
    );
    let err = expect_rejected(
        decode_manifest(&bytes),
        "duplicate trash block_uuid must be rejected on decode",
    );
    assert!(
        matches!(err, ManifestError::DuplicateTrashUuid),
        "expected DuplicateTrashUuid, got {err:?}"
    );
}

// ---- #573: duplicate keys WITHIN one entry's own map ------------------
//
// The three tests above (`rejects_duplicate_device_uuid_in_vector_clock`,
// `rejects_duplicate_block_uuid`, `rejects_duplicate_trash_uuid`) are a
// DIFFERENT property: two distinct ARRAY ENTRIES sharing a value
// (`device_uuid`, `block_uuid`) in their otherwise-valid maps. What
// follows is a repeated MAP KEY inside a single entry's own map —
// `device_uuid` appearing twice inside one `vector_clock` entry, not two
// `vector_clock` entries sharing a `device_uuid`. Do not conflate the
// two; they exercise different code paths (`parse_vector_clock` /
// `parse_blocks` / `parse_trash`'s post-loop duplicate-VALUE sweep vs.
// each single-entry parser's own per-key loop).
//
// `build_manifest_map_with_overrides` (test_support.rs) cannot express
// this: it always emits empty `vector_clock`/`blocks`/`trash` arrays, so
// there is no entry map to inject a duplicate key into. These builders
// hand-construct one entry's `Value::Map` directly, the same way #568's
// `a_manifest_with_a_repeated_key_is_rejected` /
// `a_manifest_with_a_repeated_unknown_key_is_rejected`
// (`decode/tests.rs`) hand-construct the top-level map.

/// A valid `vector_clock` entry map with `repeated`'s key/value pair
/// appended a second time.
fn vector_clock_entry_value_with_duplicate(repeated: &'static str) -> Value {
    let mut entries: Vec<(Value, Value)> = vec![
        (
            Value::Text(KEY_DEVICE_UUID.into()),
            Value::Bytes([0x33; UUID_LEN].to_vec()),
        ),
        (Value::Text(KEY_COUNTER.into()), Value::Integer(7u64.into())),
    ];
    let dup = entries
        .iter()
        .find(|(k, _)| matches!(k, Value::Text(s) if s == repeated))
        .expect("repeated must be one of this entry's own keys")
        .clone();
    entries.push(dup);
    Value::Map(entries)
}

/// A valid `kdf_params` map with `repeated`'s key/value pair appended a
/// second time.
fn kdf_params_value_with_duplicate(repeated: &'static str) -> Value {
    let k = dummy_kdf_params();
    let mut entries: Vec<(Value, Value)> = vec![
        (
            Value::Text(KEY_MEMORY_KIB.into()),
            Value::Integer(u64::from(k.memory_kib).into()),
        ),
        (
            Value::Text(KEY_ITERATIONS.into()),
            Value::Integer(u64::from(k.iterations).into()),
        ),
        (
            Value::Text(KEY_PARALLELISM.into()),
            Value::Integer(u64::from(k.parallelism).into()),
        ),
        (Value::Text(KEY_SALT.into()), Value::Bytes(k.salt.to_vec())),
    ];
    let dup = entries
        .iter()
        .find(|(kk, _)| matches!(kk, Value::Text(s) if s == repeated))
        .expect("repeated must be one of this entry's own keys")
        .clone();
    entries.push(dup);
    Value::Map(entries)
}

/// A valid `blocks` entry map's eight known-key entries, in no particular
/// order — `parse_block_entry` dispatches by key text, not position.
fn block_entry_base_entries() -> Vec<(Value, Value)> {
    vec![
        (
            Value::Text(KEY_BLOCK_UUID.into()),
            Value::Bytes([0xb1; UUID_LEN].to_vec()),
        ),
        (
            Value::Text(KEY_BLOCK_NAME.into()),
            Value::Text("logins".to_string()),
        ),
        (
            Value::Text(KEY_FINGERPRINT.into()),
            Value::Bytes([0xff; BLOCK_FINGERPRINT_LEN].to_vec()),
        ),
        (Value::Text(KEY_RECIPIENTS.into()), Value::Array(Vec::new())),
        (
            Value::Text(KEY_VECTOR_CLOCK_SUMMARY.into()),
            Value::Array(Vec::new()),
        ),
        (
            Value::Text(KEY_SUITE_ID.into()),
            Value::Integer(u64::from(SUITE_ID_V1).into()),
        ),
        (
            Value::Text(KEY_CREATED_AT_MS.into()),
            Value::Integer(1u64.into()),
        ),
        (
            Value::Text(KEY_LAST_MOD_MS.into()),
            Value::Integer(2u64.into()),
        ),
    ]
}

fn block_entry_value_with_duplicate(repeated: &'static str) -> Value {
    let mut entries = block_entry_base_entries();
    let dup = entries
        .iter()
        .find(|(k, _)| matches!(k, Value::Text(s) if s == repeated))
        .expect("repeated must be one of this entry's own keys")
        .clone();
    entries.push(dup);
    Value::Map(entries)
}

/// A valid `blocks` entry map with `unknown_key` (a forward-compat key
/// outside the fixed §4.2 shape) present twice.
fn block_entry_value_with_duplicate_unknown(unknown_key: &str) -> Value {
    let mut entries = block_entry_base_entries();
    entries.push((
        Value::Text(unknown_key.to_string()),
        Value::Integer(1u64.into()),
    ));
    entries.push((
        Value::Text(unknown_key.to_string()),
        Value::Integer(2u64.into()),
    ));
    Value::Map(entries)
}

/// A valid `trash` entry map's five known-key entries.
fn trash_entry_base_entries() -> Vec<(Value, Value)> {
    vec![
        (
            Value::Text(KEY_BLOCK_UUID.into()),
            Value::Bytes([0xde; UUID_LEN].to_vec()),
        ),
        (
            Value::Text(KEY_TOMBSTONED_AT_MS.into()),
            Value::Integer(1u64.into()),
        ),
        (
            Value::Text(KEY_TOMBSTONED_BY.into()),
            Value::Bytes([0xaa; UUID_LEN].to_vec()),
        ),
        (
            Value::Text(KEY_FINGERPRINT.into()),
            Value::Bytes([0xcd; BLOCK_FINGERPRINT_LEN].to_vec()),
        ),
        (
            Value::Text(KEY_PURGED_AT_MS.into()),
            Value::Integer(3u64.into()),
        ),
    ]
}

fn trash_entry_value_with_duplicate(repeated: &'static str) -> Value {
    let mut entries = trash_entry_base_entries();
    let dup = entries
        .iter()
        .find(|(k, _)| matches!(k, Value::Text(s) if s == repeated))
        .expect("repeated must be one of this entry's own keys")
        .clone();
    entries.push(dup);
    Value::Map(entries)
}

/// A valid `trash` entry map with `unknown_key` present twice.
fn trash_entry_value_with_duplicate_unknown(unknown_key: &str) -> Value {
    let mut entries = trash_entry_base_entries();
    entries.push((
        Value::Text(unknown_key.to_string()),
        Value::Integer(1u64.into()),
    ));
    entries.push((
        Value::Text(unknown_key.to_string()),
        Value::Integer(2u64.into()),
    ));
    Value::Map(entries)
}

/// The four `*_value_with_duplicate` builders above all APPEND the repeated
/// pair, so the duplicate always sits at the last index of the entry list.
/// Deriving the expectation from the built value rather than hardcoding it
/// keeps these assertions correct if a builder gains a key.
///
/// `DuplicateKey`'s `index` had no assertion anywhere in the tree until the
/// #584 review — every test matched it as `..`. A producer reporting a
/// hardcoded `0`, an outer loop's variable, or an off-by-one was undetectable.
fn last_index_of(v: &Value) -> usize {
    match v {
        Value::Map(entries) => entries.len() - 1,
        other => panic!("expected a map, got {other:?}"),
    }
}

/// #573: every nested manifest map rejects a repeated key. The top level
/// has done this since #568; these four had no check at all and silently
/// last-won.
///
/// `field` names the SPECIFIC repeated key, not the container — a
/// compile-time `KEY_*` constant either way, so the #474 data-free
/// guarantee is unchanged.
#[test]
fn vector_clock_entry_rejects_every_duplicate_key() {
    for repeated in [KEY_DEVICE_UUID, KEY_COUNTER] {
        let v = vector_clock_entry_value_with_duplicate(repeated);
        let expected_index = last_index_of(&v);
        match parse_vector_clock_entry(&v) {
            Err(ManifestError::DuplicateKey { field, index }) => {
                assert_eq!(
                    field, repeated,
                    "DuplicateKey must name the key that was actually repeated"
                );
                assert_eq!(
                    index, expected_index,
                    "DuplicateKey must report the ordinal of the repeat"
                );
            }
            other => panic!(
                "expected DuplicateKey for {repeated}, got {}",
                unexpected(&other)
            ),
        }
    }
}

/// Same property as above, for `parse_kdf_params`'s fixed four-key shape.
#[test]
fn kdf_params_rejects_every_duplicate_key() {
    for repeated in [KEY_MEMORY_KIB, KEY_ITERATIONS, KEY_PARALLELISM, KEY_SALT] {
        let v = kdf_params_value_with_duplicate(repeated);
        let expected_index = last_index_of(&v);
        match parse_kdf_params(&v) {
            Err(ManifestError::DuplicateKey { field, index }) => {
                assert_eq!(
                    field, repeated,
                    "DuplicateKey must name the key that was actually repeated"
                );
                assert_eq!(
                    index, expected_index,
                    "DuplicateKey must report the ordinal of the repeat"
                );
            }
            other => panic!(
                "expected DuplicateKey for {repeated}, got {}",
                unexpected(&other)
            ),
        }
    }
}

/// Same property, for `parse_block_entry`'s eight known keys.
#[test]
fn block_entry_rejects_every_duplicate_key() {
    for repeated in [
        KEY_BLOCK_UUID,
        KEY_BLOCK_NAME,
        KEY_FINGERPRINT,
        KEY_RECIPIENTS,
        KEY_VECTOR_CLOCK_SUMMARY,
        KEY_SUITE_ID,
        KEY_CREATED_AT_MS,
        KEY_LAST_MOD_MS,
    ] {
        let v = block_entry_value_with_duplicate(repeated);
        let expected_index = last_index_of(&v);
        match parse_block_entry(&v) {
            Err(ManifestError::DuplicateKey { field, index }) => {
                assert_eq!(
                    field, repeated,
                    "DuplicateKey must name the key that was actually repeated"
                );
                assert_eq!(
                    index, expected_index,
                    "DuplicateKey must report the ordinal of the repeat"
                );
            }
            other => panic!(
                "expected DuplicateKey for {repeated}, got {}",
                unexpected(&other)
            ),
        }
    }
}

/// Same property, for `parse_trash_entry`'s five known keys.
#[test]
fn trash_entry_rejects_every_duplicate_key() {
    for repeated in [
        KEY_BLOCK_UUID,
        KEY_TOMBSTONED_AT_MS,
        KEY_TOMBSTONED_BY,
        KEY_FINGERPRINT,
        KEY_PURGED_AT_MS,
    ] {
        let v = trash_entry_value_with_duplicate(repeated);
        let expected_index = last_index_of(&v);
        match parse_trash_entry(&v) {
            Err(ManifestError::DuplicateKey { field, index }) => {
                assert_eq!(
                    field, repeated,
                    "DuplicateKey must name the key that was actually repeated"
                );
                assert_eq!(
                    index, expected_index,
                    "DuplicateKey must report the ordinal of the repeat"
                );
            }
            other => panic!(
                "expected DuplicateKey for {repeated}, got {}",
                unexpected(&other)
            ),
        }
    }
}

/// A repeated forward-compat UNKNOWN key must be rejected with the
/// literal "<unknown>". The repeated key's own text is
/// attacker-influenced content from inside the encrypted manifest and
/// must never reach an error payload (#474).
#[test]
fn block_entry_rejects_duplicate_unknown_key_without_naming_it() {
    let v = block_entry_value_with_duplicate_unknown("v2_extension_field");
    let expected_index = last_index_of(&v);
    let err = expect_rejected(parse_block_entry(&v), "must reject");
    match &err {
        ManifestError::DuplicateKey { field, index } => {
            assert_eq!(*field, "<unknown>");
            assert_eq!(
                *index, expected_index,
                "the ordinal is data-free and must still be the repeat's own"
            );
        }
        other => panic!("expected DuplicateKey, got {other:?}"),
    }
    assert!(
        !format!("{err}").contains("v2_extension_field"),
        "the repeated key's text must never reach the error payload"
    );
}

/// Same property, for `parse_trash_entry`'s unknown bag.
#[test]
fn trash_entry_rejects_duplicate_unknown_key_without_naming_it() {
    let v = trash_entry_value_with_duplicate_unknown("v3_extension_field");
    let expected_index = last_index_of(&v);
    let err = expect_rejected(parse_trash_entry(&v), "must reject");
    match &err {
        ManifestError::DuplicateKey { field, index } => {
            assert_eq!(*field, "<unknown>");
            assert_eq!(
                *index, expected_index,
                "the ordinal is data-free and must still be the repeat's own"
            );
        }
        other => panic!("expected DuplicateKey, got {other:?}"),
    }
    assert!(
        !format!("{err}").contains("v3_extension_field"),
        "the repeated key's text must never reach the error payload"
    );
}

/// A repeated `contact_uuid` inside one block's `recipients` is ACCEPTED
/// (vault-format §4.2's one exception to the repeated-value rules).
///
/// This is the negative counterpart to the three duplicate-rejection tests
/// above, and until #594 nothing pinned it. That mattered in a specific
/// way: §4.2 now states the exception normatively, and a reader "tidying
/// up" the asymmetry — adding a uniqueness check to `parse_recipients`
/// beside the three it has — would narrow a v1-FROZEN decoder and start
/// rejecting manifests this codebase has always been able to emit. The
/// rule has a reason: a repeated recipient denotes no additional grant, so
/// unlike a repeated `block_uuid` (two entries claiming one block, which
/// two conformant readers could resolve differently) it introduces no
/// ambiguity to resolve.
///
/// `conformance.py`'s section MUQ pins the same acceptance from the
/// clean-room side, via `manifest_uniqueness_kat.json`'s
/// `recipients__duplicate_contact_uuid` row.
#[test]
fn accepts_duplicate_contact_uuid_in_recipients() {
    let dupe_recipient = [0xc1; UUID_LEN];
    let m = Manifest {
        manifest_version: MANIFEST_VERSION_V1,
        vault_uuid: [0x01; UUID_LEN],
        format_version: FORMAT_VERSION_V1,
        suite_id: SUITE_ID_V1,
        owner_user_uuid: [0x02; UUID_LEN],
        vector_clock: Vec::new(),
        blocks: vec![BlockEntry {
            block_uuid: [0x77; UUID_LEN],
            block_name: "blk".to_string(),
            fingerprint: [0x01; BLOCK_FINGERPRINT_LEN],
            recipients: vec![dupe_recipient, dupe_recipient],
            vector_clock_summary: Vec::new(),
            suite_id: SUITE_ID_V1,
            created_at_ms: 1,
            last_mod_ms: 2,
            unknown: BTreeMap::new(),
        }],
        trash: Vec::new(),
        kdf_params: dummy_kdf_params(),
        unknown: BTreeMap::new(),
    };
    let bytes = encode_manifest(&m).expect("encode duplicate recipients");
    // `unexpected` rather than a bare `{:?}` on the Result: a `Manifest`'s
    // own Debug prints every `block_name`, which is user-authored
    // plaintext, and that reaches CI logs on failure (#584 review).
    let outcome = decode_manifest(bytes.expose());
    assert!(
        outcome.is_ok(),
        "duplicate recipients must be ACCEPTED (§4.2's one exception): {}",
        unexpected(&outcome)
    );
    let decoded = outcome.expect("asserted Ok immediately above");
    assert_eq!(
        decoded.blocks[0].recipients,
        vec![dupe_recipient, dupe_recipient],
        "the repeat must round-trip verbatim, not be silently deduplicated"
    );
}

/// A duplicate key is reported even when the second copy is MALFORMED.
///
/// Every fixture above repeats a well-typed pair, so none of them can see
/// the ordering this test pins: the vacancy check runs *before* the second
/// copy is parsed. That ordering was an accident of how the guards were
/// hand-written (`if slot.is_some() { .. }` preceding
/// `slot = Some(take_*(..)?)`), and #589's slot type preserves it
/// deliberately — [`Once::set`] takes a closure precisely so the fill
/// cannot run once the slot is known to be occupied.
///
/// Without this test an eager `set(field, index, take_u64(v, KEY)?)` would
/// flip these four rejections from `DuplicateKey` to `WrongType`, changing
/// what a v1-frozen decoder reports for a real input class, with the whole
/// suite green.
///
/// One case per nested parser, each repeating a key whose second copy is a
/// text string where the spec requires bytes or an integer.
#[test]
fn a_duplicate_key_outranks_a_malformed_second_copy() {
    /// A `Value::Text` is the wrong CBOR type for every key exercised
    /// below, so reaching the fill at all yields `WrongType`.
    fn malformed() -> Value {
        Value::Text("not the type this key requires".into())
    }

    /// `entry` with `(repeated, <malformed>)` appended.
    fn with_malformed_repeat(entry: &Value, repeated: &'static str) -> Value {
        let Value::Map(entries) = entry else {
            panic!("expected a map, got {entry:?}");
        };
        assert!(
            entries
                .iter()
                .any(|(k, _)| matches!(k, Value::Text(s) if s == repeated)),
            "{repeated} must already be present for the append to be a REPEAT"
        );
        let mut entries = entries.clone();
        entries.push((Value::Text(repeated.into()), malformed()));
        Value::Map(entries)
    }

    // Each case is (parser name, the parse call, the repeated key). The
    // parsers have different return types, so each runs its own match
    // rather than sharing a loop over boxed closures.
    macro_rules! assert_duplicate_wins {
        ($parsed:expr, $repeated:expr, $what:literal) => {
            match $parsed {
                Err(ManifestError::DuplicateKey { field, index }) => {
                    assert_eq!(field, $repeated, "{} must name the repeated key", $what);
                    assert_eq!(index, 2, "{} must report the ordinal of the repeat", $what);
                }
                other => panic!(
                    "{}: a duplicate key must outrank the malformed second copy, got {}",
                    $what,
                    unexpected(&other)
                ),
            }
        };
    }

    // `vector_clock` entry: two keys, so the repeat lands at index 2.
    let vc = with_malformed_repeat(
        &vector_clock_entry_value_with_duplicate(KEY_COUNTER),
        KEY_COUNTER,
    );
    // That helper already appended a well-typed repeat, so strip it back
    // to the two-key original before appending the malformed one.
    let Value::Map(mut vc_entries) = vc else {
        panic!("expected a map")
    };
    vc_entries.remove(2);
    assert_duplicate_wins!(
        parse_vector_clock_entry(&Value::Map(vc_entries)),
        KEY_COUNTER,
        "vector_clock entry"
    );

    // `kdf_params`: four keys; plant the repeat directly after the second
    // so the index is 2 here too.
    let Value::Map(kdf) = kdf_params_value_with_duplicate(KEY_MEMORY_KIB) else {
        panic!("expected a map")
    };
    let mut kdf: Vec<(Value, Value)> = kdf.into_iter().take(2).collect();
    kdf.push((Value::Text(KEY_MEMORY_KIB.into()), malformed()));
    assert_duplicate_wins!(
        parse_kdf_params(&Value::Map(kdf)),
        KEY_MEMORY_KIB,
        "kdf_params"
    );

    // `blocks` entry.
    let Value::Map(block) = block_entry_value_with_duplicate(KEY_BLOCK_UUID) else {
        panic!("expected a map")
    };
    let mut block: Vec<(Value, Value)> = block.into_iter().take(2).collect();
    block.push((Value::Text(KEY_BLOCK_UUID.into()), malformed()));
    assert_duplicate_wins!(
        parse_block_entry(&Value::Map(block)),
        KEY_BLOCK_UUID,
        "block entry"
    );

    // `trash` entry.
    let Value::Map(trash) = trash_entry_value_with_duplicate(KEY_BLOCK_UUID) else {
        panic!("expected a map")
    };
    let mut trash: Vec<(Value, Value)> = trash.into_iter().take(2).collect();
    trash.push((Value::Text(KEY_BLOCK_UUID.into()), malformed()));
    assert_duplicate_wins!(
        parse_trash_entry(&Value::Map(trash)),
        KEY_BLOCK_UUID,
        "trash entry"
    );
}
