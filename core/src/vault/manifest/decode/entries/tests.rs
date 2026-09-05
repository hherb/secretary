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

/// A valid `vector_clock` entry map's two known-key entries.
fn vector_clock_entry_base_entries() -> Vec<(Value, Value)> {
    let entries = vec![
        (
            Value::Text(KEY_DEVICE_UUID.into()),
            Value::Bytes([0x33; UUID_LEN].to_vec()),
        ),
        (Value::Text(KEY_COUNTER.into()), Value::Integer(7u64.into())),
    ];
    assert_census(&entries, 2, "parse_vector_clock_entry");
    entries
}

/// A valid `vector_clock` entry map with `repeated`'s key/value pair
/// appended a second time.
fn vector_clock_entry_value_with_duplicate(repeated: &'static str) -> Value {
    let mut entries = vector_clock_entry_base_entries();
    let dup = entries
        .iter()
        .find(|(k, _)| matches!(k, Value::Text(s) if s == repeated))
        .expect("repeated must be one of this entry's own keys")
        .clone();
    entries.push(dup);
    Value::Map(entries)
}

/// A valid `kdf_params` map's four known-key entries.
fn kdf_params_base_entries() -> Vec<(Value, Value)> {
    let k = dummy_kdf_params();
    let entries = vec![
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
    assert_census(&entries, 4, "parse_kdf_params");
    entries
}

/// A valid `kdf_params` map with `repeated`'s key/value pair appended a
/// second time.
fn kdf_params_value_with_duplicate(repeated: &'static str) -> Value {
    let mut entries = kdf_params_base_entries();
    let dup = entries
        .iter()
        .find(|(kk, _)| matches!(kk, Value::Text(s) if s == repeated))
        .expect("repeated must be one of this entry's own keys")
        .clone();
    entries.push(dup);
    Value::Map(entries)
}

/// The known-key census each fixture builder below encodes.
///
/// **What this catches and what it does not**, because the wider reading is
/// wrong. It reds when a builder's own entry list drifts from the count the
/// sweeps were written against — i.e. when someone edits the builder. It is
/// NOT a tripwire on the parser's match arms: adding a new arm to
/// `parse_block_entry` changes nothing here.
///
/// For a *required* key that is self-correcting anyway — the parser would
/// report `MissingField` against the unchanged fixture and every test using
/// it reds at once. For an *optional* key nothing reds, and that shape is
/// live rather than hypothetical: `parse_trash_entry` already has two
/// (`fingerprint`, `purged_at_ms`). Adding a third means updating the count
/// here by hand.
fn assert_census(entries: &[(Value, Value)], expected: usize, parser: &str) {
    assert_eq!(
        entries.len(),
        expected,
        "{parser}'s fixture is expected to carry all {expected} known keys; \
         a change here means the arm census moved and the sweeps below need \
         the new key"
    );
}

/// A valid `blocks` entry map's eight known-key entries, in no particular
/// order — `parse_block_entry` dispatches by key text, not position.
fn block_entry_base_entries() -> Vec<(Value, Value)> {
    let entries = vec![
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
    ];
    assert_census(&entries, 8, "parse_block_entry");
    entries
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
    let entries = vec![
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
    ];
    assert_census(&entries, 5, "parse_trash_entry");
    entries
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

    /// The first two entries of `base`, plus a third repeating `repeated`
    /// with a malformed value.
    ///
    /// Truncating to two keys first is what fixes the repeat's ordinal at
    /// **2** for every parser, whatever its map's real width — so the
    /// `index` assertion below is one constant rather than four.
    fn with_malformed_repeat(base: Vec<(Value, Value)>, repeated: &'static str) -> Value {
        let mut entries: Vec<(Value, Value)> = base.into_iter().take(2).collect();
        assert!(
            entries
                .iter()
                .any(|(k, _)| matches!(k, Value::Text(s) if s == repeated)),
            "{repeated} must be among the first two keys, or the third entry \
             is not a REPEAT and this test proves nothing"
        );
        entries.push((Value::Text(repeated.into()), malformed()));
        Value::Map(entries)
    }

    // Arguments are (the parse call, the repeated key, the parser's name).
    // The parsers have different return types, so each runs its own match
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

    assert_duplicate_wins!(
        parse_vector_clock_entry(&with_malformed_repeat(
            vector_clock_entry_base_entries(),
            KEY_COUNTER
        )),
        KEY_COUNTER,
        "vector_clock entry"
    );
    assert_duplicate_wins!(
        parse_kdf_params(&with_malformed_repeat(
            kdf_params_base_entries(),
            KEY_MEMORY_KIB
        )),
        KEY_MEMORY_KIB,
        "kdf_params"
    );
    assert_duplicate_wins!(
        parse_block_entry(&with_malformed_repeat(
            block_entry_base_entries(),
            KEY_BLOCK_UUID
        )),
        KEY_BLOCK_UUID,
        "block entry"
    );
    assert_duplicate_wins!(
        parse_trash_entry(&with_malformed_repeat(
            trash_entry_base_entries(),
            KEY_BLOCK_UUID
        )),
        KEY_BLOCK_UUID,
        "trash entry"
    );
}

/// `entries` with the single pair named by `dropped` removed.
///
/// Asserts the key was present *exactly once* first, so a sweep that names a
/// key the fixture does not carry fails loudly instead of silently testing
/// the unmodified map — which would pass, because the unmodified map parses.
fn without_key(mut entries: Vec<(Value, Value)>, dropped: &str) -> Vec<(Value, Value)> {
    let before = entries.len();
    entries.retain(|(k, _)| !matches!(k, Value::Text(s) if s == dropped));
    assert_eq!(
        entries.len(),
        before - 1,
        "{dropped} must be present exactly once for its removal to be the \
         thing under test"
    );
    entries
}

/// The text of a fixture entry's key.
fn text_key(k: &Value) -> String {
    match k {
        Value::Text(s) => s.clone(),
        other => panic!("non-text fixture key: {other:?}"),
    }
}

/// Every §4.2-required key of every nested map, dropped one at a time, must
/// be named by the resulting [`ManifestError::MissingField`].
///
/// **The `set` half of this property was swept; the `require` half was not.**
/// #589 made both a shared implementation, and `decode/tests.rs`'s top-level
/// sweep records the consequence for `set`: once the arms share one
/// `Once::set`, the `KEY_*` constant each arm passes is the only per-arm
/// thing left, and nothing but a sweep can pin it. That argument holds
/// verbatim for `Once::require`, and until this test there was exactly ONE
/// assertion on a manifest `MissingField` name in the whole tree
/// (`decode/tests.rs::rejects_missing_required_field_vault_uuid`, covering
/// `vault_uuid`) against 26 `require` call sites.
///
/// `parse_block_entry` in particular ends in an eight-line struct literal of
/// `x.require(KEY_X)?` calls — the canonical copy-paste site. A wrong
/// constant there still *rejects* the manifest, so this is a diagnostic
/// contract rather than an acceptance one; that diagnostic is a
/// `&'static str` which crosses the FFI, and this repo already treats "which
/// field gets named" as behaviour worth pinning cross-language (#597/#605).
///
/// The key lists are DERIVED from the fixture builders, not hardcoded, so a
/// key added to a builder is swept automatically. The per-parser counts are
/// asserted because that is the half derivation cannot check: they sum to 17,
/// which with `decode/tests.rs`'s nine top-level keys is all 26 `require`
/// sites.
#[test]
fn every_nested_parser_names_the_required_key_it_is_missing() {
    /// The two §4.2 keys of a `trash` entry that are genuinely optional.
    /// They take `Once::into_option`, not `Once::require`, and are asserted
    /// separately below — dropping one must still *parse*.
    const TRASH_OPTIONAL: [&str; 2] = [KEY_FINGERPRINT, KEY_PURGED_AT_MS];

    macro_rules! assert_missing_names_it {
        ($parsed:expr, $dropped:expr, $what:literal) => {
            match $parsed {
                Err(ManifestError::MissingField { field }) => assert_eq!(
                    field, $dropped,
                    "{} must name the required key that was dropped",
                    $what
                ),
                other => panic!(
                    "{}: dropping {} must report MissingField, got {}",
                    $what,
                    $dropped,
                    unexpected(&other)
                ),
            }
        };
    }

    let mut swept = 0usize;

    for (k, _) in vector_clock_entry_base_entries() {
        let dropped = text_key(&k);
        let v = Value::Map(without_key(vector_clock_entry_base_entries(), &dropped));
        assert_missing_names_it!(parse_vector_clock_entry(&v), dropped, "vector_clock entry");
        swept += 1;
    }
    assert_eq!(swept, 2, "vector_clock entries have two required keys");

    let mut kdf_swept = 0usize;
    for (k, _) in kdf_params_base_entries() {
        let dropped = text_key(&k);
        let v = Value::Map(without_key(kdf_params_base_entries(), &dropped));
        assert_missing_names_it!(parse_kdf_params(&v), dropped, "kdf_params");
        kdf_swept += 1;
    }
    assert_eq!(kdf_swept, 4, "kdf_params has four required keys");
    swept += kdf_swept;

    let mut block_swept = 0usize;
    for (k, _) in block_entry_base_entries() {
        let dropped = text_key(&k);
        let v = Value::Map(without_key(block_entry_base_entries(), &dropped));
        assert_missing_names_it!(parse_block_entry(&v), dropped, "block entry");
        block_swept += 1;
    }
    assert_eq!(block_swept, 8, "block entries have eight required keys");
    swept += block_swept;

    let mut trash_swept = 0usize;
    for (k, _) in trash_entry_base_entries() {
        let dropped = text_key(&k);
        if TRASH_OPTIONAL.contains(&dropped.as_str()) {
            continue;
        }
        let v = Value::Map(without_key(trash_entry_base_entries(), &dropped));
        assert_missing_names_it!(parse_trash_entry(&v), dropped, "trash entry");
        trash_swept += 1;
    }
    assert_eq!(
        trash_swept, 3,
        "trash entries have three required keys and two optional ones"
    );
    swept += trash_swept;

    assert_eq!(
        swept, 17,
        "the four nested parsers hold 17 of the decoder's 26 `require` sites; \
         the other nine are the top level's, swept in `decode/tests.rs`"
    );
}

/// The mirror of the sweep above: `TrashEntry`'s two optional §4.2 keys must
/// NOT be required.
///
/// This is what pins that they take [`Once::into_option`] rather than
/// [`Once::require`]. The two accessors are not interchangeable by accident —
/// swapping one for the other is a type error against `TrashEntry`'s field
/// types — but that is a property of the destination struct, not of `Once`,
/// and it would stop holding the day a spec-required field is declared
/// `Option<T>`. Asserting the observable behaviour costs four lines.
#[test]
fn a_trash_entry_missing_an_optional_key_still_parses() {
    for absent in [KEY_FINGERPRINT, KEY_PURGED_AT_MS] {
        let v = Value::Map(without_key(trash_entry_base_entries(), absent));
        let entry = parse_trash_entry(&v)
            .unwrap_or_else(|e| panic!("{absent} is optional in §4.2, got Err({e:?})"));
        match absent {
            KEY_FINGERPRINT => assert!(
                entry.fingerprint.is_none(),
                "an absent fingerprint must decode to None"
            ),
            KEY_PURGED_AT_MS => assert!(
                entry.purged_at_ms.is_none(),
                "an absent purged_at_ms must decode to None"
            ),
            other => panic!("unexpected optional key {other}"),
        }
    }
}
