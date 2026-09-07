//! Building the corpus's manifest bodies: the structurally complete base
//! manifest, the needle splice, and the `ciborium` surgery the
//! non-splice cases need.
//!
//! Extracted from `manifest_canonicality_kat.rs` (#612).

use std::collections::BTreeMap;

use secretary_core::vault::manifest::{
    encode_manifest, BlockEntry, KdfParamsRef, Manifest, TrashEntry, VectorClockEntry,
};
use secretary_core::vault::UnknownValue;

use super::cases::{Level, Shape, NEEDLE};

/// One `BlockEntry` carrying TWO recipients and TWO
/// `vector_clock_summary` entries, both in ascending order.
fn block_entry(uuid_byte: u8, name: &str) -> BlockEntry {
    BlockEntry {
        block_uuid: [uuid_byte; 16],
        block_name: name.to_string(),
        fingerprint: [0xFF; 32],
        recipients: vec![[0x31; 16], [0x32; 16]],
        vector_clock_summary: vec![
            VectorClockEntry {
                device_uuid: [0x41; 16],
                counter: 7,
            },
            VectorClockEntry {
                device_uuid: [0x42; 16],
                counter: 9,
            },
        ],
        suite_id: secretary_core::version::SUITE_ID,
        created_at_ms: 1_700_000_000_000,
        last_mod_ms: 1_700_000_000_000,
        unknown: BTreeMap::new(),
    }
}

/// One `TrashEntry`.
fn trash_entry(uuid_byte: u8) -> TrashEntry {
    TrashEntry {
        block_uuid: [uuid_byte; 16],
        tombstoned_at_ms: 1_700_000_000_000,
        tombstoned_by: [0xAA; 16],
        fingerprint: None,
        purged_at_ms: None,
        unknown: BTreeMap::new(),
    }
}

/// A structurally complete manifest whose `unknown` bag at `level`
/// carries exactly one entry: [`NEEDLE`].
///
/// **Every one of the five §4.2 sort-discipline arrays carries TWO
/// entries** (#595). It used to carry none or one: `vector_clock`,
/// `recipients` and `vector_clock_summary` were `Vec::new()` in every
/// row and `blocks`/`trash` held at most one element, so all five sort
/// disciplines were satisfied only VACUOUSLY -- bit-for-bit the
/// criticism this slice levels at `golden_vault_001`. An array of
/// length 0 or 1 is sorted no matter what the encoder or the decoder's
/// order check does, so no-op'ing either left the whole corpus green.
/// The sort disciplines are the *newly narrowing* half of the §4.2
/// reader contract (#572) -- the half a clean-room implementer reading
/// `docs/` alone would get wrong -- which makes them precisely what
/// this cross-language corpus exists to pin.
///
/// Two entries is the minimum that can be out of order, and the
/// values are chosen ascending so the fixture itself is conformant;
/// the REJECTION side of the discipline is covered by
/// `array_sort_disciplines_are_enforced_and_not_vacuous` below and by
/// `conformance.py`'s `section_manifest_body_array_sort_guard`.
/// Nothing else about these fields is load-bearing, except that
/// `format_version`/`suite_id` must be the real constants or the
/// baseline decode would fail before the splice is ever exercised.
pub fn base_manifest(level: Level) -> Manifest {
    let placeholder = UnknownValue::from_canonical_cbor(NEEDLE)
        .expect("NEEDLE is canonical CBOR by construction");

    let mut m = Manifest {
        manifest_version: 1,
        vault_uuid: [0x01; 16],
        format_version: secretary_core::version::FORMAT_VERSION,
        suite_id: secretary_core::version::SUITE_ID,
        owner_user_uuid: [0x02; 16],
        vector_clock: vec![
            VectorClockEntry {
                device_uuid: [0x21; 16],
                counter: 3,
            },
            VectorClockEntry {
                device_uuid: [0x22; 16],
                counter: 5,
            },
        ],
        blocks: vec![
            block_entry(0xB1, "corpus-block"),
            block_entry(0xB2, "corpus-block-2"),
        ],
        trash: vec![trash_entry(0xDE), trash_entry(0xDF)],
        kdf_params: KdfParamsRef {
            memory_kib: 262_144,
            iterations: 3,
            parallelism: 1,
            salt: [0x11; 32],
        },
        unknown: BTreeMap::new(),
    };

    match level {
        Level::Top => {
            m.unknown.insert("zzz_needle".to_string(), placeholder);
        }
        Level::Block => {
            m.blocks[0]
                .unknown
                .insert("zzz_needle".to_string(), placeholder);
        }
        Level::Trash => {
            m.trash[0]
                .unknown
                .insert("zzz_needle".to_string(), placeholder);
        }
    }

    m
}

/// Locate [`NEEDLE`]'s unique occurrence in `bytes`, panicking loudly
/// if it is absent or repeated -- either would mean the splice below
/// targets the wrong location (or an ambiguous one).
pub fn locate_needle(bytes: &[u8], level: Level) -> usize {
    let hits: Vec<usize> = bytes
        .windows(NEEDLE.len())
        .enumerate()
        .filter(|(_, w)| *w == NEEDLE)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "NEEDLE must occur exactly once in the {} base manifest, or the \
         splice could hit the wrong location",
        level.label()
    );
    hits[0]
}

/// Rebuild one row's manifest body from the `SHAPES` table.
///
/// **The single implementation of the splice**, used by BOTH the
/// generator and the replay's rebuild-and-compare, so the bytes a row
/// is checked against cannot drift from the bytes that produced it.
///
/// The replay comparison this exists for binds a row's BYTES to its
/// LABEL, which nothing did before (#614 review). The corpus's whole
/// premise is "7 shapes x 3 levels", and the level dimension was
/// unpinned: replacing all six `block__`/`trash__` rejecting bodies
/// with their `top__` counterparts left the Rust replay AND all 26
/// `conformance.py` sections green -- a corpus silently collapsed to
/// one nesting level while reporting PASS. Same rebuild-and-compare
/// discipline #599's review put on `manifest_uniqueness_kat.rs`.
pub fn body_for(level: Level, shape: &Shape) -> Vec<u8> {
    let base = encode_manifest(&base_manifest(level))
        .expect("encode base manifest")
        .expose()
        .to_vec();
    let at = locate_needle(&base, level);
    let mut spliced = base;
    spliced.splice(at..at + NEEDLE.len(), shape.bytes.iter().copied());
    spliced
}

// ---------------------------------------------------------------------------
// The mutation family's bodies (#613)
// ---------------------------------------------------------------------------
//
// These bodies cannot be produced by `encode_manifest` -- it sorts all five
// arrays and emits map keys in canonical order, which are the very
// disciplines under test -- so each one round-trips the encoded baseline
// through `ciborium::Value` and reorders exactly one sequence there. The
// round trip is an identity on the rest of the body: `encode_manifest`'s
// output is canonical, and `ciborium`'s serializer emits definite lengths
// and shortest-form heads, so nothing but the reordered sequence moves.
// `body_for_case` asserts that the mutation actually changed the bytes, so
// a case that silently became a no-op fails rather than joining the corpus
// as a body the decoder accepts.

use ciborium::Value;

use super::cases::{Case, MapPath, Mutation, SortedArray};

/// The entry list of the CBOR map `v`, or a panic naming what it is instead.
fn map_entries_mut(v: &mut Value) -> &mut Vec<(Value, Value)> {
    match v {
        Value::Map(entries) => entries,
        other => panic!("expected a CBOR map, got {other:?}"),
    }
}

/// The value stored under text key `key` in the CBOR map `v`.
fn value_at_key_mut<'a>(v: &'a mut Value, key: &str) -> &'a mut Value {
    map_entries_mut(v)
        .iter_mut()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, val)| val)
        .unwrap_or_else(|| panic!("key {key:?} not found"))
}

/// The item list of the CBOR array stored under text key `key` in map `v`.
fn array_items_mut<'a>(v: &'a mut Value, key: &str) -> &'a mut Vec<Value> {
    match value_at_key_mut(v, key) {
        Value::Array(items) => items,
        other => panic!("key {key:?} is not an array: {other:?}"),
    }
}

/// Serialize a decoded body back to bytes.
fn encode_value(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(v, &mut out).expect("re-encode mutated body");
    out
}

/// Reverse one of §4.2's five sorted arrays inside an encoded manifest body.
///
/// The array is named by a closed [`SortedArray`], not by a `(&str,
/// Option<&str>)` key pair: the pair made 23 non-§4.2 combinations
/// representable (all of which panicked, but only because of what today's
/// base manifest happens to contain), and it let a row's label disagree
/// with what the row actually reverses.
///
/// **The nested variants carry a block INDEX**, so the corpus can plant at
/// `blocks[1]` as well as `blocks[0]`. Without that, a reader or classifier
/// scoped to the first block is conformant against the whole corpus --
/// measured in both languages, and the mirror of the defect #608's review
/// fixed on `manifest_uniqueness_kat`.
///
/// **The single implementation of this reversal**, shared by the corpus
/// generator and by `array_sort_disciplines_are_enforced_and_not_vacuous`,
/// so the bytes the fixture-independent test exercises cannot drift from
/// the bytes the `arraysort__*` rows commit.
pub fn reverse_array(body: &[u8], array: SortedArray) -> Vec<u8> {
    let mut v: Value = ciborium::de::from_reader(body).expect("parse body");
    let (outer, inner) = array.path();
    let target = match inner {
        None => array_items_mut(&mut v, outer),
        Some((key, index)) => {
            let entries = array_items_mut(&mut v, outer);
            let entry = entries.get_mut(index).unwrap_or_else(|| {
                panic!("{outer}[{index}] does not exist -- {array:?} cannot be built")
            });
            array_items_mut(entry, key)
        }
    };
    assert!(
        target.len() >= 2,
        "array {array:?} has {} element(s) -- a sort discipline cannot be \
         violated with fewer than 2, so this case would be vacuous",
        target.len()
    );
    target.reverse();
    encode_value(&v)
}

/// Reverse the ENTRY ORDER of the map at `path`, leaving every key and
/// every value byte-identical.
///
/// Two entries would be enough to violate the order; the assertion below
/// is what stops a future base manifest whose target map shrank to one
/// entry from making a row vacuous -- it would re-encode to itself and be
/// ACCEPTED, joining the corpus as a row that proves nothing.
pub fn reverse_map_keys(body: &[u8], path: MapPath) -> Vec<u8> {
    let mut v: Value = ciborium::de::from_reader(body).expect("parse body");
    {
        let target: &mut Value = match path {
            MapPath::Top => &mut v,
            MapPath::KdfParams => value_at_key_mut(&mut v, "kdf_params"),
            MapPath::FirstBlock => array_items_mut(&mut v, "blocks")
                .first_mut()
                .expect("blocks must be non-empty"),
            MapPath::FirstTrash => array_items_mut(&mut v, "trash")
                .first_mut()
                .expect("trash must be non-empty"),
        };
        let entries = map_entries_mut(target);
        assert!(
            entries.len() >= 2,
            "map {path:?} has {} entr(y/ies) -- key order cannot be violated \
             with fewer than 2, so this case would be vacuous",
            entries.len()
        );
        entries.reverse();
    }
    encode_value(&v)
}

/// Rebuild one corpus row's manifest body from its [`Case`].
///
/// **The single implementation for BOTH families**, used by the generator
/// and by the replay's rebuild-and-compare, so the bytes a row is checked
/// against cannot drift from the bytes that produced it (#614 review).
pub fn body_for_case(case: Case) -> Vec<u8> {
    match case {
        Case::Splice { level, shape } => body_for(level, shape),
        Case::Mutate(mutation_case) => {
            // Every mutation row is built from the SAME `Level::Top`
            // baseline, so a divergence between two of them is always the
            // mutation and never the base.
            let base = encode_manifest(&base_manifest(Level::Top))
                .expect("encode base manifest")
                .expose()
                .to_vec();
            let mutated = match mutation_case.mutation {
                Mutation::ReverseArray(array) => reverse_array(&base, array),
                Mutation::ReverseMapKeys(path) => reverse_map_keys(&base, path),
            };
            assert_ne!(
                mutated,
                base,
                "mutation {} produced the baseline body unchanged -- the row \
                 would be an ACCEPT masquerading as a REJECT",
                mutation_case.label()
            );
            mutated
        }
    }
}
