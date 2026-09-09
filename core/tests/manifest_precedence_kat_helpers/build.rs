//! Building the corpus's bodies: an all-valid baseline, and the
//! `ciborium` surgery that plants one repeated map key in it.
//!
//! **The bodies cannot come from `encode_manifest`.** A `Manifest` is a
//! struct, so a repeated map key is not representable in it at all, and
//! since #586 the encoder rejects one anyway. Surgery on the encoded
//! baseline is the only way to produce these bytes -- the same
//! arrangement #600 left `manifest_uniqueness_kat.rs` in for the
//! array-element twin, and for the same reason.

use std::collections::BTreeMap;

use ciborium::Value;
use secretary_core::vault::manifest::{
    encode_manifest, BlockEntry, KdfParamsRef, Manifest, TrashEntry, VectorClockEntry,
};

use super::cases::{Case, Level, Shape};

/// A body with one repeated key planted, and the ordinal of the repeat.
pub struct PlantedBody {
    pub bytes: Vec<u8>,
    /// The repeat's position within its own map, as the Rust decoder's
    /// `enumerate()` reports it. `None` for the accept control.
    ///
    /// DERIVED from the plant -- the index the surgery inserted at --
    /// never read back from the decoder. A generator that recorded the
    /// decoder's own ordinal would assert nothing.
    pub dup_index: Option<usize>,
}

fn vclock(device: u8, counter: u64) -> VectorClockEntry {
    VectorClockEntry {
        device_uuid: [device; 16],
        counter,
    }
}

fn block_entry(uuid_byte: u8, name: &str) -> BlockEntry {
    BlockEntry {
        block_uuid: [uuid_byte; 16],
        block_name: name.to_string(),
        fingerprint: [0xFF; 32],
        recipients: vec![[0x31; 16], [0x32; 16]],
        vector_clock_summary: vec![vclock(0x41, 7), vclock(0x42, 9)],
        suite_id: secretary_core::version::SUITE_ID,
        created_at_ms: 1_700_000_000_000,
        last_mod_ms: 1_700_000_000_000,
        unknown: BTreeMap::new(),
    }
}

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

/// A structurally complete, fully valid manifest.
///
/// **Deliberately this corpus's own, not shared with its two siblings.**
/// `manifest_canonicality_kat` and `manifest_uniqueness_kat` each own one
/// too, and the independence is the point rather than an oversight: an
/// integration test is its own crate, so sharing would mean `#[path]`-
/// including another test's helpers, and #623 is queued to regenerate
/// every canonicality body -- which would red this corpus for a reason
/// that has nothing to do with precedence.
///
/// **Every array holds TWO entries, and repeats are planted at BOTH
/// ends** -- `vector_clock[0]` and `trash[0]`, against `blocks[1]` and
/// `blocks[1].vector_clock_summary[1]`. That is #608's review lesson in
/// full rather than half of it: planting only in element 1 catches a
/// reader scoped to element 0 and leaves the `skip(1)` mirror image
/// conformant, and planting only in element 0 has the same defect the
/// other way. `Level::elem` owns the assignment and
/// `both_array_ends_are_planted` reds if a future edit collapses them.
pub fn base_manifest() -> Manifest {
    Manifest {
        manifest_version: 1,
        vault_uuid: [0x01; 16],
        format_version: secretary_core::version::FORMAT_VERSION,
        suite_id: secretary_core::version::SUITE_ID,
        owner_user_uuid: [0x02; 16],
        vector_clock: vec![vclock(0x21, 3), vclock(0x22, 5)],
        blocks: vec![
            block_entry(0xB1, "precedence-block"),
            block_entry(0xB2, "precedence-block-2"),
        ],
        trash: vec![trash_entry(0xDE), trash_entry(0xDF)],
        kdf_params: KdfParamsRef {
            memory_kib: 262_144,
            iterations: 3,
            parallelism: 1,
            salt: [0x11; 32],
        },
        unknown: BTreeMap::new(),
    }
}

/// The encoded, all-valid baseline every row is built from.
pub fn baseline_bytes() -> Vec<u8> {
    encode_manifest(&base_manifest())
        .expect("the all-valid baseline must encode")
        .expose()
        .to_vec()
}

/// The second copy planted for a shape.
///
/// Every value here is well-FORMED CBOR. What varies is whether it is
/// valid for the key it is planted under, and §4.2 requires the repeat to
/// be reported without that ever being determined.
fn second_copy(shape: Shape, original: &Value) -> Value {
    match shape {
        // Clones the value already under the key, so the row breaks §6.2
        // rule 5 and nothing else. The base case the others are measured
        // against.
        Shape::WellTyped => original.clone(),
        // Wrong for every key this corpus repeats: each is a byte string
        // or an unsigned integer.
        Shape::WrongType => Value::Text("not the type this key requires".into()),
        // Right type, too wide for the key's declared `u32`. Only planted
        // under `kdf_params.iterations`; see `Shape::OutOfRange`.
        Shape::OutOfRange => Value::Integer((1u64 << 40).into()),
        // A well-typed, in-range `u8` naming a manifest version v1 does
        // not speak. Only planted under `manifest_version`.
        Shape::BadVersion => Value::Integer(7u64.into()),
        Shape::Float => Value::Float(3.5),
        // Tag 1 (RFC 8949 epoch time) over an integer: a well-formed tag,
        // so the body is rejected for BEING tagged, not for being
        // malformed.
        Shape::Tag => Value::Tag(1, Box::new(Value::Integer(1_700_000_000u64.into()))),
        Shape::Control => unreachable!("the control plants nothing"),
    }
}

/// The map a level names, as a mutable entry list.
///
/// Every array index comes from [`Level::elem`] rather than being written
/// here, so a level whose doc says element 0 cannot plant in element 1.
/// The one index NOT from that table is the enclosing `blocks[1]` for
/// [`Level::BlockSummary`], which is the block [`Level::Block`] itself
/// plants in; `elem` names the index within a level's OWN array.
fn target_map(root: &mut Value, level: Level) -> &mut Vec<(Value, Value)> {
    let elem = |lvl: Level| {
        lvl.elem()
            .unwrap_or_else(|| panic!("{lvl:?} is not inside an array"))
    };
    match level {
        Level::Top | Level::TopVersion => as_map(root),
        Level::KdfParams => as_map(field_mut(root, "kdf_params")),
        Level::VectorClock => as_map(array_elem_mut(field_mut(root, "vector_clock"), elem(level))),
        Level::Block => as_map(array_elem_mut(field_mut(root, "blocks"), elem(level))),
        Level::Trash => as_map(array_elem_mut(field_mut(root, "trash"), elem(level))),
        Level::BlockSummary => {
            let block = array_elem_mut(field_mut(root, "blocks"), Level::Block.elem().unwrap());
            as_map(array_elem_mut(
                field_mut(block, "vector_clock_summary"),
                elem(level),
            ))
        }
    }
}

fn as_map(v: &mut Value) -> &mut Vec<(Value, Value)> {
    match v {
        Value::Map(m) => m,
        other => panic!("expected a map, got {other:?}"),
    }
}

fn field_mut<'a>(v: &'a mut Value, key: &str) -> &'a mut Value {
    as_map(v)
        .iter_mut()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, val)| val)
        .unwrap_or_else(|| panic!("no key {key:?} in this map"))
}

fn array_elem_mut(v: &mut Value, index: usize) -> &mut Value {
    match v {
        Value::Array(items) => items
            .get_mut(index)
            .unwrap_or_else(|| panic!("array has no element {index}")),
        other => panic!("expected an array, got {other:?}"),
    }
}

/// Build one row's bytes.
///
/// The repeat is inserted IMMEDIATELY AFTER the key it repeats, so the
/// entry list stays non-decreasing and the row's only planted faults are
/// the repeat and whatever the second copy carries. Appending at the end
/// would additionally break §6.2 rule 1 (map-key order) and muddy what
/// the row is evidence for.
pub fn body_for(case: &Case) -> PlantedBody {
    let baseline = baseline_bytes();
    let mut root: Value = ciborium::de::from_reader(&baseline[..]).expect("parse baseline");

    let dup_index = match case.shape {
        Shape::Control => None,
        shape => {
            let key = case.level.key();
            let entries = target_map(&mut root, case.level);
            let at = entries
                .iter()
                .position(|(k, _)| k.as_text() == Some(key))
                .unwrap_or_else(|| panic!("no key {key:?} to repeat in {:?}", case.level));
            let copy = second_copy(shape, &entries[at].1);
            entries.insert(at + 1, (Value::Text(key.into()), copy));
            Some(at + 1)
        }
    };

    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&root, &mut bytes).expect("re-encode the planted body");
    PlantedBody { bytes, dup_index }
}
