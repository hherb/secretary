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
