//! Committed seeds for crypto-design §6.2 rule 6 (#667): the generator, the
//! check that binds every committed seed to its row, and the pin that keeps
//! `ciborium`'s recursion limit equal to the spec's on every decode path that
//! still relies on it. See `nesting_depth_seeds_helpers` for the table.
//!
//! The Python half of the binding is conformance Section NDL, check 6.

mod nesting_depth_seeds_helpers;

use std::collections::{BTreeMap, BTreeSet};

use nesting_depth_seeds_helpers::{
    all_cases, base, entries, map, observe, seed_dir, NestingCase, Observed, Placement, Verdict,
    EXPECTED_CASE_COUNT, SEEDED_TARGETS, SEED_PREFIX,
};
use secretary_core::cbor::{CborErrorKind, CborFault, V1_MAX_NESTING_DEPTH};

/// How to regenerate, quoted in every failure that needs it.
const REGENERATE: &str = "cargo test --release --locked -p secretary-core --test \
                          nesting_depth_seeds -- --ignored generate_nesting_depth_seeds";
/// Major 5 with one entry, the one-byte text `"k"`: the head of the document
/// the path pin nests below.
const ONE_ENTRY_MAP_AND_KEY: [u8; 3] = [0xa1, 0x61, b'k'];
const ARRAY_1: u8 = 0x81;
const UINT_0: u8 = 0x00;

fn assert_rust_answers_its_verdict(case: &NestingCase, bytes: &[u8]) {
    let got = observe(case.target, bytes);
    let ok = match (case.verdict(), &got) {
        (Verdict::Accept, Observed::Accepted) => true,
        // On the record path the byte walk must answer (it reports an offset;
        // ciborium does not), so the Rust walk's enforcement is pinned here too.
        (Verdict::TooDeep, Observed::TooDeep { offset }) => {
            case.target != "record" || offset.is_some()
        }
        _ => false,
    };
    assert!(
        ok,
        "seed {} for {}: Rust answered {got:?}, the row expects {:?}",
        case.file_name(),
        case.target,
        case.verdict()
    );
}

fn assert_each_target_plants_distinct_bytes<'a>(
    built: impl Iterator<Item = (&'a NestingCase, &'a [u8])>,
) {
    let mut planted: BTreeMap<(&str, &[u8]), String> = BTreeMap::new();
    for (case, bytes) in built {
        if let Some(other) = planted.insert((case.target, bytes), case.file_name()) {
            panic!(
                "target {}: seeds {other} and {} plant identical bytes",
                case.target,
                case.file_name()
            );
        }
    }
}

#[test]
fn the_case_table_holds_every_expected_row() {
    assert_eq!(all_cases().len(), EXPECTED_CASE_COUNT);
}

/// Every target commits the boundary PAIR (accept at the limit, refuse one
/// past it), and a known-key row only past the limit, where it cannot be
/// answered by the type check.
#[test]
fn every_target_carries_the_boundary_pair() {
    let cases = all_cases();
    for target in SEEDED_TARGETS {
        for depth in [V1_MAX_NESTING_DEPTH, V1_MAX_NESTING_DEPTH + 1] {
            assert!(
                cases.iter().any(|c| c.target == *target
                    && c.depth == depth
                    && c.placement == Placement::Unknown),
                "{target} has no unknown-key row at depth {depth}"
            );
        }
    }
    for case in cases.iter().filter(|c| c.placement == Placement::KnownTags) {
        assert_eq!(case.verdict(), Verdict::TooDeep, "{}", case.file_name());
    }
}

#[test]
fn reassembling_each_base_is_byte_identical() {
    for target in SEEDED_TARGETS {
        let bytes = base(target);
        assert_eq!(
            map(&entries(&bytes)),
            bytes,
            "{target}: the entry split must round-trip"
        );
    }
}

#[test]
fn every_seed_label_is_unique() {
    let cases = all_cases();
    let labels: BTreeSet<(&str, String)> =
        cases.iter().map(|c| (c.target, c.file_name())).collect();
    assert_eq!(
        labels.len(),
        cases.len(),
        "two rows share a target and file name"
    );
}

#[test]
fn nesting_depth_seeds_are_committed_and_label_bound() {
    let cases = all_cases();
    let built: Vec<Vec<u8>> = cases.iter().map(NestingCase::bytes).collect();
    assert_each_target_plants_distinct_bytes(cases.iter().zip(built.iter().map(Vec::as_slice)));
    for (case, want) in cases.iter().zip(&built) {
        assert!(
            SEEDED_TARGETS.contains(&case.target),
            "{} names an unowned target",
            case.file_name()
        );
        assert_rust_answers_its_verdict(case, want);
        let committed = std::fs::read(case.path()).unwrap_or_else(|e| {
            panic!(
                "seed {} is not committed ({e}); run `{REGENERATE}`",
                case.path().display()
            )
        });
        assert!(
            committed == *want,
            "seed {} differs from what its row plants: regenerate deliberately with `{REGENERATE}`",
            case.path().display()
        );
    }
    for target in SEEDED_TARGETS {
        let on_disk: BTreeSet<String> = std::fs::read_dir(seed_dir(target))
            .unwrap_or_else(|e| panic!("list seeds for {target}: {e}"))
            .map(|entry| {
                entry
                    .expect("a directory entry")
                    .file_name()
                    .into_string()
                    .expect("UTF-8")
            })
            .filter(|name| name.starts_with(SEED_PREFIX))
            .collect();
        let declared: BTreeSet<String> = cases
            .iter()
            .filter(|c| c.target == *target)
            .map(NestingCase::file_name)
            .collect();
        assert_eq!(
            on_disk, declared,
            "target {target}: committed `{SEED_PREFIX}` seeds and the table disagree"
        );
    }
}

/// Writes every seed, after every row has been built and asserted (#614).
#[test]
#[ignore]
fn generate_nesting_depth_seeds() {
    let cases = all_cases();
    let built: Vec<Vec<u8>> = cases.iter().map(NestingCase::bytes).collect();
    assert_each_target_plants_distinct_bytes(cases.iter().zip(built.iter().map(Vec::as_slice)));
    for (case, bytes) in cases.iter().zip(&built) {
        assert_rust_answers_its_verdict(case, bytes);
    }
    for (case, bytes) in cases.iter().zip(built) {
        let path = case.path();
        std::fs::write(&path, bytes).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    }
}

const ARRAY_INDEFINITE: u8 = 0x9f;
const MAP_1: u8 = 0xa1;
const TAG_1: u8 = 0xc1;
const BREAK: u8 = 0xff;
/// Major 6, tag number 2: a positive bignum (RFC 8949 §3.4.3).
const TAG_BIGNUM_POSITIVE: u8 = 0xc2;
/// Major 2 (byte string) with additional-info 0: the base a definite
/// byte-string head of a given length is derived from below, so a head can
/// never disagree with the payload length actually written after it.
const MAJOR_BYTES_BASE: u8 = 0x40;
/// The narrow bignum payload width: it fits in 64 bits, so `ciborium`
/// 0.2.2 folds the whole tag into an integer and charges it no nesting
/// level at all (#666).
const BIGNUM_NARROW_PAYLOAD_LEN: usize = 1;
/// The wide bignum payload width: one byte past the eight that fit a
/// `u64`, so `ciborium` 0.2.2 keeps it a `Value::Tag` instead of folding it
/// -- but a kept tag is still charged no level by ciborium's own recursion
/// counting, only by the byte walk.
const BIGNUM_WIDE_PAYLOAD_LEN: usize = 9;
/// Major 2, additional-info [`BIGNUM_NARROW_PAYLOAD_LEN`]: a definite byte
/// string of that length.
const BYTES_1: u8 = MAJOR_BYTES_BASE | BIGNUM_NARROW_PAYLOAD_LEN as u8;
/// Major 2, additional-info [`BIGNUM_WIDE_PAYLOAD_LEN`]: a definite byte
/// string of that length.
const BYTES_9: u8 = MAJOR_BYTES_BASE | BIGNUM_WIDE_PAYLOAD_LEN as u8;
/// The bignum payload byte, repeated for both widths.
const BIGNUM_PAYLOAD_BYTE: u8 = 0x01;

/// The shapes a level can take. Rule 6 charges each alike, and an upgrade to
/// the parser could change how it charges one shape while still charging
/// arrays -- ciborium already exempts one tag shape (#666).
#[derive(Clone, Copy, Debug)]
enum Chain {
    /// A one-entry map whose value holds `depth - 1` one-element arrays.
    Arrays,
    /// The same, with the last level a tag instead of an array.
    TagLast,
    /// A one-entry map whose value holds `depth - 1` indefinite arrays.
    IndefiniteArrays,
    /// `depth` one-entry maps, each the KEY of the one outside it.
    MapKeys,
    /// The same shape as `TagLast`, but the last level is a positive bignum
    /// tag over a 1-byte string -- the width `ciborium` 0.2.2 folds into an
    /// integer, so its own recursion count charges the tag no level (#666).
    BignumNarrowLast,
    /// The same, over a 9-byte string -- wide enough that `ciborium` keeps
    /// it a `Value::Tag` rather than folding it, but its recursion count
    /// still charges the tag no level either way.
    BignumWideLast,
}

/// A `depth`-level document of `shape`. It need not be a valid document of
/// any kind; a scalar at the bottom is not a level.
fn nested_document(depth: usize, shape: Chain) -> Vec<u8> {
    let mut body = Vec::new();
    match shape {
        Chain::Arrays
        | Chain::TagLast
        | Chain::IndefiniteArrays
        | Chain::BignumNarrowLast
        | Chain::BignumWideLast => {
            body.extend(ONE_ENTRY_MAP_AND_KEY);
            let (open, inner) = match shape {
                Chain::IndefiniteArrays => (ARRAY_INDEFINITE, depth - 1),
                Chain::TagLast | Chain::BignumNarrowLast | Chain::BignumWideLast => {
                    (ARRAY_1, depth - 2)
                }
                _ => (ARRAY_1, depth - 1),
            };
            body.extend(std::iter::repeat_n(open, inner));
            match shape {
                Chain::TagLast => {
                    body.push(TAG_1);
                    body.push(UINT_0);
                }
                Chain::BignumNarrowLast => {
                    body.push(TAG_BIGNUM_POSITIVE);
                    body.push(BYTES_1);
                    body.extend(std::iter::repeat_n(
                        BIGNUM_PAYLOAD_BYTE,
                        BIGNUM_NARROW_PAYLOAD_LEN,
                    ));
                }
                Chain::BignumWideLast => {
                    body.push(TAG_BIGNUM_POSITIVE);
                    body.push(BYTES_9);
                    body.extend(std::iter::repeat_n(
                        BIGNUM_PAYLOAD_BYTE,
                        BIGNUM_WIDE_PAYLOAD_LEN,
                    ));
                }
                _ => body.push(UINT_0),
            }
            if let Chain::IndefiniteArrays = shape {
                body.extend(std::iter::repeat_n(BREAK, inner));
            }
        }
        Chain::MapKeys => {
            body.extend(std::iter::repeat_n(MAP_1, depth));
            body.extend(std::iter::repeat_n(UINT_0, depth + 1));
        }
    }
    body
}

/// crypto-design §6.2 rule 6 on every CBOR decode path, in every level shape.
///
/// **Only two of the five paths still pin `ciborium` 0.2.2's own recursion
/// limit**: `ContactCard::from_canonical_cbor` and
/// `IdentityBundle::from_canonical_cbor`. An upgrade that moved ciborium's
/// limit -- or stopped charging a tag or an indefinite container -- would
/// move the spec's limit silently on THOSE TWO, and that is what reds here.
/// The other three -- `decode_manifest`, `block::decode_plaintext` and
/// `record::decode` -- now run the byte walk (`cbor::well_formed`) ahead of
/// ciborium, so they pin the walk's own limit, which answers before ciborium
/// ever sees the body. **This NARROWS what this test proves about
/// ciborium**: a silent ciborium-limit move used to be caught by four paths
/// here and is now caught by two -- do not read the five-row loop below as
/// unchanged ciborium coverage.
///
/// A depth-256 body must fail for any reason other than `RecursionLimit` (it
/// is not a valid document), and a depth-257 body must fail with it.
/// (ciborium charges no level for a bignum over a definite-length byte
/// string of at most 16 bytes; that edge is #666's, scoped to the three walk
/// paths in `the_walk_paths_charge_a_level_for_a_short_bignum` below, since
/// the two ciborium-backed paths do not refuse it for depth at all.)
#[test]
fn every_decode_path_enforces_exactly_the_v1_limit() {
    use secretary_core::identity::card::{CardError, ContactCard};
    use secretary_core::unlock::bundle::{BundleError, IdentityBundle};
    use secretary_core::vault::block::{decode_plaintext, BlockError};
    use secretary_core::vault::manifest::{decode_manifest, ManifestError};
    use secretary_core::vault::record::{decode, RecordError};

    type FaultOf = fn(&[u8]) -> Option<CborFault>;
    let paths: [(&str, FaultOf); 5] = [
        ("decode_manifest", |b| match decode_manifest(b) {
            Err(ManifestError::CborDecode(f)) => Some(f),
            _ => None,
        }),
        ("block::decode_plaintext", |b| match decode_plaintext(b) {
            Err(BlockError::CborDecode(f)) => Some(f),
            _ => None,
        }),
        (
            "ContactCard::from_canonical_cbor",
            |b| match ContactCard::from_canonical_cbor(b) {
                Err(CardError::CborDecode(f)) => Some(f),
                _ => None,
            },
        ),
        (
            "IdentityBundle::from_canonical_cbor",
            |b| match IdentityBundle::from_canonical_cbor(b) {
                Err(BundleError::CborFault(f)) => Some(f),
                _ => None,
            },
        ),
        ("record::decode", |b| match decode(b) {
            Err(RecordError::CborDecode(f)) => Some(f),
            _ => None,
        }),
    ];
    let limit_kind = Some(CborErrorKind::RecursionLimit);
    let shapes = [
        Chain::Arrays,
        Chain::TagLast,
        Chain::IndefiniteArrays,
        Chain::MapKeys,
    ];
    for (name, fault_of) in paths {
        for shape in shapes {
            assert_ne!(
                fault_of(&nested_document(V1_MAX_NESTING_DEPTH, shape)).map(|f| f.kind),
                limit_kind,
                "{name} refuses a {shape:?} chain of depth {V1_MAX_NESTING_DEPTH}, which rule 6 allows"
            );
            assert_eq!(
                fault_of(&nested_document(V1_MAX_NESTING_DEPTH + 1, shape)).map(|f| f.kind),
                limit_kind,
                "{name} does not refuse a {shape:?} chain of depth {} with RecursionLimit",
                V1_MAX_NESTING_DEPTH + 1
            );
        }
    }
}

/// ciborium charges NO nesting level for a bignum tag over a definite-length
/// byte string of at most 16 bytes, so before #666 a document whose 257th
/// level was one slipped past the limit on every path that relied on
/// ciborium: the narrow form (value fits 64 bits) was folded to an integer
/// and reported by the re-encode, the wide form stayed a `Value::Tag` and
/// was reported as rule 4. Both are depth faults, and the byte walk charges
/// a level for a tag like any other container.
///
/// Scoped to the three WALK paths on purpose. `ContactCard` and
/// `IdentityBundle` still rely on ciborium and still do NOT refuse these
/// bodies for depth; that is #641's and #677's, not a gap this test hides.
#[test]
fn the_walk_paths_charge_a_level_for_a_short_bignum() {
    use secretary_core::vault::block::{decode_plaintext, BlockError};
    use secretary_core::vault::manifest::{decode_manifest, ManifestError};
    use secretary_core::vault::record::{decode, RecordError};

    type FaultOf = fn(&[u8]) -> Option<CborFault>;
    let paths: [(&str, FaultOf); 3] = [
        ("decode_manifest", |b| match decode_manifest(b) {
            Err(ManifestError::CborDecode(f)) => Some(f),
            _ => None,
        }),
        ("block::decode_plaintext", |b| match decode_plaintext(b) {
            Err(BlockError::CborDecode(f)) => Some(f),
            _ => None,
        }),
        ("record::decode", |b| match decode(b) {
            Err(RecordError::CborDecode(f)) => Some(f),
            _ => None,
        }),
    ];
    for (name, fault_of) in paths {
        for shape in [Chain::BignumNarrowLast, Chain::BignumWideLast] {
            assert_ne!(
                fault_of(&nested_document(V1_MAX_NESTING_DEPTH, shape)).map(|f| f.kind),
                Some(CborErrorKind::RecursionLimit),
                "{name} refuses a {shape:?} chain of depth {V1_MAX_NESTING_DEPTH}, which rule 6 allows"
            );
            assert_eq!(
                fault_of(&nested_document(V1_MAX_NESTING_DEPTH + 1, shape)).map(|f| f.kind),
                Some(CborErrorKind::RecursionLimit),
                "{name} does not refuse a {shape:?} chain of depth {} with RecursionLimit",
                V1_MAX_NESTING_DEPTH + 1
            );
        }
    }
}
