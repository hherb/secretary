//! Cross-language rejection-PRECEDENCE corpus for the manifest body (#618).
//!
//! # What this corpus is for
//!
//! A manifest body can break more than one rule at once. Both the Rust
//! decoder and `conformance.py`'s clean-room reader then reject it -- so
//! nothing here is a safety property -- but until `docs/vault-format.md`
//! §4.2 gained its precedence paragraph, nothing said WHICH rule either
//! was required to report, and the two disagreed.
//!
//! The property this pins, in §4.2's words:
//!
//! 1. **crypto-design §6.2 rule 4** (no tags, no floats) is enforced by a
//!    walk of the WHOLE body that completes before any key is
//!    interpreted, so it outranks everything below.
//! 2. **A repeated map key** is reported without interpreting its second
//!    copy, so it outranks the type, range and version checks on that
//!    key's value.
//!
//! Rules 1, 2 and 3 are deliberately absent from that ordering, and §4.2
//! says why: a reader whose parse normalises encoding-level choices can
//! only detect them at the §4.3 step-4 re-encode, which necessarily runs
//! after interpretation, while a byte-retaining reader must detect them
//! during its scan, before it. Fixing an order between those and the two
//! rules above would outlaw one of the two reader architectures §4.2
//! itself admits.
//!
//! **So this corpus carries no row pairing a repeat with a rule 1-3
//! violation**, and adding one would make it reject a conformant reader.
//! An earlier revision did carry one; see `Shape`'s doc for what replaced
//! it and why a local assertion pins that property better than a
//! cross-language row could.
//!
//! # Why it is a corpus and not two unit tests
//!
//! Rust pinned point 2 from #589 onward (`Once::set` takes a closure so
//! the fill cannot run on an occupied slot) and point 1 from v1 onward
//! (`reject_floats_and_tags` runs before `parse_manifest_map`). Neither
//! was in `docs/`, `conformance.py` agreed with point 2 only by
//! construction and DISAGREED with point 1, and `differential_replay.rs`
//! cannot see any of it -- it scores reject-vs-reject as agreement
//! without comparing the reported rule (#618). A clean-room implementer
//! reading `docs/` alone had nothing to implement.
//!
//! # Reading the fixture
//!
//! One row per `(map, second-copy shape)` pair plus one accept control.
//! `expect` is a closed three-word vocabulary; `field` names the repeated
//! key on the rows that report one; `dup_index` is Rust-only, since §4.2
//! requires no ordinal and `conformance.py` reports none.

mod manifest_precedence_kat_helpers;

use secretary_core::vault::manifest::decode_manifest;

use manifest_precedence_kat_helpers::assert::assert_precedence;
use manifest_precedence_kat_helpers::build::body_for;
use manifest_precedence_kat_helpers::cases::{all_cases, Expect, Level, Shape};
use manifest_precedence_kat_helpers::fixture_path;

/// The committed fixture, as a list of rows.
fn rows() -> Vec<serde_json::Value> {
    let path = fixture_path();
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let doc: serde_json::Value = serde_json::from_str(&text).expect("fixture is JSON");
    doc["rows"]
        .as_array()
        .expect("fixture has a `rows` array")
        .clone()
}

fn field_str<'a>(row: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    match &row[key] {
        serde_json::Value::Null => None,
        v => Some(
            v.as_str()
                .unwrap_or_else(|| panic!("{key} must be a string")),
        ),
    }
}

/// Every committed row is replayed through `decode_manifest`, and the
/// verdict must be exactly what its `expect` column declares.
#[test]
fn manifest_precedence_kat_replays() {
    let rows = rows();
    assert_eq!(
        rows.len(),
        all_cases().len(),
        "the fixture must hold one row per case; regenerate it"
    );

    for row in &rows {
        let label = row["label"].as_str().expect("label");
        let bytes = hex::decode(row["manifest_body_hex"].as_str().expect("hex"))
            .unwrap_or_else(|e| panic!("row {label}: bad hex: {e}"));
        let expect = expect_of(row, label);
        let dup_index = row["dup_index"].as_u64().map(|n| n as usize);

        assert_precedence(
            label,
            expect,
            field_str(row, "field"),
            dup_index,
            &decode_manifest(&bytes),
        );
    }
}

/// Reconstruct a row's `Expect` from its `expect` column, rejecting an
/// unrecognised word rather than treating it as "no expectation".
///
/// The `field` column is checked here too, because the pairing is what
/// carries meaning: `duplicate_key` without a key to name would degrade to
/// "rejected as a duplicate of something", and every other word forbids
/// one.
fn expect_of(row: &serde_json::Value, label: &str) -> Expect {
    let want = row["expect"].as_str().expect("expect column");
    let field = field_str(row, "field");
    let expect = match want {
        "accept" => Expect::Accept,
        "duplicate_key" => Expect::DuplicateKey,
        "rule4" => Expect::Rule4,
        other => panic!(
            "row {label}: unrecognised expect {other:?}; the closed vocabulary is {:?}",
            Expect::ALL_NAMES
        ),
    };
    assert_eq!(
        field.is_some(),
        expect == Expect::DuplicateKey,
        "row {label}: a `field` column is required exactly when `expect` is \
         duplicate_key, and forbidden otherwise"
    );
    expect
}

/// A row's BYTES must be the ones its label describes.
///
/// Every other assertion in this file is derived from the label or the
/// columns, so without this the bodies are unconstrained: #614's review
/// measured that replacing a canonicality corpus's nested-level bodies
/// with their top-level counterparts left both languages GREEN, silently
/// collapsing a "N shapes x M levels" premise to one level. `body_for` is
/// the single implementation of the plant, used by the generator and
/// here, so a row's bytes cannot drift from what produced them.
#[test]
fn every_row_body_matches_the_case_its_label_names() {
    let rows = rows();
    for case in all_cases() {
        let label = case.label();
        let row = rows
            .iter()
            .find(|r| r["label"].as_str() == Some(label.as_str()))
            .unwrap_or_else(|| panic!("no fixture row labelled {label}"));
        let committed = hex::decode(row["manifest_body_hex"].as_str().expect("hex")).expect("hex");
        assert_eq!(
            committed,
            body_for(&case).bytes,
            "row {label}: the committed body is not the one this case plants"
        );
    }
}

/// Every column a row declares must be the one the CASE TABLE derives.
///
/// Without this the fixture is SELF-CERTIFYING: `manifest_precedence_kat_replays`
/// checks the fixture against the decoder and `every_row_body_matches_the_case_
/// its_label_names` checks its bytes, but nothing checked its EXPECTATION
/// against `cases.rs` -- the file that states what §4.2 requires. A change to
/// the decoder's precedence plus a regenerated fixture would simply become the
/// new contract, and both languages would agree with the edit. Measured before
/// this existed: `Case::expect` and `Case::field` were reachable only from the
/// `#[ignore]`d generator, so no test running under `cargo test` consulted the
/// table at all.
///
/// The same assertion `manifest_canonicality_kat.rs` makes for its
/// `expect_cause` column, and for the reason its comment gives there.
#[test]
fn every_row_matches_the_case_table() {
    let rows = rows();
    for case in all_cases() {
        let label = case.label();
        let row = rows
            .iter()
            .find(|r| r["label"].as_str() == Some(label.as_str()))
            .unwrap_or_else(|| panic!("no fixture row labelled {label}"));

        let hand_edited = |column: &str| {
            format!(
                "row {label}: the fixture's `{column}` disagrees with the case table -- \
                 the row was hand-edited, or the table changed without regenerating it"
            )
        };
        assert_eq!(
            row["expect"].as_str(),
            Some(case.expect().name()),
            "{}",
            hand_edited("expect")
        );
        assert_eq!(
            field_str(row, "field"),
            case.field(),
            "{}",
            hand_edited("field")
        );
        assert_eq!(
            field_str(row, "map"),
            case.map_label(),
            "{}",
            hand_edited("map")
        );
        assert_eq!(
            row["dup_index"].as_u64().map(|n| n as usize),
            body_for(&case).dup_index,
            "{}",
            hand_edited("dup_index")
        );
    }
}

/// Nested repeats are planted at BOTH ends of their arrays.
///
/// #608's review measured that a corpus planting only in `blocks[1]` leaves
/// `for block in blocks.iter().skip(1)` fully conformant -- the mirror image of
/// the element-0-scoped reader that planting in element 1 does catch. A corpus
/// that plants every nested repeat at one end covers one direction and reads as
/// if it covered both.
#[test]
fn both_array_ends_are_planted() {
    let planted: Vec<usize> = Level::ALL.iter().filter_map(|l| l.elem()).collect();
    assert!(
        planted.contains(&0) && planted.contains(&1),
        "every nested level plants in element {planted:?}: a reader scoped to the \
         other end of these arrays would be conformant against this corpus"
    );
}

/// No two levels share BOTH the map they name and the key they repeat.
///
/// Neither column identifies a level alone -- `block` and `trash` repeat the
/// same key, and the two top-level levels are the same map -- so it is the PAIR
/// that has to be unique. Section MPR discriminates a row's level by exactly
/// that pair, and a collision would make two levels' bodies interchangeable on
/// the clean-room side.
#[test]
fn every_level_is_identified_by_its_map_and_key() {
    let mut seen = std::collections::BTreeSet::new();
    for level in Level::ALL {
        assert!(
            seen.insert((level.map_label(), level.key())),
            "{level:?} shares its (map, key) pair with an earlier level, so Section \
             MPR cannot tell their rows apart"
        );
    }
}

/// The corpus reaches every map the decoder parses and every shape the
/// table declares.
///
/// A floor, not a restatement of `all_cases`: it fails if a level or a
/// shape is quietly dropped from the product, which `rows.len()` alone
/// would not catch once a row were added elsewhere.
#[test]
fn the_corpus_covers_every_level_and_every_planted_shape() {
    let rows = rows();
    let labels: Vec<&str> = rows.iter().filter_map(|r| r["label"].as_str()).collect();

    for level in Level::ALL {
        for shape in Shape::PLANTED {
            let want = format!("{}__{}", level.label(), shape.label());
            assert!(
                labels.contains(&want.as_str()),
                "the corpus has no row {want}: a reader scoped to the levels or shapes \
                 that ARE present would be conformant against it"
            );
        }
    }
    assert!(
        labels.contains(&"control__no_repeat"),
        "without the accept control, a reader that rejected every body would score \
         a perfect result"
    );
    // Outside the product on purpose (each needs a key the other levels
    // lack), so `Shape::PLANTED` above does not require them and nothing
    // else would notice one going missing.
    for want in ["kdf_params__out_of_range", "top_version__bad_version"] {
        assert!(
            labels.contains(&want),
            "the corpus has no row {want}: §4.2's second ordering names the type, \
             RANGE and VERSION checks, and without this row that ordering is \
             enumerated for the type check alone"
        );
    }
}

/// Each `expect` word is exercised by at least one row.
///
/// Defence in depth against a table that compiles but reaches only part
/// of its own vocabulary -- the gap #613 found in the canonicality
/// corpus, where two of four `NonCanonicalCause` variants had no row.
#[test]
fn every_expect_word_has_at_least_one_row() {
    let rows = rows();
    for want in Expect::ALL_NAMES {
        assert!(
            rows.iter().any(|r| r["expect"].as_str() == Some(want)),
            "no row expects {want:?}, so nothing pins that half of §4.2's precedence \
             paragraph"
        );
    }
}
