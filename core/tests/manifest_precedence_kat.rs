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
//! `expect` is a closed four-word vocabulary; `field` names the repeated
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
    // Outside the product on purpose (see `Shape::NonShortest`), so
    // `Shape::PLANTED` above does not require it and nothing else would
    // notice it going missing.
    assert!(
        labels.contains(&"top__non_shortest"),
        "the corpus has no top__non_shortest row: nothing then pins that the \
         rule-4 walk is rule-4 ONLY, and folding rules 2 and 3 into it would \
         report rule 3 where §4.2 requires the repeat"
    );
}

/// Each of the four `expect` words is exercised by at least one row.
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
