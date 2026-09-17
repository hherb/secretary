//! Committed seeds for #669's value-type ACCEPTANCE divergences: the
//! generator, and the check that binds every committed seed to its row.
//!
//! See `acceptance_seeds_helpers` for the table and for why this is a separate
//! generator from `rule_token_seeds.rs` rather than more rows in it, and
//! `docs/superpowers/specs/2026-09-16-value-type-discipline-design.md` §6.
//!
//! The Python half of the binding is conformance Section VT.

mod acceptance_seeds_helpers;

use std::collections::{BTreeMap, BTreeSet};

use acceptance_seeds_helpers::{
    all_cases, base, rust_rejection, seed_dir, sub_value, AcceptanceCase,
    EXPECTED_ACCEPTANCE_CASE_COUNT, SEEDED_TARGETS, SEED_PREFIX,
};

/// How to regenerate, quoted in every failure that needs it.
const REGENERATE: &str = "cargo test --release --locked -p secretary-core --test \
                          acceptance_seeds -- --ignored generate_acceptance_seeds";

/// The table must not shrink unnoticed.
///
/// `acceptance_seeds_are_committed_and_label_bound` is a two-way census, so a
/// row-only or file-only deletion is loud — but a MATCHED deletion of a row
/// AND its committed seed shrinks both sides together and passes, having
/// asserted nothing about that position. The Python half floors itself with
/// `EXPECTED_CASE_COUNT`; this is its twin (#679 review).
#[test]
fn the_case_table_holds_every_expected_row() {
    assert_eq!(
        all_cases().len(),
        EXPECTED_ACCEPTANCE_CASE_COUNT,
        "the acceptance-case table holds {} rows, expected {}. A row and its seed \
         deleted together are invisible to the two-way census; if this change is \
         deliberate, move the constant.",
        all_cases().len(),
        EXPECTED_ACCEPTANCE_CASE_COUNT,
    );
}

/// Every base must be ACCEPTED, or every row below would be satisfied by a
/// decoder that rejects everything — the vacuity Section VT's check 2 closes
/// on the Python side, closed here on the Rust side for the same reason.
#[test]
fn every_seed_base_is_accepted() {
    for target in SEEDED_TARGETS {
        let rejection = rust_rejection(target, &base(target));
        assert_eq!(
            rejection, None,
            "the {target} seed base must be ACCEPTED, or its seeds prove nothing; \
             the Rust decoder rejected it with {rejection:?}"
        );
    }
}

/// Substituting NOTHING must reproduce the base byte for byte.
///
/// Every CBOR row is built by parsing the base, replacing one value and
/// re-encoding. If that round trip were not an identity, a seed would differ
/// from its base in places nobody planted, and "one planted fault" would be a
/// claim rather than a measurement — which is what every row's single-fault
/// premise rests on.
#[test]
fn the_cbor_round_trip_is_an_identity_on_every_base() {
    for target in ["contact_card", "manifest_body"] {
        let bytes = base(target);
        assert_eq!(
            sub_value(&bytes, &[], ciborium::de::from_reader(&bytes[..]).unwrap()),
            bytes,
            "{target}: parsing and re-encoding its base is not byte-identical, so a \
             planted seed would carry faults nobody planted"
        );
    }
}

fn assert_rust_names_its_variant(case: &AcceptanceCase, bytes: &[u8]) {
    let got = rust_rejection(case.target, bytes);
    assert_eq!(
        got.as_deref(),
        Some(case.variant),
        "seed {} for {}: the Rust decoder answered {got:?}, its row says {:?}",
        case.file_name(),
        case.target,
        case.variant,
    );
}

/// Every row of a target plants DIFFERENT bytes.
///
/// Nothing else requires it: the file names, variants and census are all
/// unchanged when several rows are pointed at one plant, and the PR #673
/// review measured exactly that collapse passing a sibling corpus's checks.
fn assert_each_target_plants_distinct_bytes<'a>(
    built: impl Iterator<Item = (&'a AcceptanceCase, &'a [u8])>,
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
fn acceptance_seeds_are_committed_and_label_bound() {
    let cases = all_cases();
    let built: Vec<Vec<u8>> = cases.iter().map(AcceptanceCase::bytes).collect();
    assert_each_target_plants_distinct_bytes(cases.iter().zip(built.iter().map(Vec::as_slice)));

    for (case, want) in cases.iter().zip(&built) {
        assert!(
            SEEDED_TARGETS.contains(&case.target),
            "row {} names target {}, which SEEDED_TARGETS does not own",
            case.file_name(),
            case.target
        );
        assert_rust_names_its_variant(case, want);
        let committed = std::fs::read(case.path()).unwrap_or_else(|e| {
            panic!(
                "seed {} is not committed ({e}); run `{REGENERATE}`",
                case.path().display()
            )
        });
        assert!(
            committed == *want,
            "seed {} differs from what its row plants: regenerate deliberately with \
             `{REGENERATE}`, or fix the row",
            case.path().display()
        );
    }

    // Both directions, scoped to the prefix this table owns. `manifest_body/`
    // also holds 38 seeds from three other generators; claiming every file
    // whose name contains `__`, as `rule_token_seeds.rs` does for its own
    // targets, would claim those too.
    for target in SEEDED_TARGETS {
        let on_disk: BTreeSet<String> = std::fs::read_dir(seed_dir(target))
            .unwrap_or_else(|e| panic!("list seeds for {target}: {e}"))
            .map(|entry| {
                entry
                    .expect("read a seed directory entry")
                    .file_name()
                    .into_string()
                    .expect("seed file names are UTF-8")
            })
            .filter(|name| name.starts_with(SEED_PREFIX))
            .collect();
        let declared: BTreeSet<String> = cases
            .iter()
            .filter(|c| c.target == *target)
            .map(AcceptanceCase::file_name)
            .collect();
        assert_eq!(
            on_disk, declared,
            "target {target}: the committed `{SEED_PREFIX}` seeds and the case table disagree"
        );
    }
}

/// Writes every seed. Every row is built and asserted BEFORE anything is
/// written, so a failing row leaves every file untouched (#614's lesson).
#[test]
#[ignore]
fn generate_acceptance_seeds() {
    let cases = all_cases();
    let built: Vec<Vec<u8>> = cases.iter().map(AcceptanceCase::bytes).collect();
    assert_each_target_plants_distinct_bytes(cases.iter().zip(built.iter().map(Vec::as_slice)));
    for (case, bytes) in cases.iter().zip(&built) {
        assert_rust_names_its_variant(case, bytes);
    }
    for (case, bytes) in cases.iter().zip(built) {
        let path = case.path();
        std::fs::write(&path, bytes).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    }
}
