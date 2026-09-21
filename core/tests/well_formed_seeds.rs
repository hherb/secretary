//! Committed `manifest_body/wellformed__*` seeds for the well-formedness
//! walk's ciborium leniencies (#666): the generator, and the checks that
//! bind every committed seed to its row. See `well_formed_seeds_helpers` for
//! the table and the byte-sequence derivations.
//!
//! The Python half of the binding is `conformance_lib`'s `codec/well_formed.py`
//! plus its token vocabulary; the cross-language comparison itself runs
//! through `differential_replay.rs`, not this file.

mod well_formed_seeds_helpers;

use std::collections::{BTreeMap, BTreeSet};

use secretary_core::vault::manifest::decode_manifest;
use well_formed_seeds_helpers::{
    all_cases, base, body_for, file_name, seed_dir, WellFormedCase, BENIGN_UINT,
    EXPECTED_CASE_COUNT, SEED_PREFIX,
};

/// How to regenerate, quoted in every failure that needs it.
const REGENERATE: &str = "cargo test --release --locked -p secretary-core --test \
                          well_formed_seeds -- --ignored generate_well_formed_seeds";

#[test]
fn the_case_table_holds_every_expected_row() {
    assert_eq!(all_cases().len(), EXPECTED_CASE_COUNT);
}

/// Every row plants DIFFERENT bytes. Without it, three rows pointed at one
/// plant keep every name, token and census green while testing one shape —
/// the floor `rule_token_seeds.rs` added after the PR #673 review measured
/// exactly that.
#[test]
fn every_row_plants_distinct_bytes() {
    let mut planted: BTreeMap<Vec<u8>, String> = BTreeMap::new();
    for case in all_cases() {
        let name = file_name(&case);
        if let Some(other) = planted.insert(body_for(&case), name.clone()) {
            panic!("seeds {other} and {name} plant identical bytes");
        }
    }
}

/// The base still ACCEPTS, and the splice with a benign value still
/// accepts. Without this the seven rows could all be rejecting because the
/// splice itself is malformed rather than because of what they plant.
#[test]
fn the_base_and_a_benign_splice_are_both_accepted() {
    assert!(
        decode_manifest(&base()).is_ok(),
        "the committed base must decode; the corpus row it comes from says so"
    );
    let benign = WellFormedCase {
        label: "benign_control",
        planted: &BENIGN_UINT,
        token: "",
    };
    assert!(
        decode_manifest(&body_for(&benign)).is_ok(),
        "the splice itself must be canonical: zz_future is 9 bytes, so RFC 8949 \
         §4.2.1 length-first order puts it between suite_id and vault_uuid"
    );
}

/// Each committed seed is on disk, byte-identical to the body its row
/// builds, and rejected by the real decoder with the row's token.
#[test]
fn every_committed_seed_matches_its_row() {
    for case in all_cases() {
        let name = file_name(&case);
        let path = seed_dir().join(&name);
        let on_disk = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("{name}: {e}. Regenerate with: {REGENERATE}"));
        assert_eq!(
            on_disk,
            body_for(&case),
            "{name}: committed bytes differ from the row's body. {REGENERATE}"
        );
        let got = match decode_manifest(&on_disk) {
            Ok(_) => panic!("{name}: accepted, its row expects token {}", case.token),
            Err(e) => format!("{:?}", e.rule_token()),
        };
        assert_eq!(
            got.to_lowercase().replace('_', ""),
            case.token.replace('_', ""),
            "{name}: decoder said {got}, its row says {}",
            case.token
        );
    }
}

/// The two-way census: every row has a file, and every file carrying this
/// generator's prefix has a row. A row and its seed deleted together are
/// invisible to it, which is what `EXPECTED_CASE_COUNT` pins separately.
#[test]
fn the_prefix_census_is_two_way() {
    let want: BTreeSet<String> = all_cases().iter().map(file_name).collect();
    let got: BTreeSet<String> = std::fs::read_dir(seed_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .filter(|n| n.starts_with(SEED_PREFIX))
        .collect();
    assert_eq!(
        got, want,
        "committed {SEED_PREFIX} seeds differ from the table. {REGENERATE}"
    );
}

#[test]
#[ignore]
fn generate_well_formed_seeds() {
    // Assert EVERY row against the real decoder FIRST, buffering the bytes,
    // and only then write any file — so a wrong row panics with the corpus
    // untouched. This is the ordering #614's review had to fix in
    // manifest_canonicality_kat.rs, where the seed write sat INSIDE the
    // per-row loop while the fixture was written after it, so a mid-loop
    // panic left the two outputs disagreeing.
    let mut pending: Vec<(String, Vec<u8>)> = Vec::new();
    for case in all_cases() {
        let name = file_name(&case);
        let bytes = body_for(&case);
        let got = match decode_manifest(&bytes) {
            Ok(_) => panic!("{name}: accepted; its row expects token {}", case.token),
            Err(e) => format!("{:?}", e.rule_token()),
        };
        assert_eq!(
            got.to_lowercase().replace('_', ""),
            case.token.replace('_', ""),
            "{name}: decoder said {got}, its row says {}",
            case.token
        );
        pending.push((name, bytes));
    }
    for (name, bytes) in pending {
        std::fs::write(seed_dir().join(&name), &bytes).unwrap();
    }
}
