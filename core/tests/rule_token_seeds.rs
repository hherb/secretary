//! Committed single-fault seeds for the `record`, `block_file` (#641) and
//! `contact_card` (task 10, #641/#691) replay targets: the generator, and
//! the check that binds every committed seed to its label. See
//! `rule_token_seeds_helpers` for the table, and
//! `docs/superpowers/specs/2026-09-15-token-compare-record-block-design.md`
//! §6.1.
//!
//! The Python half of the binding is conformance Section RTS.

#[path = "nesting_depth_seeds_helpers/prefix.rs"]
mod nesting_depth_seed_prefix;
mod rule_token_seeds_helpers;

use std::collections::{BTreeMap, BTreeSet};

use rule_token_seeds_helpers::{
    all_cases, rust_rejection, seed_dir, RustRejection, SeedCase, LABEL_SEPARATOR,
};

/// The targets whose seed directories this table owns every labelled file in.
const SEEDED_TARGETS: &[&str] = &["block_file", "record", "contact_card"];

/// `contact_card/` also holds two `valuetype__` seeds from #669's OLDER
/// acceptance-divergence generator (`valuetype__card_version.bin`,
/// `valuetype__created_at.bin`) — a different table, in a different file,
/// that this one does not own. Excluded the same way `nesting__` is (see
/// `nesting_depth_seed_prefix` above), through one constant per language
/// (`_CONTACT_CARD_FOREIGN_PREFIX` on the Python side).
const CONTACT_CARD_FOREIGN_PREFIX: &str = "valuetype__";

/// How to regenerate, quoted in every failure that needs it.
const REGENERATE: &str = "cargo test --release --locked -p secretary-core --test \
                          rule_token_seeds -- --ignored generate_rule_token_seeds";

fn assert_rust_names_its_token(case: &SeedCase, bytes: &[u8]) {
    let got = rust_rejection(case.target, bytes);
    let want = RustRejection {
        token: case.token,
        variant: case.variant.to_owned(),
    };
    assert_eq!(
        got.as_ref(),
        Some(&want),
        "seed {} for {}: the Rust decoder rejected with {got:?}, its row says {want:?}",
        case.file_name(),
        case.target,
    );
}

/// Every row of a target plants DIFFERENT bytes. Nothing else requires it:
/// the file names, tokens and census are unchanged when three rows are
/// pointed at one plant, and the PR #673 review measured Section RTS passing
/// with three `malformed_cbor` seeds overwritten by `truncated`'s bytes —
/// exactly the leniencies the byte walk exists for. The same floor Section
/// MPR's body-distinctness check gives the manifest precedence corpus.
fn assert_each_target_plants_distinct_bytes<'a>(
    built: impl Iterator<Item = (&'a SeedCase, &'a [u8])>,
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
fn rule_token_seeds_are_committed_and_label_bound() {
    let cases = all_cases();
    let built: Vec<Vec<u8>> = cases.iter().map(SeedCase::bytes).collect();
    assert_each_target_plants_distinct_bytes(cases.iter().zip(built.iter().map(Vec::as_slice)));
    for (case, want) in cases.iter().zip(&built) {
        assert!(
            SEEDED_TARGETS.contains(&case.target),
            "row {} names target {}, which SEEDED_TARGETS does not own",
            case.file_name(),
            case.target
        );
        assert_rust_names_its_token(case, want);
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

    // Both directions: no committed labelled seed without a row, no row
    // without its file.
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
            // `nesting__` files belong to `nesting_depth_seeds.rs` (#667).
            // `valuetype__` files under `contact_card/` belong to #669's
            // older acceptance-divergence generator, a different table in a
            // different file that this one does not own.
            .filter(|name| {
                name.contains(LABEL_SEPARATOR)
                    && !name.starts_with(nesting_depth_seed_prefix::SEED_PREFIX)
                    && !(*target == "contact_card" && name.starts_with(CONTACT_CARD_FOREIGN_PREFIX))
            })
            .collect();
        let declared: BTreeSet<String> = cases
            .iter()
            .filter(|c| c.target == *target)
            .map(SeedCase::file_name)
            .collect();
        assert_eq!(
            on_disk, declared,
            "target {target}: the committed labelled seeds and the case table disagree"
        );
    }
}

/// Writes every seed. Every row is built and checked BEFORE anything is
/// written, so a failing row leaves every file untouched (#614's lesson).
#[test]
#[ignore]
fn generate_rule_token_seeds() {
    let cases = all_cases();
    let built: Vec<Vec<u8>> = cases.iter().map(SeedCase::bytes).collect();
    assert_each_target_plants_distinct_bytes(cases.iter().zip(built.iter().map(Vec::as_slice)));
    for (case, bytes) in cases.iter().zip(&built) {
        assert_rust_names_its_token(case, bytes);
    }
    for (case, bytes) in cases.iter().zip(built) {
        let path = case.path();
        std::fs::write(&path, bytes).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    }
}
