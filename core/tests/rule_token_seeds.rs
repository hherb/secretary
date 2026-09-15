//! Committed single-fault seeds for the `record` and `block_file` replay
//! targets (#641): the generator, and the check that binds every committed
//! seed to its label. See `rule_token_seeds_helpers` for the table, and
//! `docs/superpowers/specs/2026-09-15-token-compare-record-block-design.md`
//! §6.1.
//!
//! The Python half of the binding is conformance Section RTS.

mod rule_token_seeds_helpers;

use std::collections::BTreeSet;

use rule_token_seeds_helpers::{all_cases, rust_token, seed_dir, SeedCase, LABEL_SEPARATOR};

/// The targets whose seed directories this table owns every labelled file in.
const SEEDED_TARGETS: &[&str] = &["block_file"];

/// How to regenerate, quoted in every failure that needs it.
const REGENERATE: &str = "cargo test --release --locked -p secretary-core --test \
                          rule_token_seeds -- --ignored generate_rule_token_seeds";

fn assert_rust_names_its_token(case: &SeedCase, bytes: &[u8]) {
    let got = rust_token(case.target, bytes);
    assert_eq!(
        got,
        Some(case.token),
        "seed {} for {}: the Rust decoder named {got:?}, its row says {:?}",
        case.file_name(),
        case.target,
        case.token
    );
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
    for case in &cases {
        assert!(
            SEEDED_TARGETS.contains(&case.target),
            "row {} names target {}, which SEEDED_TARGETS does not own",
            case.file_name(),
            case.target
        );
        let want = case.bytes();
        assert_rust_names_its_token(case, &want);
        let committed = std::fs::read(case.path()).unwrap_or_else(|e| {
            panic!(
                "seed {} is not committed ({e}); run `{REGENERATE}`",
                case.path().display()
            )
        });
        assert!(
            committed == want,
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
            .filter(|name| name.contains(LABEL_SEPARATOR))
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
    let built: Vec<_> = all_cases()
        .iter()
        .map(|case| {
            let bytes = case.bytes();
            assert_rust_names_its_token(case, &bytes);
            (case.path(), bytes)
        })
        .collect();
    for (path, bytes) in built {
        std::fs::write(&path, bytes).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    }
}
