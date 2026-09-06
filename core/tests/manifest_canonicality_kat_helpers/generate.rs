//! The corpus generator (`#[test] #[ignore]`), run by hand after a
//! deliberate, reviewed change to the `CASES` table.
//!
//! Extracted from `manifest_canonicality_kat.rs` (#612).

use std::path::PathBuf;

use secretary_core::vault::manifest::{decode_manifest, encode_manifest};

use super::assert::{assert_rejection_mechanism, cause_name};
use super::build::{base_manifest, body_for};
use super::cases::{Level, SHAPES};
use super::fixture_path;

/// Regenerates `core/tests/data/manifest_canonicality_kat.json` and
/// the `core/fuzz/seeds/manifest_body/` seed corpus.
///
/// Run manually only:
///
///     cargo test --release --workspace -- --ignored generate_manifest_canonicality_kat --nocapture
///
/// **This generator asserts the specification; it does not launder
/// it.** For every (level, shape) pair it compares `decode_manifest`'s
/// ACTUAL verdict against `Shape::expect_accept` -- and, for a
/// rejecting pair, its actual rejection against `Shape::expect_cause`
/// through the same `assert_rejection_mechanism` the replay uses
/// (#604) -- panicking on a mismatch instead of recording whatever the
/// decoder happened to do.
/// A generator that wrote down the observed verdict would make
/// `manifest_canonicality_kat_replays` vacuous -- it would pass no
/// matter how the decoder's behaviour changed, because the fixture
/// would always describe the current behaviour rather than the
/// required one. If this panics, the fix is either the decoder (a
/// real regression) or the table in this file's `SHAPES` (a
/// deliberate, reviewed spec change) -- never silently accepting
/// whatever value comes out.
#[test]
#[ignore]
fn generate_manifest_canonicality_kat() {
    let mut rows = Vec::new();

    let seeds_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds/manifest_body");
    std::fs::create_dir_all(&seeds_dir)
        .unwrap_or_else(|e| panic!("create {}: {e}", seeds_dir.display()));

    // Nothing is written until every (level, shape) pair has been
    // asserted. The seed write used to sit INSIDE this loop while the
    // JSON was written after it, so a mid-loop panic left the two
    // outputs disagreeing -- and the claim "panics, fixture left
    // untouched" was true of the JSON only (#614 review).
    let mut seeds: Vec<(PathBuf, Vec<u8>)> = Vec::new();

    for level in Level::ALL {
        let base_bytes = encode_manifest(&base_manifest(level))
            .expect("encode base manifest")
            .expose()
            .to_vec();
        decode_manifest(&base_bytes).expect("baseline manifest (before any splice) must decode");

        for shape in SHAPES {
            let spliced = body_for(level, shape);

            let outcome = decode_manifest(&spliced);
            let got_accept = outcome.is_ok();
            assert_eq!(
                got_accept,
                shape.verdict.accepts(),
                "GENERATOR MUST NOT LAUNDER THE SPEC: level={} shape={} table \
                 says expect_accept={}, decoder actually returned accept={}. \
                 This is either a decoder regression or a deliberate, reviewed \
                 change to vault-format.md §4.2's table -- it must not be \
                 silently absorbed by regenerating the fixture.",
                level.label(),
                shape.label,
                shape.verdict.accepts(),
                got_accept
            );

            let label = format!("{}__{}", level.label(), shape.label);

            // The cause column gets the SAME treatment as
            // `expect_accept`: asserted against the decoder, never
            // recorded from it. `assert_rejection_mechanism` is the
            // single implementation of that comparison, so the
            // generator and the replay cannot drift onto two readings
            // of one column -- and it is fail-closed in both arms.
            //
            // BOTH arms are asserted. The `Ok` arm is not vacuous: it
            // is the one combination `Verdict` alone cannot make
            // unrepresentable at the point the decoder disagrees with
            // the table, and behind the old `if let Err(..)` it was
            // checked nowhere in the generator at all.
            match &outcome {
                Err(err) => {
                    assert_rejection_mechanism(&label, shape.verdict.cause().map(cause_name), err);
                }
                Ok(_) => assert!(
                    shape.verdict.cause().is_none(),
                    "row {label:?}: shape is ACCEPTED by the decoder but its \
                     table entry declares a rejection cause -- a body that \
                     decodes has no rejection to explain"
                ),
            }

            rows.push(serde_json::json!({
                "label": label,
                "manifest_body_hex": hex::encode(&spliced),
                "expect_accept": shape.verdict.accepts(),
                "expect_cause": shape.verdict.cause().map(cause_name),
            }));

            seeds.push((seeds_dir.join(format!("{label}.bin")), spliced));
        }
    }

    assert_eq!(rows.len(), 21, "expected 7 shapes x 3 levels = 21 rows");

    let doc = serde_json::json!({ "rows": rows });
    let json = serde_json::to_string_pretty(&doc).expect("serialize fixture");
    std::fs::write(fixture_path(), json).expect("write fixture");
    for (seed_path, bytes) in &seeds {
        std::fs::write(seed_path, bytes)
            .unwrap_or_else(|e| panic!("write seed {}: {e}", seed_path.display()));
    }
}
