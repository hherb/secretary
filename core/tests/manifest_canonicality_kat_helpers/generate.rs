//! The corpus generator (`#[test] #[ignore]`), run by hand after a
//! deliberate, reviewed change to the case tables.
//!
//! Extracted from `manifest_canonicality_kat.rs` (#612).

use std::path::PathBuf;

use secretary_core::vault::manifest::{decode_manifest, encode_manifest};

use super::assert::{assert_rejection_mechanism, cause_name};
use super::build::{base_manifest, body_for_case};
use super::cases::{all_cases, Level};
use super::fixture_path;

/// Regenerates `core/tests/data/manifest_canonicality_kat.json` and
/// the `core/fuzz/seeds/manifest_body/` seed corpus.
///
/// Run manually only:
///
///     cargo test --release --workspace -- --ignored generate_manifest_canonicality_kat --nocapture
///
/// **This generator asserts the specification; it does not launder it.**
/// For every case it compares `decode_manifest`'s ACTUAL verdict against
/// the case's declared [`Verdict`] -- and, for a rejecting case, its
/// actual rejection against the declared cause through the same
/// `assert_rejection_mechanism` the replay uses (#604) -- panicking on a
/// mismatch instead of recording whatever the decoder happened to do.
///
/// A generator that wrote down the observed verdict would make
/// `manifest_canonicality_kat_replays` vacuous -- it would pass no matter
/// how the decoder's behaviour changed, because the fixture would always
/// describe the current behaviour rather than the required one. If this
/// panics, the fix is either the decoder (a real regression) or the
/// `SHAPES` / `MUTATIONS` table (a deliberate, reviewed spec change) --
/// never silently accepting whatever value comes out.
///
/// [`Verdict`]: super::cases::Verdict
#[test]
#[ignore]
fn generate_manifest_canonicality_kat() {
    let mut rows = Vec::new();

    let seeds_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds/manifest_body");
    std::fs::create_dir_all(&seeds_dir)
        .unwrap_or_else(|e| panic!("create {}: {e}", seeds_dir.display()));

    // Nothing is written until EVERY case has been asserted. The seed write
    // used to sit inside the loop while the JSON was written after it, so a
    // mid-loop panic left the two outputs disagreeing -- and the claim
    // "panics, fixture left untouched" was true of the JSON only (#614
    // review).
    let mut seeds: Vec<(PathBuf, Vec<u8>)> = Vec::new();

    // The baseline every case is built from must itself decode, at each
    // level, BEFORE any case is spliced or mutated. A broken baseline would
    // otherwise show up as every row rejecting for the wrong reason.
    for level in Level::ALL {
        let base_bytes = encode_manifest(&base_manifest(level))
            .expect("encode base manifest")
            .expose()
            .to_vec();
        decode_manifest(&base_bytes)
            .expect("baseline manifest (before any splice or mutation) must decode");
    }

    for case in all_cases() {
        let label = case.label();
        let body = body_for_case(case);
        let verdict = case.verdict();

        let outcome = decode_manifest(&body);
        let got_accept = outcome.is_ok();
        assert_eq!(
            got_accept,
            verdict.accepts(),
            "GENERATOR MUST NOT LAUNDER THE SPEC: case={label} table says \
             expect_accept={}, decoder actually returned accept={got_accept}. \
             This is either a decoder regression or a deliberate, reviewed \
             change to vault-format.md §4.2's table -- it must not be \
             silently absorbed by regenerating the fixture.",
            verdict.accepts()
        );

        // The cause column gets the SAME treatment as `expect_accept`:
        // asserted against the decoder, never recorded from it.
        // `assert_rejection_mechanism` is the single implementation of that
        // comparison, so the generator and the replay cannot drift onto two
        // readings of one column -- and it is fail-closed in both arms.
        //
        // BOTH arms are asserted. The `Ok` arm is not vacuous: it is the one
        // combination `Verdict` alone cannot make unrepresentable at the
        // point the decoder disagrees with the table, and behind the old
        // `if let Err(..)` it was checked nowhere in the generator at all.
        match &outcome {
            Err(err) => {
                assert_rejection_mechanism(&label, verdict.cause().map(cause_name), err);
            }
            Ok(_) => assert!(
                verdict.cause().is_none(),
                "case {label}: accepted by the decoder but its table entry \
                 declares a rejection cause -- a body that decodes has no \
                 rejection to explain"
            ),
        }

        rows.push(serde_json::json!({
            "label": label,
            "manifest_body_hex": hex::encode(&body),
            "expect_accept": verdict.accepts(),
            "expect_cause": verdict.cause().map(cause_name),
        }));

        seeds.push((seeds_dir.join(format!("{label}.bin")), body));
    }

    assert_eq!(
        rows.len(),
        all_cases().len(),
        "every case must produce exactly one row"
    );

    let doc = serde_json::json!({ "rows": rows });
    let json = serde_json::to_string_pretty(&doc).expect("serialize fixture");
    std::fs::write(fixture_path(), json).expect("write fixture");
    for (seed_path, bytes) in &seeds {
        std::fs::write(seed_path, bytes)
            .unwrap_or_else(|e| panic!("write seed {}: {e}", seed_path.display()));
    }
}
