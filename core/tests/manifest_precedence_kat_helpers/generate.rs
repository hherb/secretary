//! The corpus generator (`#[test] #[ignore]`), run by hand after a
//! deliberate, reviewed change to the case table.

use secretary_core::vault::manifest::decode_manifest;

use super::assert::assert_precedence;
use super::build::{baseline_bytes, body_for};
use super::cases::all_cases;
use super::fixture_path;

/// Regenerates `core/tests/data/manifest_precedence_kat.json`.
///
/// Run manually only:
///
///     cargo test --release --workspace -- --ignored generate_manifest_precedence_kat --nocapture
///
/// **This generator asserts the specification; it does not launder it.**
/// Every row's verdict is compared against the table through the same
/// [`assert_precedence`] the replay uses, so the two cannot drift, and a
/// wrong table entry panics with the fixture left untouched rather than
/// being written down as the new contract.
///
/// Nothing is written until every row has been asserted -- #614's review
/// found the canonicality generator writing its seeds inside the loop
/// while its JSON was written after it, so a mid-loop panic left the two
/// outputs disagreeing. This corpus writes ONE file and buffers it
/// anyway, so the property holds by construction rather than by care.
#[test]
#[ignore]
fn generate_manifest_precedence_kat() {
    // The baseline must decode BEFORE any surgery. A broken baseline
    // would otherwise surface as every row rejecting for the wrong
    // reason -- and the rule-4 rows would still look correct, because
    // they expect a rejection either way.
    decode_manifest(&baseline_bytes())
        .expect("the all-valid baseline must decode before any repeat is planted");

    let mut rows = Vec::new();
    for case in all_cases() {
        let label = case.label();
        let planted = body_for(&case);
        let expect = case.expect();

        assert_precedence(
            &label,
            expect,
            case.field(),
            planted.dup_index,
            &decode_manifest(&planted.bytes),
        );

        rows.push(serde_json::json!({
            "label": label,
            "manifest_body_hex": hex::encode(&planted.bytes),
            "expect": expect.name(),
            "field": case.field(),
            // Python-only, and the mirror of `dup_index` below:
            // `ManifestError::DuplicateKey` carries no map name, so the
            // Rust replay checks this column against the case table but
            // never against a decoder verdict. Section MPR asserts it
            // against `DuplicateMapKey.label`.
            "map": case.map_label(),
            // Rust-only: `conformance.py` reports no ordinal, and §4.2
            // does not require one. Recorded so the Rust replay's
            // assertion is data-driven rather than recomputed.
            "dup_index": planted.dup_index,
        }));
    }

    assert_eq!(
        rows.len(),
        all_cases().len(),
        "every case must produce exactly one row"
    );

    let doc = serde_json::json!({ "rows": rows });
    let json = serde_json::to_string_pretty(&doc).expect("serialize fixture");
    std::fs::write(fixture_path(), json).expect("write fixture");
}
