//! Cross-language corpus for `docs/vault-format.md` §4.2's per-rule table.
//!
//! `Manifest`, `BlockEntry` and `TrashEntry` each carry their own
//! forward-compat `unknown` bag (`core/src/vault/manifest/types.rs`). Each
//! row here splices one of seven CBOR subtree shapes into ONE of those
//! three bags and records the verdict `decode_manifest` gives the
//! resulting manifest body. 7 shapes x 3 levels (top-level, block-entry,
//! trash-entry) = 21 rows, labelled `<level>__<shape>` (e.g.
//! `block__rule5_duplicate_key`) so the level is visible without decoding
//! the hex.
//!
//! The same fixture is replayed by `core/tests/python/conformance.py`'s
//! `py_decode_manifest`, so the two implementations' acceptance sets are
//! compared row by row rather than asserted to match in prose (#583,
//! #592). It is also written out as raw seed files under
//! `core/fuzz/seeds/manifest_body/`, so `core/tests/differential_replay.rs`
//! exercises the same 21 bodies. The `manifest_body`
//! DIFFERENTIAL-REPLAY target was introduced alongside this corpus
//! (#592/#595), so it never "passed vacuously" on an older `main`;
//! without these seeds it would replay zero inputs, which the seeds and
//! `differential_replay.rs`'s own per-target input floor prevent. It is
//! not one of the seven `cargo-fuzz` targets -- #596 tracks that.
//!
//! The seven shapes' expected verdicts are the SPECIFICATION (vault-format
//! §4.2's five-row table), not an observed decoder behaviour: rules 1
//! (map-key order) and 5 (duplicate keys) are TOLERATED inside an
//! `unknown` subtree, because `ciborium`'s `Value::Map` is an ordered
//! `Vec` of pairs that survives the decode-then-re-encode check unchanged;
//! rules 2 (indefinite-length item) and 3 (non-shortest-form integer) are
//! REJECTED because they are encoding-level departures the parse
//! normalises away, so the re-encode differs from the input.
//!
//! **Rule 4 (float) is rejected by a different mechanism, and conflating
//! the two is the specific error `decode/mod.rs` warns against.** A
//! normalising parse PRESERVES a float and re-encodes it identically, so
//! the step-4 comparison structurally cannot see one. Floats and tags are
//! rejected by `reject_floats_and_tags`, a whole-body walk that runs
//! BEFORE `parse_manifest_map` and long before the re-encode -- as
//! `docs/vault-format.md` §4.2 states normatively and as this file's own
//! `rule4_float` shape comment says. Reading rule 4 as re-encode-enforced
//! invites deleting that walk as redundant, at which point floats and tags
//! inside `unknown` subtrees are silently accepted.
//!
//! `generate_manifest_canonicality_kat` asserts these verdicts against the
//! decoder's actual output rather than recording whatever comes out --
//! see that function's own doc for why the distinction is load-bearing.

#![forbid(unsafe_code)]

use secretary_core::vault::manifest::{decode_manifest, NonCanonicalCause};

mod manifest_canonicality_kat_helpers;

use helpers::assert::{assert_rejection_mechanism, cause_name, Mechanism};
use helpers::build::{base_manifest, body_for};
use helpers::cases::{Level, SHAPES};
use helpers::fixture_path;
use manifest_canonicality_kat_helpers as helpers;

#[test]
fn cause_names_are_distinct() {
    let all = [
        NonCanonicalCause::ArraySortOrder,
        NonCanonicalCause::IndefiniteLength,
        NonCanonicalCause::NonShortestForm,
        NonCanonicalCause::Unclassified,
    ];
    let names: std::collections::BTreeSet<&'static str> =
        all.iter().copied().map(cause_name).collect();
    assert_eq!(
        names.len(),
        all.len(),
        "cause_name must be injective -- the fixture vocabulary is the cross-language \
         contract, and two causes sharing a spelling makes them indistinguishable to \
         conformance.py, got {names:?}"
    );
}

#[test]
fn manifest_canonicality_kat_replays() {
    let raw = std::fs::read_to_string(fixture_path()).expect(
        "fixture must exist -- generate it with:\n  \
         cargo test --release --workspace -- --ignored generate_manifest_canonicality_kat --nocapture",
    );
    let doc: serde_json::Value = serde_json::from_str(&raw).expect("fixture JSON");
    let rows = doc["rows"].as_array().expect("rows array");
    assert!(!rows.is_empty(), "corpus must not be empty");
    assert_eq!(
        rows.len(),
        21,
        "corpus must carry all 7 shapes x 3 levels (top/block/trash)"
    );

    // Every (level, shape) pair must be present, not merely 21 rows: a
    // fixture holding 21 copies of one row satisfies a bare length check
    // and proves nothing (#595).
    let mut labels: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    let mut accepted = 0usize;
    let mut rejected = 0usize;
    let mut re_encode = 0usize;
    let mut float_walk = 0usize;
    let mut causes_seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for row in rows {
        let label = row["label"].as_str().expect("label");
        labels.insert(label.to_string());
        let body = hex::decode(row["manifest_body_hex"].as_str().expect("body")).expect("hex");
        let expect_accept = row["expect_accept"].as_bool().expect("expect_accept");
        let outcome = decode_manifest(&body);
        let got = outcome.is_ok();
        assert_eq!(
            got, expect_accept,
            "row {label:?}: expected accept={expect_accept}, got accept={got}"
        );
        // Absent column => PANIC, never a default. A fixture stripped of
        // `expect_cause` must fail LOUDLY: read with a default, every
        // rejecting row would score as "declares no cause" and quietly
        // demand the FloatWalk mechanism -- a green run proving the
        // opposite of what it claims. Same fail-open shape #608's review
        // found in `parsed.get(array, [])`.
        //
        // `.get()` rather than the `[]` index is what makes that
        // distinction possible at all: `serde_json`'s `[]` returns
        // `Value::Null` for a key that is simply absent, and `null` is a
        // MEANINGFUL value in this column, so after indexing the two are
        // indistinguishable.
        let declared = row.get("expect_cause").unwrap_or_else(|| {
            panic!(
                "row {label:?}: fixture has no `expect_cause` column -- regenerate it with \
                 `cargo test --release --workspace -- --ignored generate_manifest_canonicality_kat`"
            )
        });
        let expect_cause: Option<&str> =
            if declared.is_null() {
                None
            } else {
                Some(declared.as_str().unwrap_or_else(|| {
                    panic!("row {label:?}: expect_cause must be a string or null")
                }))
            };

        // The corpus must agree with the SHAPES table it was generated
        // from -- in its BYTES as well as its columns. Without this, a
        // hand-edited row would simply become the new contract and both
        // languages would agree with the edit; the fixture would be
        // self-certifying. This is the "both sides check the FIXTURE, not
        // just the verdict" discipline #599's review put on the
        // uniqueness corpus.
        let (level_name, shape_name) = label.split_once("__").expect("label is <level>__<shape>");
        let level = Level::from_label(level_name)
            .unwrap_or_else(|| panic!("row {label:?}: no Level named {level_name:?}"));
        let shape = SHAPES
            .iter()
            .find(|s| s.label == shape_name)
            .unwrap_or_else(|| panic!("row {label:?}: no SHAPES entry named {shape_name:?}"));

        // Bind the row's BYTES to its LABEL. Every other assertion in this
        // loop is derived from the label or the columns, so before this
        // the body itself was unconstrained: swapping all six
        // `block__`/`trash__` rejecting bodies for their `top__`
        // counterparts left this replay AND all 26 `conformance.py`
        // sections green, collapsing a corpus whose stated premise is
        // "7 shapes x 3 levels" down to one level with nothing objecting
        // (#614 review). `body_for` is the same splice the generator
        // writes with, so the two cannot drift.
        let rebuilt = body_for(level, shape);
        assert_eq!(
            hex::encode(&body),
            hex::encode(&rebuilt),
            "row {label:?}: committed manifest_body_hex is not what splicing shape \
             {shape_name:?} into a {level_name:?}-level `unknown` bag produces -- the \
             fixture was hand-edited, or SHAPES/base_manifest changed without \
             regenerating it"
        );

        let declared_by_table = shape.verdict.cause().map(cause_name);
        assert_eq!(
            expect_cause, declared_by_table,
            "row {label:?}: fixture declares cause {expect_cause:?} but the SHAPES table \
             declares {declared_by_table:?} -- one of the two was hand-edited"
        );
        assert_eq!(
            expect_accept,
            shape.verdict.accepts(),
            "row {label:?}: fixture declares expect_accept={expect_accept} but the \
             SHAPES table declares {} -- one of the two was hand-edited",
            shape.verdict.accepts()
        );

        if expect_accept {
            assert!(
                expect_cause.is_none(),
                "row {label:?}: an ACCEPTED row cannot declare a rejection cause"
            );
            accepted += 1;
        } else {
            rejected += 1;
            if let Some(name) = expect_cause {
                causes_seen.insert(name.to_string());
            }
            match assert_rejection_mechanism(label, expect_cause, outcome.as_ref().unwrap_err()) {
                Mechanism::ReEncode => re_encode += 1,
                Mechanism::FloatWalk => float_walk += 1,
            }
        }
    }

    // The executable form of this module's "two mechanisms" paragraph, and
    // of a fact three handoff documents carried only in prose: SIX of the
    // 21 rows land on `NonCanonicalEncoding` (rules 2 and 3, three levels
    // each), not nine. The other three are caught earlier, by
    // `reject_floats_and_tags`. Asserting the split by COUNT as well as
    // per-row is what stops a future change that routed floats through the
    // re-encode from passing: each row would still be "rejected", and only
    // these totals would move.
    assert_eq!(
        re_encode, 6,
        "exactly rules 2 and 3, at three levels each, must reach the \
         re-encode comparison"
    );
    assert_eq!(
        float_walk, 3,
        "exactly the three rule4_float rows must be caught by \
         reject_floats_and_tags, BEFORE the re-encode"
    );

    // #604's coverage gap, made EXECUTABLE rather than left in prose.
    // `NonCanonicalCause` has four variants; this corpus reaches two.
    // `ArraySortOrder` needs an out-of-order array and `Unclassified`
    // needs outer-map key disorder -- neither is an `unknown`-subtree
    // splice, which is the only shape this corpus's generator builds, so
    // both stay pinned by Rust unit tests with no cross-language
    // agreement (#613).
    //
    // Asserting the SET is a deliberate speed bump so the gap above
    // cannot quietly stop being true while this comment still claims it.
    //
    // Be precise about what reaches it, because "widening the corpus reds
    // here" was wrong: ADDING an eighth shape trips `rows.len() == 21`
    // far above, whose message says nothing about #613. This fires when a
    // shape is REPLACED by one carrying a third cause -- and it is
    // defence in depth either way, the one property on this corpus that
    // was not shown to fire by mutation, because every mutation
    // constructible against today's fixture trips an earlier per-row
    // assertion first.
    assert_eq!(
        causes_seen,
        ["IndefiniteLength", "NonShortestForm"]
            .into_iter()
            .map(String::from)
            .collect::<std::collections::BTreeSet<String>>(),
        "the set of causes this corpus exercises has changed -- update the \
         #613 coverage note above rather than only this assertion"
    );
    assert!(
        accepted > 0,
        "corpus has no ACCEPT rows -- it would pass by rejecting everything"
    );
    // The mirror floor. Without it an accept-only corpus would pass against
    // a decoder that accepted everything -- the exact failure the ACCEPT
    // floor above guards in the other direction.
    assert!(
        rejected > 0,
        "corpus has no REJECT rows -- it would pass by accepting everything"
    );

    let expected: std::collections::BTreeSet<String> = Level::ALL
        .iter()
        .flat_map(|lvl| {
            SHAPES
                .iter()
                .map(move |sh| format!("{}__{}", lvl.label(), sh.label))
        })
        .collect();
    assert_eq!(
        labels, expected,
        "corpus label set must be exactly Level::ALL x SHAPES"
    );
}

/// The five §4.2 array sort disciplines are ENFORCED, and the corpus that
/// carries them is not vacuous (#595).
///
/// Two halves, and the second is the one that was missing. Every corpus row
/// now carries two entries in all five arrays, but "two entries, in order"
/// is only evidence that sorted input is ACCEPTED. This reverses each array
/// in turn and asserts the decoder REJECTS -- so no-op'ing
/// `parse_manifest_map`'s order checks, or `encode_manifest`'s sort, fails
/// here. Before this, all five arrays were empty or single-element in every
/// row, so both could be removed with the whole suite green.
///
/// The out-of-order body cannot be produced by `encode_manifest` (it sorts
/// on output, which is the discipline under test), so each case round-trips
/// through `ciborium::Value` and reverses one array there.
#[test]
fn array_sort_disciplines_are_enforced_and_not_vacuous() {
    use ciborium::Value;

    /// Reverse one array inside the decoded manifest body.
    ///
    /// `outer` names a top-level key; if `inner` is `Some`, `outer` must be
    /// an array of maps and the reversal targets `outer[0][inner]` instead.
    /// Two levels is all the manifest has, so this is written flat rather
    /// than as a general path walk.
    fn reverse_array(body: &[u8], outer: &str, inner: Option<&str>) -> Vec<u8> {
        fn array_mut<'a>(v: &'a mut Value, key: &str) -> &'a mut Vec<Value> {
            let entries = match v {
                Value::Map(m) => m,
                other => panic!("expected a map, got {other:?}"),
            };
            let slot = entries
                .iter_mut()
                .find(|(k, _)| k.as_text() == Some(key))
                .map(|(_, val)| val)
                .unwrap_or_else(|| panic!("key {key:?} not found"));
            match slot {
                Value::Array(a) => a,
                other => panic!("key {key:?} is not an array: {other:?}"),
            }
        }

        let mut v: Value = ciborium::de::from_reader(body).expect("parse body");
        let target = match inner {
            None => array_mut(&mut v, outer),
            Some(k) => {
                let first = array_mut(&mut v, outer)
                    .first_mut()
                    .expect("outer array must be non-empty");
                array_mut(first, k)
            }
        };
        assert!(
            target.len() >= 2,
            "array {outer}/{inner:?} has {} element(s) -- a sort discipline \
             cannot be violated with fewer than 2, so this case would be \
             vacuous",
            target.len()
        );
        target.reverse();

        let mut out = Vec::new();
        ciborium::ser::into_writer(&v, &mut out).expect("re-encode");
        out
    }

    let body = {
        let m = base_manifest(Level::Top);
        secretary_core::vault::manifest::encode_manifest(&m)
            .expect("encode")
            .expose()
            .to_vec()
    };
    decode_manifest(&body).expect("baseline: the unreversed fixture must decode");

    for (outer, inner) in [
        ("vector_clock", None),
        ("blocks", None),
        ("trash", None),
        ("blocks", Some("recipients")),
        ("blocks", Some("vector_clock_summary")),
    ] {
        let mutated = reverse_array(&body, outer, inner);
        assert_ne!(
            mutated, body,
            "reversing {outer}/{inner:?} produced an identical body -- the \
             case is vacuous"
        );
        assert!(
            decode_manifest(&mutated).is_err(),
            "{outer}/{inner:?} reversed was ACCEPTED -- §4.2's sort \
             discipline for it is not enforced"
        );
    }
}
