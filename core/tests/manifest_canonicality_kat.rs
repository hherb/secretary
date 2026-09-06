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

use secretary_core::vault::manifest::{decode_manifest, ManifestError, NonCanonicalCause};

mod manifest_canonicality_kat_helpers;

use helpers::assert::{assert_rejection_mechanism, cause_name, Mechanism, ALL_CAUSES};
use helpers::build::{base_manifest, body_for_case, reverse_array};
use helpers::cases::{all_cases, Case, Level, Verdict, MUTATIONS, SHAPES};
use helpers::fixture_path;
use manifest_canonicality_kat_helpers as helpers;

#[test]
fn cause_names_are_distinct() {
    let names: std::collections::BTreeSet<&'static str> =
        ALL_CAUSES.iter().copied().map(cause_name).collect();
    assert_eq!(
        names.len(),
        ALL_CAUSES.len(),
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

    // The corpus is TWO families, and the count is derived from the table
    // rather than written out, so adding a case cannot leave a literal
    // behind. `all_cases` is also the lookup below, which is what makes
    // that lookup total.
    let cases = all_cases();
    let by_label: std::collections::BTreeMap<String, Case> =
        cases.iter().map(|c| (c.label(), *c)).collect();
    assert_eq!(
        by_label.len(),
        cases.len(),
        "two cases share a label -- one would silently shadow the other in \
         every lookup below"
    );
    assert_eq!(
        rows.len(),
        cases.len(),
        "corpus must carry every case: 7 shapes x 3 levels spliced, plus the \
         {} whole-body mutation rows (#613)",
        MUTATIONS.len()
    );

    // Every case must be present, not merely N rows: a fixture holding N
    // copies of one row satisfies a bare length check and proves nothing
    // (#595).
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

        // The corpus must agree with the case table it was generated
        // from -- in its BYTES as well as its columns. Without this, a
        // hand-edited row would simply become the new contract and both
        // languages would agree with the edit; the fixture would be
        // self-certifying. This is the "both sides check the FIXTURE, not
        // just the verdict" discipline #599's review put on the
        // uniqueness corpus.
        let case = *by_label.get(label).unwrap_or_else(|| {
            panic!(
                "row {label:?}: no case carries this label -- the fixture was \
                 hand-edited, or a case was renamed without regenerating it. \
                 Known labels: {:?}",
                by_label.keys().collect::<Vec<_>>()
            )
        });

        // Bind the row's BYTES to its LABEL. Every other assertion in this
        // loop is derived from the label or the columns, so before this
        // the body itself was unconstrained: swapping all six
        // `block__`/`trash__` rejecting bodies for their `top__`
        // counterparts left this replay AND all 26 `conformance.py`
        // sections green, collapsing a corpus whose stated premise is
        // "7 shapes x 3 levels" down to one level with nothing objecting
        // (#614 review). `body_for_case` is the same builder the generator
        // writes with -- for BOTH families -- so the two cannot drift.
        let rebuilt = body_for_case(case);
        assert_eq!(
            hex::encode(&body),
            hex::encode(&rebuilt),
            "row {label:?}: committed manifest_body_hex is not what this row's case \
             produces -- the fixture was hand-edited, or SHAPES/MUTATIONS/base_manifest \
             changed without regenerating it"
        );

        let declared_by_table = case.verdict().cause().map(cause_name);
        assert_eq!(
            expect_cause, declared_by_table,
            "row {label:?}: fixture declares cause {expect_cause:?} but the case table \
             declares {declared_by_table:?} -- one of the two was hand-edited"
        );
        assert_eq!(
            expect_accept,
            case.verdict().accepts(),
            "row {label:?}: fixture declares expect_accept={expect_accept} but the \
             case table declares {} -- one of the two was hand-edited",
            case.verdict().accepts()
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
    // of a fact three handoff documents carried only in prose: the
    // `rule4_float` rows are caught EARLIER than every other rejection, by
    // `reject_floats_and_tags`, and are the ONLY rows that are. Asserting
    // the split by COUNT as well as per-row is what stops a future change
    // that routed floats through the re-encode from passing: each row
    // would still be "rejected", and only these totals would move.
    //
    // Both totals are derived from the case table rather than written out
    // -- with two families and 30 rows a hand-maintained literal is a
    // second place for the truth to live, and #613's own row additions
    // would have had to edit it.
    let want_float_walk = cases
        .iter()
        .filter(|c| matches!(c.verdict(), Verdict::RejectBeforeReEncode))
        .count();
    let want_re_encode = cases
        .iter()
        .filter(|c| matches!(c.verdict(), Verdict::RejectAtReEncode(_)))
        .count();
    assert_eq!(
        re_encode, want_re_encode,
        "every row whose case declares RejectAtReEncode must reach the \
         re-encode comparison"
    );
    assert_eq!(
        float_walk, want_float_walk,
        "exactly the rule4_float rows must be caught by \
         reject_floats_and_tags, BEFORE the re-encode"
    );
    // A floor under both, so a table that stopped declaring either kind
    // cannot satisfy the two equalities above by agreeing on zero.
    assert_eq!(
        want_float_walk, 3,
        "the three rule4_float rows are the corpus's only pre-re-encode \
         rejections"
    );
    assert_eq!(
        want_re_encode, 15,
        "6 splice rows (rules 2 and 3, three levels each) plus the 9 \
         whole-body mutation rows (#613)"
    );

    // ALL FOUR `NonCanonicalCause` variants now carry corpus rows, so both
    // languages agree on the whole cause vocabulary rather than half of it
    // (#613 closed; #604 reached two).
    //
    // Written as the exhaustive `ALL_CAUSES` list rather than four
    // literals: a FIFTH variant added later fails to compile in
    // `cause_name`'s match, and once the author adds an arm there and a
    // row to `ALL_CAUSES`, it reds HERE with a message that says what to
    // do -- instead of silently joining a vocabulary no corpus row
    // exercises. That recurrence of #613 is what this assertion is FOR.
    //
    // **Still defence in depth, and the honest reason is worth keeping.**
    // The version this replaced conceded it was the one property on this
    // corpus never shown to fire by mutation, and that is unchanged --
    // an intermediate draft of this very comment claimed "deleting either
    // family's rows from `MUTATIONS` reds it directly (verified by
    // mutation)", which was then measured and is FALSE: dropping the four
    // `keyorder__*` cases trips the `rows.len() == cases.len()`
    // assertion 180 lines above, and regenerating past that trips
    // `want_re_encode == 15`. Every mutation constructible against
    // today's tree front-runs this one.
    //
    // What IS measured: the comparison is live -- pointing one
    // `ALL_CAUSES` entry at a neighbouring variant reds this and
    // `cause_names_are_distinct` together, and shortening the array is a
    // compile error (the `; 4]` length annotation). The direction it
    // exists for needs a real fifth variant to exercise, so it is argued
    // rather than measured. The PYTHON counterpart of the same claim --
    // Section MCC's `discriminators_seen` against `_CAUSE_EXPECTATION` --
    // is mutation-proven, because a Python table entry can be added
    // without adding a Rust enum variant.
    assert_eq!(
        causes_seen,
        ALL_CAUSES
            .iter()
            .copied()
            .map(|c| cause_name(c).to_string())
            .collect::<std::collections::BTreeSet<String>>(),
        "every NonCanonicalCause variant must carry at least one corpus row \
         -- a variant with none has no cross-language agreement at all, \
         which is the gap #613 closed"
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

    // The whole label set, both families. `labels` is a set, so duplicate
    // rows collapse into it silently -- which is why this is checked
    // against the case table rather than inferred from `rows.len()`.
    let all_labels: std::collections::BTreeSet<String> = cases.iter().map(|c| c.label()).collect();
    assert_eq!(
        labels, all_labels,
        "corpus label set must be exactly the case table's"
    );

    // The SPLICE family's own premise, preserved verbatim from before
    // #613 widened the corpus: it must still be the full
    // `Level::ALL x SHAPES` product. Checking the union alone would let a
    // future edit trade a splice row for a mutation row and keep the
    // totals -- and the level dimension is what #614's review had to add
    // an assertion for after 21 rows drawn from one nesting level passed.
    //
    // Sound only because no mutation label can be read as a splice label;
    // `no_mutation_label_can_be_read_as_a_splice_row` pins that
    // disjointness rather than leaving it to the eye.
    let splice_labels: std::collections::BTreeSet<String> = labels
        .iter()
        .filter(|label| {
            label
                .split_once("__")
                .is_some_and(|(level, _)| Level::from_label(level).is_some())
        })
        .cloned()
        .collect();
    let expected: std::collections::BTreeSet<String> = Level::ALL
        .iter()
        .flat_map(|lvl| {
            SHAPES
                .iter()
                .map(move |sh| format!("{}__{}", lvl.label(), sh.label))
        })
        .collect();
    assert_eq!(
        splice_labels, expected,
        "the splice family must still be exactly Level::ALL x SHAPES"
    );
}

/// No [`MUTATIONS`] label may parse as a `<level>__<shape>` splice label.
///
/// The replay partitions the corpus by reading a label's prefix as a
/// [`Level`], so a mutation row whose prefix collided with one would be
/// counted into the splice family's product assertion -- which would then
/// fail for a reason having nothing to do with the row that caused it, or
/// (if it displaced a real splice row) pass while a genuine gap opened.
/// The namespaces are `arraysort__` / `keyorder__` versus `top__` /
/// `block__` / `trash__`; nothing but this test stops a future case
/// choosing a colliding one.
#[test]
fn no_mutation_label_can_be_read_as_a_splice_row() {
    for case in MUTATIONS {
        let prefix = case
            .label
            .split_once("__")
            .unwrap_or_else(|| panic!("mutation label {:?} is not <family>__<case>", case.label))
            .0;
        assert!(
            Level::from_label(prefix).is_none(),
            "mutation label {:?} starts with the Level prefix {prefix:?} -- it \
             would be counted into the splice family's Level::ALL x SHAPES \
             product assertion",
            case.label
        );
    }
}

/// The five §4.2 array sort disciplines are ENFORCED, each with the cause
/// that names it, and the corpus carrying them is not vacuous (#595, #613).
///
/// Three halves, and the third arrived with #613. Every corpus row carries
/// two entries in all five arrays, but "two entries, in order" is only
/// evidence that sorted input is ACCEPTED. This reverses each array in turn
/// and asserts the decoder REJECTS -- so no-op'ing `parse_manifest_map`'s
/// order checks, or `encode_manifest`'s sort, fails here. Before #595, all
/// five arrays were empty or single-element in every row, so both could be
/// removed with the whole suite green.
///
/// The third half is the CAUSE. Until #613 this asserted only `is_err()`,
/// which every other §4.2 rejection also satisfies -- so a classifier that
/// stopped attributing array disorder and fell through to `Unclassified`
/// passed here unchanged. That mattered because `NonCanonicalCause::
/// ArraySortOrder`'s whole claim is that it is DECISIVE, read off the
/// parsed `Manifest` rather than off a divergence position.
///
/// **Deliberately kept even though `arraysort__*` now covers the same five
/// arrays.** These two are not redundant: the corpus rows replay COMMITTED
/// bytes, this computes them fresh from the current `base_manifest`, and
/// the reversal is the single shared `reverse_array` so the two cannot
/// drift. Delete the fixture entirely and the five disciplines are still
/// pinned here.
#[test]
fn array_sort_disciplines_are_enforced_and_not_vacuous() {
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
        let err = decode_manifest(&mutated).expect_err(&format!(
            "{outer}/{inner:?} reversed was ACCEPTED -- §4.2's sort \
             discipline for it is not enforced"
        ));
        match err {
            ManifestError::NonCanonicalEncoding { cause, .. } => assert_eq!(
                cause,
                NonCanonicalCause::ArraySortOrder,
                "{outer}/{inner:?} reversed was rejected, but the cause was \
                 {cause:?} -- ArraySortOrder is DECISIVE (read off the parsed \
                 Manifest by `classify::arrays_are_sorted`), so anything else \
                 means the classifier stopped attributing array disorder"
            ),
            other => panic!(
                "{outer}/{inner:?} reversed must be rejected by the §4.3 step-4 \
                 re-encode comparison, got {other}"
            ),
        }
    }
}
