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

use std::path::PathBuf;

use secretary_core::vault::manifest::{decode_manifest, ManifestError, NonCanonicalCause};

/// Which of the decoder's two independent canonicality mechanisms rejected
/// a row.
///
/// They are not interchangeable, and `decode/mod.rs` carries a standing
/// warning against conflating them: a normalising parse PRESERVES a float
/// and re-encodes it identically, so the §4.3 step-4 comparison
/// structurally cannot see one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mechanism {
    /// The step-4 re-encode comparison, which #590 gave a cause and a
    /// byte locator.
    ReEncode,
    /// `reject_floats_and_tags`, the whole-body walk that runs first.
    FloatWalk,
}

/// The fixture's spelling of a [`NonCanonicalCause`].
///
/// This is the cross-language vocabulary #604 exists to establish: before
/// it, the label-suffix -> cause mapping lived in this file's
/// `assert_rejection_mechanism` and nowhere else, so `conformance.py` had
/// nothing to agree with. The names are now recorded per row in
/// `manifest_canonicality_kat.json` and read back by both languages.
///
/// **Exhaustive on purpose.** A fifth `NonCanonicalCause` variant fails to
/// COMPILE here rather than silently acquiring no fixture spelling.
///
/// That is a DIFFERENT axis from the `other => panic!` arm this function
/// replaced, which was fail-closed on an unrecognised SHAPES entry. That
/// axis is still covered, just elsewhere: `Shape::verdict` is a required
/// field, and the replay asserts both `rows.len() == 21` and
/// `labels == Level::ALL x SHAPES`. Nothing about this match protects it.
fn cause_name(cause: NonCanonicalCause) -> &'static str {
    match cause {
        NonCanonicalCause::ArraySortOrder => "ArraySortOrder",
        NonCanonicalCause::IndefiniteLength => "IndefiniteLength",
        NonCanonicalCause::NonShortestForm => "NonShortestForm",
        NonCanonicalCause::Unclassified => "Unclassified",
    }
}

/// Assert that `err` is the rejection the corpus row DECLARES, and say
/// which mechanism produced it.
///
/// `expect_cause` is the row's `expect_cause` column: `Some(name)` for a
/// row the §4.3 step-4 re-encode comparison catches, `None` for one
/// rejected before that comparison ever runs. **The fixture is the source
/// of truth** — this function no longer matches on the label suffix, so
/// the Rust test is a consumer of the cross-language contract rather than
/// its sole author (#604).
///
/// Fail-closed in both arms. A cause spelling no `NonCanonicalCause`
/// produces can never match, so a typo'd or invented fixture value panics
/// naming both sides. And `None` asserts a NEGATIVE — that the row did not
/// reach the re-encode at all — which is the assertion that would catch a
/// future change routing floats through the comparison: such a row would
/// still be "rejected", and only this would notice.
fn assert_rejection_mechanism(
    label: &str,
    expect_cause: Option<&str>,
    err: &ManifestError,
) -> Mechanism {
    match expect_cause {
        // Rule 2 and rule 3 are encoding-level departures the parse
        // normalises away, so the re-encode is the only signal — and #590's
        // classifier walks the whole input, which is the one place the
        // evidence survives.
        Some(want) => {
            let got = match err {
                ManifestError::NonCanonicalEncoding { cause, .. } => cause_name(*cause),
                other => panic!(
                    "row {label:?}: corpus declares cause {want:?}, so this row must be \
                     rejected by the §4.3 step-4 re-encode comparison -- got {other}"
                ),
            };
            assert_eq!(
                got, want,
                "row {label:?}: corpus declares cause {want:?}, decoder produced {got:?}"
            );
            Mechanism::ReEncode
        }
        // A null cause means "rejected BEFORE the re-encode produced a
        // NonCanonicalEncoding". `reject_floats_and_tags`
        // (`decode/mod.rs`) is the only mechanism that reaches this
        // arm for any body this corpus builds.
        //
        // LIMIT, stated because the obvious wider claim is false and an
        // earlier version of this comment made it: this asserts the error
        // VARIANT FAMILY, not the mechanism. `ManifestError::Canonical`
        // is `#[from] CanonicalError`, so it also spans `DuplicateKey`,
        // `CapacityBoundExceeded` and `CborEncode` -- which
        // `encode_manifest` can raise AT the step-4 re-encode, i.e. the
        // opposite mechanism, and which would be miscounted as FloatWalk
        // here. The tight form
        // `Canonical(CanonicalError::FloatRejected { .. })` is what
        // `manifest/decode/tests.rs`'s `rejects_float_in_unknown_value`
        // asserts; it
        // is unavailable HERE because `vault::canonical` is
        // `pub(crate)` (`core/src/vault/mod.rs:24`) and this is an
        // integration test, i.e. a separate crate. The mechanism is
        // therefore pinned in-crate and the family pinned here; do not
        // read this arm as doing both.
        None => {
            assert!(
                matches!(err, ManifestError::Canonical(_)),
                "row {label:?}: corpus declares no cause, so this row must be caught \
                 before the re-encode produces a NonCanonicalEncoding -- for this \
                 corpus that means reject_floats_and_tags, got {err}"
            );
            Mechanism::FloatWalk
        }
    }
}

/// `cause_name` must be INJECTIVE: two variants sharing a fixture
/// spelling would be indistinguishable to `conformance.py`.
///
/// The exhaustive `match` in `cause_name` stops a variant having NO
/// spelling; nothing in it stops two arms having the SAME one, and a
/// copy-paste is the likely way that happens. Today's corpus reaches only
/// two of the four variants, so no row would notice.
///
/// The array below is the one place a fifth variant is not a compile
/// error. That axis is covered in-crate by `manifest/cause/tests.rs`'s
/// `every_variant_is_listed_in_all_causes`, which an integration test
/// cannot reach (`--cfg test` is not propagated to dependencies).
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

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/manifest_canonicality_kat.json")
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
        let level = generate::Level::from_label(level_name)
            .unwrap_or_else(|| panic!("row {label:?}: no Level named {level_name:?}"));
        let shape = generate::SHAPES
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
        let rebuilt = generate::body_for(level, shape);
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

    let expected: std::collections::BTreeSet<String> = generate::Level::ALL
        .iter()
        .flat_map(|lvl| {
            generate::SHAPES
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
        let m = generate::base_manifest(generate::Level::Top);
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

// ---------------------------------------------------------------------------
// Generator (run manually; writes the fixture + the differential-replay
// seed corpus)
// ---------------------------------------------------------------------------

mod generate {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use secretary_core::vault::manifest::{
        decode_manifest, encode_manifest, BlockEntry, KdfParamsRef, Manifest, NonCanonicalCause,
        TrashEntry, VectorClockEntry,
    };
    use secretary_core::vault::UnknownValue;

    /// What `decode_manifest` MUST do with a manifest carrying one of the
    /// seven subtree shapes -- the specification, not an observed value.
    ///
    /// **One enum rather than a `bool` plus an `Option`.** That is the
    /// shape #608's review removed from `manifest_uniqueness_kat.rs`'s
    /// `Case` for making two invalid states representable, and this
    /// corpus is read as that one's pair. Both states are unrepresentable
    /// here: an ACCEPTED shape cannot carry a cause, and a shape rejected
    /// before the re-encode cannot carry one either. The accept-plus-cause
    /// combination in particular was previously invisible to the
    /// GENERATOR -- its cause assertion sat behind `if let Err(..)`, so a
    /// mistyped table entry was written into the fixture and the fuzz
    /// seeds before anything objected (#614 review).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum Verdict {
        /// The decoder must accept a body carrying this subtree.
        Accept,
        /// Rejected BY the §4.3 step-4 re-encode comparison, which #590
        /// gave a cause and a byte locator.
        RejectAtReEncode(NonCanonicalCause),
        /// Rejected BEFORE that comparison ever runs. Today the only such
        /// mechanism is `reject_floats_and_tags`. Naming the state is the
        /// point: as a bare `None` it was indistinguishable from "this
        /// shape accepts, so there is no rejection to explain".
        RejectBeforeReEncode,
    }

    impl Verdict {
        /// DERIVED, never stored -- which is what stops it disagreeing
        /// with the cause. Same treatment `Case::accepts()` gives the
        /// sibling corpus.
        pub(super) fn accepts(self) -> bool {
            matches!(self, Verdict::Accept)
        }

        /// This shape's `expect_cause` column value: `Some` only for a
        /// rejection the re-encode comparison itself produced.
        pub(super) fn cause(self) -> Option<NonCanonicalCause> {
            match self {
                Verdict::RejectAtReEncode(c) => Some(c),
                Verdict::Accept | Verdict::RejectBeforeReEncode => None,
            }
        }
    }

    /// One of the seven canonical-CBOR-profile shapes from vault-format
    /// §4.2's per-rule table, plus the verdict the spec assigns it.
    pub(super) struct Shape {
        pub(super) label: &'static str,
        /// Raw CBOR bytes of the subtree to splice into an `unknown` bag.
        pub(super) bytes: &'static [u8],
        /// See `generate_manifest_canonicality_kat`'s doc for why the
        /// generator asserts this rather than recording whatever comes
        /// out.
        ///
        /// Only two of the four `NonCanonicalCause` variants are reachable
        /// from this corpus. `ArraySortOrder` and `Unclassified` need
        /// bodies that are not `unknown`-subtree splices at all, so they
        /// stay pinned by Rust unit tests only, with no cross-language
        /// agreement -- tracked as #613 rather than left unrecorded.
        pub(super) verdict: Verdict,
    }

    pub(super) const SHAPES: &[Shape] = &[
        Shape {
            label: "control_canonical",
            // map(1) { "a": 1 } -- fully canonical: definite-length map
            // head (A1), definite-length 1-byte text key (61 = text(1),
            // 61 = 'a'), shortest-form uint 1 (01).
            bytes: &[0xA1, 0x61, 0x61, 0x01],
            verdict: Verdict::Accept,
        },
        Shape {
            label: "control_array",
            // array(2) [1, 2] -- fully canonical: definite-length array
            // head (82), two shortest-form uints (01, 02).
            bytes: &[0x82, 0x01, 0x02],
            verdict: Verdict::Accept,
        },
        Shape {
            label: "rule1_key_order",
            // map(2) { "zz": 1, "a": 2 } -- the 2-byte key "zz" (62 7A 7A)
            // precedes the 1-byte key "a" (61 61), violating RFC 8949
            // §4.2.1's length-then-bytewise key order. TOLERATED:
            // `ciborium::Value::Map` is an ordered Vec of pairs, so entry
            // order survives the parse and re-encodes byte-identically.
            bytes: &[0xA2, 0x62, 0x7A, 0x7A, 0x01, 0x61, 0x61, 0x02],
            verdict: Verdict::Accept,
        },
        Shape {
            label: "rule5_duplicate_key",
            // map(2) { "a": 1, "a": 2 } -- the key "a" (61 61) repeats.
            // TOLERATED for the same reason as rule1 above: `Value::Map`
            // does not deduplicate, so the repeat survives the round
            // trip.
            bytes: &[0xA2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02],
            verdict: Verdict::Accept,
        },
        Shape {
            label: "rule2_indefinite_map",
            // Indefinite-length map head (BF) { "a": 1 }, closed by a
            // break byte (FF), instead of the definite-length A1 head.
            // REJECTED: `ciborium` parses this into a definite-length
            // `Value::Map` on the way in, so the re-encode emits A1 and
            // differs from the indefinite-length input.
            bytes: &[0xBF, 0x61, 0x61, 0x01, 0xFF],
            verdict: Verdict::RejectAtReEncode(NonCanonicalCause::IndefiniteLength),
        },
        Shape {
            label: "rule3_non_shortest_int",
            // map(1) { "a": <uint8-headed 1> } -- the value 1 is written
            // as 18 01 (uint8 additional-info head + payload byte)
            // instead of the shortest form 01. REJECTED: `ciborium`
            // parses the value as the integer 1 and re-encodes it in
            // shortest form, differing from the non-shortest input.
            bytes: &[0xA1, 0x61, 0x61, 0x18, 0x01],
            verdict: Verdict::RejectAtReEncode(NonCanonicalCause::NonShortestForm),
        },
        Shape {
            label: "rule4_float",
            // map(1) { "a": 1.5f32 } -- FA is the major-type-7 float32
            // head, followed by the IEEE-754 big-endian encoding of 1.5
            // (3F C0 00 00). REJECTED outright: §6.2 rule 4 bans floats
            // anywhere in the body, caught by `reject_floats_and_tags`
            // before the re-encode ever runs.
            bytes: &[0xA1, 0x61, 0x61, 0xFA, 0x3F, 0xC0, 0x00, 0x00],
            verdict: Verdict::RejectBeforeReEncode,
        },
    ];

    /// The placeholder subtree spliced into each level's `unknown` bag
    /// before generation starts. Byte-identical to `control_canonical`
    /// above (a fully canonical `{"a": 1}`) -- deliberately, so it lands
    /// at a genuinely decoder-accepted position to splice over. Same
    /// splice-over-a-needle technique as
    /// `core/src/vault/manifest/decode/tests.rs::unknown_subtree_tolerates_key_order_and_duplicates_but_not_encoding`.
    pub(super) const NEEDLE: &[u8] = &[0xA1, 0x61, 0x61, 0x01];

    #[derive(Clone, Copy)]
    pub(super) enum Level {
        Top,
        Block,
        Trash,
    }

    impl Level {
        pub(super) const ALL: [Level; 3] = [Level::Top, Level::Block, Level::Trash];

        pub(super) fn label(self) -> &'static str {
            match self {
                Level::Top => "top",
                Level::Block => "block",
                Level::Trash => "trash",
            }
        }

        /// Inverse of [`Level::label`], for reading a row label back.
        ///
        /// Exhaustive on purpose, like `cause_name`: a fourth `Level`
        /// fails to compile here rather than silently making every row
        /// at that level unrebuildable.
        pub(super) fn from_label(label: &str) -> Option<Level> {
            Level::ALL.into_iter().find(|lvl| lvl.label() == label)
        }
    }

    /// One `BlockEntry` carrying TWO recipients and TWO
    /// `vector_clock_summary` entries, both in ascending order.
    fn block_entry(uuid_byte: u8, name: &str) -> BlockEntry {
        BlockEntry {
            block_uuid: [uuid_byte; 16],
            block_name: name.to_string(),
            fingerprint: [0xFF; 32],
            recipients: vec![[0x31; 16], [0x32; 16]],
            vector_clock_summary: vec![
                VectorClockEntry {
                    device_uuid: [0x41; 16],
                    counter: 7,
                },
                VectorClockEntry {
                    device_uuid: [0x42; 16],
                    counter: 9,
                },
            ],
            suite_id: secretary_core::version::SUITE_ID,
            created_at_ms: 1_700_000_000_000,
            last_mod_ms: 1_700_000_000_000,
            unknown: BTreeMap::new(),
        }
    }

    /// One `TrashEntry`.
    fn trash_entry(uuid_byte: u8) -> TrashEntry {
        TrashEntry {
            block_uuid: [uuid_byte; 16],
            tombstoned_at_ms: 1_700_000_000_000,
            tombstoned_by: [0xAA; 16],
            fingerprint: None,
            purged_at_ms: None,
            unknown: BTreeMap::new(),
        }
    }

    /// A structurally complete manifest whose `unknown` bag at `level`
    /// carries exactly one entry: [`NEEDLE`].
    ///
    /// **Every one of the five §4.2 sort-discipline arrays carries TWO
    /// entries** (#595). It used to carry none or one: `vector_clock`,
    /// `recipients` and `vector_clock_summary` were `Vec::new()` in every
    /// row and `blocks`/`trash` held at most one element, so all five sort
    /// disciplines were satisfied only VACUOUSLY -- bit-for-bit the
    /// criticism this slice levels at `golden_vault_001`. An array of
    /// length 0 or 1 is sorted no matter what the encoder or the decoder's
    /// order check does, so no-op'ing either left the whole corpus green.
    /// The sort disciplines are the *newly narrowing* half of the §4.2
    /// reader contract (#572) -- the half a clean-room implementer reading
    /// `docs/` alone would get wrong -- which makes them precisely what
    /// this cross-language corpus exists to pin.
    ///
    /// Two entries is the minimum that can be out of order, and the
    /// values are chosen ascending so the fixture itself is conformant;
    /// the REJECTION side of the discipline is covered by
    /// `array_sort_disciplines_are_enforced_and_not_vacuous` below and by
    /// `conformance.py`'s `section_manifest_body_array_sort_guard`.
    /// Nothing else about these fields is load-bearing, except that
    /// `format_version`/`suite_id` must be the real constants or the
    /// baseline decode would fail before the splice is ever exercised.
    pub(super) fn base_manifest(level: Level) -> Manifest {
        let placeholder = UnknownValue::from_canonical_cbor(NEEDLE)
            .expect("NEEDLE is canonical CBOR by construction");

        let mut m = Manifest {
            manifest_version: 1,
            vault_uuid: [0x01; 16],
            format_version: secretary_core::version::FORMAT_VERSION,
            suite_id: secretary_core::version::SUITE_ID,
            owner_user_uuid: [0x02; 16],
            vector_clock: vec![
                VectorClockEntry {
                    device_uuid: [0x21; 16],
                    counter: 3,
                },
                VectorClockEntry {
                    device_uuid: [0x22; 16],
                    counter: 5,
                },
            ],
            blocks: vec![
                block_entry(0xB1, "corpus-block"),
                block_entry(0xB2, "corpus-block-2"),
            ],
            trash: vec![trash_entry(0xDE), trash_entry(0xDF)],
            kdf_params: KdfParamsRef {
                memory_kib: 262_144,
                iterations: 3,
                parallelism: 1,
                salt: [0x11; 32],
            },
            unknown: BTreeMap::new(),
        };

        match level {
            Level::Top => {
                m.unknown.insert("zzz_needle".to_string(), placeholder);
            }
            Level::Block => {
                m.blocks[0]
                    .unknown
                    .insert("zzz_needle".to_string(), placeholder);
            }
            Level::Trash => {
                m.trash[0]
                    .unknown
                    .insert("zzz_needle".to_string(), placeholder);
            }
        }

        m
    }

    /// Locate [`NEEDLE`]'s unique occurrence in `bytes`, panicking loudly
    /// if it is absent or repeated -- either would mean the splice below
    /// targets the wrong location (or an ambiguous one).
    pub(super) fn locate_needle(bytes: &[u8], level: Level) -> usize {
        let hits: Vec<usize> = bytes
            .windows(NEEDLE.len())
            .enumerate()
            .filter(|(_, w)| *w == NEEDLE)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(
            hits.len(),
            1,
            "NEEDLE must occur exactly once in the {} base manifest, or the \
             splice could hit the wrong location",
            level.label()
        );
        hits[0]
    }

    /// Rebuild one row's manifest body from the `SHAPES` table.
    ///
    /// **The single implementation of the splice**, used by BOTH the
    /// generator and the replay's rebuild-and-compare, so the bytes a row
    /// is checked against cannot drift from the bytes that produced it.
    ///
    /// The replay comparison this exists for binds a row's BYTES to its
    /// LABEL, which nothing did before (#614 review). The corpus's whole
    /// premise is "7 shapes x 3 levels", and the level dimension was
    /// unpinned: replacing all six `block__`/`trash__` rejecting bodies
    /// with their `top__` counterparts left the Rust replay AND all 26
    /// `conformance.py` sections green -- a corpus silently collapsed to
    /// one nesting level while reporting PASS. Same rebuild-and-compare
    /// discipline #599's review put on `manifest_uniqueness_kat.rs`.
    pub(super) fn body_for(level: Level, shape: &Shape) -> Vec<u8> {
        let base = encode_manifest(&base_manifest(level))
            .expect("encode base manifest")
            .expose()
            .to_vec();
        let at = locate_needle(&base, level);
        let mut spliced = base;
        spliced.splice(at..at + NEEDLE.len(), shape.bytes.iter().copied());
        spliced
    }

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
            decode_manifest(&base_bytes)
                .expect("baseline manifest (before any splice) must decode");

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
                        super::assert_rejection_mechanism(
                            &label,
                            shape.verdict.cause().map(super::cause_name),
                            err,
                        );
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
                    "expect_cause": shape.verdict.cause().map(super::cause_name),
                }));

                seeds.push((seeds_dir.join(format!("{label}.bin")), spliced));
            }
        }

        assert_eq!(rows.len(), 21, "expected 7 shapes x 3 levels = 21 rows");

        let doc = serde_json::json!({ "rows": rows });
        let json = serde_json::to_string_pretty(&doc).expect("serialize fixture");
        std::fs::write(super::fixture_path(), json).expect("write fixture");
        for (seed_path, bytes) in &seeds {
            std::fs::write(seed_path, bytes)
                .unwrap_or_else(|e| panic!("write seed {}: {e}", seed_path.display()));
        }
    }
}
