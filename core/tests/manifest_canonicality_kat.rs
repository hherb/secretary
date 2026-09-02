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
//! exercises the same 21 bodies. The `manifest_body` target is NEW in this
//! change -- it was added one commit ahead of this corpus, so it never
//! existed on `main` and never "passed vacuously" there; without these
//! seeds it would have replayed zero inputs, which is what the seeds and
//! `differential_replay.rs`'s own per-target input floor now prevent.
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

/// Assert that `err` is the rejection `shape` must produce, and say which
/// mechanism produced it.
///
/// **Fail-closed on the shape name**: an unrecognised rejecting shape
/// panics rather than being waved through, so adding an eighth shape to
/// `SHAPES` without declaring its mechanism reds this test instead of
/// silently widening what the corpus tolerates.
fn assert_rejection_mechanism(label: &str, shape: &str, err: &ManifestError) -> Mechanism {
    match shape {
        // Rule 2 and rule 3 are encoding-level departures the parse
        // normalises away, so the re-encode is the only signal — and #590's
        // classifier reads the offending head straight out of the input,
        // which is the one place the evidence survives.
        "rule2_indefinite_map" => {
            assert!(
                matches!(
                    err,
                    ManifestError::NonCanonicalEncoding {
                        cause: NonCanonicalCause::IndefiniteLength,
                        ..
                    }
                ),
                "row {label:?}: expected an IndefiniteLength cause, got {err}"
            );
            Mechanism::ReEncode
        }
        "rule3_non_shortest_int" => {
            assert!(
                matches!(
                    err,
                    ManifestError::NonCanonicalEncoding {
                        cause: NonCanonicalCause::NonShortestForm,
                        ..
                    }
                ),
                "row {label:?}: expected a NonShortestForm cause, got {err}"
            );
            Mechanism::ReEncode
        }
        // Rule 4 never reaches the re-encode. Asserting the NEGATIVE here
        // is the point: if a future change routed floats through the
        // comparison instead, this row would still be "rejected" and only
        // this assertion would notice.
        "rule4_float" => {
            assert!(
                matches!(err, ManifestError::Canonical(_)),
                "row {label:?}: floats must be caught by reject_floats_and_tags, \
                 not the re-encode, got {err}"
            );
            Mechanism::FloatWalk
        }
        other => panic!(
            "row {label:?}: shape {other:?} rejects but declares no mechanism -- \
             add it to assert_rejection_mechanism rather than loosening this match"
        ),
    }
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
        if expect_accept {
            accepted += 1;
        } else {
            rejected += 1;
            let shape = label.split_once("__").expect("label is <level>__<shape>").1;
            match assert_rejection_mechanism(label, shape, outcome.as_ref().unwrap_err()) {
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
        decode_manifest, encode_manifest, BlockEntry, KdfParamsRef, Manifest, TrashEntry,
        VectorClockEntry,
    };
    use secretary_core::vault::UnknownValue;

    /// One of the seven canonical-CBOR-profile shapes from vault-format
    /// §4.2's per-rule table, plus the verdict the spec assigns it.
    pub(super) struct Shape {
        pub(super) label: &'static str,
        /// Raw CBOR bytes of the subtree to splice into an `unknown` bag.
        pub(super) bytes: &'static [u8],
        /// What `decode_manifest` MUST do with a manifest carrying this
        /// subtree -- the specification, not an observed value. See
        /// `generate_manifest_canonicality_kat`'s doc for why the
        /// generator asserts this rather than recording whatever comes
        /// out.
        pub(super) expect_accept: bool,
    }

    pub(super) const SHAPES: &[Shape] = &[
        Shape {
            label: "control_canonical",
            // map(1) { "a": 1 } -- fully canonical: definite-length map
            // head (A1), definite-length 1-byte text key (61 = text(1),
            // 61 = 'a'), shortest-form uint 1 (01).
            bytes: &[0xA1, 0x61, 0x61, 0x01],
            expect_accept: true,
        },
        Shape {
            label: "control_array",
            // array(2) [1, 2] -- fully canonical: definite-length array
            // head (82), two shortest-form uints (01, 02).
            bytes: &[0x82, 0x01, 0x02],
            expect_accept: true,
        },
        Shape {
            label: "rule1_key_order",
            // map(2) { "zz": 1, "a": 2 } -- the 2-byte key "zz" (62 7A 7A)
            // precedes the 1-byte key "a" (61 61), violating RFC 8949
            // §4.2.1's length-then-bytewise key order. TOLERATED:
            // `ciborium::Value::Map` is an ordered Vec of pairs, so entry
            // order survives the parse and re-encodes byte-identically.
            bytes: &[0xA2, 0x62, 0x7A, 0x7A, 0x01, 0x61, 0x61, 0x02],
            expect_accept: true,
        },
        Shape {
            label: "rule5_duplicate_key",
            // map(2) { "a": 1, "a": 2 } -- the key "a" (61 61) repeats.
            // TOLERATED for the same reason as rule1 above: `Value::Map`
            // does not deduplicate, so the repeat survives the round
            // trip.
            bytes: &[0xA2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02],
            expect_accept: true,
        },
        Shape {
            label: "rule2_indefinite_map",
            // Indefinite-length map head (BF) { "a": 1 }, closed by a
            // break byte (FF), instead of the definite-length A1 head.
            // REJECTED: `ciborium` parses this into a definite-length
            // `Value::Map` on the way in, so the re-encode emits A1 and
            // differs from the indefinite-length input.
            bytes: &[0xBF, 0x61, 0x61, 0x01, 0xFF],
            expect_accept: false,
        },
        Shape {
            label: "rule3_non_shortest_int",
            // map(1) { "a": <uint8-headed 1> } -- the value 1 is written
            // as 18 01 (uint8 additional-info head + payload byte)
            // instead of the shortest form 01. REJECTED: `ciborium`
            // parses the value as the integer 1 and re-encodes it in
            // shortest form, differing from the non-shortest input.
            bytes: &[0xA1, 0x61, 0x61, 0x18, 0x01],
            expect_accept: false,
        },
        Shape {
            label: "rule4_float",
            // map(1) { "a": 1.5f32 } -- FA is the major-type-7 float32
            // head, followed by the IEEE-754 big-endian encoding of 1.5
            // (3F C0 00 00). REJECTED outright: §6.2 rule 4 bans floats
            // anywhere in the body, caught by `reject_floats_and_tags`
            // before the re-encode ever runs.
            bytes: &[0xA1, 0x61, 0x61, 0xFA, 0x3F, 0xC0, 0x00, 0x00],
            expect_accept: false,
        },
    ];

    /// The placeholder subtree spliced into each level's `unknown` bag
    /// before generation starts. Byte-identical to `control_canonical`
    /// above (a fully canonical `{"a": 1}`) -- deliberately, so it lands
    /// at a genuinely decoder-accepted position to splice over. Same
    /// splice-over-a-needle technique as
    /// `core/src/vault/manifest/decode/tests.rs::unknown_subtree_tolerates_key_order_and_duplicates_but_not_encoding`.
    const NEEDLE: &[u8] = &[0xA1, 0x61, 0x61, 0x01];

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

    /// Regenerates `core/tests/data/manifest_canonicality_kat.json` and
    /// the `core/fuzz/seeds/manifest_body/` seed corpus.
    ///
    /// Run manually only:
    ///
    ///     cargo test --release --workspace -- --ignored generate_manifest_canonicality_kat --nocapture
    ///
    /// **This generator asserts the specification; it does not launder
    /// it.** For every (level, shape) pair it compares `decode_manifest`'s
    /// ACTUAL verdict against `Shape::expect_accept` and panics on a
    /// mismatch instead of recording whatever the decoder happened to do.
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

        for level in Level::ALL {
            let m = base_manifest(level);
            let base_bytes = encode_manifest(&m)
                .expect("encode base manifest")
                .expose()
                .to_vec();
            decode_manifest(&base_bytes)
                .expect("baseline manifest (before any splice) must decode");

            let at = locate_needle(&base_bytes, level);

            for shape in SHAPES {
                let mut spliced = base_bytes.clone();
                spliced.splice(at..at + NEEDLE.len(), shape.bytes.iter().copied());

                let got_accept = decode_manifest(&spliced).is_ok();
                assert_eq!(
                    got_accept,
                    shape.expect_accept,
                    "GENERATOR MUST NOT LAUNDER THE SPEC: level={} shape={} table \
                     says expect_accept={}, decoder actually returned accept={}. \
                     This is either a decoder regression or a deliberate, reviewed \
                     change to vault-format.md §4.2's table -- it must not be \
                     silently absorbed by regenerating the fixture.",
                    level.label(),
                    shape.label,
                    shape.expect_accept,
                    got_accept
                );

                let label = format!("{}__{}", level.label(), shape.label);

                rows.push(serde_json::json!({
                    "label": label,
                    "manifest_body_hex": hex::encode(&spliced),
                    "expect_accept": shape.expect_accept,
                }));

                let seed_path = seeds_dir.join(format!("{label}.bin"));
                std::fs::write(&seed_path, &spliced)
                    .unwrap_or_else(|e| panic!("write seed {}: {e}", seed_path.display()));
            }
        }

        assert_eq!(rows.len(), 21, "expected 7 shapes x 3 levels = 21 rows");

        let doc = serde_json::json!({ "rows": rows });
        let json = serde_json::to_string_pretty(&doc).expect("serialize fixture");
        std::fs::write(super::fixture_path(), json).expect("write fixture");
    }
}
