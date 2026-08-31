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
//! exercises the same 21 bodies (that target's seed directory was empty
//! before this task, so it iterated zero inputs and passed vacuously).
//!
//! The seven shapes' expected verdicts are the SPECIFICATION (vault-format
//! §4.2's five-row table), not an observed decoder behaviour: rules 1
//! (map-key order) and 5 (duplicate keys) are TOLERATED inside an
//! `unknown` subtree, because `ciborium`'s `Value::Map` is an ordered
//! `Vec` of pairs that survives the decode-then-re-encode check unchanged;
//! rules 2 (indefinite-length item), 3 (non-shortest-form integer) and 4
//! (float) are REJECTED, because they are encoding-level departures the
//! parse normalises away, so the re-encode differs from the input.
//! `generate_manifest_canonicality_kat` asserts these verdicts against the
//! decoder's actual output rather than recording whatever comes out --
//! see that function's own doc for why the distinction is load-bearing.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use secretary_core::vault::manifest::decode_manifest;

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

    let mut accepted = 0usize;
    for row in rows {
        let label = row["label"].as_str().expect("label");
        let body = hex::decode(row["manifest_body_hex"].as_str().expect("body")).expect("hex");
        let expect_accept = row["expect_accept"].as_bool().expect("expect_accept");
        let got = decode_manifest(&body).is_ok();
        assert_eq!(
            got, expect_accept,
            "row {label:?}: expected accept={expect_accept}, got accept={got}"
        );
        if expect_accept {
            accepted += 1;
        }
    }
    assert!(
        accepted > 0,
        "corpus has no ACCEPT rows -- it would pass by rejecting everything"
    );
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

    /// A minimal but structurally complete manifest whose `unknown` bag
    /// at `level` carries exactly one entry: [`NEEDLE`]. Every other
    /// field is a fixed, arbitrary value -- this fixture exercises the
    /// canonicality check, not the rest of the schema, so nothing about
    /// the other fields is load-bearing.
    pub(super) fn base_manifest(level: Level) -> Manifest {
        let placeholder = UnknownValue::from_canonical_cbor(NEEDLE)
            .expect("NEEDLE is canonical CBOR by construction");

        let mut m = Manifest {
            manifest_version: 1,
            vault_uuid: [0x01; 16],
            format_version: secretary_core::version::FORMAT_VERSION,
            suite_id: secretary_core::version::SUITE_ID,
            owner_user_uuid: [0x02; 16],
            vector_clock: Vec::new(),
            blocks: Vec::new(),
            trash: Vec::new(),
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
                let mut block = BlockEntry {
                    block_uuid: [0xB1; 16],
                    block_name: "corpus-block".to_string(),
                    fingerprint: [0xFF; 32],
                    recipients: Vec::new(),
                    vector_clock_summary: Vec::new(),
                    suite_id: secretary_core::version::SUITE_ID,
                    created_at_ms: 1_700_000_000_000,
                    last_mod_ms: 1_700_000_000_000,
                    unknown: BTreeMap::new(),
                };
                block.unknown.insert("zzz_needle".to_string(), placeholder);
                m.blocks.push(block);
            }
            Level::Trash => {
                let mut trash = TrashEntry {
                    block_uuid: [0xDE; 16],
                    tombstoned_at_ms: 1_700_000_000_000,
                    tombstoned_by: [0xAA; 16],
                    fingerprint: None,
                    purged_at_ms: None,
                    unknown: BTreeMap::new(),
                };
                trash.unknown.insert("zzz_needle".to_string(), placeholder);
                m.trash.push(trash);
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
