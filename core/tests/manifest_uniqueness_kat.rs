//! Cross-language corpus for `docs/vault-format.md` §4.2's repeated-value
//! rules — the manifest's four uniqueness invariants, and the one
//! documented exception.
//!
//! **Scope, and why this is a SEPARATE corpus from
//! `manifest_canonicality_kat`.** That corpus covers §4.2's per-rule
//! table: five *per-item encoding* rules, spliced into a forward-compat
//! `unknown` bag at three nesting levels. The rules here are
//! *array-level*: they constrain the relationship BETWEEN sibling
//! elements, which no per-item rule can express. The two are also
//! independent — a sortedness check passes for a repeated element,
//! because `[x, x]` **is** sorted — so neither corpus subsumes the other,
//! and folding these rows into that one would have required loosening its
//! `7 shapes x 3 levels = 21` invariant, itself a pin against a fixture
//! of 21 identical rows.
//!
//! **What §4.2 states, and what this pins (#594).** Repeated values are
//! forbidden in four of the five sorted arrays, and a reader rejects
//! them: `device_uuid` within `vector_clock` or within any
//! `vector_clock_summary`, `block_uuid` within `blocks`, and `block_uuid`
//! within `trash`. `recipients` is the explicit exception — a repeated
//! `contact_uuid` is accepted and round-trips, since it denotes no
//! additional grant. That exception is a row here too, not an omission:
//! a corpus carrying only rejections passes against a decoder that
//! rejects everything.
//!
//! **The §4.3 step-4 re-encode structurally cannot see any of this**, which
//! is why the rules need their own pin. A body carrying `[x, x]` parses to
//! `[x, x]` and re-encodes to `[x, x]`, byte for byte. This is the same
//! trap `rule4_float` documents in the sibling corpus — a rule that reads
//! like it falls out of the round-trip and does not — and it is exactly
//! what `conformance.py`'s `py_decode_manifest` got wrong: it enforced the
//! sort disciplines, ended with the re-encode, and accepted all four
//! repeat shapes that `decode_manifest` rejects (#594).
//!
//! **Fixture bodies are built by `encode_manifest`, which does not
//! deduplicate.** Handing it a `Manifest` with two identical `block_uuid`s
//! yields a well-formed, sorted body its own decoder then rejects. That is
//! **#586** — the encoder can emit a body the decoder refuses — used
//! deliberately here as the cheapest correct source of ground-truth bytes,
//! not overlooked. If #586 is ever closed by validating on the encode side,
//! `generate_manifest_uniqueness_kat` starts failing at the `encode_manifest`
//! call and the fix is to build these four bodies by post-hoc `ciborium`
//! surgery, the way `array_sort_disciplines_are_enforced_and_not_vacuous`
//! already builds its out-of-order bodies.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use secretary_core::vault::manifest::decode_manifest;

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/manifest_uniqueness_kat.json")
}

#[test]
fn manifest_uniqueness_kat_replays() {
    let raw = std::fs::read_to_string(fixture_path()).expect(
        "fixture must exist -- generate it with:\n  \
         cargo test --release --workspace -- --ignored generate_manifest_uniqueness_kat --nocapture",
    );
    let doc: serde_json::Value = serde_json::from_str(&raw).expect("fixture JSON");
    let rows = doc["rows"].as_array().expect("rows array");

    let mut labels: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut accepted = 0usize;
    let mut rejected = 0usize;

    for row in rows {
        let label = row["label"].as_str().expect("label");
        labels.insert(label.to_string());
        let body = hex::decode(row["manifest_body_hex"].as_str().expect("body")).expect("hex");
        let expect_accept = row["expect_accept"].as_bool().expect("expect_accept");
        let got = decode_manifest(&body).is_ok();
        assert_eq!(
            got, expect_accept,
            "row {label:?}: expected accept={expect_accept}, got accept={got}"
        );
        if expect_accept {
            accepted += 1;
        } else {
            rejected += 1;
        }
    }

    // Both floors, for the reason the sibling corpus states: a reject-only
    // corpus passes against a decoder that rejects everything, and an
    // accept-only one against a decoder that accepts everything. The
    // `recipients` exception and the all-distinct control carry the accept
    // side here.
    assert!(
        accepted > 0,
        "corpus has no ACCEPT rows -- it would pass by rejecting everything"
    );
    assert!(
        rejected > 0,
        "corpus has no REJECT rows -- it would pass by accepting everything"
    );

    // Label-set equality, not a bare count: a fixture holding N copies of
    // one row satisfies a length check and proves nothing.
    let expected: std::collections::BTreeSet<String> = generate::CASES
        .iter()
        .map(|c| c.label.to_string())
        .collect();
    assert_eq!(
        labels, expected,
        "corpus label set must be exactly the CASES table"
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
        VectorClockEntry,
    };

    /// One array-level uniqueness case: a mutation applied to the
    /// all-distinct baseline, plus the verdict §4.2 assigns it.
    pub(super) struct Case {
        pub(super) label: &'static str,
        /// Applied to a fresh [`base_manifest`]. A no-op for the control.
        pub(super) mutate: fn(&mut Manifest),
        /// What `decode_manifest` MUST do — the specification, not an
        /// observed value. See `generate_manifest_uniqueness_kat`'s doc.
        pub(super) expect_accept: bool,
    }

    pub(super) const CASES: &[Case] = &[
        Case {
            // The baseline, unmutated: every array distinct and ascending.
            // Without it a decoder that rejected every input would satisfy
            // the four reject rows below and prove nothing.
            label: "control__all_distinct",
            mutate: |_m| {},
            expect_accept: true,
        },
        Case {
            // Two `blocks[]` entries claiming the same block with DIFFERENT
            // names — the ambiguity §4.2 forbids, not a byte-identical
            // repeat: two conformant readers could resolve it first-wins or
            // last-wins and disagree about the vault's contents.
            label: "blocks__duplicate_block_uuid",
            mutate: |m| m.blocks[1].block_uuid = m.blocks[0].block_uuid,
            expect_accept: false,
        },
        Case {
            // §7 tracks only the most-recent tombstone per block, so two
            // trash entries for one `block_uuid` have no defined meaning.
            label: "trash__duplicate_block_uuid",
            mutate: |m| m.trash[1].block_uuid = m.trash[0].block_uuid,
            expect_accept: false,
        },
        Case {
            // A vector clock is per-device: two counters for one device is
            // nonsensical, and which one wins would decide a rollback check.
            label: "vector_clock__duplicate_device_uuid",
            mutate: |m| m.vector_clock[1].device_uuid = m.vector_clock[0].device_uuid,
            expect_accept: false,
        },
        Case {
            // The same rule one level down. `parse_vector_clock` serves both
            // arrays, so this and the row above share the
            // `VectorClockDuplicateDevice` variant -- but they are separate
            // rows because a reader can easily check one array and forget
            // the nested one, which is a divergence no top-level row detects.
            label: "vector_clock_summary__duplicate_device_uuid",
            mutate: |m| {
                let first = m.blocks[0].vector_clock_summary[0].device_uuid;
                m.blocks[0].vector_clock_summary[1].device_uuid = first;
            },
            expect_accept: false,
        },
        Case {
            // THE DOCUMENTED EXCEPTION (§4.2). A repeated `contact_uuid`
            // denotes no additional grant, so it is accepted and
            // round-trips. `parse_recipients` deliberately has no
            // uniqueness check. This row is what stops a reader from
            // "tidying up" the asymmetry into a fifth rejection, which
            // would narrow a v1-frozen decoder.
            label: "recipients__duplicate_contact_uuid",
            mutate: |m| {
                let first = m.blocks[0].recipients[0];
                m.blocks[0].recipients[1] = first;
            },
            expect_accept: true,
        },
    ];

    /// One `BlockEntry` carrying TWO recipients and TWO
    /// `vector_clock_summary` entries, all distinct and ascending.
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

    /// A structurally complete manifest with **two distinct entries in all
    /// five §4.2 arrays**.
    ///
    /// Two is the minimum that can carry a repeat, so a baseline with
    /// fewer would make every case here vacuous — the same vacuity the
    /// sibling corpus was found to have in the PR #595 review, where three
    /// arrays were empty and two held one element. Carrying no `unknown`
    /// bag at any level is deliberate: these rules are about the known
    /// arrays, and an unknown subtree would only add a variable the
    /// verdicts do not depend on.
    pub(super) fn base_manifest() -> Manifest {
        Manifest {
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
        }
    }

    /// Regenerates `core/tests/data/manifest_uniqueness_kat.json` and this
    /// corpus's six `core/fuzz/seeds/manifest_body/` seeds.
    ///
    /// Run manually only:
    ///
    ///     cargo test --release --workspace -- --ignored generate_manifest_uniqueness_kat --nocapture
    ///
    /// **This generator asserts the specification; it does not launder
    /// it.** For every case it compares `decode_manifest`'s ACTUAL verdict
    /// against `Case::expect_accept` and panics on a mismatch instead of
    /// recording whatever the decoder happened to do. A generator that
    /// wrote down the observed verdict would make
    /// `manifest_uniqueness_kat_replays` vacuous — it would pass no matter
    /// how the decoder's behaviour changed, because the fixture would
    /// always describe the current behaviour rather than the required one.
    /// If this panics, the fix is either the decoder (a real regression) or
    /// the `CASES` table (a deliberate, reviewed change to
    /// `docs/vault-format.md` §4.2) — never silently absorbing the new
    /// value by regenerating.
    ///
    /// The seeds share `core/fuzz/seeds/manifest_body/` with the sibling
    /// corpus. Neither generator clears that directory and the label
    /// namespaces are disjoint, so the two coexist; `differential_replay.rs`
    /// picks these six up as a third replay path with no wiring change (its
    /// per-target floor is `seen > 0`).
    #[test]
    #[ignore]
    fn generate_manifest_uniqueness_kat() {
        let seeds_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds/manifest_body");
        std::fs::create_dir_all(&seeds_dir)
            .unwrap_or_else(|e| panic!("create {}: {e}", seeds_dir.display()));

        let mut rows = Vec::new();
        for case in CASES {
            let mut m = base_manifest();
            (case.mutate)(&mut m);

            let body = encode_manifest(&m)
                .unwrap_or_else(|e| {
                    panic!(
                        "case {}: encode_manifest refused to emit the body ({e:?}). \
                         See this file's module doc: these fixtures rely on #586 \
                         (the encoder does not validate uniqueness). If #586 has \
                         been closed, build the rejecting bodies by ciborium \
                         surgery instead.",
                        case.label
                    )
                })
                .expose()
                .to_vec();

            let got_accept = decode_manifest(&body).is_ok();
            assert_eq!(
                got_accept, case.expect_accept,
                "GENERATOR MUST NOT LAUNDER THE SPEC: case={} table says \
                 expect_accept={}, decoder actually returned accept={}. This is \
                 either a decoder regression or a deliberate, reviewed change to \
                 vault-format.md §4.2's repeated-value rules -- it must not be \
                 silently absorbed by regenerating the fixture.",
                case.label, case.expect_accept, got_accept
            );

            rows.push(serde_json::json!({
                "label": case.label,
                "manifest_body_hex": hex::encode(&body),
                "expect_accept": case.expect_accept,
            }));

            let seed_path = seeds_dir.join(format!("uniq__{}.bin", case.label));
            std::fs::write(&seed_path, &body)
                .unwrap_or_else(|e| panic!("write seed {}: {e}", seed_path.display()));
        }

        assert_eq!(rows.len(), CASES.len(), "one row per case");

        let doc = serde_json::json!({ "rows": rows });
        let json = serde_json::to_string_pretty(&doc).expect("serialize fixture");
        std::fs::write(super::fixture_path(), json).expect("write fixture");
    }
}
