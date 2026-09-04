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
//! **Fixture bodies are built by post-hoc `ciborium` surgery (#600 is
//! CLOSED).** They used to be built by handing `encode_manifest` a
//! `Manifest` carrying the repeat — the cheapest correct source of
//! ground-truth bytes while the encoder declined to enforce §4.2's writer
//! half. The tripwire the paragraph here used to describe then fired
//! exactly as written: `encode_case` panicked at its `encode_manifest`
//! call, in the generator AND in `manifest_uniqueness_kat_replays`'s
//! rebuild-and-compare. The four rejecting bodies are now produced the way
//! a non-conformant peer would have to produce them — encode the
//! all-distinct baseline, then edit one field in the bytes — following
//! `array_sort_disciplines_are_enforced_and_not_vacuous`, which does the
//! same for the sort disciplines and for the same reason.
//!
//! **The fixture did not change.** Every row's bytes are byte-identical to
//! the ones #594 generated; `manifest_uniqueness_kat_replays` asserts that
//! against the committed JSON on every run, and the two ACCEPT rows
//! additionally assert that surgery and `encode_manifest` agree byte for
//! byte, which is what stops the surgery path from quietly redefining what
//! the corpus contains.
//!
//! **The corpus pins BOTH directions now.** §4.2's repeated-value
//! paragraph is a writer obligation as well as a reader one ("writers MUST
//! NOT emit them and readers MUST reject them"), so every row asserts the
//! encoder's verdict alongside the decoder's, each against its own
//! [`ManifestError`] variant — the encode side has its own
//! `Encode*` variants, deliberately (see their docs).
//!
//! **Do not cite #586 for this.** An earlier version of this comment did,
//! and it was wrong in a way that mattered: #586 is scoped to
//! `CanonicalMap::push` accepting a duplicate **map key**, and its proposed
//! fix ("reject adjacent equal keys after the sort in
//! `CanonicalMap::serialize`") operates on keys only. Closing #586 exactly
//! as specified would not touch duplicate array **elements** and would not
//! make this generator fail — so the tripwire the paragraph above describes
//! did not exist under that citation. Same class, different rule; #600 is
//! the array-level twin (#599 review).

#![forbid(unsafe_code)]

use std::path::PathBuf;

use secretary_core::vault::manifest::decode_manifest;

use generate::Verdict;

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/manifest_uniqueness_kat.json")
}

/// Replay the corpus, and prove the corpus itself is what it claims to be.
///
/// **The second half is the point, and it was missing (#599 review).** The
/// first version of this test asserted only
/// `decode_manifest(&body).is_ok() == expect_accept`, with both operands
/// read out of the fixture. That is satisfied by a fixture whose four
/// REJECT bodies are a single garbage byte — demonstrated by execution, the
/// test stayed green — and by one whose `recipients` row has been quietly
/// swapped for a duplicate-`blocks` body, which deletes §4.2's only
/// exception from the corpus. Label-set equality catches a dropped or
/// renamed row; nothing looked at the bytes.
///
/// So every row's body is now rebuilt from [`generate::CASES`] and
/// [`generate::base_manifest`] and required to match the fixture byte for
/// byte, and each REJECT row must produce the specific [`ManifestError`]
/// variant §4.2 assigns it. A hand-edited fixture reds here; a row rejected
/// for an unrelated reason reds here. This is the in-Rust counterpart of
/// the control section MUQ carries on the Python side, and of
/// `array_sort_disciplines_are_enforced_and_not_vacuous` in the sibling
/// corpus — which builds its mutations at test time for the same reason.
///
/// Rebuilding through `encode_manifest` couples this test to the encoder,
/// deliberately: if #586's class is ever closed on the array-element side
/// (see this file's module doc, and #600), the rebuild fails here as well
/// as in the generator, which is the signal wanted rather than a silent
/// divergence between a frozen fixture and a changed encoder.
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
    // Accumulated rather than asserted in the loop: a regression that moves
    // several positions at once is far more readable in one run than one
    // row at a time, and the Python section already reports this way.
    let mut issues: Vec<String> = Vec::new();

    for row in rows {
        let label = row["label"].as_str().expect("label");
        labels.insert(label.to_string());
        let body = hex::decode(row["manifest_body_hex"].as_str().expect("body")).expect("hex");
        let expect_accept = row["expect_accept"].as_bool().expect("expect_accept");

        let outcome = decode_manifest(&body);
        let got = outcome.is_ok();
        if got != expect_accept {
            issues.push(format!(
                "row {label:?}: expected accept={expect_accept}, got accept={got}"
            ));
        }
        if expect_accept {
            accepted += 1;
        } else {
            rejected += 1;
        }

        // The fixture must be the corpus the CASES table describes, not
        // merely a set of bodies that happen to produce the right verdicts.
        let Some(case) = generate::CASES.iter().find(|c| c.label == label) else {
            // Label-set equality below reports this; skip the byte checks
            // rather than indexing into a table that has no such row.
            continue;
        };
        if case.verdict.accepts() != expect_accept {
            issues.push(format!(
                "row {label:?}: fixture says expect_accept={expect_accept}, CASES says {}",
                case.verdict.accepts()
            ));
        }
        let rebuilt = generate::encode_case(case);
        if rebuilt != body {
            issues.push(format!(
                "row {label:?}: fixture body is not what CASES produces ({} vs {} bytes) -- \
                 the fixture has been hand-edited, or the encoder changed; regenerate with \
                 --ignored generate_manifest_uniqueness_kat",
                body.len(),
                rebuilt.len()
            ));
        }
        if let (Verdict::Reject { decode, .. }, Err(e)) = (&case.verdict, &outcome) {
            if !decode(e) {
                issues.push(format!(
                    "row {label:?}: rejected for the WRONG reason ({e:?}) -- the row is named \
                     for a §4.2 repeated-value rule, so a rejection from any other check \
                     leaves that rule untested"
                ));
            }
        }

        // ---- the WRITER half of the same rule (#600) ----------------
        //
        // §4.2 binds writers as well as readers, and until #600 this
        // codebase enforced only the reader half — `encode_manifest`
        // would emit, and `sign_manifest` sign, every one of the four
        // bodies above. Asserting it here rather than in a separate
        // test keeps one table as the single statement of what §4.2
        // requires in both directions.
        let mut mutated = generate::base_manifest();
        (case.mutate)(&mut mutated);
        let encoded = secretary_core::vault::manifest::encode_manifest(&mutated);
        if encoded.is_ok() != case.verdict.accepts() {
            issues.push(format!(
                "row {label:?}: encode_manifest returned accept={}, expected {expect_accept} \
                 -- §4.2 binds writers as well as readers",
                encoded.is_ok()
            ));
        }
        match (&case.verdict, &encoded) {
            (Verdict::Reject { encode, .. }, Err(e)) if !encode(e) => issues.push(format!(
                "row {label:?}: encode_manifest rejected for the WRONG reason ({e:?})"
            )),
            // The ACCEPT rows carry the cross-check that keeps the
            // surgery path honest: where the encoder CAN still emit the
            // body, it must agree with what surgery produced, byte for
            // byte. Without it, `plant` could silently drift from
            // `mutate` and the corpus would pin whatever surgery
            // happened to build.
            //
            // Keyed on `Accept`, not on "no encode predicate" (#608
            // review): the old shape let one unrelated field switch this
            // cross-check off on an ACCEPT row, silently, and it is the
            // corpus's only defence against that drift.
            (Verdict::Accept, Ok(bytes)) if bytes.expose() != rebuilt.as_slice() => {
                issues.push(format!(
                    "row {label:?}: surgery and encode_manifest disagree ({} vs {} bytes) -- \
                     the `plant` closure has drifted from its `mutate`",
                    rebuilt.len(),
                    bytes.expose().len()
                ))
            }
            _ => {}
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

    assert!(
        issues.is_empty(),
        "manifest uniqueness corpus disagreements ({}):\n  {}",
        issues.len(),
        issues.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// Generator (run manually; writes the fixture + the differential-replay
// seed corpus)
// ---------------------------------------------------------------------------

mod generate {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use ciborium::Value;
    use secretary_core::vault::manifest::{
        decode_manifest, encode_manifest, BlockEntry, KdfParamsRef, Manifest, ManifestError,
        TrashEntry, VectorClockEntry,
    };

    /// One array-level uniqueness case: a mutation applied to the
    /// all-distinct baseline, plus the verdict §4.2 assigns it.
    pub(super) struct Case {
        pub(super) label: &'static str,
        /// Applied to a fresh [`base_manifest`]. A no-op for the control.
        ///
        /// Since #600 this no longer builds the fixture bytes — [`plant`]
        /// does. It drives the WRITER-side assertion instead: what
        /// `encode_manifest` must do when handed this manifest. Keeping
        /// both is what makes §4.2's two halves executable from one table.
        ///
        /// [`plant`]: Self::plant
        pub(super) mutate: fn(&mut Manifest),
        /// Applied to the PARSED baseline body, and the sole source of
        /// this row's fixture bytes.
        ///
        /// Expresses the same edit as [`mutate`] one layer down, on CBOR
        /// rather than on the typed struct, because `encode_manifest` now
        /// refuses to emit four of the six (#600). The two cannot be
        /// cross-checked on a REJECT row — the encoder produces nothing to
        /// compare against — so each `plant` is written to mirror its
        /// `mutate` and the ACCEPT rows carry the cross-check for the
        /// mechanism.
        ///
        /// [`mutate`]: Self::mutate
        pub(super) plant: fn(&mut Value),
        /// What BOTH directions MUST do — the specification, not an
        /// observed value. See `generate_manifest_uniqueness_kat`'s doc.
        pub(super) verdict: Verdict,
    }

    /// §4.2's verdict for one row, in both directions at once.
    ///
    /// **An enum rather than the `bool` + two `Option`s this replaced
    /// (#608 review), because that shape made two invalid states
    /// representable and both were silent.** A REJECT row written
    /// `expect_accept: false, expect_err: None, expect_encode_err: None`
    /// compiled, and `manifest_uniqueness_kat_replays` PASSED it —
    /// degrading the row to "rejected somehow", which is precisely the
    /// vacuity this file's own doc records #599 as having removed. And
    /// the surgery-vs-encoder byte cross-check keyed on
    /// `expect_encode_err.is_none()` rather than on acceptance, so
    /// setting that one field on an ACCEPT row silently disabled the
    /// corpus's ONLY defence against `plant` drifting from `mutate`.
    ///
    /// Both are now unrepresentable: a `Reject` cannot omit either
    /// predicate, and the cross-check matches on `Accept`, which is what
    /// it actually means.
    pub(super) enum Verdict {
        /// §4.2 requires both directions to accept. These rows carry the
        /// byte-for-byte `plant`-vs-`encode_manifest` cross-check, which
        /// is possible only here: on a REJECT row the encoder produces
        /// nothing to compare against.
        Accept,
        /// §4.2 requires both directions to reject — each with its OWN
        /// [`ManifestError`] variant, because the two genuinely differ:
        /// the encoder reports `EncodeDuplicateBlockUuid` where the
        /// decoder reports `DuplicateBlockUuid`. Asserting the encode
        /// verdict against the DECODE variant would pass only if the two
        /// were collapsed, which is the design this codebase deliberately
        /// rejected.
        ///
        /// Predicates rather than values because `ManifestError` has no
        /// `PartialEq` (deliberately — several variants carry `CborFault`
        /// payloads). Without them, `is_ok() == false` is the whole
        /// assertion, so a row could be rejected for an entirely
        /// unrelated reason — a malformed body, a missing field — and the
        /// corpus would still report the uniqueness rule as pinned.
        Reject {
            decode: fn(&ManifestError) -> bool,
            encode: fn(&ManifestError) -> bool,
        },
    }

    impl Verdict {
        /// Whether §4.2 requires this row to be accepted.
        ///
        /// The fixture records this as a `bool`, and
        /// `manifest_uniqueness_kat_replays` compares the two — so it is
        /// DERIVED here rather than stored alongside the predicates,
        /// which is what stops it disagreeing with them.
        pub(super) fn accepts(&self) -> bool {
            matches!(self, Verdict::Accept)
        }
    }

    /// Where in its array each case plants its repeat, and in which block.
    ///
    /// **Both axes are deliberately varied across the table**, because a
    /// corpus that plants every repeat at the same coordinates pins less
    /// than it appears to. Two specific weaknesses are closed by spreading
    /// them, and both were live until #599's review measured them:
    ///
    /// - **Position within the array.** Every array here holds THREE
    ///   distinct entries, and the repeat lands on the FIRST adjacent pair
    ///   in some rows and the LAST in others. With a two-element array (the
    ///   first version of this corpus) a full adjacent scan and a
    ///   `ids[0] == ids[1]` check are indistinguishable; with three and only
    ///   one position exercised, a first-pair-only or last-pair-only reader
    ///   still passes. Three entries with both positions used is the
    ///   smallest corpus that separates all three implementations.
    /// - **Which block.** The nested `vector_clock_summary` and
    ///   `recipients` rows plant into `blocks[1]`, not `blocks[0]`. §4.2
    ///   constrains "**each** block's" summary, and a reader that checks
    ///   only the first block was conformant against the `blocks[0]`
    ///   version of this corpus — demonstrated by execution: wrapping the
    ///   Python check in `if i == 0:` left the whole suite green.
    pub(super) const CASES: &[Case] = &[
        Case {
            // The baseline, unmutated: every array distinct and ascending.
            // Without it a decoder that rejected every input would satisfy
            // the four reject rows below and prove nothing.
            label: "control__all_distinct",
            mutate: |_m| {},
            plant: |_v| {},
            verdict: Verdict::Accept,
        },
        Case {
            // Two `blocks[]` entries claiming the same block with DIFFERENT
            // names — the ambiguity §4.2 forbids, not a byte-identical
            // repeat: two conformant readers could resolve it first-wins or
            // last-wins and disagree about the vault's contents.
            //
            // Repeat on the LAST adjacent pair (indices 1,2).
            label: "blocks__duplicate_block_uuid",
            mutate: |m| m.blocks[2].block_uuid = m.blocks[1].block_uuid,
            plant: |v| copy_field(v, Array::Top("blocks"), 1, 2, "block_uuid"),
            verdict: Verdict::Reject {
                decode: |e| matches!(e, ManifestError::DuplicateBlockUuid),
                encode: |e| matches!(e, ManifestError::EncodeDuplicateBlockUuid),
            },
        },
        Case {
            // §7 tracks only the most-recent tombstone per block, so two
            // trash entries for one `block_uuid` have no defined meaning.
            //
            // Repeat on the FIRST adjacent pair (indices 0,1).
            label: "trash__duplicate_block_uuid",
            mutate: |m| m.trash[1].block_uuid = m.trash[0].block_uuid,
            plant: |v| copy_field(v, Array::Top("trash"), 0, 1, "block_uuid"),
            verdict: Verdict::Reject {
                decode: |e| matches!(e, ManifestError::DuplicateTrashUuid),
                encode: |e| matches!(e, ManifestError::EncodeDuplicateTrashUuid),
            },
        },
        Case {
            // A vector clock is per-device: two counters for one device is
            // nonsensical, and which one wins would decide a rollback check.
            //
            // Repeat on the LAST adjacent pair (indices 1,2).
            label: "vector_clock__duplicate_device_uuid",
            mutate: |m| m.vector_clock[2].device_uuid = m.vector_clock[1].device_uuid,
            plant: |v| copy_field(v, Array::Top("vector_clock"), 1, 2, "device_uuid"),
            verdict: Verdict::Reject {
                decode: |e| matches!(e, ManifestError::VectorClockDuplicateDevice),
                encode: |e| matches!(e, ManifestError::EncodeVectorClockDuplicateDevice),
            },
        },
        Case {
            // The same rule one level down, and in the SECOND block. That
            // index is the point of the row: `parse_vector_clock` serves
            // both arrays, so this and the row above share the
            // `VectorClockDuplicateDevice` variant, and a reader checking
            // only `blocks[0]` is a divergence no other row detects.
            //
            // Repeat on the FIRST adjacent pair (indices 0,1).
            label: "vector_clock_summary__duplicate_device_uuid",
            mutate: |m| {
                let first = m.blocks[1].vector_clock_summary[0].device_uuid;
                m.blocks[1].vector_clock_summary[1].device_uuid = first;
            },
            plant: |v| {
                copy_field(
                    v,
                    Array::InBlock(1, "vector_clock_summary"),
                    0,
                    1,
                    "device_uuid",
                )
            },
            verdict: Verdict::Reject {
                decode: |e| matches!(e, ManifestError::VectorClockDuplicateDevice),
                encode: |e| matches!(e, ManifestError::EncodeVectorClockDuplicateDevice),
            },
        },
        Case {
            // THE DOCUMENTED EXCEPTION (§4.2). A repeated `contact_uuid`
            // denotes no additional grant, so it is accepted and
            // round-trips. `parse_recipients` deliberately has no
            // uniqueness check. This row is what stops a reader from
            // "tidying up" the asymmetry into a fifth rejection, which
            // would narrow a v1-frozen decoder.
            //
            // In `blocks[1]`, on the LAST adjacent pair (indices 1,2), for
            // the same two reasons the reject rows spread their positions.
            label: "recipients__duplicate_contact_uuid",
            mutate: |m| {
                let second = m.blocks[1].recipients[1];
                m.blocks[1].recipients[2] = second;
            },
            plant: |v| copy_element(v, Array::InBlock(1, "recipients"), 1, 2),
            verdict: Verdict::Accept,
        },
    ];

    /// One `BlockEntry` carrying THREE recipients and THREE
    /// `vector_clock_summary` entries, all distinct and ascending.
    ///
    /// Three, not two: see [`CASES`]'s doc. Two is the minimum that can
    /// carry a repeat at all, but it cannot distinguish an adjacent scan
    /// from a `ids[0] == ids[1]` check, because those are the same
    /// question on a two-element list.
    fn block_entry(uuid_byte: u8, name: &str) -> BlockEntry {
        BlockEntry {
            block_uuid: [uuid_byte; 16],
            block_name: name.to_string(),
            fingerprint: [0xFF; 32],
            recipients: vec![[0x31; 16], [0x32; 16], [0x33; 16]],
            vector_clock_summary: vec![
                VectorClockEntry {
                    device_uuid: [0x41; 16],
                    counter: 7,
                },
                VectorClockEntry {
                    device_uuid: [0x42; 16],
                    counter: 9,
                },
                VectorClockEntry {
                    device_uuid: [0x43; 16],
                    counter: 11,
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

    /// A structurally complete manifest with **three distinct entries in
    /// all five §4.2 arrays**.
    ///
    /// Two would be the minimum that can carry a repeat, so a baseline
    /// with fewer would make every case here vacuous — the same vacuity
    /// the sibling corpus was found to have in the PR #595 review, where
    /// three arrays were empty and two held one element. Three is what
    /// separates a full adjacent scan from a fixed-pair check; [`CASES`]'s
    /// doc states why, and spends the extra element by planting repeats at
    /// both ends across the table. Carrying no `unknown` bag at any level
    /// is deliberate: these rules are about the known arrays, and an
    /// unknown subtree would only add a variable the verdicts do not
    /// depend on.
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
                VectorClockEntry {
                    device_uuid: [0x23; 16],
                    counter: 7,
                },
            ],
            blocks: vec![
                block_entry(0xB1, "corpus-block"),
                block_entry(0xB2, "corpus-block-2"),
                block_entry(0xB3, "corpus-block-3"),
            ],
            trash: vec![trash_entry(0xDE), trash_entry(0xDF), trash_entry(0xE0)],
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

        // Everything is computed and asserted BEFORE anything is written.
        // Writing inside the loop left cases 0..N-1's seeds updated on disk
        // while the fixture JSON still described the old corpus whenever a
        // later case tripped an assertion below -- a half-applied
        // regeneration from a generator whose whole doc is about not
        // absorbing changes silently (#599 review). Detectable via
        // `git status`, since the seeds are tracked, but a generator should
        // not need that.
        let mut rows = Vec::new();
        let mut seeds: Vec<(PathBuf, Vec<u8>)> = Vec::new();
        for case in CASES {
            let body = encode_case(case);

            let outcome = decode_manifest(&body);
            let got_accept = outcome.is_ok();
            assert_eq!(
                got_accept,
                case.verdict.accepts(),
                "GENERATOR MUST NOT LAUNDER THE SPEC: case={} table says \
                 expect_accept={}, decoder actually returned accept={}. This is \
                 either a decoder regression or a deliberate, reviewed change to \
                 vault-format.md §4.2's repeated-value rules -- it must not be \
                 silently absorbed by regenerating the fixture.",
                case.label,
                case.verdict.accepts(),
                got_accept
            );
            // Same stance one level finer: the VARIANT is part of the
            // specification this table records, so a row that starts being
            // rejected by some other check is a mismatch to resolve, not a
            // detail to regenerate over.
            if let (Verdict::Reject { decode, .. }, Err(e)) = (&case.verdict, &outcome) {
                assert!(
                    decode(e),
                    "GENERATOR MUST NOT LAUNDER THE SPEC: case={} was rejected by a \
                     DIFFERENT check than the §4.2 repeated-value rule it is named \
                     for ({e:?}).",
                    case.label
                );
            }

            // The writer half, asserted in the generator for the same
            // reason as the reader half: a fixture must not be minted
            // from a tree whose encoder disagrees with the table.
            let mut mutated = base_manifest();
            (case.mutate)(&mut mutated);
            let encoded = encode_manifest(&mutated);
            assert_eq!(
                encoded.is_ok(),
                case.verdict.accepts(),
                "GENERATOR MUST NOT LAUNDER THE SPEC: case={} table says \
                 expect_accept={}, encode_manifest actually returned accept={}. \
                 §4.2 binds writers as well as readers.",
                case.label,
                case.verdict.accepts(),
                encoded.is_ok()
            );
            if let (Verdict::Reject { encode, .. }, Err(e)) = (&case.verdict, &encoded) {
                assert!(
                    encode(e),
                    "GENERATOR MUST NOT LAUNDER THE SPEC: case={} was refused by the \
                     encoder for a DIFFERENT reason than the §4.2 repeated-value rule \
                     it is named for ({e:?}).",
                    case.label
                );
            }

            rows.push(serde_json::json!({
                "label": case.label,
                "manifest_body_hex": hex::encode(&body),
                "expect_accept": case.verdict.accepts(),
            }));
            seeds.push((seeds_dir.join(format!("uniq__{}.bin", case.label)), body));
        }

        assert_eq!(rows.len(), CASES.len(), "one row per case");

        let doc = serde_json::json!({ "rows": rows });
        let json = serde_json::to_string_pretty(&doc).expect("serialize fixture");
        std::fs::write(super::fixture_path(), json).expect("write fixture");
        for (path, body) in &seeds {
            std::fs::write(path, body)
                .unwrap_or_else(|e| panic!("write seed {}: {e}", path.display()));
        }

        // Sweep orphans, so the seed set is a FUNCTION of `CASES` rather
        // than the union of every label the table has ever had. Renaming a
        // case otherwise leaves `uniq__<old>.bin` behind, and
        // `differential_replay.rs` keeps replaying it forever against a row
        // that no longer exists (#599 review).
        //
        // Scoped to this corpus's `uniq__` prefix: the directory is SHARED
        // with `manifest_canonicality_kat`'s 21 `top__`/`block__`/`trash__`
        // seeds, and deleting those here would silently shrink a corpus this
        // generator does not own.
        let keep: std::collections::BTreeSet<&std::path::Path> =
            seeds.iter().map(|(p, _)| p.as_path()).collect();
        for entry in std::fs::read_dir(&seeds_dir).expect("read seeds dir") {
            let path = entry.expect("dir entry").path();
            let is_ours = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("uniq__") && n.ends_with(".bin"));
            if is_ours && !keep.contains(path.as_path()) {
                std::fs::remove_file(&path)
                    .unwrap_or_else(|e| panic!("remove orphan seed {}: {e}", path.display()));
                println!("removed orphan seed {}", path.display());
            }
        }
    }

    /// The canonical body for one case: the all-distinct baseline,
    /// encoded, then edited in the bytes.
    ///
    /// Shared by the generator and by `manifest_uniqueness_kat_replays`'s
    /// rebuild-and-compare, so the fixture the corpus replays and the
    /// bytes the table describes cannot drift apart.
    ///
    /// **The baseline goes through `encode_manifest`; the repeat does
    /// not** (#600). Four of the six rows carry a body the encoder now
    /// refuses to emit, which is the whole of #600 — so the repeat is
    /// planted in the CBOR afterwards. Two properties make that
    /// substitution byte-exact rather than merely plausible:
    ///
    /// 1. `ciborium`'s parse/re-encode is the identity on a canonical
    ///    body (it normalises on parse and keeps map entries as an
    ///    ordered `Vec`), so the control row — whose `plant` is a no-op —
    ///    reproduces `encode_manifest`'s bytes exactly, and
    ///    `manifest_uniqueness_kat_replays` compares it against the
    ///    frozen fixture.
    /// 2. Every `plant` overwrites one fixed-width field with another
    ///    element's value of the same field, and the §4.2 sorts are
    ///    STABLE, so the mutated manifest would have sorted into the same
    ///    positions the baseline did. That is why the fixture did not
    ///    change when the bodies stopped coming from the encoder.
    pub(super) fn encode_case(case: &Case) -> Vec<u8> {
        let baseline = encode_manifest(&base_manifest())
            .expect("the all-distinct baseline must encode")
            .expose()
            .to_vec();
        let mut v: Value = ciborium::de::from_reader(&baseline[..]).expect("parse baseline");
        (case.plant)(&mut v);
        let mut out = Vec::new();
        ciborium::ser::into_writer(&v, &mut out).expect("re-encode");
        out
    }

    // -----------------------------------------------------------------
    // Body surgery
    // -----------------------------------------------------------------
    //
    // `core/src/vault/manifest/test_support/surgery.rs` does the same job
    // for the manifest module's own unit tests. The duplication is a
    // crate-boundary consequence, not an oversight: an integration test
    // sees only `secretary_core`'s PUBLIC API, and promoting test-only
    // manifest surgery onto the shipped surface to spare thirty lines
    // here would be the worse trade. `manifest_canonicality_kat.rs`
    // carries a third, for the same reason.

    /// Which array inside a manifest body a plant targets.
    pub(super) enum Array {
        /// A top-level array key — `vector_clock`, `blocks` or `trash`.
        Top(&'static str),
        /// An array inside one `blocks` entry — `recipients` or
        /// `vector_clock_summary`. The index is into `blocks` AS ENCODED,
        /// i.e. after the §4.2 ascending-`block_uuid` sort.
        InBlock(usize, &'static str),
    }

    /// Copy `field` from element `from` onto element `to`, planting a
    /// repeated value in a `map`-element array.
    pub(super) fn copy_field(v: &mut Value, array: Array, from: usize, to: usize, field: &str) {
        let items = array_mut(v, array);
        let source = entry_field(&items[from], field).clone();
        assert_ne!(
            &source,
            entry_field(&items[to], field),
            "elements {from} and {to} already share {field:?} -- the case would be vacuous"
        );
        *entry_field_mut(&mut items[to], field) = source;
    }

    /// Copy a whole element from `from` onto `to`, for an array whose
    /// elements are scalars rather than maps (`recipients`).
    pub(super) fn copy_element(v: &mut Value, array: Array, from: usize, to: usize) {
        let items = array_mut(v, array);
        let source = items[from].clone();
        assert_ne!(
            &source, &items[to],
            "elements {from} and {to} are already equal -- the case would be vacuous"
        );
        items[to] = source;
    }

    fn array_mut(v: &mut Value, array: Array) -> &mut Vec<Value> {
        match array {
            Array::Top(key) => key_array_mut(v, key),
            Array::InBlock(index, key) => {
                let block = key_array_mut(v, "blocks")
                    .get_mut(index)
                    .unwrap_or_else(|| panic!("blocks[{index}] does not exist"));
                key_array_mut(block, key)
            }
        }
    }

    fn key_array_mut<'a>(v: &'a mut Value, key: &str) -> &'a mut Vec<Value> {
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

    fn entry_field<'a>(entry: &'a Value, field: &str) -> &'a Value {
        match entry {
            Value::Map(m) => m
                .iter()
                .find(|(k, _)| k.as_text() == Some(field))
                .map(|(_, val)| val)
                .unwrap_or_else(|| panic!("entry has no field {field:?}")),
            other => panic!("array element is not a map: {other:?}"),
        }
    }

    fn entry_field_mut<'a>(entry: &'a mut Value, field: &str) -> &'a mut Value {
        match entry {
            Value::Map(m) => m
                .iter_mut()
                .find(|(k, _)| k.as_text() == Some(field))
                .map(|(_, val)| val)
                .unwrap_or_else(|| panic!("entry has no field {field:?}")),
            other => panic!("array element is not a map: {other:?}"),
        }
    }
}
