# NEXT_SESSION.md — `block_file` and `record` are token-compared, strictly (#641)

Branch `feature/token-compare-record-block`, worktree
`.worktrees/token-compare-record-block`, base `4f350d64` (`main`, immediately
after PR #662 merged).

The user chose this slice by options-plus-recommendation, recorded in the
design spec's decision table (D1-D5): **both targets on one branch,
`block_file` first**; a **target-aware** tolerance rather than the manifest's
global one; a **byte-level well-formedness pre-walk** wired into
`record::decode` only; **no report-order spec text** for §6.1/§6.3 (strict
parity, filed as #668); and **generated single-fault seeds** so CI has
rejecting inputs to compare.

**Issues filed this slice (8):** [#666](https://github.com/hherb/secretary/issues/666)
(walk rollout), [#667](https://github.com/hherb/secretary/issues/667) (depth
residual), [#668](https://github.com/hherb/secretary/issues/668) (§6.1/§6.3
report order), [#669](https://github.com/hherb/secretary/issues/669)
(card/trash bool-as-int), [#670](https://github.com/hherb/secretary/issues/670)
(record optional key present at its default),
[#671](https://github.com/hherb/secretary/issues/671) (residual review nits) and
[#672](https://github.com/hherb/secretary/issues/672) (session-process
references in shipped source), and from the PR #673 review
[#676](https://github.com/hherb/secretary/issues/676) (type-level invariants for
the replay-target and seed tables). The review also extended #666 and #648 by
comment. **#641 stays open** for `contact_card`, `bundle_file` and
`vault_toml`.

**Read §(3a) first.** Three of those issues are ACCEPTANCE divergences — one
decoder accepts a body the other rejects — and none is reachable from any
committed or corpus input, which is why the replay reports full agreement.
They rank above every report-order item.

**The headline: the two targets carrying decrypted user content now compare
WHICH rule each decoder names, with zero tolerance.** Before this slice they
were not token-compared at all. The design spike measured 2,949 `record`
disagreements under provisional mappings; the full local corpus now agrees on
every input — **`record` 7,488 of 7,488, `block_file` 141 of 141** — and CI
makes a strict comparison on each of 57 committed single-fault seeds. §(1c),
and §(1i) for what the PR #673 review changed.

---

## (0) Starting state

`origin/main` had advanced to `4f350d64` (PR #662) since the last baton, so the
first `git fetch origin && git log --oneline main..origin/main` was not empty;
this branch was cut from `4f350d64` (its merge-base). `.worktrees/diff-replay-split`
was removed (it is absent from `git worktree list`). PR
[#665](https://github.com/hherb/secretary/pull/665) (npm advisories:
js-yaml, brace-expansion, postcss in both JS lockfiles) was opened first, from
`.worktrees/npm-dev-advisories`, and is still open. The two detached
`.claude/worktrees/*` checkouts belong to other sessions and were left alone.

---

## (1) What shipped

Run `git log --oneline main..HEAD` for the current set.

| SHA | What |
|---|---|
| `21c44c0e` | design spec |
| `637b1ba1` | implementation plan; Section WF added to the spec |
| `c0098a23` | the phase-dependent tolerance becomes per-TARGET (`PHASE_DEPENDENT_TOLERANCE_TARGETS = ["manifest_body"]`) |
| `1e117193` | `RecordError::rule_token()` and `BlockError::rule_token()`, exhaustive matches, no new vocabulary |
| `de5fe679` | generated single-fault `block_file` seeds, bound to their labels in Rust |
| `fe181845` | Python's merged `prev >= nxt` block envelope check split into sort and repeat; Section RTS binds the `block_file` seeds |
| `67bb6649` | review fix: an unreadable seed is a `FAIL:` line, not a traceback out of `main()` |
| `75cbb7c5` | `block_file` token-compared |
| `492a9c08` | Rust byte walk (`cbor::well_formed::walk_first_item`) in front of ciborium in `record::decode` |
| `19bce3d3` | walk branches the first test list missed (indefinite majors 1 and 6, reserved ai 29/30, float32/64, tag 3, a big-endian multi-byte length) |
| `befcf264` | Python scanner faults typed (`MalformedCbor`), and the Python twin walk `walk_body`; Section WF |
| `4a26be99` | review fix: Section CS asserts `MalformedCbor`'s `ValueError` base |
| `136c9325` | `py_decode_record` reordered into `record::decode`'s phase order, with typed rejections |
| `bbdb1fa1` | generated single-fault `record` seeds, bound in both languages |
| `59e15b76` | `record` token-compared |
| `19711c28` | review fix: `MIN_CORPUS_INPUTS`'s doc for three compared targets |
| `fc715901` | CLAUDE.md, ROADMAP, protocol doc, fuzz README, test.yml comment; #666-#669 filed |
| `80dd11b1`..`1d172304` | the final review's fix wave, 25 commits — §(1f) |
| `6bc7b58c` | this baton and the `NEXT_SESSION.md` retarget |
| `43e40052`..`ba48487c` | the PR #673 review's fix wave, 13 commits — §(1i) |
| (this commit) | this baton updated for that fix wave |

In `core/tests/data/` only the `_comment` of `rule_token_vocabulary.json`
changed (PR #673 review: its "58 of the 136" tolerance figure); no token and
no flag moved. No `RecordError`/`BlockError` variant, public signature or FFI
mapping changed. `record.rs` grew 3,037 → 3,062 lines and `block.rs` 3,222 → 3,229;
both were already tracked for splitting (#556, #563). Every new SOURCE file is
under 500 lines; the design spec, the plan and this handoff are not.

### (1a) Target-aware tolerance

`tokens_agree(target, rust, python)`: equal tokens agree; unequal tokens agree
only when the target is in `PHASE_DEPENDENT_TOLERANCE_TARGETS` (today
`manifest_body` alone) and either token is phase-dependent. The licence comes
from vault-format §4.2's two manifest reader designs, which say nothing about
§6.1 or §6.3. `tolerance_admits_only_phase_dependent_pairs` pins the breadth per
target: **54** of 136 unequal pairs on `manifest_body`, **0** on every other
target. It was 58 on `manifest_body` until the PR #673 review withheld the
four pairs that name `malformed_cbor` against a phase-dependent token. §4.2
makes well-formedness a precondition for both orderings, so those pairs have
no licence. This slice's own `MalformedCbor` retyping of Python's scanner
raises had turned what used to be harness failures into tolerated agreement.

### (1b) `block_file`: a Python split

The spike found every rejecting `block_file` input already pairing one Rust
variant with one Python raise site. Both gaps were in what Python's raises
carried. Python's merged `prev >= nxt` gave one message for both "unsorted"
and "repeated"; it is now two typed classes in `wire/envelope_rules.py`,
reporting the FIRST adjacent pair that is not strictly ascending, as
`block.rs`'s `match cmp` over `windows(2)` does. And the `format_version` and
`suite_id` raises were plain `ParseError` (`container_malformed`) where Rust
says `unsupported_version`; they are now `UnsupportedEnvelopeVersion`
(`fe181845`). The PR #673 review added one `container_malformed` class per
remaining envelope check, so each seed pins its check, not only its token.

### (1c) `record`: the #618 shape, one target down

The spike (design spec §1.2, provisional mappings, tolerance still global)
measured **4,385 agree, 2,949 disagree, 120 tolerated** over 7,454 inputs. Three
causes: Python read the top-level head before establishing well-formedness
(2,847 pairs), had no rule-4 walk ahead of interpretation (101), and checked
trailing bytes before schema faults (~120).

- **Rust** (`492a9c08`): `walk_first_item` walks the first CBOR item's bytes
  iteratively, then checks rule 4 (no tag, no float), before ciborium parses.
  It closes four forms ciborium's parse lets through. `undefined` read as
  `null` (57 inputs) is well-formed RFC 8949 that vault-format §4.2's
  well-formedness precondition excludes. A bignum tag 2/3 that fits 64 bits,
  turned into an integer before the parsed-tree rule-4 walk sees a tag (28), is
  well-formed and breaks crypto-design §6.2 rule 4. A nested indefinite-length
  string chunk (4) breaks RFC 8949 §3.2.3. The fourth, the two-byte simple forms
  `f8 14`..`f8 17` (RFC 8949 §3.3), was found only in the PR #673 review. Rust already rejected every
  one of those bodies, at the latest at the re-encode comparison, so **no Rust
  verdict moved**:
  over the 7,454-input corpus, accept 3 → 3, **0 statuses moved**, **89 reported
  variants moved** (33 `TagRejected`→`CborDecode`, 27 `NotAMap`→`TagRejected`,
  16 `NonTextKey`→`CborDecode`, 7 `FloatRejected`→`CborDecode`,
  5 `NotAMap`→`CborDecode`, 1 `CborDecode`→`TagRejected`).
- **Python** (`136c9325`): `py_decode_record` runs `walk_body` first, then the
  map head, then each entry in wire order (key type, repeat, value checked as
  read), then missing keys, then canonical form. Counted with the FINAL mappings
  and an untokened rejection scored as a disagreement, the reorder took the
  corpus from **4,072 agree / 3,382 disagree** to **7,454 / 0**, and 22
  hand-built bodies reaching arms the corpus never reaches from **2 / 20** to
  **22 / 0**. (3,382 is not comparable to the spike's 2,949: different mappings,
  no tolerance.)
- **An acceptance divergence was found and fixed here.** `created_at_ms: true`
  was ACCEPTED by Python (`isinstance(True, int)`) and rejected by
  `record.rs::take_u64` as `WrongType`; confirmed through a Rust probe, not only
  by reading the arm. It was not the target's only one — §(3a).

### (1d) Committed seeds, and what CI now compares

`core/tests/rule_token_seeds.rs` builds each seed from a committed accepting
base (`golden.bin`, `login.cbor`) by planting ONE fault; the file name
`<token>__<shape>.bin` is derived from the case row. The `#[ignore]` generator
asserts every case before writing any file;
`rule_token_seeds_are_committed_and_label_bound` regenerates and requires byte
identity, the token its name states, and a two-way census. Section **RTS**
binds the same files in Python.

| Target | Seeds | Tokens |
|---|---|---|
| `block_file` | **23** | `container_malformed` 9, `array_sort_order` 6, `repeated_array_value` 6, `unsupported_version` 2 |
| `record` | **34** | `wrong_type` 15, `malformed_cbor` 4, `non_canonical_unclassified` 4, `rule4_tag_or_float` 3, `duplicate_map_key` 3, `integer_out_of_range` 3, `missing_field` 2 |

Since the PR #673 review each row also names its exact Rust error variant, and
Section RTS requires each `block_file` seed's Python class by name (§(1i)).

- Eight `block_file` seeds use **three-entry tables**. Four are faulted at the
  second adjacent pair (fix wave, `3bafc2ad`): with two entries, a reader
  checking the first pair alone was conformant (measured: such a reader ACCEPTS
  all four). Four more are faulted at the FIRST of three (PR #673 review,
  `8f5512f2`): until then every table was faulted at its last pair.
- **Committed replay inputs 50 → 107.** `MIN_CORPUS_INPUTS`: `record` 3 → 37,
  `block_file` 1 → 24. Those floors include the accepting bases, so the strict
  comparisons CI makes are **34** on `record` and **23** on `block_file`. With
  zero tolerance every rejecting committed input reaches a strict comparison,
  which covers #658 for these two targets; `manifest_body`'s #658 stays open.
- Section **WF** pins `walk_body` case for case against the Rust walk tests:
  **52** cases (43 before the PR #673 review). **REG 30 → 32.**
- Section RTS **check 5** holds two-fault bodies built in-section and never
  committed, because §6.1/§6.3 fix no order (#618's rule; #668): **9 `record`
  cases plus 1 `block_file` parity case** (`[high, low, low]` →
  `array_sort_order`). Eight record rows each name the drift they catch; the
  ninth is a regression pin the pre-#641 order also passed. The two field-level
  rows came from the PR #673 review. The record rows' Rust twins are
  `core/src/vault/record_order_tests.rs` (9 tests).

### (1e) Measured results

**CI shape** (PR #673 review fix wave, at `c8601343`): 46 passed; the finish
lines read `record: 37 of 37 input(s) compared, 37 committed` and
`block_file: 24 of 24 input(s) compared, 24 committed`; no disagreement or
harness-failure line. (It was 45 passed, 25 of 25 and 20 of 20 at `be6c9125`.)

**Full local corpus**, re-run at `ba48487c` after the PR #673 review fix wave
(the main checkout's runtime corpus symlinked in, removed after):

```
[differential_replay] vault_toml: 60931 of 60931 input(s) compared, 3 committed, in 21.0s
[differential_replay] record: 7488 of 7488 input(s) compared, 37 committed, in 1.6s
[differential_replay] contact_card: 6396 of 6396 input(s) compared, 2 committed, in 1.1s
[differential_replay] bundle_file: 25 of 25 input(s) compared, 1 committed, in 0.0s
[differential_replay] manifest_file: 10 of 10 input(s) compared, 1 committed, in 0.0s
[differential_replay] manifest_body: 39 of 39 input(s) compared, 39 committed, in 0.0s
[differential_replay] block_file: 141 of 141 input(s) compared, 24 committed, in 0.0s
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 45 filtered out; finished in 26.44s
```

`record` 7,488 = 7,451 runtime + 37 committed; `block_file` 141 = 117 + 24.
The first measurement, at `1d172304`, before the review:

```
[differential_replay] vault_toml: 60931 of 60931 input(s) compared, 3 committed, in 23.4s
[differential_replay] record: 7476 of 7476 input(s) compared, 25 committed, in 1.8s
[differential_replay] contact_card: 6396 of 6396 input(s) compared, 2 committed, in 1.1s
[differential_replay] bundle_file: 25 of 25 input(s) compared, 1 committed, in 0.0s
[differential_replay] manifest_file: 10 of 10 input(s) compared, 1 committed, in 0.0s
[differential_replay] manifest_body: 39 of 39 input(s) compared, 39 committed, in 0.0s
[differential_replay] block_file: 137 of 137 input(s) compared, 20 committed, in 0.0s
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 44 filtered out; finished in 28.32s
```

`record` 7,476 = 7,451 runtime + 25 committed; `block_file` 137 = 117 + 20.
Strictly compared, 0 tolerated pairs, no disagreement, no harness failure.

| | Before this slice | After |
|---|---|---|
| Token-compared targets | `manifest_body` | `manifest_body`, `block_file`, `record` |
| Tolerated unequal pairs on `record` / `block_file` | not compared at all | **0** / **0** |
| `record` disagreements, local corpus | 2,949 (spike, provisional mappings) | **0** |
| Full-corpus agreement | not measured by token | `record` 7,488/7,488, `block_file` 141/141 |
| Committed replay inputs (CI) | 50 | **107** |
| Conformance REG | 30/30 | **32/32** |

### (1f) The final review and its fix wave

One whole-branch review (verdict "with fixes": 2 Important, 11 Minor, plus a
triage of 29 deferred task-review minors), one fix wave, one scoped re-review
(all 20 findings addressed, no new Important). One commit per finding:

| Finding | Commit |
|---|---|
| **I1** — check 5 could not see a walk-order drift: three rows added whose two faults, each alone, name different tokens | `115de3bf` |
| **I2** — a record optional key present at its default (`tags: []`, `tombstone: false`, `tombstoned_at_ms: 0`): Python accepts, Rust rejects | filed **#670**; ROADMAP `be6c9125` |
| M1 — a rule-4 `NonCanonicalItem` was relabelled `RecordNonCanonical`; now re-raised | `80dd11b1` |
| M2 — six doc claims re-measured or narrowed | `fc5520cd` `8d25e838` `76a8ad1d` `5355f4a1` `fe97766b` `79d09409` |
| M3 — "spec §" citations in shipped Rust pointed at the design doc without naming it | `6d81db24` |
| M4 — `RuleToken` docs name every producer, and the LIMITS block is `manifest_body`-only | `6db57d14` |
| M5 — block plaintext decode does not walk first; says so, points at #666 | `fea25dda` |
| M6 — three-entry block tables (4 seeds) plus the `[high, low, low]` parity case | `3bafc2ad`, `1d172304` |
| M7 — Rust twins of check 5 | `93f3ae17` |
| M8 — a known record key with no value check fails loudly (`UncheckedKnownKey`) | `7bea637c` |
| M9 — Section WF checks rule-4 cases by exact kind and offset, not substring | `dff3f367` |
| M10 — process references in Section WF | `b4d322d6` |
| M11 — `rust_token` is a copy of the replay's pipeline, not the same one | `6df670eb` |
| deferred minors: little-endian comment, RTV census 4 → 5, `_reject_rule4_head` callers, split-UTF-8 exact fault, `cbor_scanner.py` stale credit, `TOKEN_COMPARED_TARGETS` doc | `8764e197` `3a8efedd` `c884147f` `a65a0e20` `b4d6ead6` `39deebd2` |
| #667's body said "two" cases and listed three | issue edit, no commit |
| six residual nits from the scoped re-review | filed **#671** |
| pre-existing "controller ruling"/"task brief" references in shipped source | filed **#672** |

### (1g) Mutation evidence — pasted, gate named per row

Every row is `scripts/mutate.py` output; `--self-test` was 20/20 before each
run, and `git status --short` was empty after each. **All 21 rows
`RED_AS_EXPECTED`** (3 + 13 + 5; this said 22 until the PR #673 review
counted). Each table was measured at a different commit, named above
it.

**The replay gate itself** — BF1 at `75cbb7c5`, RC1/RC2 at `59e15b76`:

| # | Mutation | Gate | Live | Outcome | Reds |
|---|---|---|---|---|---|
| BF1 | Python names a repeat as disorder; strict on block_file, it would have been tolerated before target-awareness | `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay` | yes (interpreter) | RED_AS_EXPECTED | differential_replay_full_corpus |
| RC1 | Rust names a negative timestamp wrong_type where Python names integer_out_of_range | `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay` | yes (artifact) | RED_AS_EXPECTED | differential_replay_full_corpus |
| RC2 | Python names a repeated record key wrong_type | `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay` | yes (interpreter) | RED_AS_EXPECTED | differential_replay_full_corpus |

**The slice's own table** — Task 12, at `fc715901` (before the fix wave):

| # | Mutation | Gate | Live | Outcome | Reds |
|---|---|---|---|---|---|
| R1 | a RecordError arm repointed at another token | `cargo test --release --locked --no-fail-fast -p secretary-core --lib --test rule_token_seeds` | yes (artifact) | RED_AS_EXPECTED | every_record_error_variant_carries_its_declared_token, rule_token_seeds_are_committed_and_label_bound |
| R2 | a BlockError arm repointed at another token | `cargo test --release --locked --no-fail-fast -p secretary-core --lib --test rule_token_seeds` | yes (artifact) | RED_AS_EXPECTED | every_block_error_variant_carries_its_declared_token, rule_token_seeds_are_committed_and_label_bound |
| R3 | the tolerance loses target-awareness | `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay` | yes (artifact) | RED_AS_EXPECTED | tolerance_admits_only_phase_dependent_pairs, a_phase_dependent_pair_on_an_unlicensed_compared_target_disagrees |
| R4 | the walk accepts undefined | `cargo test --release --locked --no-fail-fast -p secretary-core --lib --test rule_token_seeds` | yes (artifact) | RED_AS_EXPECTED | undefined_and_unassigned_simple_values_are_malformed, each_ciborium_leniency_is_rejected_by_both_and_renamed_by_the_walk, rule_token_seeds_are_committed_and_label_bound |
| R5 | the walk accepts a nested indefinite chunk (a chunk re-enters chunks_end through string_end) | `cargo test --release --locked --no-fail-fast -p secretary-core --lib --test rule_token_seeds` | yes (artifact) | RED_AS_EXPECTED | a_nested_indefinite_chunk_is_malformed, each_ciborium_leniency_is_rejected_by_both_and_renamed_by_the_walk, rule_token_seeds_are_committed_and_label_bound |
| R6 | the walk reports a tag before proving the item well-formed | `cargo test --release --locked -p secretary-core --lib` | yes (artifact) | RED_AS_EXPECTED | well_formedness_outranks_rule_four_anywhere_in_the_item |
| R7 | record::decode runs the walk but ignores its verdict | `cargo test --release --locked --no-fail-fast -p secretary-core --lib --test rule_token_seeds` | yes (artifact) | RED_AS_EXPECTED | each_ciborium_leniency_is_rejected_by_both_and_renamed_by_the_walk, rule_token_seeds_are_committed_and_label_bound |
| P1 | equal envelope ids are no longer classified as a repeat | `uv run core/tests/python/conformance.py` | yes (interpreter) | RED_AS_EXPECTED | rule-token seeds are rejected with the rule their file names |
| P2 | record values are no longer checked as their key is read | `uv run core/tests/python/conformance.py` | yes (interpreter) | RED_AS_EXPECTED | rule-token seeds are rejected with the rule their file names |
| P3 | the Python walk stops checking UTF-8 | `uv run core/tests/python/conformance.py` | yes (interpreter) | RED_AS_EXPECTED | well-formedness walk, the twin of cbor::well_formed, rule-token seeds are rejected with the rule their file names |
| P4 | the record path names rule 2 where Rust cannot | `uv run core/tests/python/conformance.py` | yes (interpreter) | RED_AS_EXPECTED | rule-token seeds are rejected with the rule their file names |
| P5 | a well-formedness fault is named a wrong type | `uv run core/tests/python/conformance.py` | yes (interpreter) | RED_AS_EXPECTED | rule-token seeds are rejected with the rule their file names |
| S1 | a row plants different bytes than its committed seed holds | `cargo test --release --locked -p secretary-core --test rule_token_seeds` | yes (artifact) | RED_AS_EXPECTED | rule_token_seeds_are_committed_and_label_bound |

**The fix wave** — at `be6c9125`, M6P at `1d172304`:

| # | Mutation | Gate | Live | Outcome | Reds |
|---|---|---|---|---|---|
| I1A | py_decode_record reads the top-level map head and every key's type before walk_body (the pre-#641 order) | `uv run core/tests/python/conformance.py` | yes (interpreter) | RED_AS_EXPECTED | rule-token seeds are rejected with the rule their file names |
| I1B | py_decode_record checks missing required keys before the per-entry value checks (design spec section 8's check-5 row) | `uv run core/tests/python/conformance.py` | yes (interpreter) | RED_AS_EXPECTED | rule-token seeds are rejected with the rule their file names |
| M6 | the block envelope reader checks only the first adjacent pair of each table | `uv run core/tests/python/conformance.py` | yes (interpreter) | RED_AS_EXPECTED | rule-token seeds are rejected with the rule their file names |
| M7 | record::decode runs the walk but ignores its verdict: the Rust order twins must see it | `cargo test --release --locked -p secretary-core --lib` | yes (artifact) | RED_AS_EXPECTED | a_non_map_top_level_item_holding_a_malformed_item_reports_malformed_cbor, a_non_text_key_whose_value_is_malformed_reports_malformed_cbor |
| M6P | the block envelope reader scans a whole table for a repeat before judging order | `uv run core/tests/python/conformance.py` | yes (interpreter) | RED_AS_EXPECTED | rule-token seeds are rejected with the rule their file names |

**The `--no-fail-fast` trap (found by Task 12).** A gate of
`cargo test ... --lib --test rule_token_seeds` is fail-fast: once the lib
unittests fail, cargo never starts the `rule_token_seeds` binary, so an
`expect_red` naming a test in that binary can never appear on a `FAILED` line.
Measured with a control row (R1 with the fail-fast gate): exit 1,
`WRONG_TESTS_RED`, missing `rule_token_seeds_are_committed_and_label_bound`.
Any mutation row whose gate builds two test targets needs `--no-fail-fast`.
This is not yet in CLAUDE.md's mutation-harness block.

### (1h) The gate set

At `be6c9125` (the fix wave; `1d172304` after it is a Python comment,
re-verified by `conformance.py`, M6P and the full-corpus run above). Before
the push, the same gates were re-run at this handoff commit; the PR
description records those results.

| Gate | Result |
|---|---|
| `cargo test --release --locked --workspace` | 0 — **2189 passed**, 0 failed, 23 ignored |
| the differential-replay step (CI spelling) | 0 — **45 passed**, record 25/25, block_file 20/20 |
| `cargo test --release --locked -p secretary-core --test rule_token_seeds` | 0 — 3 passed, 1 ignored |
| both `cargo clippy ... --tests -- -D warnings` spellings, rustdoc `-D warnings`, `cargo fmt --all --check` | all 0 |
| `uv run core/tests/python/conformance.py` | 0 — 0 `FAIL`, WF 43/43, RTS "19 labelled seeds" / "22 labelled seeds" / "7/7 record and 1/1 block_file parity-order cases", REG **32/32** |
| `spec_test_name_freshness.py` | exit 1, **98** unresolved = `main`'s baseline (#642) |
| secret-slot and error-payload guards, `--self-test` first | all 0 |

Task 12, at `fc715901`, additionally ran the mutation harness pytest
(278 passed), `actionlint .github/workflows/test.yml` and all six hygiene
guards with their self-tests: all 0.

**Re-run after the PR #673 review fix wave**, at `c8601343`; `ba48487c` after it
is a pure file split, re-verified by the rows marked below:

| Gate | Result |
|---|---|
| `cargo test --release --locked --workspace` | 0 — **2195 passed**, 0 failed, 23 ignored |
| the differential-replay step (CI spelling) | 0 — **46 passed**, record 37/37, block_file 24/24 |
| both `cargo clippy ... -- -D warnings` spellings (with and without `--tests`), rustdoc `-D warnings`, `cargo fmt --all --check` | all 0 (clippy `-p secretary-core --tests` re-run at `ba48487c`: 0) |
| `cargo test --release --locked -p secretary-core --test rule_token_seeds` | 0 — 3 passed, 1 ignored (re-run at `ba48487c`, and the generator left all 57 seeds byte-identical) |
| `uv run core/tests/python/conformance.py` | 0 — 0 `FAIL`, WF 52/52, RTS "23 labelled seeds" / "34 labelled seeds" / "9/9 record and 1/1 block_file parity-order cases", REG **32/32** |
| error-payload, secret-slot and test-support-placement guards, `--self-test` first | all 0 |
| full local corpus (§(1e)) | record 7,488/7,488, block_file 141/141, at `ba48487c` |

Not re-run for this fix wave, because nothing they read changed:
`spec_test_name_freshness.py`, the mutation harness pytest, `actionlint`, and the
iOS, Android and lean-binding guards.

### (1i) The PR #673 review and its fix wave

`/pr-review-toolkit:review-pr` ran five agents (code, tests, comments, silent
failures, types). The code review found no Critical or Important issue. It
also measured the claim this slice rests on: the old and new `record::decode`
pipelines, over 15,000 mutated records, disagreed on accept/reject **0** times
(the agent's measurement in a scratch copy, not re-run here).
The other four found real gaps, and every Important one was reproduced by
execution before it was fixed. One commit per concern:

| Finding | Commit |
|---|---|
| **Important — a regression this slice introduced.** Retyping `scanner.py`'s raises to `MalformedCbor` turned a would-be harness failure into tolerated agreement on `manifest_body`: Python names `malformed_cbor` for `undefined` or a nested chunk, while ciborium lets Rust reach a phase-dependent token. `malformed_cbor` is now never tolerated, citing §4.2's well-formedness precondition. Breadth 58 → **54** | `43e40052` |
| **Important** — `AI_FOUR_BYTES => 3` passed all 1,112 `secretary-core` tests (`--no-fail-fast`) while rejecting any record with a 64 KiB+ field. Every argument width is now pinned in both walks, and the proptest requires `walk_first_item == Ok(len)` for every accepted input | `341df85d` |
| **Important** — the bool-as-integer fix was unpinned (a revert left `conformance.py` at exit 0); no seed required distinct bytes; a `container_malformed` seed did not pin its check (deleting Python's `sig_ed_len` check stayed green); every sort/repeat seed faulted the last pair; 10 record rejection paths had no seed; token inheritance was silent; an `_ORDERING_CASES` mismatch raised out of `main()`. Seeds 41 → 57, each row naming its Rust variant, one Python class per envelope check | `8f5512f2` |
| Field-level parity order, both languages | `a968bde8` |
| The breadth test filtered by the list it checks; list pinned literally | `ba1c2992` |
| `first_rule4` could hold a `Malformed` fault; now a `Rule4` type | `8f0a0214` |
| **Important** — leniencies attributed to the wrong rules, and a fourth (`f8 14`..`f8 17`) missed; `scanner.py`'s correction overclaimed; the wide-bignum dependency pinned | `a0b3255b` |
| **Important** — "`block_file` needed only the sort/repeat split" omitted the version-raise typing (4 documents) | `f12ae251` |
| **Important** — Section WF's depth row could not catch a recursive walk; a row past Python's recursion limit added | `f10121ed` |
| Walker cases: chunked bytes, a nested close, an eight-byte overrun | `bef18e20` |
| Stale "one token-compared target" (2), "Four follow-ups", `WrongType`/`MissingField` scope, "every new file under 500 lines", WF "last eight" | `04096abd` |
| rustfmt; the record seed table split at 555 lines | `c8601343`, `ba48487c` |
| `is_phase_dependent()` reads as target-independent | comment on **#648** |
| a fourth leniency and `UnknownValue::from_canonical_cbor` on the unwalked paths | comments on **#666** |
| four optional type refactors (one target table, a seed-target enum, `Head.major`, Python `_Frame`) | filed **#676** |
| `CanonicalDuplicateKey` → `duplicate_map_key` rather than `encoder_refusal` | **no change**: it follows the documented `ManifestError::Canonical` precedent and is unreachable from bytes |

**Mutation evidence** — `scripts/mutate.py` at `04096abd`, `--self-test` 20/20
first, exit 0, `git status --short` empty after. S2's row mutated
`rule_token_seeds_helpers/record.rs`, which `ba48487c` then moved to
`record/plants.rs`:

| # | Mutation | Gate | Live | Outcome | Reds |
|---|---|---|---|---|---|
| T1 | malformed_cbor tolerated against a phase-dependent token again | `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay` | yes (artifact) | RED_AS_EXPECTED | tolerance_admits_only_phase_dependent_pairs, malformed_cbor_against_a_phase_dependent_token_disagrees_on_the_licensed_target |
| W1 | four-byte argument read as three (the review's measured false green) | `cargo test --release --locked -p secretary-core --lib -- well_formed record_walk` | yes (artifact) | RED_AS_EXPECTED | each_argument_width_consumes_exactly_its_own_bytes, a_four_byte_length_argument_spans_its_whole_payload, a_record_using_every_argument_width_is_accepted_and_walked_to_its_end |
| W2 | Python twin of W1 | `uv run core/tests/python/conformance.py` | yes (interpreter) | RED_AS_EXPECTED | well-formedness walk, the twin of cbor::well_formed |
| S1 | bool-as-integer fix reverted | `uv run core/tests/python/conformance.py` | yes (interpreter) | RED_AS_EXPECTED | rule-token seeds are rejected with the rule their file names |
| S2 | a plant collapsed onto a sibling's bytes | `cargo test --release --locked -p secretary-core --test rule_token_seeds` | yes (artifact) | RED_AS_EXPECTED | rule_token_seeds_are_committed_and_label_bound |
| S3 | same token, sibling variant (`SigEdWrongLength` → `Truncated`) | `cargo test --release --locked -p secretary-core --test rule_token_seeds` | yes (artifact) | RED_AS_EXPECTED | rule_token_seeds_are_committed_and_label_bound |
| S4 | Python `sig_ed_len` check deleted (the review's measured green) | `uv run core/tests/python/conformance.py` | yes (interpreter) | RED_AS_EXPECTED | rule-token seeds are rejected with the rule their file names |
| S5 | a verdict class inherits its token | `uv run core/tests/python/conformance.py` | yes (interpreter) | RED_AS_EXPECTED | rule-token seeds are rejected with the rule their file names |
| S6 | an `_ORDERING_CASES` mismatch (a `FAIL:` line appearing proves no raise out of `main()`) | `uv run core/tests/python/conformance.py` | yes (interpreter) | RED_AS_EXPECTED | rule-token seeds are rejected with the rule their file names |
| O1 | a field's missing keys checked before its values | `uv run core/tests/python/conformance.py` | yes (interpreter) | RED_AS_EXPECTED | rule-token seeds are rejected with the rule their file names |
| O2 | the fields map decoded after the top-level entries | `uv run core/tests/python/conformance.py` | yes (interpreter) | RED_AS_EXPECTED | rule-token seeds are rejected with the rule their file names |
| L1 | `record` added to the phase-dependent target list | `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay` | yes (artifact) | RED_AS_EXPECTED | tolerance_admits_only_phase_dependent_pairs |

Two limits on that table, stated rather than implied:

- **S2 cannot say WHICH assertion fired.** The distinct-bytes check and the
  committed-bytes comparison share one test. By reading, the distinctness check
  runs first. The Python distinctness check, which a source mutation cannot
  reach because the seeds are binary, was proven by a direct control instead.
  A temp copy of `seeds/record/` with `undefined_value` overwritten by
  `truncated`'s bytes gave exactly one issue ("... are byte-identical") and
  none on the real tree. The token check alone passes that copy, since
  truncated bytes also name `malformed_cbor`.
- **The Rust field-level order tests and the depth row have no mutation row.**
  Their drifts are not single text substitutions. The Rust tests assert both
  single-fault controls beside each two-fault body. The depth row was checked
  directly: the recursive `scanner._scan_item` raises `RecursionError` on it.

---

## (2) What this slice does **not** claim

- **Corpus agreement is not full alignment.** Three acceptance divergences are
  open and unreachable from any committed or corpus input: #667 case 2, #669,
  #670 — §(3a).
- **The report orders pinned here are PARITY between our two implementations,
  not spec.** vault-format §6.1 and §6.3 fix no report order (#668). Every
  committed seed plants one fault, so no cross-language row pins an order the
  spec leaves open; the orders are pinned by Section RTS check 5 and
  `record_order_tests.rs`, both labelled parity.
- **The walk is wired into `record::decode` only.** `decode_manifest` and block
  plaintext decode keep ciborium's four leniencies in both languages (#666,
  which the PR #673 review extended with the fourth, the two-byte simple form,
  and with `UnknownValue::from_canonical_cbor`).
- **ciborium's depth limit is unaddressed** (#667): a Rust-only rejection past
  256 levels; Python raises `RecursionError` from about 995 levels.
- **CI replays committed inputs only** (107). The full-corpus agreement is a
  local measurement; CI has no `core/fuzz/corpus/`.
- **#641 is not closed**: `contact_card`, `bundle_file` and `vault_toml` remain,
  and `manifest_file` stays blocked by #640.
- **Task 12's 13 rows were measured before the fix wave**, which later changed
  the `block_file` seed set (15 → 19) and added check-5 rows; they were not
  re-run after it. The fix wave's five rows cover its own changes.
- **Some rows are gated narrower than design spec §8 lists**: the walk rows
  (R4, R5) gate on `--lib --test rule_token_seeds`, not on the replay, and the
  Python rows (P1-P5) on `conformance.py`, not on a replay disagreement. That the
  replay reds a real disagreement is evidenced separately by BF1, RC1 and RC2.
- **`UncheckedKnownKey` and the `block_file` `[high, low, low]` parity order in
  Rust are pinned by nothing in CI** (#671 items 4 and 6).
- **The design spec is the approved design, not the as-built record.**
  `docs/superpowers/specs/2026-09-15-token-compare-record-block-design.md` was
  not updated for implementation deltas. Do not cite its §6.2 or §9 as the
  current lists. The deltas:
  - check 5 grew from 4 `record` cases to **7**, plus **1** `block_file` parity
    case;
  - `core/src/vault/record_order_tests.rs` (Rust twins of check 5) is not in
    §9's file list;
  - Section WF holds **52** cases, not the plan's 35 (the walk branches added in
    `19bce3d3`, then nine more in the PR #673 review);
  - **57** generated seeds, not the plan's 37: four three-entry `block_file`
    tables faulted at the second pair, then 16 more in the PR #673 review;
  - check 5 grew again, to **9** `record` cases, in that review;
  - spec §1's "no acceptance diverges" was true of the corpus only; hand-built
    bodies found bool-as-uint (fixed) and #670 (open).

---

## (3) What is next — with acceptance criteria

### (3a) Acceptance divergences first

Each changes a VERDICT, so each ranks above report-order polish.

- **#670 — a record optional key present at its default value.** `tags: []`,
  `tombstone: false`, `tombstoned_at_ms: 0`: Python accepts, Rust rejects
  (`NonCanonicalEncoding`; its encoder omits defaults, so the re-encode
  differs). §6.3 says what absent and default mean, never whether the
  present-default spelling is canonical. **Acceptance:** a §6.3 decision
  (options in the issue), the side that changes, and a committed seed or an RTS
  case for each of the three keys.
- **#669 — `codec/card.py` and `codec/trash_entry.py` accept a CBOR bool where
  an integer belongs.** Rust rejects at all four positions (`card_version`,
  `created_at`, `tombstoned_at_ms`, `purged_at_ms`). **Acceptance:** Python
  rejects all four; a conformance case per position, mutation-proven.
- **#667 case 2 — an UNKNOWN record value nested more than 256 deep.** Python
  accepts, Rust rejects (`CborDecode(RecursionLimit)`). Case 1, a known `tags`
  value, is a token disagreement (`wrong_type` vs `malformed_cbor`); case 3 is a
  Python `RecursionError` harness failure from about 995 levels. **Acceptance:**
  a decision to state a v1 depth limit normatively or document it as an
  implementation limit, and a Python side that returns a verdict at every depth.

### (3b) The rest

- **#641 — `contact_card`, `bundle_file`, `vault_toml`.** Same pattern:
  `rule_token()` per error enum by exhaustive match, typed Python exceptions,
  generated single-fault seeds with a label binding in both languages, strict by
  default (not in `PHASE_DEPENDENT_TOLERANCE_TARGETS`). Measure first, as this
  slice's spike did; the full local corpus run above replayed 6,396
  `contact_card`, 25 `bundle_file` and 60,931 `vault_toml` inputs (committed
  seeds included). **Acceptance:** a full-corpus
  local run with the runtime corpus present, recorded in the handoff beside CI's
  finish lines.
- **#666 — wire the walk into `decode_manifest` and block plaintext decode**, in
  both languages. `manifest_body` has no fuzz corpus, so measure first.
- **#668 and #646 — report-order spec decisions.** §6.1/§6.3 order text, and
  #646's narrowing of the `manifest_body` tolerance. Both are spec slices as
  much as code.
- **#612** — `core/tests/manifest_uniqueness_kat.rs` past 500 lines (measure;
  the issue says 810). Acceptance unchanged: under 500 via a helpers directory,
  test name set diffed.
- **#657** — nothing pins that the CI replay step stays wired.
- **#660** — `conformance.py`'s `parse_known_args` fall-through.
- **#671, #672** — polish; small, independent.
- **#676** — make the replay-target and seed-table invariants type-level
  (optional; filed from the PR #673 type-design review).
- **#648, #658, #661, #633, #642, #623 / #624 / #625 / #626 / #628 / #629 / #630,
  #635, #640, #643, #653, #654** stay open.

### Issues this slice closes in code — verify against the code

None outright: #641 stays open for three targets. Per the `(#N)`-not-`Closes #N`
convention, no issue auto-closes on merge.

```bash
grep -n "PHASE_DEPENDENT_TOLERANCE_TARGETS" core/tests/differential_replay_helpers/targets.rs
grep -n '"record"\|"block_file"' core/tests/differential_replay_helpers/targets.rs
ls core/fuzz/seeds/block_file/*__*.bin | wc -l    # 23
ls core/fuzz/seeds/record/*__*.bin | wc -l        # 34
grep -c '"RTS"\|"WF"' core/tests/python/conformance_lib/sections/registry.py   # 2
```

---

## (4) Open decisions and risks

- **The depth residual (#667)** is now a measured acceptance divergence, not a
  theoretical one. No corpus input reaches it, and nothing pins that.
- **#648 — `RuleToken`'s public home.** This slice added two more `pub fn
  rule_token()`s, on `RecordError` and `BlockError`, so the public surface #648
  asks about grew. #648's second point is now narrower: `container_malformed`
  and `malformed_cbor` are produced by committed seeds and compared strictly,
  while `aead_failure`, `signature_invalid`, `encoder_refusal` and
  `internal_error` are still reachable from no compared target (`BlockError`'s
  AEAD, KEM and signature arms map onto the first two as diagnostics only).
- **The bool-as-uint acceptance divergence** was found by hand-built bodies,
  not by the corpus, and fixed on the record path only. Its siblings are #669,
  and #670 is a second class of the same "the corpus cannot see it" kind.
  **When token agreement is 100%, ask what the corpus cannot generate.**
- **The design spec is stale by design** (§(2)). The plan and spec stay in
  `docs/superpowers/` as the approved record.
- **Mixed `Co-Authored-By` trailers**: 55 commits name Opus, 2 name Sonnet (the
  model that wrote them). No history was rewritten; a squash merge makes it
  moot.
- **`.gitignore`'s `corpus/` rule matches directories only**, so a
  `core/fuzz/corpus` symlink shows as untracked. Remove it after each run; do
  not commit one.
- **CI evidence:** read the replay step's finish lines in the
  `cargo test (ubuntu-latest)` job log, not the green tick —
  `record: 37 of 37` and `block_file: 24 of 24` must appear.
- **Files past 500 lines** still include `record.rs` (#556) and `block.rs`
  (#563), both slightly larger after this slice.

---

## (5) How to resume — the exact commands

```bash
# FIRST — it fired again this slice:
git fetch origin && git log --oneline main..origin/main

cd /Users/hherb/src/secretary/.worktrees/token-compare-record-block
pwd && git branch --show-current && git worktree list

# --- the replay, CI shape (a fresh worktree has no corpus/) ---
cargo test --release --locked -p secretary-core \
  --features differential-replay --test differential_replay      # 46 passed; record 37 of 37, block_file 24 of 24

# --- the replay over the real fuzz corpus ---
# In the MAIN checkout it just works. From a worktree, borrow main's corpus and
# REMOVE the link afterwards (the gitignore rule does not cover a symlink):
test ! -e core/fuzz/corpus && ln -s /Users/hherb/src/secretary/core/fuzz/corpus core/fuzz/corpus
cargo test --release --locked -p secretary-core \
  --features differential-replay --test differential_replay -- differential_replay_full_corpus
rm core/fuzz/corpus && git status --short                        # no corpus entry

# --- regenerate the single-fault seeds after an intentional change ---
# Asserts every case first, writes only if all pass; review the diff before committing.
cargo test --release --locked -p secretary-core --test rule_token_seeds -- --ignored generate_rule_token_seeds
cargo test --release --locked -p secretary-core --test rule_token_seeds   # 3 passed, 1 ignored

# --- the clean-room verifier ---
uv run core/tests/python/conformance.py                              # 0 FAIL, WF 52/52, REG 32/32

# --- prove the replay is not vacuous on the new targets ---
# Write specs to a scratch dir, never the tree. Python probes need the verifier's deps,
# so launch the harness with the full PEP 723 set:
SCRATCH=$(mktemp -d)
cat > "$SCRATCH/rc.toml" <<'EOF'
[[mutation]]
id = "RC1"
lang = "rust"
path = "core/src/vault/rule_tokens/record.rs"
old = "RecordError::IntegerOverflow { .. } => RuleToken::IntegerOutOfRange,"
new = "RecordError::IntegerOverflow { .. } => RuleToken::WrongType,"
gate = "cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay"
expect = "red"
expect_red = ["differential_replay_full_corpus"]
note = "Rust names a negative timestamp wrong_type where Python names integer_out_of_range"
probe = { package = "secretary-core" }

[[mutation]]
id = "BF1"
lang = "python"
path = "core/tests/python/conformance_lib/wire/envelope_rules.py"
old = 'token = "repeated_array_value"'
new = 'token = "array_sort_order"'
gate = "cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay"
expect = "red"
expect_red = ["differential_replay_full_corpus"]
note = "Python names a repeat as disorder on block_file"
probe = { module = "conformance_lib.wire.envelope_rules", expr = "EnvelopeRepeatedValue.token", equals = "array_sort_order", syspath = "core/tests/python" }
EOF
uv run scripts/mutate.py --self-test                                 # 20/20
uv run --with cryptography --with pynacl --with "pqcrypto<1" \
  --with argon2-cffi --with blake3 --with cbor2 scripts/mutate.py "$SCRATCH/rc.toml"   # both RED_AS_EXPECTED, exit 0
git status --short                                                    # MUST be empty
# A row whose gate builds two test targets (--lib --test X) needs --no-fail-fast — §(1g).

# --- the rest of the gate set ---
cargo test --release --locked --workspace
cargo clippy --release --locked --workspace --tests -- -D warnings
cargo clippy --release --locked -p secretary-core --features differential-replay --tests -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
cargo fmt --all --check
uv run --with pytest python3 -m pytest scripts/mutation_harness -q   # 278 passed
uv run core/tests/python/spec_test_name_freshness.py                 # exit 1, 98 = baseline
actionlint .github/workflows/test.yml

# --- six hygiene guards, --self-test FIRST, as LITERAL commands ---
bash ffi/scripts/check-lean-binding.sh --self-test         && bash ffi/scripts/check-lean-binding.sh
bash ios/scripts/check-public-log-hygiene.sh --self-test   && bash ios/scripts/check-public-log-hygiene.sh
bash android/scripts/check-log-hygiene.sh --self-test      && bash android/scripts/check-log-hygiene.sh
bash scripts/check-secret-slot-hygiene.sh --self-test      && bash scripts/check-secret-slot-hygiene.sh
uv run scripts/check-error-payload-hygiene.py --self-test  && uv run scripts/check-error-payload-hygiene.py
uv run scripts/check-test-support-placement.py --self-test && uv run scripts/check-test-support-placement.py
```

---

## (6) Where this document lives

`NEXT_SESSION.md` at the repo root is a **symlink**, retargeted this session to
`docs/handoffs/2026-09-15-token-compare-record-block-shipped.md`. This file is
the single authored baton — do not create a second copy, and do not sync it to
`main` during a pause window.
