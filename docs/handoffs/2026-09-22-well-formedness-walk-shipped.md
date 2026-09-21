# NEXT_SESSION.md — the byte-level well-formedness walk reaches every vault-body decoder (#666, #685)

Branch `feature/well-formedness-walk-manifest-block`, worktree
`.worktrees/wellformed-walk`, base `bf63cc39` (`main`).

**STATUS: implementation, docs, mutation evidence and the full gate set are
done. Push and PR remain — the controller runs the whole-branch review
first.**

**The headline:** #641 added `cbor::well_formed::walk_first_item` — a
byte-level CBOR well-formedness walk that runs BEFORE ciborium's own parse —
and wired it into `record::decode` only. #666 tracked wiring the same walk
into the other two vault-body decoders, `decode_manifest` and
`block::decode_plaintext`, in both languages; #685 is a related
`py_decode_trash_entry` `RecursionError` this slice also closed. This is
code catching up to a frozen spec: `docs/vault-format.md` §4.2 already
required well-formedness to precede every other check, on every vault-body
decoder — no normative doc changed.

Measured on the design's eleven-shape probe (one value planted under an
unknown key in the committed accepting `manifest_body` base):

- **Three cross-language divergences in the NEVER-tolerated `malformed_cbor`
  class closed** — `undefined`, the two-byte simple form, a nested
  indefinite chunk. Rust used to answer these at the re-encode
  (`non_canonical_unclassified` / `rule2_indefinite_length`) because
  ciborium had already normalised them away by the time `decode_manifest`
  looked; Python always said `malformed_cbor`.
- **Three TOLERATED divergences closed too** — a bignum that fits 64 bits
  (ciborium silently folds it to an integer, so Rust used to answer at the
  re-encode instead of as rule 4), and two precedence bodies (a tag then
  `undefined`, a float then `undefined`) where Rust used to report the
  earlier rule-4 fault instead of the later well-formedness one.
- **One case where BOTH implementations agreed on an answer §4.2
  forbids** — a float followed by `undefined`: both sides said
  `rule4_tag_or_float`, both wrong, and no cross-language gate could ever
  have seen it, because agreement is not conformance. This is the sharpest
  argument for the slice.

**Issues this slice touched:**

- **Closed in code:** [#666](https://github.com/hherb/secretary/issues/666)
  and [#685](https://github.com/hherb/secretary/issues/685). Per the
  `(#N)`-not-`Closes #N` convention, both stay open on the tracker until a
  human closes them.
- **Filed:**
  - [#686](https://github.com/hherb/secretary/issues/686):
    `core/src/vault/manifest/decode/tests.rs` is 1393 lines, past the
    500-line split threshold — same class as #630 (`encode/tests.rs`, 620
    lines, still open).
  - [#687](https://github.com/hherb/secretary/issues/687):
    `value_type_discipline.py`'s `PASS 2` line is computed from the
    declared case table, not from Check 2's (`_control_issues`) execution —
    deleting the check's call line leaves the section's stdout
    byte-identical. Found in this slice's Task 7 review. Sequenced against
    #683 (which names byte-identical Section VT output as its own
    acceptance criterion).

---

## (0) Starting state

`main` was at `bf63cc39` at branch creation; re-checked with `git fetch
origin && git rev-list --count main..origin/main` while writing this baton
(2026-09-22 03:29 AEST) — **0**, `main` unmoved. Re-check again at push
time regardless; a slice can land underneath a long session.

---

## (1) What shipped

| SHA | What |
|---|---|
| `52c42717` | design spec: the eleven-shape measurement, decisions, what the slice does not do |
| `2e89793b` | implementation plan (10 tasks) |
| `b37de0e4` | baseline token measurements for all 47 pre-existing `manifest_body` seeds, on the branch |
| `ece97b7b` | fix: baseline doc corrected to use `BlockError::rule_token()`, not `Display` text |
| `37adf961` | **the shared helper**: `canonical::walk_first_item_checked`, one `WalkFault` projection for every caller; `record::decode` refactored onto it |
| `5a3de7a9` | `decode_manifest` walks the bytes for well-formedness first |
| `871d4230` | tighten manifest walk test assertions and prose (review fix) |
| `bcabba23` | `block::decode_plaintext` walks the bytes for well-formedness first |
| `b581e4ed` | pin the short-bignum depth edge on all three walk paths |
| `96ae2aeb` | fix: derive the bignum byte-string heads from their payload length |
| `fcd2a78f` | Python: `py_decode_manifest` reports the well-formedness fault first (one `walk_body` call replaces two separate passes) |
| `579aa2c9` | Python: `py_decode_trash_entry` walks bytes before `cbor2` resolves shareable tags (#685) |
| `94f9f560` | Section VT's `PASS 2c` count derived from execution, not hardcoded (review fix) |
| `ce7183ec` | 7 `wellformed__*` committed `manifest_body` seeds |
| `125ee680` | 2 more seeds: the short-bignum depth edge at both widths |
| `f35adc6d` | fix: derive the bignum byte-string heads in the seed helper too (review fix) |

Plus one more commit — this handoff, `CLAUDE.md`, `ROADMAP.md`, the plan-doc
corrections, and the `NEXT_SESSION.md` retarget, all together (`git log -1`
on the branch tip names its SHA).

### (1a) The primary measurement table — before this slice

From design spec §1, re-verified in Task 1 against the branch. A throwaway
probe spliced one value into the committed accepting `manifest_body` base
under an unknown key `zz_future` (length-first canonical position):

| Planted value | Rust (before) | Python | Agree before? |
| --- | --- | --- | --- |
| `00` (control) | accept | accept | yes |
| `f7` (`undefined`) | `non_canonical_unclassified` | `malformed_cbor` | **no — never tolerated** |
| `f8 15` (two-byte simple) | `non_canonical_unclassified` | `malformed_cbor` | **no — never tolerated** |
| `5f 5f 41 61 ff ff` (nested chunk) | `rule2_indefinite_length` | `malformed_cbor` | **no — never tolerated** |
| `61 ff` (invalid UTF-8) | `malformed_cbor` | `malformed_cbor` | yes |
| `c2 41 01` (bignum, fits 64 bits) | `non_canonical_unclassified` | `rule4_tag_or_float` | no — tolerated |
| `c2 49 01*9` (bignum, 9 bytes) | `rule4_tag_or_float` | `rule4_tag_or_float` | yes |
| `d8 1c 81 d8 1d 00` (tags 28/29) | `rule4_tag_or_float` | `rule4_tag_or_float` | yes |
| `82 c2 41 01 f7` (tag, then `undefined`) | `non_canonical_unclassified` | `rule4_tag_or_float` | no — tolerated |
| `82 f7 c2 41 01` (`undefined`, then tag) | `non_canonical_unclassified` | `rule4_tag_or_float` | no — tolerated |
| `82 f9 00 00 f7` (float, then `undefined`) | `rule4_tag_or_float` | `rule4_tag_or_float` | yes — **both non-conformant** |

**After this slice, every row agrees strictly, and the `82 f9 00 00 f7` row
is conformant on both sides** (`malformed_cbor`/`malformed_cbor`). Seven of
the eleven rows became committed `wellformed__*` seeds (the control and the
three already-agreeing rows — 9-byte bignum, the tags-28/29 shape, and the
`undefined`-then-tag ordering, whose walk finds the leading `undefined`
immediately and never needs the parking machinery — needed no seed, since
they were already correct or are exercised elsewhere).

The full 47-seed baseline (`.superpowers/sdd/.../baseline-{rust,py}.txt`,
git-ignored, archived in design spec §1.1) showed **0 of 47 pre-existing
`manifest_body` seeds moved** — the STOP condition Task 1 was watching for
did not fire.

### (1b) What the gate run measured, post-slice

```
[differential_replay] record: 44 of 44 input(s) compared, 44 committed
[differential_replay] manifest_body: 57 of 57 input(s) compared, 57 committed
[differential_replay] block_file: 24 of 24 input(s) compared, 24 committed
test result: ok. 46 passed; 0 failed
```

`conformance.py`: all sections PASS, exit 0. Section CS: "3 parked, 2
rule-4" (the parking pin now covers both languages). Section RTV: "41/56
bodies rejected, 41 carrying a vocabulary token, 9 distinct tokens" —
**unmoved from pre-slice**, because both `malformed_cbor` and
`rule4_tag_or_float` were already in the vocabulary. Section REG: "35
drivers discovered, 35 registered" — **unmoved**, because Section CS grew
by one check rather than becoming a new section.

Committed replay corpus: **131 → 140** (9 new `manifest_body` seeds: 7
`wellformed__*`, 2 `nesting__257_unknown_bignum_{narrow,wide}`).
`manifest_body`'s STRICT token-comparison count (pairs no phase-dependent
tolerance can excuse): **15 → 24 of 57**, all nine new seeds reaching it,
none excused — `RuleToken::is_phase_dependent` names neither
`MalformedCbor` nor `Rule4TagOrFloat` (the only two tokens the nine seeds
can produce) `true`.

---

## (2) Mutation evidence (design §7)

Spec written to the session scratchpad (never the tree, #516). Self-test
first: `uv run scripts/mutate.py --self-test` → **20/20**. Then the real
spec via `uv run --with cryptography --with pynacl --with "pqcrypto<1"
--with argon2-cffi --with blake3 --with cbor2 scripts/mutate.py
"$SCRATCH/wellformed.toml"`. `git status --short` empty before and after.

Design §7 lists 7 mutation rows. Two were split into language-specific
pairs where the design table names one conceptual defect present in both
implementations (the eager-parking row); five rows were already proven
live during this slice's own task reviews and are cited rather than
re-run, per the controller's instruction to cover only what those did not:

**Cited from review (not re-run this session):**

| Mutation | Result |
| --- | --- |
| `decode_manifest`'s walk call deleted | reds the 3 intended manifest unit tests plus both bignum depth seeds |
| `block::decode_plaintext`'s walk call deleted | reds its 3 walk tests, control green |
| `walk_first_item`'s rule-4 parking made eager (Rust) | reds exactly the 2 `wellformed__*_then_malformed` seeds in the differential replay, nothing else |
| Python's `walk_body` call in `py_decode_manifest` reverted to the two old calls | reds Section NDL check 4 |
| Python's `walk_body` call in `py_decode_trash_entry` reverted | reds the #685 regression test |

**Run this session** (spec: `$SCRATCH/wellformed.toml`):

| # | Mutation | Gate | Outcome | Reds |
|---|---|---|---|---|
| WF1 | The shared helper's `Malformed` arm redirected onto its rule-4 arm — every well-formedness fault through `walk_first_item_checked` misreports as `rule4_tag_or_float` | `cargo test --release --locked -p secretary-core --lib canonical::walk` | RED_AS_EXPECTED | `a_malformed_body_reaches_the_callers_cbor_decode_arm`, `a_later_malformed_fault_outranks_an_earlier_tag` |
| WF2 | Python's `_walk` tag-arm rule-4 fault raised eagerly instead of parked | `uv run core/tests/python/conformance.py` | RED_AS_EXPECTED | `CBOR scanner unit coverage` (Section CS) |
| WF3 | The v1 depth limit (`V1_MAX_NESTING_DEPTH`) lowered 256 → 255 | `cargo test --release --locked -p secretary-core --test nesting_depth_seeds` | RED_AS_EXPECTED | `every_decode_path_enforces_exactly_the_v1_limit`, `nesting_depth_seeds_are_committed_and_label_bound` |

All three `RED_AS_EXPECTED`. `git status --short` empty after the run.

---

## (3) The fuzz-corpus replay (design §7's residual evidence)

`core/fuzz/corpus/` in THIS worktree is empty (no `manifest_body/`
directory exists at all, matching the design's own stated residual —
`manifest_body` has never had a fuzz target). The main checkout
(`/Users/hherb/src/secretary/core/fuzz/corpus`) holds a populated runtime
corpus:

```
block_file:     117
bundle_file:      24
contact_card:   6394
manifest_file:     9
record:         7451
vault_toml:    60928
```

Symlinked in, replayed, removed, `git status --short` confirmed empty
(only the doc edits already described above — CLAUDE.md, ROADMAP.md, the
plan-doc corrections — showed as modified at this point in the session):

```
[differential_replay] vault_toml: 60937 of 60937 input(s) compared, 9 committed, in 99.0s
[differential_replay] record: 7495 of 7495 input(s) compared, 44 committed, in 9.0s
[differential_replay] contact_card: 6398 of 6398 input(s) compared, 4 committed, in 9.4s
[differential_replay] bundle_file: 25 of 25 input(s) compared, 1 committed, in 0.0s
[differential_replay] manifest_file: 10 of 10 input(s) compared, 1 committed, in 0.0s
[differential_replay] manifest_body: 57 of 57 input(s) compared, 57 committed, in 0.1s
[differential_replay] block_file: 141 of 141 input(s) compared, 24 committed, in 0.2s
test differential_replay_full_corpus ... ok
```

**All seven targets, full agreement — `record`'s 7,495 inputs (7,451
runtime + 44 committed) is the breadth evidence design §7 asks for; 0
verdicts moved.** `manifest_body`'s corpus is entirely committed (57 of
57 — no runtime directory exists for it, matching the design's own stated
residual: `manifest_body` has never had a fuzz target). **State plainly:
the record breadth evidence does not extend to `manifest_body`.**
`manifest_body`'s acceptance-unchanged claim rests on the hand-built seed
set (§1a/1b) plus the golden vault — a residual the design spec states
outright rather than papering over ("a few dozen hand-built bodies where
`record`'s is thousands of fuzzer-found ones").

---

## (4) The rest of the gate set

Every gate, `rc=0`:

```
uv run core/tests/python/conformance.py                                    — rc=0 (0 FAIL, all sections PASS)
cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay  — rc=0 (46 passed)
cargo test --release --locked --workspace                                  — rc=0 (2235 passed, 0 failed, tree-wide)
cargo clippy --release --locked --workspace --tests -- -D warnings         — rc=0
cargo clippy --release --locked -p secretary-core --features differential-replay --tests -- -D warnings — rc=0
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace                 — rc=0
cargo fmt --all --check                                                    — rc=0
uv run --with pytest python3 -m pytest scripts/mutation_harness -q -k "not C10 and not N4"  — rc=0 (276 passed, 2 deselected)
bash ffi/scripts/check-lean-binding.sh --self-test/check                   — rc=0/rc=0
bash ios/scripts/check-public-log-hygiene.sh --self-test/check             — rc=0/rc=0
bash android/scripts/check-log-hygiene.sh --self-test/check                — rc=0/rc=0
bash scripts/check-secret-slot-hygiene.sh --self-test/check                — rc=0/rc=0
uv run scripts/check-error-payload-hygiene.py --self-test/check            — rc=0/rc=0
uv run scripts/check-test-support-placement.py --self-test/check           — rc=0/rc=0
```

Every `--self-test` was run FIRST and as a literal command (never a zsh
loop). All twenty gate commands `rc=0`.

---

## (5) Corrections made to the committed plan

`docs/superpowers/plans/2026-09-22-well-formedness-walk-manifest-block.md`:

- **Task 6's Files list** omitted
  `core/tests/python/conformance_lib/sections/nesting_depth.py`. That edit
  was necessary and was verified correct in the Task 6 review: NDL check 4
  had hard-asserted the PRE-fix asymmetry between the manifest's
  content-blind depth pass and the record's content-aware walk as a
  deliberate property; once `py_decode_manifest` adopted `walk_body`, that
  asymmetry no longer existed and the check had to move with it.
- **Task 8's prose** said "four tests" where its own code block defines
  five (`the_case_table_holds_every_expected_row`,
  `every_row_plants_distinct_bytes`,
  `the_base_and_a_benign_splice_are_both_accepted`,
  `every_committed_seed_matches_its_row`, `the_prefix_census_is_two_way`) —
  confirmed against the shipped `core/tests/well_formed_seeds.rs` (5
  `#[test]` fns + 1 `#[ignore]`d generator).

Both fixed in place so a future reader diffing plan against branch does not
find them unexplained.

---

## (6) What is next

- **[#677](https://github.com/hherb/secretary/issues/677)**: sweep
  `bundle_file` and `manifest_file` (offset-based envelopes; the
  value-substitution method does not apply).
- **[#641](https://github.com/hherb/secretary/issues/641)**: token-compare
  `contact_card` next — it now has committed rejecting inputs and a
  documented depth rule; put depth first on both sides.
- **[#678](https://github.com/hherb/secretary/issues/678)**: the
  required-key half of Section VT's check 4.
- **New from this slice:**
  - **[#686](https://github.com/hherb/secretary/issues/686)**:
    `manifest/decode/tests.rs` split (1393 lines). Acceptance: directory
    module split by role, behaviour-preserving move, test name set diffed
    against a measured baseline, `cargo test --release --workspace`
    unchanged in count.
  - **[#687](https://github.com/hherb/secretary/issues/687)**:
    `value_type_discipline.py`'s Check 2 PASS line. Acceptance: the PASS
    line (or a replacement) is derived from `_control_issues()`'s actual
    execution, with a control proving deleting the call moves the output.
    Coordinate with #683's split.
- **Standing:** #668 (report-order spec text for §6.1/§6.3), #646
  (narrowing the per-token tolerance), #612 (`manifest_uniqueness_kat.rs`
  past 500 lines), #657 (nothing pins the CI replay step stays wired),
  #672 (session-process words in shipped source).

---

## (7) Open decisions and risks

- **No proptest, by design (#666's own acceptance criterion was
  reinterpreted).** The walk can only narrow or reject, never widen
  acceptance (it runs before any parse and returns `Ok`/`Err` only), so the
  only direction worth proving is "nothing previously accepted is now
  rejected" — proven for `record` by full local-corpus replay (0 verdicts
  moved), argued-plus-spot-checked for `manifest_body` (no fuzz corpus
  exists for it). A future `manifest_body` fuzz target would close that gap
  and is explicitly out of scope here.
- **`manifest_body` has no fuzz corpus.** Nobody has measured how often
  this precedence matters in the wild for that target, only for `record`
  (where it does: #641's slice found live divergences in the real fuzz
  corpus). This is a residual, not a defect — restated so a future reader
  does not read the `record` breadth evidence as covering `manifest_body`
  too.
- **The ciborium-only depth paths are untouched.** `ContactCard::from_canonical_cbor`
  and `IdentityBundle::from_canonical_cbor` still show the old bignum-edge
  split (`non_canonical_unclassified`/`rule4_tag_or_float` vs Python's
  uniform `malformed_cbor`) — never in scope for #666, and `contact_card`'s
  eventual token comparison (#641) must put depth first when it lands.

---

## (8) How to resume — the exact commands

```bash
git fetch origin && git log --oneline main..origin/main

cd /Users/hherb/src/secretary/.worktrees/wellformed-walk
pwd && git branch --show-current && git worktree list   # feature/well-formedness-walk-manifest-block

# --- the clean-room verifier ---
uv run core/tests/python/conformance.py
#   0 FAIL; Section CS "3 parked, 2 rule-4"; RTV "9 distinct tokens"; REG 35/35

# --- the replay, CI shape ---
cargo test --release --locked -p secretary-core \
  --features differential-replay --test differential_replay
#   46 passed; record 44 of 44, manifest_body 57 of 57, block_file 24 of 24

# --- the replay over the real fuzz corpus; REMOVE the link afterwards ---
test ! -e core/fuzz/corpus && ln -s /Users/hherb/src/secretary/core/fuzz/corpus core/fuzz/corpus
cargo test --release --locked -p secretary-core \
  --features differential-replay --test differential_replay -- differential_replay_full_corpus
rm core/fuzz/corpus && git status --short                # no corpus entry

# --- the new seed generator (asserts every row BEFORE writing any file) ---
cargo test --release --locked -p secretary-core --test well_formed_seeds -- --ignored generate_well_formed_seeds
cargo test --release --locked -p secretary-core --test well_formed_seeds
git status --short                                        # regenerated seeds must be byte-identical

# --- prove the new gates are not decorative (spec to the SCRATCHPAD, never the tree) ---
uv run scripts/mutate.py --self-test                                  # 20/20
uv run --with cryptography --with pynacl --with "pqcrypto<1" \
  --with argon2-cffi --with blake3 --with cbor2 scripts/mutate.py "$SCRATCH/wellformed.toml"
git status --short                                                     # MUST be empty

# --- the rest of the gate set ---
cargo test --release --locked --workspace
cargo clippy --release --locked --workspace --tests -- -D warnings
cargo clippy --release --locked -p secretary-core --features differential-replay --tests -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
cargo fmt --all --check
uv run --with pytest python3 -m pytest scripts/mutation_harness -q -k "not C10 and not N4"

# --- six hygiene guards, --self-test FIRST, as LITERAL commands ---
bash ffi/scripts/check-lean-binding.sh --self-test         && bash ffi/scripts/check-lean-binding.sh
bash ios/scripts/check-public-log-hygiene.sh --self-test   && bash ios/scripts/check-public-log-hygiene.sh
bash android/scripts/check-log-hygiene.sh --self-test      && bash android/scripts/check-log-hygiene.sh
bash scripts/check-secret-slot-hygiene.sh --self-test      && bash scripts/check-secret-slot-hygiene.sh
uv run scripts/check-error-payload-hygiene.py --self-test  && uv run scripts/check-error-payload-hygiene.py
uv run scripts/check-test-support-placement.py --self-test && uv run scripts/check-test-support-placement.py
```

**What remains before merge:**

1. Re-check `main..origin/main`, merge if it moved.
2. The controller runs the whole-branch review (this session was told not
   to push or open a PR).
3. Push and open the PR after the review's fix wave, titled to match this
   file's H1.

---

## (9) Where this document lives

This file. `NEXT_SESSION.md` at the repo root is a symlink to it,
retargeted in the same commit as this file's creation.
