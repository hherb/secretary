# NEXT_SESSION.md — every measured value-type acceptance divergence is closed (#669)

Branch `feature/bool-as-integer`, worktree `.worktrees/bool-as-integer`, base
`2e1e63d3` (`main`, immediately after PR #673 merged).

The user chose this slice by options-plus-recommendation, then approved four
further decisions as measurement changed the design underneath it (D4, D6 and
the two replacements D6 went through). **Read §(2) before trusting any
coverage claim in here** — two of this slice's structural rules were designed,
prototyped, measured and thrown away before the third survived, and the
reasons are the most transferable thing in this document.

**The headline: `conformance.py` accepted 16 bodies the Rust decoder rejects,
and none of them was reachable from any committed or corpus input** — which is
why the differential replay reported full agreement the entire time. All 16 are
closed, both mechanisms behind them are now structurally enforced, and 14
committed seeds make CI compare both decoders on each body.

**Issues this slice touched:** [#669](https://github.com/hherb/secretary/issues/669)
(widened by a measured census comment — it named 4 positions, the sweep found
10), and two filed: [#677](https://github.com/hherb/secretary/issues/677)
(`bundle_file` / `manifest_file` never swept) and
[#678](https://github.com/hherb/secretary/issues/678) (a REQUIRED key losing
its check). **#669 is closed in code** — per the `(#N)`-not-`Closes #N`
convention it stays open on the tracker until a human closes it.

---

## (0) Starting state

`origin/main` was at `2e1e63d3` and `main..origin/main` was empty. No open PRs.
The tree was clean. `.worktrees/` held three stale checkouts from merged
branches (`npm-dev-advisories`, `setup-android-tools`,
`token-compare-record-block`) plus two detached `.claude/worktrees/*` belonging
to other sessions — all left alone.

---

## (1) What shipped

| SHA | What |
|---|---|
| `b784490a` | design spec, built on the sweep rather than on #669's text |
| `9692096c` | D6 rewritten: the AST census was prototyped and failed |
| `04bb3998` | D6 rewritten again: the table refactor was designed and rejected |
| `88f73acc` | implementation plan |
| `0ce8ffce` | Section VT + `integer_rules.py`: **16 failing cases**, 10 controls passing |
| `4b3216ea` | M1 closed at all 12 sites → 8 issues remain |
| `ac9ff343` | M2 closed: the two unvalidated optional keys → 0 issues |
| `9ecaef6f` | check 3, the sanctioned-module rule |
| `4e92e1f4` | checks 4 and 4b, the optional-key census and dispatch totality |
| `18edf7c5` | `wire/vault_toml.py`, six positions |
| `3ed065f5` | 14 label-bound acceptance seeds + `acceptance_seeds.rs` |
| `d0605152` | `MIN_CORPUS_INPUTS` raised |
| `d2033150` | **check 4b's negative control** + RTV's corpus token set 6 → 8 |
| `a5cf45e1` | rustfmt |
| (this commit) | CLAUDE.md, ROADMAP, this baton |

No `docs/` change. `vault-format.md` types every affected field — `<u64>`,
`u16`, a 32-byte digest — so Rust implements the spec and Python did not. No
Rust production code changed at all: this slice is `conformance_lib`, one new
Rust *test* target, and 14 seed files.

### (1a) What was measured, before anything was designed

439 bodies, each one substitution from a committed accepting base, run through
the real Rust decoder and through `diff_replay.replay_bytes`, verdicts
compared.

| Target | Bodies | Divergences |
|---|---|---|
| `manifest_body` | 326 (shared with `contact_card`) | **8** |
| `contact_card` | (above) | **2** |
| `vault_toml` | 61 | **6** |
| `record` | 52 | **0** |

`record`'s zero is the negative control, and it earns its place twice: the
method finds divergences where they exist rather than everywhere, and #641's
record work holds under structured wrong-type input and not only under fuzz.

### (1b) Two mechanisms, and why the second matters more

**M1 — `isinstance(x, int)` with no bool exclusion.** Python's `bool`
subclasses `int`. Eight replay-visible positions (`codec/card.py` ×2,
`codec/vault_toml.py` ×6), two on `codec/trash_entry.py` (a standalone decoder
no replay target reaches), six more in `wire/vault_toml.py` where the shape is
`!= 1` and bare `int(...)`. Two copies in the tree were already correct
(#641) — the #597 shape: not one rule with a gap, four copies of one sentence
of which two were wrong.

**M2 — the check was never written.** `TrashEntry`'s two `Option` fields,
`trash[].fingerprint` and `trash[].purged_at_ms`, were validated by **nothing**
and accepted any CBOR value at all — on `manifest_body`, **token-compared and
replayed in CI**.

**M2 was invisible to the grep that found M1.** A census keyed on
`isinstance(..., int)` can only find positions that HAVE a check. *"Has no
check to find" is its own search* — the same lesson the memory-hygiene memo
records for a `.zeroize()` grep. #669 named four positions; the sweep found ten.

### (1c) Section VT

Five checks, across `sections/value_type_discipline.py` (407) and
`sections/value_type_structure.py` (391), split before writing so each rule and
its LIMITS block sit in one file.

| Check | What |
|---|---|
| 1 | all 16 divergences rejected, with Rust's exact token where the target is token-compared |
| 2 | a control per case: the base value restored must ACCEPT |
| 3 | `isinstance(..., int)` confined to `integer_rules.py`, default-deny |
| 4 | `KNOWN − REQUIRED` censused two ways; **7 optional keys** tree-wide |
| 4b | `record.py`'s wire-order dispatch is total, **plus an undeclared-key control** |

### (1d) Committed seeds

14, prefix `valuetype__`, generated and label-bound by
`core/tests/acceptance_seeds.rs`. They bind a Rust error **variant**, not a
token: `contact_card` and `vault_toml` have no token taxonomy (#641), and the
variant is finer anyway — it separates `WrongType` from `InvalidByteLength` on
one field. Three substitutions per manifest key so a **partial** fix reds.

Three preconditions are tests rather than assumptions: every base is accepted;
the CBOR round-trip is a byte identity (so "one planted fault" is measured);
every label is unique.

**Committed replay inputs 107 → 121.** `MIN_CORPUS_INPUTS`: `vault_toml` 3→9,
`contact_card` 2→4, `manifest_body` 39→45.

### (1e) Measured results

**Full local corpus**, runtime corpus symlinked in and removed afterwards:

```
[differential_replay] vault_toml: 60937 of 60937 input(s) compared, 9 committed, in 21.6s
[differential_replay] record: 7488 of 7488 input(s) compared, 37 committed, in 1.7s
[differential_replay] contact_card: 6398 of 6398 input(s) compared, 4 committed, in 1.2s
[differential_replay] bundle_file: 25 of 25 input(s) compared, 1 committed, in 0.0s
[differential_replay] manifest_file: 10 of 10 input(s) compared, 1 committed, in 0.0s
[differential_replay] manifest_body: 45 of 45 input(s) compared, 45 committed, in 0.0s
[differential_replay] block_file: 141 of 141 input(s) compared, 24 committed, in 0.0s
```

**75,044 inputs, all agreeing.** Section VT: `PASS 1` 16 cases, `PASS 2` 10
controls, `PASS 3` 18 modules scanned, `PASS 4` 7 optional keys, `PASS 4b`.
**REG 33/33.** RTV `8 distinct tokens`.

### (1f) The gate set

| Gate | Result |
|---|---|
| `cargo test --release --locked --workspace` | 0 — **2199 passed**, 0 failed, 24 ignored |
| the differential-replay step (CI spelling) | 0 — 46 passed |
| `cargo clippy` both spellings, rustdoc `-D warnings`, `cargo fmt --all --check` | all 0 |
| `uv run core/tests/python/conformance.py` | 0 — no `FAIL`, REG 33/33 |
| all six hygiene guards, `--self-test` first | all 0 |
| full local corpus (§1e) | 75,044 / 75,044 |

Not re-run, because nothing they read changed: `spec_test_name_freshness.py`,
the mutation-harness pytest, `actionlint`.

### (1g) Mutation evidence — all seven `RED_AS_EXPECTED`, gate named per row

`scripts/mutate.py`, `--self-test` **20/20** first, exit 0, `git status` empty
after.

| # | Mutation | Gate | Live | Outcome |
|---|---|---|---|---|
| V1 | the shared predicate stops excluding bool | `conformance.py` | yes (interpreter) | RED_AS_EXPECTED |
| V2 | a fifth hand-copy of the rule | `conformance.py` | yes (interpreter) | RED_AS_EXPECTED |
| V3 | the trash `fingerprint` check deleted | `conformance.py` | yes (interpreter) | RED_AS_EXPECTED |
| V4 | the trash `purged_at_ms` check deleted | `conformance.py` | yes (interpreter) | RED_AS_EXPECTED |
| V5 | `_check_fixed_bytes` checks type but not LENGTH | `conformance.py` | yes (interpreter) | RED_AS_EXPECTED |
| V6 | mechanism A's fall-through removed | `conformance.py` | yes (interpreter) | RED_AS_EXPECTED |
| V7 | a row's plant collapses onto a sibling's bytes | `cargo test … --test acceptance_seeds` | yes (artifact) | RED_AS_EXPECTED |

Every Python row probes **the section's own verdict** (`True → False`), which
is the contract each row is about, rather than a source-text presence.

---

## (2) What this slice does **not** claim — read this first

- **Two structural designs were built and thrown away, and rebuilding either
  would be a regression.**
  - *An AST census* (every `KNOWN` key must reach a type-check call) was
    prototyped against the real tree: **1 true positive, 39 false positives,
    and it MISSED `trash[].fingerprint`** — a package-global key set sees
    `fingerprint` checked under `blocks[]` and credits `trash[]` with it. Four
    structural causes, none of them tuning: keys aren't scoped to their map;
    checks reach values through local bindings; checks are loop-mediated with
    no literal subscript; not every check is a `_check_*` call.
  - *A table-driven refactor* (`*_VALUE_CHECKS` the decoder iterates) would
    make a skipped key unrepresentable — and would **FLATTEN the interleaved
    type/sentinel checks** that `_validate_manifest_shape` and Rust's
    `parse_manifest_map` both perform, changing which fault a two-fault body
    reports on a token-compared target. A guard that introduces a
    cross-language divergence is worse than the gap it closes. #678.
- **Check 4 governs OPTIONAL keys only.** A REQUIRED key losing its check is
  not seen. The sweep found zero instances; #678 owns it.
- **Check 3 reads TEXT.** An aliased `isinstance` import or a metaprogrammed
  call evades it. It scans `codec/` and nowhere else — `wire/` is out of scope
  because it enforces no acceptance set. (#679 review: "it is fixed" was true of `wire/vault_toml.py` only — `wire/card.py` carried both mechanisms and was missed. Both are now fixed AND covered by check 1c; check 3 still does not scan `wire/`.)
- **The sweep is not a proof of absence.** One leaf at a time, one base per
  target, a fixed substitution set. A divergence needing two simultaneous
  faults, or a value shape outside that set, was not measured. Say "the sweep
  found none", never "there are none".
- **`bundle_file` and `manifest_file` were never swept** — binary envelopes
  read by offset, so the substitution method does not apply. #677.
- **#641 is untouched**: `contact_card`, `bundle_file` and `vault_toml` are
  still not token-compared. This slice compares their **verdicts**, not their
  rules.
- **The plan had a real gap, and it cost a detection.** Its seed task ran the
  Rust replay and not `conformance.py`, so generating the seeds broke Section
  RTV and that went unnoticed until the next task. Generalise: after changing a
  **corpus**, run *both* verifiers, not the one whose target you were editing.

---

## (3) What is next — with acceptance criteria

### (3a) Acceptance divergences that remain

- **#670 — a record optional key present at its default** (`tags: []`,
  `tombstone: false`, `tombstoned_at_ms: 0`): Python accepts, Rust rejects.
  Needs a **§6.3 spec decision** (options in the issue), then the side that
  changes, then a seed per key. This is now the only known acceptance
  divergence with no structural cover.
- **#667 case 2 — an UNKNOWN record value nested past 256.** Python accepts,
  Rust rejects (`CborDecode(RecursionLimit)`). Needs a decision on stating a
  v1 depth limit normatively vs documenting it, and a Python side that returns
  a verdict at every depth (its scanner still recurses; ~995 levels raises
  `RecursionError`, a harness failure rather than a verdict).
- **#677 — sweep `bundle_file` and `manifest_file`** with an offset-based
  corruption sweep rather than value substitution. **Acceptance:** one body per
  (field, corruption) from each committed base, both decoders compared, any
  divergence fixed or filed.

### (3b) The rest

- **#641** — token-compare `contact_card`, `bundle_file`, `vault_toml`. The 14
  new seeds give `contact_card` and `vault_toml` rejecting committed inputs for
  the first time, so a strict comparison there now has something to compare.
- **#678** — the required-key half of check 4, with the interleaving problem
  solved rather than flattened.
- **#666** — wire the well-formedness walk into `decode_manifest` and block
  plaintext decode.
- **#668, #646** — report-order spec decisions. **#657** — nothing pins that
  the CI replay step stays wired. **#612, #660, #671, #672, #676** — polish.

---

## (4) Open decisions and risks

- **#670 is the last known open acceptance divergence** and it is a spec
  question, not a bug: §6.3 says what absent and default *mean*, never whether
  the present-default spelling is canonical.
- **Section VT's PASS lines report numbers (16 / 10 / 18 / 7)**, deliberately,
  so a case or a key silently lost shows as a moved figure. Treat a changed
  number as a finding, not as drift to re-baseline.
- **`_CORPUS_TOKENS` (Section RTV) and the seed set move together.** Adding a
  committed `manifest_body` seed that reaches a new token requires editing that
  set; RTV's failure message says so by name.
- **`.gitignore`'s `corpus/` rule matches directories only**, so a
  `core/fuzz/corpus` symlink shows as untracked. Remove it after each run.
- **Files past 500 lines** still include `record.rs` (#556) and `block.rs`
  (#563); this slice touched neither. Every file it created is under 500.

---

## (5) How to resume — the exact commands

```bash
# FIRST — it has fired on two of the last three slices:
git fetch origin && git log --oneline main..origin/main

cd /Users/hherb/src/secretary/.worktrees/bool-as-integer
pwd && git branch --show-current && git worktree list

# --- the clean-room verifier (Section VT is the new one) ---
uv run core/tests/python/conformance.py        # 0 FAIL, VT 16/10/18/7, REG 33/33

# --- the replay, CI shape ---
cargo test --release --locked -p secretary-core \
  --features differential-replay --test differential_replay      # 46 passed

# --- the replay over the real fuzz corpus; REMOVE the link afterwards ---
test ! -e core/fuzz/corpus && ln -s /Users/hherb/src/secretary/core/fuzz/corpus core/fuzz/corpus
cargo test --release --locked -p secretary-core \
  --features differential-replay --test differential_replay -- differential_replay_full_corpus
rm core/fuzz/corpus && git status --short                        # no corpus entry

# --- regenerate the acceptance seeds after an intentional change ---
# Asserts every row BEFORE writing any file; review the diff before committing.
cargo test --release --locked -p secretary-core --test acceptance_seeds -- --ignored generate_acceptance_seeds
cargo test --release --locked -p secretary-core --test acceptance_seeds   # 4 passed, 1 ignored

# --- prove Section VT is not decorative (spec to the SCRATCHPAD, never the tree) ---
uv run scripts/mutate.py --self-test                                 # 20/20
uv run --with cryptography --with pynacl --with "pqcrypto<1" \
  --with argon2-cffi --with blake3 --with cbor2 scripts/mutate.py "$SCRATCH/vt.toml"
git status --short                                                    # MUST be empty

# --- the rest of the gate set ---
cargo test --release --locked --workspace                             # 2199 passed
cargo clippy --release --locked --workspace --tests -- -D warnings
cargo clippy --release --locked -p secretary-core --features differential-replay --tests -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
cargo fmt --all --check

# --- six hygiene guards, --self-test FIRST, as LITERAL commands ---
bash ffi/scripts/check-lean-binding.sh --self-test         && bash ffi/scripts/check-lean-binding.sh
bash ios/scripts/check-public-log-hygiene.sh --self-test   && bash ios/scripts/check-public-log-hygiene.sh
bash android/scripts/check-log-hygiene.sh --self-test      && bash android/scripts/check-log-hygiene.sh
bash scripts/check-secret-slot-hygiene.sh --self-test      && bash scripts/check-secret-slot-hygiene.sh
uv run scripts/check-error-payload-hygiene.py --self-test  && uv run scripts/check-error-payload-hygiene.py
uv run scripts/check-test-support-placement.py --self-test && uv run scripts/check-test-support-placement.py
```

---

## (5b) The #679 review round — what it found, and the one generalisable lesson

Five review agents plus direct verification. Every finding below was
**measured**, with a control, in a throwaway sandbox; the worktree was never
mutated.

### Four critical, all in the new gate rather than in the fix

1. **`codec/trash_entry.py`'s type checks were revertible with the verifier
   green.** `TRASH_ENTRY_DIRECT_KEYS` was a hand-written frozenset passed as
   the census's `direct_keys` while two docstrings said both arguments were
   "DERIVED from the cases that actually run". Control: deleting the decoder's
   `fingerprint` check alone → caught. Deleting the case row alone → silent.
   Deleting **both** → silent, with `PASS 4: … each covered` still printed. No
   replay target reaches that decoder, so nothing else in the tree covered it.
   Now derived from `_TRASH_ENTRY_CASES`, with its own PASS line.
2. **8 of check 1's 16 rows passed on any rejection.** Token-less targets have
   no rule to compare, so `status == "reject"` was the whole assertion. With
   `is_integer` reverted and the plants made to reject another way, those rows
   reported nothing. They now require the rejection to name the position, and
   reject an `ENCODER_REFUSAL_PREFIX` answer.
3. **`_cbor_sub` INSERTED instead of substituting.** A misspelled or later-
   renamed key added an unrecognised key and left the real value untouched;
   the body was rejected as "unknown field" and counted as a pass. `_toml_sub`
   and the Rust `set_at` both already failed closed here.
4. **`KeySetPair.coverage` was a free string with a silent fall-through.** A
   one-character typo, and equally a VALID word applied to a file check 4b
   does not probe, matched no branch and appended no issue — re-opening M2
   through the guard built to prevent M2. `coverage` is now a closed
   vocabulary refused at construction.

### The miss in the fix itself

`wire/card.py` carried **both** of #669's mechanisms — a bare
`card_version != 1` (M1) and no check at all on `created_at` (M2) — and was
never touched. The handoff said `wire/` "is fixed, just not policed"; that was
true of `wire/vault_toml.py` alone. `wire/golden_vault_verify.py:301`'s
`!= 1` is **not** a defect: its input comes from `py_decode_manifest`, which
has already type-gated `manifest_version`.

### The generalisable lesson

**A check written to close a backstop can itself be backstopped.** The first
version of check 1c asserted only that `parse_and_verify_card` raised
`ParseError` — and passed with `wire/card.py`'s fix fully reverted, because
planting a bool changes the signed bytes and the hybrid self-signature rejects
the body whatever the type check does. It was written *while* fixing finding 2,
which is the same defect, and still shipped vacuous until mutation-tested.
Assert the reason, not the rejection.

### Mutation evidence (each `before → after`, with a passing control)

| mutation | before | after |
|---|---|---|
| delete trash case row + the decoder check it pins | silent | caught |
| misspell a `contact_card` position | silent | caught |
| revert `is_integer` (the whole of #669) | 8 rows silent | 17 issues |
| typo a `coverage` value | silent | unconstructible (raises) |
| gut a `record.py` dispatch arm to accept | silent | caught |
| `CODEC_ROOT` → empty directory | PASS, "0 scanned" | caught by the floor |
| revert `wire/card.py` (either half) | silent | caught |
| revert the `wire/vault_toml.py` loop | silent | caught |
| two rows plant identical bytes | silent, printed 16 | caught |
| cross-map optional-key crediting | silent | caught |

### Also corrected

`scanner.py "476 → 479"` (never touched by #669; 479 at both ends — a
neighbouring-number copy inside the paragraph warning about them); "three
other generators" → **two**; `manifest_decode.py`'s guard attributed to #641 →
**#595**; the corpus-coverage figures 24/38 → **30/44** and "7 reach a real
comparison" → **13**, in `token.rs`, `tolerance.rs`, `python_bridge.rs` and
CLAUDE.md; `MIN_CORPUS_INPUTS`'s "only git-tracked inputs count" (the tagging
is by DIRECTORY); the Rust `trash!` macro now DERIVES its label so a lying file
name is unconstructible; `variant_name` keeps a `&'static str` payload, so the
six `vault_toml` rows no longer all assert `MissingField` and the two card rows
no longer assert `CardError`'s 16-site catch-all.

Filed rather than fixed: **#680** (six alias key-set pairings whose census can
never fire), plus measured detail added to **#678** (the specific required-key
positions with zero cover) and **#677** (the 439-body sweep was never committed
as a re-runnable generator).

---

## (6) Where this document lives

`NEXT_SESSION.md` at the repo root is a **symlink**, retargeted this session to
`docs/handoffs/2026-09-17-value-type-discipline-shipped.md`. This file is the
single authored baton — do not create a second copy, and do not sync it to
`main` during a pause window.
