# NEXT_SESSION.md — `NonCanonicalCause` gets full cross-language coverage (#613), and half of #612

Branch `feature/cause-coverage`, worktree `.worktrees/cause-coverage`,
base `0f570e06` (`main`, i.e. immediately after PR #617 merged).

This slice is **(a)** from the previous baton's queue, taken with the
`#612` split folded in — both decisions were put to the user with
options-plus-recommendation and both took the recommendation (§(1)).

**One issue filed:** [#621](https://github.com/hherb/secretary/issues/621),
found by probing a case the new section's own claim does not cover. The
slice closes **#613** and **half of #612**.

---

## (0) The starting-state check fired clean again — keep running it first

`git fetch origin && git log --oneline main..origin/main` returned empty and
`main` was at `0f570e06`, so the previous slice (#589/#582) had merged. Cost:
one command. Keep it as the first thing you do, **before reading this file** —
the baton is a symlink into `docs/handoffs/`, so a stale checkout resolves it
silently to an old file with no marker of any kind.

Housekeeping done at the same time: `.worktrees/decoder-slot-invariant` removed
and `feature/decoder-slot-invariant` deleted (merged as PR #617). The throwaway
`/tmp/base-613` baseline worktree used for the name-set and freshness diffs was
removed at the end. **Two older local branches were deliberately left alone** —
`feature/manifest-uniqueness-parity` and `feature/noncanonical-cause`. Both are
squash-merged (their diffs against `main` are net *deletions*, i.e. they are
behind it), so `git branch -d` will not take them and `-D` is a destructive op I
did not run without asking. `backup-pre-reword-1787543234` is a deliberate
backup; leave it.

---

## (1) What shipped

### Commits

| SHA | What |
|---|---|
| `80c3c488` | **#612 half** — `manifest_canonicality_kat.rs` 956 → 374 lines + a `_helpers/` directory. Behaviour-preserving, committed separately so it is checkable as a pure move |
| `27601b87` | **#613** — the two-family corpus, the second KIND of Python expectation, two structured discriminators, 21 → 30 rows |
| *(review round)* | **#622 review** — `blocks[1]` array rows, closed `SortedArray` enum with derived labels, per-CAUSE coverage floor, shared row-shape + body-distinctness guards, four corrected claims; 30 → 32 rows |
| `266fca4b` | CLAUDE.md + ROADMAP, with the drifted `conformance_lib` figures re-measured |
| *(this)* | the baton — a commit cannot cite its own SHA, so this row stays symbolic |

### The defect

#604 gave `manifest_canonicality_kat.json` an `expect_cause` column and had
both languages replay it, establishing a cross-language vocabulary for #590's
`NonCanonicalCause`. **It covered two of the four variants.** `ArraySortOrder`
and `Unclassified` had no corpus row, no `conformance.py` counterpart, and were
pinned by Rust unit tests alone — `Unclassified` being the arm #590's first
implementation got wrong *in the direction a peer could choose*, i.e. the one
whose correctness argument most wanted a second implementation to agree with it.

They were unreachable **by construction**: every row was one of seven CBOR
subtree shapes spliced into a forward-compat `unknown` bag, and neither cause is
an `unknown` subtree. So neither could be an eighth `Shape`.

### The ruling put to the user before implementation

Two questions, options-plus-recommendation, both answered with the
recommendation:

1. **One fixture, two case families** — not a second fixture file (which
   duplicates the generator, the rebuild-and-compare, the fail-closed column
   reads and the coverage floors, and splits one cause vocabulary across two
   contracts), and not forcing the new rows into the 7×3 product (which would
   make "level" mean two different things, and the arrays do not map onto levels
   anyway — `blocks`, `trash` and `vector_clock` are all top-level).
2. **Split `manifest_canonicality_kat.rs` in this slice**, since #613 grows it
   past 1250 lines against a standing 500-line guideline and the generator's
   iteration was being rewritten anyway. `manifest_uniqueness_kat.rs` (848) was
   deliberately NOT swept in — it has nothing to do with cause coverage.

### What landed

- **`cases.rs`** yields one `all_cases()` list over `Case::{Splice, Mutate}`.
  Splice family: the untouched `Level::ALL × SHAPES` product. Mutation family:
  **9** whole-body reorderings of the same `Level::Top` baseline — 5
  `arraysort__*` (one per §4.2 sorted array) and 4 `keyorder__*` (top /
  `kdf_params` / `blocks[0]` / `trash[0]`). Four map positions rather than one
  because they are four different parsers on both sides.
- **21 → 32 rows, 27 → 38 seeds, with the 21 existing rows and every existing
  seed byte-identical.** Asserted against the merge-base fixture; that is the
  evidence the change is additive rather than a regeneration.
- **`body_for_case` is the single builder for BOTH families**, used by the
  generator and by the replay's rebuild-and-compare, preserving #614's
  bytes-bound-to-label property. Row-count and mechanism totals are now DERIVED
  from the case table rather than written as literals.
- **`_CAUSE_EXPECTATION` replaces `_CAUSE_TO_RULE`**, holding `RuleNumber(n)`
  **or** `ExceptionKind(cls)`. `manifest_decode.py` gained two structured
  discriminators, `ArraySortOrderViolation` and `NonCanonicalBody`.
- **The shared corpus description** (`sections/manifest_canonicality_corpus.py`,
  114 lines) declares the label set once for MCK and MCC. It defines no
  `section*` driver; REG still reports 26/26.
- `array_sort_disciplines_are_enforced_and_not_vacuous` shares the single
  `reverse_array` and asserts the **cause**, not just `is_err()` — the gap #613
  names in its own text.
- One new test: `no_mutation_label_can_be_read_as_a_splice_row`.

### Non-vacuity, by mutation

Every restore verified by **sha256**.

| # | Mutation | Result |
|---|---|---|
| M1 | delete `classify`'s `ArraySortOrder` arm | **2 Rust tests red**; `conformance.py` stays green — the independent-mechanism property, measured rather than argued |
| M2 | sort branch → plain `ValueError` | MCC reds **exactly 5** rows |
| M3 | re-encode branch → plain `ValueError` | MCC reds **exactly 4** rows |
| M4 | a cause in `_CAUSE_EXPECTATION` with no corpus row | MCC's coverage floor reds, naming the missing discriminator |
| M5a | drop the 4 `keyorder__*` cases | `rows.len() == cases.len()` reds — **this is what falsified a comment I had already written** |
| M5b | shorten `ALL_CAUSES` | **compile error** (the `; 4]` length annotation) |
| M5c | duplicate an `ALL_CAUSES` entry | `cause_names_are_distinct` **and** the replay both red — the comparison is live |
| M6 | swap one row's body for another's | rebuild-and-compare reds, naming the row |
| M7 | drop one mutation row | shared `label_issues` reds in **both** sections |

### The measured result

- **`cargo test --release --workspace`: 99 binaries, 2101 passed, 0 failed, 21
  ignored**, exit 0.
- **Test NAME SET measured against an `origin/main` baseline** in a throwaway
  worktree: `main` **2121**, branch **2122**. One removed, two added, and both
  are accounted for: `generate::generate_manifest_canonicality_kat` moved to
  `manifest_canonicality_kat_helpers::generate::…` (the split's only unavoidable
  rename), and `no_mutation_label_can_be_read_as_a_splice_row` is genuinely new.
  **The previous baton's "branch = 2118" was pre-review-round** — that round
  added exactly 3 tests, which is why `main` now measures 2121.
- `--features differential-replay` clean (99 binaries, 2102 passed, 0 failed).
- `cargo fmt --all --check`, `cargo clippy --release --workspace --tests -- -D
  warnings`, `RUSTDOCFLAGS="-D warnings" cargo doc` (forced non-cached with
  `touch core/src/lib.rs`) all clean. `core/fuzz` checks under the pinned
  nightly.
- **`conformance.py` exit 0**, 26 sections, REG `26 drivers, 26 registered`.
  MCC now reports `15 caused + 3 uncaused rejections … all 5 discriminators
  exercised (ArraySortOrderViolation, NonCanonicalBody, rule 2, rule 3, rule 4)`.
- **All six hygiene guards pass, each `--self-test` first.** No probe residue.
- **`spec_test_name_freshness.py` = 90, byte-identical to `origin/main`** —
  `diff`ed in full against a baseline worktree with an explicit `cd` inside the
  subshell.
- **Format invariants:** UDL and normative `docs/` diffs **empty**.
  `core/tests/data/` gains 9 rows and `core/fuzz/seeds/` 9 files, **with nothing
  rewritten** — `git status` showed 9 untracked and 0 modified seeds.
- Every file under 500: entry 489, largest helper 470, `manifest_canonicality_
  cause.py` 388, `manifest_decode.py` 382.

### README was deliberately not touched

Checked, not assumed: `grep` for `613|612|canonicality|manifest_canonicality`
returns nothing in README.md. It is a status/roadmap table that cites no KAT
internals, no section count and no test count, and this slice changes no
user-visible behaviour and no on-disk format. `ROADMAP.md` and `CLAUDE.md` both
changed.

---

## (2) What this slice does **not** claim

- **The `causes_seen` assertion is still DEFENCE IN DEPTH.** Read §(4) — an
  intermediate version of its own comment claimed it was mutation-proven, and
  measuring falsified that. What changed with #613 is the CONTENT of the claim
  (full coverage, rather than a recorded gap), not its strength.
- **"The two implementations agree on the rule" holds ROW BY ROW, and every row
  violates exactly ONE rule.** For a body violating two they disagree — measured,
  and filed as **#621**. See §(4).
- **`ArraySortOrderViolation` and `NonCanonicalBody` carry no payload, and that
  is deliberate.** Their IDENTITY is the whole discriminator, so the default
  `BaseException.__reduce__` round-trips through `copy`/`pickle`. That is exactly
  why `NonCanonicalItem`, which carries a rule number, needed the explicit
  `__reduce__` #614's review added. Adding a payload to either means adding a
  `__reduce__` with it.
- **The sort/repeat asymmetry inside `_check_sorted_and_distinct` is not an
  inconsistency to tidy.** The SORT branch raises the new type; the REPEAT branch
  stays a plain `ValueError` because Section MUQ discriminates *that* one by a
  message fragment naming the repeated id. Collapsing them onto one type would
  let a sortedness-only reader satisfy MUQ — the exact #594 divergence.
- **`array_sort_disciplines_are_enforced_and_not_vacuous` is NOT redundant with
  the five `arraysort__*` rows**, even though they share `reverse_array`: it
  computes its bodies fresh from the current `base_manifest`, so the five
  disciplines stay pinned if the fixture is deleted entirely. Do not delete it as
  superseded.
- **No spec change, no new error variant, no on-disk format change.**
  `NonCanonicalCause` and `ManifestError` are byte-identical to `main`'s.
- **#602 / #603 / #587 / #596 / #610 / #611 / #618 / #619 / #620 stay open and
  untouched**, as does the other half of #612.

---

## (3) What is next — with acceptance criteria

**(a) #621 — the multi-violation precedence divergence, filed by this slice.**
Take the committed `arraysort__vector_clock` body, splice the
`rule2_indefinite_map` subtree over its needle, and the two readers disagree:
Rust says `ArraySortOrder`, Python says rule 2, at the *same byte offset* (929).
Both reject, so nothing is unsafe and no acceptance set moves — but Section MCC's
whole stated claim is that the two agree on which rule a body violates, and for a
multi-violation body they do not. Neither order is written down, and each is
locally reasonable (`classify_non_canonical` tries arrays first *deliberately*;
the byte-retaining reader reaches `_check_canonical_item` during its scan loop,
before the sort check exists). **Acceptance:** `docs/vault-format.md` §4.2 either
fixes a precedence — in which case corpus rows violating two rules at once assert
the declared winner in both languages — or states explicitly that the reported
rule is unspecified when several apply, in which case MCC's docstring and
`classify.rs` say so, so the next person measuring it does not read it as a
defect. Declaring it unspecified is a legitimate and much cheaper answer.

**(b) #612's other half — `manifest_uniqueness_kat.rs` (848 lines).** The
`_helpers/` pattern is now demonstrated twice in `core/tests/`, and the two
corpora are read as a pair. **Acceptance:** under 500, sharing its `Case` /
`Verdict` / surgery helpers through a `manifest_uniqueness_kat_helpers/` rather
than a second test binary, and committed as a behaviour-preserving move with the
test name set diffed (this slice's `80c3c488` is the worked example — one
unavoidable module-path rename, nothing else).

**(c) #602 — `identity::card` and `sync::state` are outside #586's choke point**,
including the hybrid-signed `ContactCard::signed_bytes`. No live exposure (all
three build keys from fixed literals) but that is a property of today's call
sites, not of the encoder. **Acceptance:** those paths reject a duplicate key too,
or `card.rs`'s deliberately-permissive `encode_map` is documented as a reviewed
exception with the hostile-peer fixtures that need it named.

**(d) #596 — a `manifest_body` cargo-fuzz target, the natural eighth.** The
`--diff-replay` wiring exists and the seed corpus is now **36** bodies (was 27).
**Acceptance:** `core/fuzz/fuzz_targets/manifest_body.rs` exists,
`cargo fuzz run manifest_body` starts from the committed seeds, and CLAUDE.md's
"Seven targets" line becomes eight.

**(e) #610 / #611 / #587 / #603 / #618 / #619 / #620 stay open and untouched.**

### Issues this slice closes — verify against the code, not this document

**#613** and **half of #612**. Per this repo's `(#N)`-not-`Closes #N` convention
both stay open until a human closes them. #613's acceptance is checkable in one
command: `conformance.py`'s MCC line must name all five discriminators, and
`python3 -c` over the fixture must show 4 distinct non-null `expect_cause`
values. #612's half is `wc -l core/tests/manifest_canonicality_kat.rs` (452).

---

## (4) Open decisions and risks

### The verification trap this session hit — the same one the last baton recorded

**I wrote a comment asserting a mutation result, then measured it and it was
false.** Updating the `causes_seen` assertion I wrote that "deleting either
family's rows from `MUTATIONS` reds it directly (verified by mutation)". It does
not: dropping the four `keyorder__*` cases trips the `rows.len() == cases.len()`
assertion 180 lines earlier, and regenerating past that trips
`want_re_encode == 15`. The comment now says what is actually true — the
assertion is defence in depth, the comparison is *live* (M5b/M5c), and the
direction it exists for needs a real fifth `NonCanonicalCause` variant to
exercise, so it is argued rather than measured. Its Python counterpart IS
mutation-proven, which is M4.

This is verbatim the trap the previous baton recorded ("a comment can assert a
property nobody measured") and it recurred **in the same file, one slice later,
in the paragraph replacing the one that had confessed the same limitation.**
Treat "verified by mutation" in a comment as a claim to run, not a claim to
read — including your own, written ten minutes ago.

### The finding that came from probing the new claim rather than the old code

#621 exists because I asked what Section MCC's *new* sentence does not cover, not
what the old code got wrong. The corpus was designed one-violation-per-row, so
the section's claim is scoped to that without saying so. **Generalise it:** when
a slice establishes a cross-language agreement property, the next question is
which inputs the corpus's construction makes unreachable — that is where #613
itself came from (a corpus that could only splice `unknown` subtrees), and it is
where #621 came from one layer on.

### A scope decision worth recording

**The `#612` split was done FIRST and committed SEPARATELY**, before any
behaviour changed, and that is what makes it reviewable: the move is checkable as
a pure move (same 3 tests + same 1 ignored, three of four names byte-identical),
and the #613 diff then contains only substance. Doing them in one commit would
have made a 900-line diff in which nobody could tell which lines moved and which
changed. If you take #612's other half, keep the same discipline.

### Standing risks this slice does not remove

- **Five of the six PEP 723 deps remain unbounded** (`cryptography`, `pynacl`,
  `argon2-cffi`, `blake3`, `cbor2`), and `ed25519_verify` still has the "no
  exception means success" shape whose failure direction would be fail-**open**
  (#544 / #550).
- **`encode_manifest` validates no v1 sentinel** (#587).
- **`identity::card` and `sync::state` remain outside the duplicate-key choke
  point** (#602), including a hybrid-signed path.
- **Multi-violation precedence is unspecified and divergent** (#621, new).
- **`differential_replay.rs` scores reject-vs-reject as agreement without
  comparing `detail`** (#618) — which is precisely why #621 was invisible to it,
  and why it will stay invisible to it after #621 is fixed.
- **The `unknown`-subtree residual is untouched**: no duplicate-key or key-order
  check looks inside an `UnknownValue`, deliberately (crypto-design §6.2 rules 1
  and 5 are scoped to material the reader interprets).

---

## (5) How to resume — the exact commands

```bash
# FIRST, before reading the baton — costs nothing when it is actually run:
git fetch origin && git log --oneline main..origin/main

cd /Users/hherb/src/secretary/.worktrees/cause-coverage
pwd && git branch --show-current && git worktree list   # expect feature/cause-coverage

# --- the gates this slice is actually about ---
cargo test --release --test manifest_canonicality_kat     # expect 4 passed, 1 ignored
uv run core/tests/python/conformance.py                   # 26 sections; REG 26/26
#   MCC must say: all 5 discriminators exercised
#   (ArraySortOrderViolation, NonCanonicalBody, rule 2, rule 3, rule 4)

# The corpus's own shape, in one command:
python3 -c "
import json,collections
r=json.load(open('core/tests/data/manifest_canonicality_kat.json'))['rows']
print(len(r),'rows')
print(sorted(collections.Counter((x['expect_accept'],x['expect_cause']) for x in r).items(),key=str))"
# expect 32 rows; 7 ArraySortOrder, 3 IndefiniteLength, 3 NonShortestForm,
#                 4 Unclassified, 3 null-reject, 12 accept

# --- the cross-language contract (no CI job covers this one) ---
cargo test --release --workspace --features differential-replay

# --- the rest of the gate set ---
cargo fmt --all --check
cargo build --release --workspace                # separate from the test run ON PURPOSE
# Redirect, then echo $? — a `| grep` pipeline reports GREP's exit code:
cargo test --release --workspace > /tmp/suite.txt 2>&1; echo "CARGO EXIT: $?"
grep -E "^test result" /tmp/suite.txt | \
  awk '{p+=$4; f+=$6; i+=$8} END {print NR, p, f, i}'   # expect 99 2101 0 21
# NOT redundant with the above — `--tests` catches unused imports the full
# suite compiles green (cost a cycle two sessions ago):
cargo clippy --release --workspace --tests -- -D warnings
touch core/src/lib.rs   # rustdoc caches; a ~5s run did nothing
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
cd core/fuzz && PATH="$HOME/.rustup/toolchains/nightly-2026-04-29-aarch64-apple-darwin/bin:$PATH" cargo check
cd -

uv run --with pyflakes python -m pyflakes core/tests/python/conformance.py \
                                          core/tests/python/conformance_lib

# --- six hygiene guards, --self-test FIRST every time ---
# (run each as a literal command; zsh does not word-split an unquoted variable,
#  so a `for g in "bash x.sh"; do $g; done` loop reports FAIL on all of them)
bash ffi/scripts/check-lean-binding.sh --self-test         && bash ffi/scripts/check-lean-binding.sh
bash ios/scripts/check-public-log-hygiene.sh --self-test   && bash ios/scripts/check-public-log-hygiene.sh
bash android/scripts/check-log-hygiene.sh --self-test      && bash android/scripts/check-log-hygiene.sh
bash scripts/check-secret-slot-hygiene.sh --self-test      && bash scripts/check-secret-slot-hygiene.sh
uv run scripts/check-error-payload-hygiene.py --self-test  && uv run scripts/check-error-payload-hygiene.py
uv run scripts/check-test-support-placement.py --self-test && uv run scripts/check-test-support-placement.py

# --- citation freshness: 90, and byte-identical to main ---
uv run core/tests/python/spec_test_name_freshness.py

# --- format invariants. The first TWO are EXPECTED to be non-empty this slice
#     (9 rows / 9 seeds, nothing rewritten); the last two MUST be empty. ---
git diff origin/main...HEAD --stat -- core/tests/data/
git diff origin/main...HEAD --stat -- core/fuzz/seeds/
git diff origin/main...HEAD -- ffi/secretary-ffi-uniffi/src/secretary.udl
# NORMATIVE docs only. A git pathspec glob CROSSES `/`, so `docs/*.md` would
# also match docs/manual/**; exclude the two non-normative trees by name.
git diff origin/main...HEAD --stat -- docs/ ':!docs/handoffs/' ':!docs/manual/'
```

Regenerating the corpus after a deliberate, reviewed change to `SHAPES` /
`MUTATIONS` (the generator ASSERTS the spec — if it panics, the fix is the
decoder or the table, never the fixture):

```bash
cargo test --release --workspace -- --ignored generate_manifest_canonicality_kat --nocapture
```

Re-proving #621 by execution, which is the fastest way to understand it:

```bash
python3 - <<'PY' > /tmp/combined.hex
import json
r = {x["label"]: x for x in json.load(open("core/tests/data/manifest_canonicality_kat.json"))["rows"]}
NEEDLE = bytes([0xA1,0x61,0x61,0x01]); INDEF = bytes([0xBF,0x61,0x61,0x01,0xFF])
b = bytes.fromhex(r["arraysort__vector_clock"]["manifest_body_hex"])
assert b.count(NEEDLE) == 1
print(b.replace(NEEDLE, INDEF).hex())
PY
# Python says rule 2; Rust says ArraySortOrder. Same bytes, same offset 929.
```

---

## (6) Where this document lives

`NEXT_SESSION.md` at the repo root is a **symlink**, retargeted this session to
`docs/handoffs/2026-09-07-cause-coverage-shipped.md`. This file is the single
authored baton — do not create a second copy at the root, and do not sync it to
`main` during a pause window (that produces an add/add conflict).


---

## Review round (#622), appended

Five specialised reviewers plus a hand pass. Everything below was MEASURED,
each restore sha256-verified.

### Two coverage gaps in the property this slice exists to pin

1. **`blocks[1]` was unreachable.** Every nested array row planted at
   `blocks[0]` (`build.rs` hard-coded `.first_mut()`), so a reader or
   classifier scoped to the first block was conformant against the whole
   tree. Measured both ways: `classify::arrays_are_sorted` narrowed to
   `.take(1)` left the **entire workspace** green; the Python reader's nested
   sort check narrowed to `blocks[0]` left **all 26 sections** green. This is
   verbatim #608's "a two-sided property needs a fixture at each end", which
   the uniqueness corpus got and the sortedness corpus never did. Two rows
   added; both mutations now red (`.take(1)` reds 2 tests, the Python
   narrowing exits 1).

2. **#623 — arrays hold 2 elements**, so a first-pair check and a full
   adjacent scan are the same function (measured: a first-pair reader leaves
   all 26 sections green). NOT fixed here: it changes `base_manifest`, hence
   all 32 bodies and 38 seeds, spending exactly the additivity evidence this
   slice rests on. Filed with the measurement and the middle-swap requirement.

### Four claims that were false

- `generate.rs` called its `Ok` arm "not vacuous". It is unreachable twice
  over — `Verdict::cause()` returns `None` for `Accept`, and the `assert_eq!`
  15 lines above has already forced `Accept`. It also contradicted
  `cases.rs`'s own `Verdict` doc. Now labelled unreachable-by-construction
  future-proofing.
- "deleting the `ArraySortOrder` arm reds **two** Rust tests" — measured
  **five** (3 `--lib` + 2 integration). The original was an integration-binary
  subtotal written as a claim about Rust tests. Same shape as the
  `--lib`/`--test` filter trap CLAUDE.md already records.
- The four `keyorder__*` rows were said to "pin the arm a peer could once
  choose". All four diverge on a major-type-3 head with ai <= 23, which #590's
  positional classifier reads identically to today's decisive one — so they
  cannot discriminate the two. Filed as **#624**.
- `manifest_encode.py`'s docstring claimed it sorts all five arrays on output.
  It never has (the only `sorted` in the file is a comment saying so), and the
  claim contradicts the mechanism asymmetry Section MCC rests on.

### Structural fixes

- **`Mutation::ReverseArray` takes a closed `SortedArray` enum**, not
  `(&str, Option<&str>)`. The pair made 28 combinations representable, of
  which 5 named a §4.2 array and only by a property of today's base manifest.
  Labels are now DERIVED, so a row whose label disagrees with what it reverses
  is unconstructible — it was representable and measured invisible to both
  languages.
- **MCC's coverage floor is per-CAUSE, plus an injectivity check.** It
  compared DISCRIMINATORS against a MANY-TO-ONE table, so a colliding new
  cause was declared covered with no corpus row: `RuleNumber(2)` PASSED,
  unique `RuleNumber(9)` correctly red. Both now red. A third expectation
  KIND used to escape as `AttributeError` out of `main()`; now a FAIL line.
- **`row_issues` + `body_issues` are shared by MCK and MCC.** MCK runs first
  on the same file and had no shape guard, so a malformed row escaped as a
  traceback with no `FAIL:` line, skipping MCC/MUQ/RC/DET/**REG**. Closing it
  required removing three later raw `r["label"]` reads that stepped around the
  guard — a guard one later read can bypass is not a guard. `body_issues` is
  the floor a label check structurally cannot provide: #614's own finding was
  a body substitution with labels retained, and it passed until now.
- Rust gained a pairwise body-distinctness floor (mutation-proven: pointing
  `BlockRecipients{1}` at block 0 reds it, naming both rows).

### Gates

`cargo test --release --workspace` 99 binaries / **2101 passed** / 0 failed /
21 ignored, exit 0 · `--features differential-replay` 2102 passed, exit 0 ·
clippy `-D warnings` exit 0 · `RUSTDOCFLAGS="-D warnings" cargo doc` exit 0 ·
`cargo fmt --all --check` clean · `conformance.py` exit 0, 26 sections, REG
26/26, MCK 32 rows (12 accept / 20 reject), MCC 17 caused + 3 uncaused, all 5
discriminators · all six hygiene guards `--self-test` then run, exit 0, no
probe residue · `core/fuzz` builds under the pinned nightly ·
`spec_test_name_freshness.py` = 90 (unchanged baseline).

**One process note.** A `conformance.py` run reported **0 FAIL lines and exit
1** — a `SyntaxError` from a botched docstring edit. Grepping for `FAIL` alone
would have scored it green. Judge by exit code.
