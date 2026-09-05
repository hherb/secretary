# NEXT_SESSION.md — the manifest canonicality corpus gets a cause column, in both languages (#604)

Branch `feature/canonicality-cause`, worktree `.worktrees/canonicality-cause`,
base `e0a6e7ad` (`main`, i.e. immediately after PR #608 merged).

This slice is **(a)** from the previous baton's queue, taken as written. It is
Rust **and** Python. Unlike the last three slices it **does** touch
`core/tests/data/` — by design, and the issue said so. `core/fuzz/seeds/`, the
UDL and normative `docs/` are all still empty.

**One issue filed: #613** (the corpus reaches two of `NonCanonicalCause`'s four
variants). Nothing else was found that is not closed here or already tracked.

---

## (0) The starting-state trap did NOT fire this session — the check is cheap, keep running it

Four consecutive sessions opened a stale handoff. This one ran
`git fetch origin && git log --oneline main..origin/main` **first**, got an
empty result, and proceeded. Total cost: one command. Keep it as the first
thing you do, before reading this file — the baton is a symlink into
`docs/handoffs/`, so a stale checkout resolves it silently to an old file with
no marker of any kind.

---

## (1) What shipped

### Commits

| SHA | What |
|---|---|
| `0c8a851c` | the slice — `expect_cause` column, `assert_rejection_mechanism` rewrite, `NonCanonicalItem`, Section MCC, CLAUDE.md + ROADMAP |
| *(review)* | the #614 review round — `Verdict` enum, replay rebuild-and-compare, MCC label floor, Section CS rule assertions, three fail-loud row-shape guards, doc corrections |
| *(this)* | the baton — a commit cannot cite its own SHA, so this row stays symbolic |

### The defect

#590 gave `ManifestError::NonCanonicalEncoding` a `NonCanonicalCause`, and
`manifest_canonicality_kat_replays` asserted one for each of the SIX
rejecting rows that reach the §4.3 step-4 re-encode (six, not nine — the
three `rule4_float` rows are caught earlier and deliberately get no cause).
**That assertion lived only in Rust.** `manifest_canonicality_kat.json` carried
`label`, `manifest_body_hex` and `expect_accept` — no cause — and the
label→cause mapping was hard-coded in one Rust test function's `match shape`.

#590's stated audience *is* the clean-room implementer ("a peer or clean-room
client with an encoder bug"), so which rule a body violates is precisely the
thing a second implementation would most want machine-readable, and it had
nothing to agree with. #594 had set the opposite precedent one slice earlier.

### What landed

- **`expect_cause` on all 21 rows** — `"IndefiniteLength"` / `"NonShortestForm"`
  on the six that reach the §4.3 step-4 re-encode, `null` on the three
  `rule4_float` rows caught earlier by `reject_floats_and_tags`.
- **`Shape::expect_cause`** — declared as the SPECIFICATION, exactly like
  `expect_accept`, and asserted by the generator rather than recorded from it.
- **`cause_name`** — the fixture's spelling of a `NonCanonicalCause`, an
  **exhaustive** match, so a fifth variant fails to COMPILE rather than
  silently acquiring no spelling. That is the fail-closed property the
  `other => panic!` arm used to give the shape names, moved to where the
  compiler enforces it.
- **`assert_rejection_mechanism` reads the column**, not the label suffix. Both
  the replay AND the generator call it, so the two cannot drift onto two
  readings of one column.
- **`NonCanonicalItem(ValueError)`** in `conformance_lib/codec/scanner.py`,
  carrying the §6.2 rule number as `.rule`. Five raise sites converted; every
  message is byte-identical, because the number is now interpolated FROM the
  attribute.
- **Section MCC** (`sections/manifest_canonicality_cause.py`, 195 lines),
  registered in `registry.py`. REG reports **26 drivers / 26 registered**.

### The ruling put to the user before implementation

Two questions, options-plus-recommendation, both answered with the
recommendation:

1. **Scope: the issue as written**, not a corpus extension to all four cause
   variants. `ArraySortOrder` and `Unclassified` need bodies that are not
   `unknown`-subtree splices, so covering them changes the 7-shapes × 3-levels
   structure and its exact label-set assertion. Filed as **#613** rather than
   left unrecorded.
2. **Rule agreement with the asymmetry documented**, not "assert only that
   Python rejects". See §(2).

### Non-vacuity, by execution

Every mutation asserted `count(old) == 1` before patching and verified the
restore by **sha256** — `manifest_canonicality_cause.py` is untracked, so
`git checkout` on it is a silent no-op.

| # | Mutation | Result |
|---|---|---|
| P1 | `NonCanonicalItem.rule` always 2 | **MCC red** |
| P3 | `_CAUSE_TO_RULE[None]` 4 → 2 | **MCC red** (so the three null-cause rows really are checked, not skipped) |
| R2/P2 | one fixture row's cause `IndefiniteLength` → `NonShortestForm` | **Rust red** (the `SHAPES` cross-check) **and MCC red** (rule mismatch) — one mutation, two languages |
| R3 | `SHAPES` table cause drifts from the fixture | **Rust red** |
| R1''' | classifier's `ai==31` arm → `NonShortestForm` | **Rust red** — the corpus catches a real classifier regression |
| R1'' | `classify_non_canonical` always `Unclassified` | **Rust red** |
| R5 | wrong `SHAPES` cause, run the **generator** | **panics, fixture AND seeds left untouched** — no laundering |
| V1 | six `block__`/`trash__` rejecting bodies swapped for their `top__` twins | **Rust red** at the rebuild-and-compare, naming row, shape and level. Before the review round this was **green in both languages** — the corpus's "7 shapes x 3 levels" premise silently collapsed to one level |
| V2 | every label rewritten to the `top` level | **MCC red** twice — duplicate labels, and levels `['top']` != `['block','top','trash']` |
| V3 | `NonCanonicalItem(4, "CBOR tag")` → rule 2 | **Section CS red**. Before the review round this left the **entire suite at exit 0, all 26 sections green** — the rule number was prose in a label |
| V4 | `class NonCanonicalItem(Exception)` (drop the `ValueError` base) | **Section CS red** with a clean issue line. Before, this aborted the run at CS with a raw traceback and no `FAIL:`, skipping all 14 later sections including REG |
| V5 | one row's `manifest_body_hex` corrupted to non-hex | **MCK and MCC both red** naming it a FIXTURE defect. Before, a traceback out of `main()`; and had it reached MCC it would have read *"the reader rejected …"* — the vocabulary reserved for a real cross-language disagreement |
| V6 | `expect_cause` set to a JSON list | **MCC red** (`must be a string or null`). Before, `TypeError: unhashable type` out of `main()` |

**Two mutations came back green and neither was a finding.** Recording them
because telling the two apart is the whole skill:

- **R1** mutated the *assertion* (`assert_eq!(got, want)` → `assert_eq!(got,
  got)`) rather than the code under test. Tautological — it proves only that
  I deleted the check. Replaced by R1''/R1''', which mutate `classify.rs`.
- **R1'** mutated the classifier's `BREAK_CODE` arm, which the corpus never
  reaches: the rule-2 body is `BF 61 61 01 FF`, so the walk returns at the
  `ai==31` check three bytes earlier. Confirmed not a hole — the same
  mutation reds `cargo test --lib manifest::decode::classify`. Division of
  labour between the corpus and the unit tests, nothing to file.

### The measured result

- **`cargo test --release --workspace`: 99 binaries, 2084 passed, 0 failed, 21
  ignored.** Test **name set** measured against an `origin/main` baseline built
  in a throwaway detached worktree: **2030 names on the branch vs 2029 on
  `main` — exactly ONE added, none removed.** The slice as first written added
  no test functions; the #614 review round added `cause_names_are_distinct`
  (`cause_name` must be injective — the exhaustive `match` stops a variant
  having no fixture spelling, nothing stopped two variants sharing one).
  Every other change strengthens an existing assertion.
- **The previous baton's "2081" is stale for post-merge `main`** and cost ten
  minutes to chase. `main` enumerates **2104** entries (2083 passed + 21
  ignored) and this branch **2105**; 2081 was measured on the feature branch
  *before* #608's review round added tests. A count that moves when your diff
  adds no tests is worth the name-set diff every time — and this paragraph is
  its own example: it read "2029 both sides, 0 added" until the review round
  added one test and the figure had to be re-measured rather than re-asserted.
- `cargo fmt --all --check`, `cargo build --release --workspace` (run
  separately from the test run on purpose) and
  `cargo clippy --release --workspace --tests -- -D warnings` all clean.
- `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace` clean, forced
  non-cached with `touch core/src/lib.rs` first.
- **KNOWN FLAKE, unrelated to this slice: [#616](https://github.com/hherb/secretary/issues/616).**
  Every test in the tree that waits on a real `notify` watcher flakes under
  load — `cli/tests/notify_quirk.rs` (4 tests) and
  `cli/src/watcher/notify_driver.rs`'s
  `writing_a_file_surfaces_a_sync_candidate`. Observed from ONE commit: 4/4
  passing, 2/4 failing, 0/4 passing, and the driver unit test failing alone.
  They are wall-clock budgeted against the watcher (`WATCHER_SETTLE` 100 ms,
  `POLL_TIMEOUT` 2 s). **This branch touches zero files under `cli/`**, and the
  flake reproduces on the merge-base too — a one-shot branch-vs-base comparison
  pointed the wrong way (base green, branch red, same minute) purely because of
  when each ran, so alternate the two before concluding anything. For a clean
  signal: `cargo test --release --workspace -- --skip raw_notify` (99 binaries,
  2080 passed, 0 failed).
- **`conformance.py` exit 0**, 26 sections, REG `26 drivers discovered, 26
  registered`. `pyflakes` clean over entrypoint and package.
- **Both gates no CI job covers:** `--features differential-replay` clean (99
  binaries, 2085 passed, 0 failed) and `core/fuzz` checks under the pinned
  nightly. `manifest_body` still holds **27** seeds.
- **All six hygiene guards pass, each `--self-test` first.** No probe residue.
- **`spec_test_name_freshness.py` = 90, byte-identical to `origin/main`** —
  `diff`ed in full against a baseline worktree.
- **Three of the four format invariants empty** (`core/fuzz/seeds/`, UDL,
  normative `docs/`). `core/tests/data/` changed **by design**; the 21 bodies
  are byte-identical to `origin/main`'s, asserted row by row.

### README was deliberately not touched

Checked rather than assumed. `README.md:103`'s clean-room claim is general and
stays true; nothing in the file cites a section count, the canonicality corpus
or the cause vocabulary. `ROADMAP.md` and `CLAUDE.md` both changed.

---

## (2) What this slice does **not** claim

- **The two implementations agree on the RULE, not the MECHANISM**, and that is
  a real asymmetry rather than a wording nicety. Rust reaches rules 2 and 3
  through the re-encode plus #590's classifier; the byte-retaining Python
  reader reaches them directly in `_check_canonical_item`, never via the
  re-encode — **all nine rejecting rows, verified by execution before the
  section was written.** vault-format §4.2 *requires* that of a byte-retaining
  reader ("reproduces its input unconditionally … and it must therefore check
  crypto-design §6.2 rules 2, 3 and 4 itself").
- **Rule 4 is not asymmetric at all**, and an earlier draft of this design had
  it wrong. §4.2 makes the separate whole-body walk normative for **every**
  reader, so a `null` cause and "§6.2 rule 4" are one statement seen from two
  sides — not a Rust implementation quirk the Python side has to tolerate.
  Verified by reading `docs/vault-format.md` before the claim shipped.
- **Two of four cause variants are covered** (#613). `causes_seen` is a
  tripwire for a future widening, and it is **defence in depth**: unlike the
  three properties above it was NOT shown to fire by mutation, because every
  mutation constructible against today's corpus trips an earlier per-row
  assertion first. Both `CLAUDE.md` and `ROADMAP.md` say so in those words.
- **No spec change.** `docs/` normative diff is empty; this slice makes an
  existing normative asymmetry executable, it does not introduce one.
- **`manifest_canonicality_kat.rs` is now 788 lines** (was 652), past the
  500-line threshold — the same complaint #612 files against its sibling
  `manifest_uniqueness_kat.rs`. Not split here because it is not worth the
  churn in this slice, and that is the whole reason: the generator and the
  replay share `SHAPES`, `cause_name`, `Verdict` and `body_for`, but a
  shared `tests/<dir>/mod.rs` helper module would carry all four without a
  second test binary, and `core/tests/` already holds six such directories
  (`common/`, `fixtures/`, `conformance_kat_helpers/`, `sync_helpers/`,
  `sync_merge_proptest_helpers/`, `convergence_helpers/`). An
  earlier draft justified the decision with "an integration test cannot
  reach a `#[cfg(test)]` module", which is true and irrelevant — nothing
  here proposes putting them in one (#614 review). **#612 was widened
  to cover both files** by a comment on the issue rather than a second issue
  being filed — and that comment also corrects #612's own headline figure,
  which is stale: `manifest_uniqueness_kat.rs` is **848** lines today, not
  the 810 in the title. Both numbers here were measured at commit time; the
  first draft of this baton said 736 and 810, and both were wrong.
- **#602 / #603 / #587 / #589 / #596 stay open and untouched.**

---

## (3) What is next — with acceptance criteria

**(a) #589 — the 21 duplicate-key guards are hand-copied, not a type
invariant.** Promoted from (b). #600's `has_repeat` is the worked example one
directory over: one name, both directions, deleting it reds both.
**Acceptance:** expressed once; all 21 sites route through it; deleting the
single implementation reds more than one test.

**(b) #613 — `ArraySortOrder` and `Unclassified` have no cross-language pin.**
Filed by this slice, and the natural continuation of it. Note the shape change
the issue spells out: those rows are not `unknown`-subtree splices, so
"7 shapes × 3 levels" and the exact label-set assertion both have to move, and
`_CAUSE_TO_RULE` needs a third KIND of entry — those causes map to no §6.2
numbered rule at all. **Acceptance:** both variants carry corpus rows, both
languages replay them, and the `causes_seen` assertion in
`manifest_canonicality_kat_replays` is updated rather than deleted.

**(c) #602 — `identity::card` and `sync::state` are outside #586's choke
point**, including the hybrid-signed `ContactCard::signed_bytes`. No live
exposure (all three build keys from fixed literals) but that is a property of
today's call sites, not of the encoder. **Acceptance:** those paths reject a
duplicate key too, or `card.rs`'s deliberately-permissive `encode_map` is
documented as a reviewed exception with the hostile-peer fixtures that need it
named.

**(d) #596 — a `manifest_body` cargo-fuzz target, the natural eighth.** The
`--diff-replay` wiring exists and the seed corpus is 27 bodies.
**Acceptance:** `core/fuzz/fuzz_targets/manifest_body.rs` exists,
`cargo fuzz run manifest_body` starts from the committed seeds, and
`CLAUDE.md`'s "Seven targets" line becomes eight.

**(e) #609 — `save_block` does not check `trash`**, so re-saving a trashed
`block_uuid` puts it in both arrays and wedges `trash_block` permanently on
`EncodeDuplicateTrashUuid`. Pre-existing; #600 turned a bricked vault into a
clean refusal, leaving the root cause and a `CorruptVault` label on what is a
state bug.

**(f) #603 / #587 / #610 / #611 / #612 stay open and untouched.**

### Issues this slice closes — verify against the code, not this document

**#604.** Per this repo's `(#N)`-not-`Closes #N` convention it stays open until
a human closes it. Nothing here closes **#613, #589, #602, #596, #603, #587,
#609, #610, #611, #612**.

---

## (4) Open decisions and risks

### Three verification traps hit this session, all caught, all worth carrying

- **A `cd` at the head of a compound command silently relocated a
  measurement.** The `spec_test_name_freshness` baseline diff was written as
  `cd <repo> && (cd <baseline> && run) && (run)` — so the second run executed
  in the **main repo**, not the worktree, and "IDENTICAL" compared
  `origin/main` against itself. It looked completely ordinary. Redone with an
  explicit `cd` **inside each** subshell and a `pwd` echoed from each. This is
  the same class the previous baton recorded for a backgrounded command: not a
  bad push, a **plausible measurement of the wrong tree**.
- **A `| grep` pipeline reports GREP's exit code.** The first
  differential-replay run was `cargo test … | grep … | tail -6`; the harness
  reported "exit code 0", which was `tail`'s. Re-run with a redirect and an
  explicit `echo $?`. The baton has said this for several sessions; it is easy
  to violate while reaching for a compact summary.
- **A comment can go stale between writing it and finishing the code.** The
  Rust column read opened `// Hard-index, never .get()` and the code — changed
  afterwards, correctly, because `serde_json`'s `[]` cannot distinguish an
  absent key from `null` — used `.get()`. Found by re-reading the diff against
  the prose before committing. Same class as #608's two false claims, one
  scale smaller.

### A scope decision worth recording

**Rule 4's `null` was nearly documented as a Rust quirk.** The design as first
sketched read "`null` means *does not reach Rust's re-encode*, which is a
mechanism fact rather than a spec fact", and Section MCC's mapping of `None`→
rule 4 would have been justified as a corpus-local convenience. Reading
`docs/vault-format.md` before writing the docstring showed the opposite: §4.2
makes the separate whole-body walk normative for **every** reader. The mapping
is a spec statement, and the section says so with the quote. The habit that
caught it is the one #608's review named — grep for what the sentence claims,
in the file it names, before the sentence ships.

### Standing risks this slice does not remove

- **Five of the six PEP 723 deps remain unbounded** (`cryptography`, `pynacl`,
  `argon2-cffi`, `blake3`, `cbor2`), and `ed25519_verify` still has the "no
  exception means success" shape whose failure direction would be fail-**open**
  (#544 / #550).
- **`encode_manifest` validates no v1 sentinel** (#587).
- **`identity::card` and `sync::state` remain outside the duplicate-key choke
  point** (#602), including a hybrid-signed path.
- **`Unclassified` has no cross-language pin** (#613) — the arm #590's first
  implementation got wrong in the direction a peer could *choose*.

### Housekeeping

**Done, not pending.** `.worktrees/encoder-uniqueness` (merged as PR #608) was
removed and `feature/encoder-uniqueness` deleted; the throwaway detached
baseline worktree used for the name-set and freshness diffs was removed too.
`git worktree list` shows the repo, two `.claude/worktrees/` checkouts this
session did not create, and this slice's.

---

## (5) How to resume — the exact commands

```bash
# FIRST, before reading the baton — cost four consecutive sessions, cost zero
# this one because it was actually run:
git fetch origin && git log --oneline main..origin/main

cd /Users/hherb/src/secretary/.worktrees/canonicality-cause
pwd && git branch --show-current && git worktree list   # expect feature/canonicality-cause

# --- the gates this slice is actually about ---
cargo test --release -p secretary-core --test manifest_canonicality_kat
uv run core/tests/python/conformance.py          # 26 sections; MCC + REG 26/26

# --- the cross-language contract (no CI job covers this one) ---
cargo test --release --workspace --features differential-replay

# --- the rest of the gate set ---
cargo fmt --all --check
cargo build --release --workspace                # separate from the test run ON PURPOSE
# Redirect, then echo $? — a `| grep` pipeline reports GREP's exit code:
cargo test --release --workspace > /tmp/suite.txt 2>&1; echo "CARGO EXIT: $?"
grep -E "^test result" /tmp/suite.txt | \
  awk '{p+=$4; f+=$6; i+=$8} END {print NR, p, f, i}'   # expect 99 2084 0 21
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

# --- citation freshness: 90, and byte-identical to main. Note the explicit cd
#     INSIDE each subshell — a leading `cd` measured the wrong tree this session.
uv run core/tests/python/spec_test_name_freshness.py

# --- format / fixture invariants. THREE must be empty; core/tests/data/ is
#     EXPECTED to differ this slice, and the 21 bodies inside it must not.
git diff origin/main...HEAD --stat -- core/fuzz/seeds/
git diff origin/main...HEAD -- ffi/secretary-ffi-uniffi/src/secretary.udl
# NORMATIVE docs only. A git pathspec glob CROSSES `/`, so `docs/*.md` would
# also match docs/manual/**; exclude the two non-normative trees by name.
git diff origin/main...HEAD --stat -- docs/ ':!docs/handoffs/' ':!docs/manual/'
```

Regenerating the fixture, and the two things that must hold afterwards:

```bash
cargo test --release --workspace -- --ignored generate_manifest_canonicality_kat --nocapture
git diff --stat -- core/fuzz/seeds/          # MUST be empty: the bodies do not change
git diff -- core/tests/data/                 # MUST be empty on a no-op regeneration
```

---

## (6) Where this document lives

`NEXT_SESSION.md` at the repo root is a **symlink**, retargeted this session to
`docs/handoffs/2026-09-04-canonicality-cause-shipped.md`. This file is the
single authored baton — do not create a second copy at the root, and do not
sync it to `main` during a pause window (that produces an add/add conflict).
