# NEXT_SESSION.md — the decoder-agreement gate now runs in CI (#647), and a mutation row names its gate (#651)

Branch `feature/diff-replay-ci`, worktree `.worktrees/diff-replay-ci`,
base `53fd6635` (`main`, immediately after PR #652 merged).

This slice is **(a)** from the previous baton's §(3) queue, taken together with
**#647** by the user options-plus-recommendation, on the reasoning that widening
a gate matters less than making it run at all.

**One issue filed:** [#655](https://github.com/hherb/secretary/issues/655).
The slice closes **#647** and **#651**.

**The headline: the gate that exists to prove the two decoders agree was the
one gate nothing ran — for three slices, while four documents cited its
results.** That is §(1a).

---

## (0) The starting-state check did NOT fire — first time in four sessions

`git fetch origin && git log --oneline main..origin/main` returned empty;
`main` was already `53fd6635`. **Run it anyway.** It fired in three of the
previous four sessions, and the symlink gives no signal when it is stale.

Housekeeping: `.worktrees/mutation-harness` removed and
`feature/mutation-harness` deleted (merged as PR #652; two-dot diff against
`main` EMPTY, so `-D` was measured rather than judged — note `git branch -d`
warns "not yet merged to HEAD" after a squash-merge, which is expected and is
not the check). Three older local branches deliberately left alone, unchanged
ruling.

---

## (1) What shipped

Five commits, the last two being the baton and its own corrections.

| SHA | What |
|---|---|
| `22b84a75` | #651 — every mutation row names its gate |
| `512ea18c` | #647 — the replay runs in CI |
| `6e0b9872` | #651 — four documents corrected |
| `e4526cb7` | the baton, and one figure reconciled across four documents |
| *(this)* | the baton's own corrections — a commit cannot cite its own SHA |

### (1a) #647 — the defect

`core/tests/differential_replay.rs` is `#![cfg(feature =
"differential-replay")]` and no workflow enabled the feature, so the file was
not merely unrun: it was **not compiled**. The corpus comparison, #634's
rule-token tolerance, that tolerance's negative control and its committed
witness were all local-only, while `CLAUDE.md`, `ROADMAP.md` and two handoffs
cited results from them.

`test.yml`'s `rust-test` job now runs it as a Linux-only step:

```
cargo test --release --locked -p secretary-core \
  --features differential-replay --test differential_replay
```

A **step, not a job**, for three measured reasons: `cargo test
(ubuntu-latest)` is already one of `main`'s 24 required contexts, so the gate
binds on day one with no ruleset edit; that job already installs `uv` and
caches the cargo build, both of which the replay needs; and a separate job's
`rust-cache` entry would pay a cold dependency build for a test measured at 15-24 s.
Linux-only mirrors `clean-room conformance` — the decoders are
platform-independent and the macOS leg would pay a cold `pqcrypto` wheel build
for no new signal. `-p secretary-core` rather than `--workspace` because the
feature gates exactly one test file and no `src/` code.

**Negative-controlled, because a gate that runs and catches nothing is #546
restated.** Re-pointing one ORDERED token, a pair §4.2 grants no licence:

| # | Mutation | Live | Outcome | Reds |
|---|---|---|---|---|
| CI647 | Rust names `missing_field` where Python names `repeated_array_value` | yes (artifact) | RED_AS_EXPECTED | `differential_replay_full_corpus` |

### (1b) The measurement that shaped the design, and a live trap

The replay feeds `core/fuzz/corpus/<target>/` **as well as** the committed
seeds, and that directory is gitignored runtime fuzz output that grows without
bound.

| Case | Inputs | Result |
|---|---|---|
| CI shape (no runtime corpus) | 50 | 4 passed, **15-24 s** (two runs) |
| One `conformance.py --diff-replay`, warm | 1 | **0.16 s** |
| This machine, corpus present | **74,924** | killed at 10 min; ~3.3 h implied |

So the `--workspace` command `CLAUDE.md` documented is unusable on any checkout
that has fuzzed, and **it presents as a hang** — `cargo test` prints nothing but
"has been running for over 60 seconds". Documented in the Commands block and
filed as **#655**. A fresh `git worktree` has no `corpus/`, which is why this
branch's worktree reproduced the CI shape for free.

### (1c) #651 — a mutation result is a property of ONE gate

The 2026-09-10 handoff recorded M8 as **"GREEN, by design … nothing catches it
and nothing should"**. The first half is right; the second generalised one
gate's answer to every gate. Re-measured here with the harness rather than
trusted — `UNEXPECTED_RED`, exit 1, twice.

**Name the CHECK, because the obvious guess is wrong.** Section RTV's **check
1 does not fire**: it iterates `_TOKENED_CLASSES`, the seven
`ManifestRejection` subclasses, and `ArraySortOrderViolation` is a plain
`ValueError` subclass that is not among them. The sole catch is **check 4**,
the corpus-token SET EQUALITY, reported on the `PASS 3` line. Neither
implementation is wrong: §4.2 frees the ORDER two readers may report rules in
and says nothing about a raise site changing WHICH rule it names.

**Four carriers, found by sweep rather than by the one the issue named** —
`CLAUDE.md`, `ROADMAP.md`, the 2026-09-10 handoff, and that slice's design
spec. ROADMAP **contradicted itself two bullets apart**: its #634 entry made
the unscoped claim while its #644 entry directly below recorded the gate
mismatch correctly.

The structural half: `render_markdown` gains a per-row **Gate** column and
`render_json` a `gate` key, so the generalisation cannot be written from a
pasted table again. Per row, not a caption — a spec may mix gates, and those
are exactly the specs where the ambiguity bites. Mutation-proven with the
harness itself, gate = the unit suite:

| # | Mutation | Live | Outcome |
|---|---|---|---|
| GC1 | header loses the Gate column | yes (interpreter) | RED_AS_EXPECTED |
| GC2 | gate cell rendered as a CONSTANT, not from the row | yes (interpreter) | RED_AS_EXPECTED |
| GC3 | gate not routed through `_cell`, so a shell pipe adds a column | yes (interpreter) | RED_AS_EXPECTED |
| GC4 | `--json` drops the gate key | yes (interpreter) | RED_AS_EXPECTED |

A side finding worth carrying: the report tests indexed cells **positionally**
(`cells[3]` for Live). A column INSERTION silently repoints such an assertion
onto whatever lands at that index — this very change would have moved two of
them with no failure. They read by header NAME now.

### (1d) Two CLAUDE.md claims this branch itself falsified

Not stale by age — falsified by the code in this branch, which is the harder
case to notice:

- "Almost none of this runs in CI … not even COMPILED in CI" is rewritten to
  what #647 leaves true, with the residual as a scope rather than a caveat.
- The #546 paragraph's "never enabled in `test.yml`" now reads as the history
  it is. **Verified before writing** that the #647 step would not have caught
  the `pqcrypto` break either: `--diff-replay` never verifies a signature,
  `ml_dsa_65_verify` being reachable only from `sections/`.

### The measured gate set

| Gate | Result |
|---|---|
| `cargo test --release --locked --workspace` | 0 — **2157 passed, 0 failed** over 91 test binaries plus 9 doc-test suites |
| the new differential-replay step | 0 — **4 passed**, 15-24 s |
| `cargo clippy --release --workspace --tests -- -D warnings` | 0 |
| `cargo fmt --all --check` | 0 |
| `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace` | 0 |
| `uv run scripts/mutate.py --self-test` | 0 — **20/20** |
| `uv run --with pytest python3 -m pytest scripts/mutation_harness -q` | 0 — **242 passed** (was 238) |
| `uv run core/tests/python/conformance.py` | 0 — 0 FAIL, REG **29/29** |
| six hygiene guards, `--self-test` first, 12 invocations | all 0 |
| `actionlint .github/workflows/test.yml` | 0, **and the parsed step names read back** |

**Branch scope, verified:** `.github/workflows/test.yml`, `CLAUDE.md`,
`ROADMAP.md`, two `docs/` files, and two files under
`scripts/mutation_harness/`. **No Rust, no FFI, no `core/`, no crypto, no
on-disk format** — `git diff origin/main...HEAD --name-only | grep -E
"^(core|ffi|desktop|ios|android|cli|browser)/"` is empty. README checked and
deliberately NOT edited: it documents specs and protocols and names no CI job
at all, so the split is established rather than inferred.

---

## (2) What this slice does **not** claim

- **CI replays the COMMITTED corpus, not the fuzz corpus.** 50 inputs:
  `core/fuzz/seeds/` plus `core/tests/data/diff_regressions/`.
  `core/fuzz/corpus/` is gitignored, so agreement on fuzz-DISCOVERED inputs is
  still proven only by whoever runs the fuzzer. Do not read "the differential
  replay is in CI" as "the fuzz corpus is differentially replayed in CI".
- **Only `manifest_body` is token-compared.** The five ordinary targets are
  #641 and `manifest_file` is blocked by #640. #647 changes where the existing
  comparison RUNS, not what it covers.
- **The tolerance is unchanged and still broader than §4.2 licenses** — 58 of
  136 unequal pairs, four groups with no licence, tracked by #646.
- ~~**The first CI run is the only real timing measurement.**~~ It has now run:
  **36 s** on `ubuntu-latest` (`00:41:18Z` → `00:41:54Z`, step `success`),
  against 15-24 s warm locally. The difference is the cold `uv` PEP 723
  environment, and it is far below the ~2 min `clean-room conformance` observes
  for the same build, because `--diff-replay` imports lazily and touches no
  Argon2id.
- **`MIN_CORPUS_INPUTS` keeps a shrunken corpus failing rather than passing
  vacuously**, but nothing pins that the CI step itself stays wired — deleting
  the workflow step is invisible to every gate in the tree.

---

## (3) What is next — with acceptance criteria

**(a) #649 — `differential_replay.rs` (measured 541 lines).** Its `_helpers/`
already exists, so the destination is not in question, and it is now worth more
than before: the file is on a blocking CI path. **Acceptance:** under 500,
split along the seams #641 and #646 will each edit so those two do not collide
in one file, committed as a behaviour-preserving move with the test name set
diffed against a MEASURED baseline.

**(b) #641 — widen the token comparison to `record` and `block_file`**, the two
targets carrying decrypted user content. Higher value now that the comparison
runs in CI. Each needs its own Rust taxonomy and typed Python exceptions;
scope it to those two and keep `TOKEN_COMPARED_TARGETS` partitioning `TARGETS`.

**(c) #612 — `manifest_uniqueness_kat.rs` (measured 848 lines).** Reopened
once already. `80c3c488` is the worked example. **Acceptance:** under 500,
sharing `Case`/`Verdict`/surgery helpers through a `_helpers/`.

**(d) #655 — the fuzz-corpus replay trap, filed this slice.** The documented
local command is unusable on a fuzzed checkout and fails as a hang.
**Acceptance:** either a bound on how many runtime-corpus inputs replay, or an
opt-out, or progress output — any of the three turns a three-hour silent hang
into something a developer can act on. Decide deliberately; sampling a corpus
weakens a decoder-agreement check and that tradeoff belongs in the issue.

**(e) #646** — narrowing the tolerance needs §4.2 to settle two of the four
groups first, so it is a spec slice as much as a code one.

**(f) #633, #642** unchanged from the last baton.

**(g) #623 / #624 / #625 / #626 / #628 / #629 / #630 / #635 / #640 / #643 /
#648 / #653 / #654 stay open and untouched.**

### Issues this slice closes — verify against the code, not this document

**#647** and **#651.** Per the `(#N)`-not-`Closes #N` convention they stay open
until a human closes them. Checkable in five commands:

```bash
grep -c "differential-replay" .github/workflows/test.yml          # >= 1 (the step)
grep -c "Gate" scripts/mutation_harness/report.py                 # >= 1 (the column)
grep -c '"gate": r.spec.gate' scripts/mutation_harness/report.py  # 1
grep -c "nothing catches it and nothing should" CLAUDE.md         # 0
grep -c "nothing catches it and nothing should" ROADMAP.md        # 0
```

---

## (4) Open decisions and risks

### The finding that generalises furthest: a result is a property of its instrument

#651 is not a documentation slip. The measurement was correct, the write-up
dropped the one fact that scoped it, and **no reader of the evidence could tell**
— the pasted table named no gate. Generalise it: when recording a measurement,
ask what varies between runs that the record does not carry. Here it was the
gate; the same question applied to a filtered `cargo test` gave #587's
`--lib`/`--test` trap, and applied to a denominator gave #644's census.

### The residual this slice deliberately leaves open

**Nothing pins that the CI step stays wired.** Deleting those five lines from
`test.yml` reds no test, no guard, and no self-test — the same shape as a
dropped registry entry before #644's `execution_census`, one layer up in the
build. No issue filed, because the honest fix is a workflow-parsing guard and
that is a slice, not a footnote. Weigh it when the next CI gap appears.

### A measurement trap this session hit

`uv run scripts/mutate.py spec.toml | tail -40` reported `EXIT=0` while the
harness exited **1** — `$?` after a pipe is `tail`'s status. That is already in
memory for `cargo test | grep` and it is the same trap. Capture to a file and
read `$?` from the unpiped command.

### Standing risks this slice does not remove

- **The harness is still not in CI**, so nothing stops a future slice
  hand-rolling one. Adoption is a convention enforced by review.
- **Five of the six PEP 723 deps remain unbounded**, and `ed25519_verify` still
  has the "no exception means success" shape whose failure direction is
  fail-**open** (#544 / #550). #647 does not help: `--diff-replay` verifies no
  signature.
- **The `unknown`-subtree residual is untouched.**
- **`card.rs` (1264), `manifest_uniqueness_kat.rs` (848), `canonical/value.rs`
  (1082), `manifest/encode/tests.rs` (620), `sync/state.rs` (570),
  `differential_replay.rs` (541)** are all past the 500-line guideline —
  #625 / #612 / #603 / #630 / #626 / #649.

---

## (5) How to resume — the exact commands

```bash
# FIRST, and BEFORE reading this file — it fired in three of the four sessions
# before this one:
git fetch origin && git log --oneline main..origin/main

cd /Users/hherb/src/secretary/.worktrees/diff-replay-ci
pwd && git branch --show-current && git worktree list

# --- the gate this slice added, i.e. the exact CI step ---
cargo test --release --locked -p secretary-core \
  --features differential-replay --test differential_replay   # 4 passed, 15-24s

# DO NOT run the `--workspace --features differential-replay` form on a
# checkout that has fuzzed: it also replays core/fuzz/corpus/ (74,924 files
# here), takes hours, and presents as a HANG. That is #655. A fresh
# `git worktree` has no corpus/ and reproduces the CI shape for free.

# --- prove the CI gate is not vacuous, end to end ---
SCRATCH=$(mktemp -d)
cat > "$SCRATCH/ci647.toml" <<'EOF'
[[mutation]]
id = "CI647"
lang = "rust"
path = "core/src/vault/manifest/token.rs"
old = '| ManifestError::DuplicateTrashUuid => RuleToken::RepeatedArrayValue,'
new = '| ManifestError::DuplicateTrashUuid => RuleToken::MissingField,'
gate = "cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay"
expect = "red"
expect_red = ["differential_replay_full_corpus"]
note = "Rust names missing_field where Python names repeated_array_value"
probe = { package = "secretary-core" }
EOF
uv run scripts/mutate.py "$SCRATCH/ci647.toml"   # RED_AS_EXPECTED, exit 0
git status --short                                # MUST be empty

# NOTE: read the exit code from the UNPIPED command. `... | tail -40` then
# `echo $?` reports tail's status, which cost a cycle this session.

# --- re-measure #651 rather than trusting this document ---
cat > "$SCRATCH/m8.toml" <<'EOF'
[[mutation]]
id = "M8-recheck"
lang = "python"
path = "core/tests/python/conformance_lib/codec/manifest_decode.py"
old = 'token = "array_sort_order"'
new = 'token = "rule2_indefinite_length"'
gate = "uv run core/tests/python/conformance.py"
expect = "green"
note = "handoff 2026-09-10 M8: recorded as GREEN by design"
probe = { module = "conformance_lib.codec.manifest_decode", expr = "ArraySortOrderViolation.token", equals = "rule2_indefinite_length", syspath = "core/tests/python" }
EOF
uv run scripts/mutate.py "$SCRATCH/m8.toml"   # UNEXPECTED_RED, exit 1 — Section RTV check 4

# --- the rest of the gate set ---
cargo test --release --locked --workspace
cargo clippy --release --locked --workspace --tests -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
uv run scripts/mutate.py --self-test                                 # 20/20
uv run --with pytest python3 -m pytest scripts/mutation_harness -q   # 242 passed
uv run core/tests/python/conformance.py                              # 29/29, 0 FAIL
actionlint .github/workflows/test.yml

# NOTE the pytest module form. `uv run --with pytest pytest` intermittently
# HANGS on this machine.

# --- six hygiene guards, --self-test FIRST, as LITERAL commands ---
# (zsh does not word-split an unquoted variable; a `for g in "bash x.sh"` loop
#  reports FAIL on all four bash guards.)
bash ffi/scripts/check-lean-binding.sh --self-test         && bash ffi/scripts/check-lean-binding.sh
bash ios/scripts/check-public-log-hygiene.sh --self-test   && bash ios/scripts/check-public-log-hygiene.sh
bash android/scripts/check-log-hygiene.sh --self-test      && bash android/scripts/check-log-hygiene.sh
bash scripts/check-secret-slot-hygiene.sh --self-test      && bash scripts/check-secret-slot-hygiene.sh
uv run scripts/check-error-payload-hygiene.py --self-test  && uv run scripts/check-error-payload-hygiene.py
uv run scripts/check-test-support-placement.py --self-test && uv run scripts/check-test-support-placement.py

# --- branch scope: workflow + scripts + docs ONLY ---
git diff origin/main...HEAD --name-only | grep -E "^(core|ffi|desktop|ios|android|cli|browser)/" || echo "clean"
```

---

## (6) Where this document lives

`NEXT_SESSION.md` at the repo root is a **symlink**, retargeted this session to
`docs/handoffs/2026-09-12-differential-replay-ci-shipped.md`. This file is the
single authored baton — do not create a second copy at the root, and do not
sync it to `main` during a pause window (that produces an add/add conflict).
