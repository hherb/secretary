# NEXT_SESSION.md — which rule each decoder reports is now COMPARED (#634), and the last divergence is normative (#621)

Branch `feature/rule-token-agreement`, worktree `.worktrees/rule-token-agreement`,
base `a6db0e80` (`main`, immediately after PR #636 merged).

This slice is **(a) + (b)** from the previous baton's §(3) queue, taken together
because they are one thought: #621's spec ruling defines #634's tolerance.

**Six issues filed**, one commented. **Two user rulings taken**, one of which I
later had to reverse on measurement — see §(2).

---

## (0) The starting-state check did NOT fire, for the first time in three sessions

`git fetch origin && git log --oneline main..origin/main` returned empty; local
`main` was already at `a6db0e80`. Run it anyway — it costs one command and it
has fired twice running.

Housekeeping: `.worktrees/dupkey-precedence` removed and
`feature/dupkey-precedence` deleted (merged as PR #636; its two-dot diff against
`main` was **0 files**, so `-d` was safe rather than judged). Three older local
branches deliberately left alone, unchanged ruling.

---

## (1) What shipped

### Commits

| SHA | What |
|---|---|
| `27c50192` | design spec |
| `b7e4151e` | spec correction: trailing bytes coarsen (measured) |
| `bb8b9b6c` | spec correction: `manifest_file` dropped (measured) |
| `bf38752a` | implementation plan |
| `3eafc5b5` | **#621** — §4.2's unspecified sentence widened to the array SORT disciplines |
| `16456c51` | `RuleToken` + the shared vocabulary fixture |
| `adf13b01` | `ManifestError::rule_token()` — exhaustive over all 35 variants |
| `253828d8` | Python: typed exceptions carrying tokens (13 raise sites) |
| `d1621254` | Section **RTV**; REG 28 → 29 |
| `357993c7` | the diff-replay reject shape carries `rule`; protocol doc |
| `f138012e` | **#634** — the comparison itself, plus the helper split |
| `47b2242b` | #621's divergent body as the tolerance's corpus witness |
| `7c5e26b2` | drop the README that broke the corpus walker |
| `4b65f240` | restore its rationale one level up |
| `67fa49bf` | `cargo fmt` a file Task 3 committed unformatted |
| `15d9f572` | CLAUDE.md, ROADMAP, README |
| *(this)* | the baton — a commit cannot cite its own SHA |

### The defect

`differential_replay.rs` exists to prove the two decoders agree. Its
reject-vs-reject arm was the constant `true`, with a comment saying the
comparison could be tightened "when we standardize them". That is why #618's two
live divergences and #621's third survived it.

### What landed

- **`ManifestError::rule_token()`** (`core/src/vault/manifest/token.rs`) — an
  **exhaustive** match over all **35** variants onto a 17-token vocabulary, so a
  new variant cannot be added without classifying it. Proven by execution: an
  unclassified variant reds with `E0004`. It lives inside the crate because it
  must read `CanonicalError`'s variants to keep §6.2 rule 4 apart from rule 5,
  which an integration test cannot (#635).
- **Python**: a `token` class attribute on typed exceptions; **thirteen** bare
  `ValueError` raise sites converted, message-preserving (Sections MUQ and MSH
  match on message fragments).
- **`tokens_agree`** tolerates a mismatch iff either token is phase-dependent —
  DERIVED from §4.2's "deliberately unspecified" paragraphs and strictly
  BROADER than them (it is per-TOKEN, so it tolerates every pair its token
  appears in), still not a pair list, which would drift from §4.2 silently. The
  two families it tolerates that §4.2 does not free are written out in
  `is_phase_dependent`'s LIMITS block: trailing bytes beside any schema fault,
  and array-sort against rule 4. A **missing** token is a harness failure; an
  **unrecognised** one is an ordinary disagreement — both red the test, but the
  mechanisms differ, and four documents said otherwise until the final review.
- **Section RTV**, registered. REG **28 → 29**.
- **0 tests removed, 13 added** (10 lib + 3 feature-gated), diffed against a name
  set measured from `main`.

### The measured gate set

Everything below was run by the controller, foreground, exit codes captured.

| Gate | Result |
|---|---|
| `cargo fmt --all --check` | 0 |
| `cargo build --release --workspace` | 0 |
| `cargo clippy --release --workspace --tests -- -D warnings` | 0 |
| same **with** `--features differential-replay` | 0 |
| `cargo test --release --workspace` | 0 — 100 binaries, 2155 passed, 0 failed, 22 ignored |
| `RUSTDOCFLAGS="-D warnings" cargo doc` (after `touch`) | 0 |
| `--features differential-replay` | 0 — 2159 passed, 0 failed |
| `conformance.py` | 0 — 0 FAIL, REG 29/29 |
| six hygiene guards, `--self-test` first | all 0 |
| `core/fuzz` under the pinned nightly | 0 |

**Which half of this slice CI actually enforces.** The 10 lib tests are covered
by `cargo test --release --workspace`, and Section RTV by the blocking
`clean-room conformance` job. `differential_replay.rs` runs in **no** workflow —
it is `#![cfg(feature = "differential-replay")]`, the feature is off by default,
and `test.yml` says so twice in its own comments. So the token COMPARISON, the
tolerance predicate as exercised over real bytes, and the committed witness are
gated by local runs only. Nothing in this repo claims otherwise; it is recorded
here because a reader weighing "is this pinned?" deserves the split rather than
having to derive it from a Cargo feature flag.

`spec_test_name_freshness.py` exits **1**. The count is **90 on `main`, 93 at
this branch's pre-review HEAD, 97 after the final review's doc fixes** — all
three measured, by unpacking each tree with `git archive` and running the script
in it. Every added citation is the SAME false-positive class as the 90
(**#642**): a backtick-quoted differential-replay TARGET name in prose — the
replay-only one and the fuzz-only one — which the script reads as a test-name
citation and cannot resolve under `core/`. The three new at HEAD come from this
slice's own prose, and the four added on top come from the review's correction
to the protocol doc's target-set paragraph. No workflow runs the script. Do not
read any of it as a regression, and do not quote 90 as the branch figure.

**Format invariants**: `core/fuzz/seeds/` EMPTY, UDL EMPTY, `core/tests/data/` is
**three ADDED files and zero modified** (checked with `--name-status`), normative
`docs/` is `vault-format.md` only.

### Non-vacuity, by mutation — every one liveness-proven

| # | Mutation | Result |
|---|---|---|
| M2 | `tokens_agree` returns `true` | RED — `tolerance_admits_only_phase_dependent_pairs` |
| M3 | `TOKEN_COMPARED_TARGETS = &[]` | RED — `every_target_is_classified` |
| M4 | `manifest_file` in BOTH lists | RED — `every_target_is_classified` |
| M5 | `as_str` returns another token's string | RED — 2 tests |
| M6 | `is_phase_dependent` true for rule 4 | RED — 3 tests |
| M7 | `ArraySortOrder` → `Rule2IndefiniteLength` | RED — 2 tests |
| M8 | phase-dependent → **another** phase-dependent | **GREEN, by design** |
| M9 | ordered → different ordered | RED — 4 differential disagreements |
| M10 | remove a firing class's token | RED — 4 harness failures |
| M11 | `diff_replay` omits `rule` | RED — 25 harness failures |
| M12a/b | drop / flip a vocabulary row | RED — Section RTV |

**M8's green is a real property, not a gap.** §4.2 declares that order free, so
nothing catches it and nothing should. **M1** (strict tolerance) is *attributed*,
not re-run: two independent agents ran it during the witness task and its review,
each with sha256-verified restores, both seeing exactly one disagreement.

**Caveat on M5/M6/M7**: measured with `--lib manifest::token`, which reports
`605 filtered out`. The claim is only *which token tests* red, and the filter
covers exactly those — but that is the same filtered-target trap #587 recorded.

---

## (2) What this slice does **not** claim

- **`manifest_file` is NOT token-compared, and I reversed my own recommendation
  to get there.** I told the user it was "nearly free" because it shares the Rust
  error enum. Measurement falsified that: one file with `format_version = 0x0099`
  gives Rust `UnsupportedFormatVersion` and Python `ParseError`. No mapping
  reconciles it — `header.rs` and the body sentinel check raise the **same
  variant**, and `ParseError` is one class shared by every target's wire decoder.
  **Sharing an error enum is not sharing a granularity.** #640.
- **Six of seven targets are uncompared** (#640, #641), recorded in a table that
  must partition `TARGETS`, not left to inference.
- **A token may only draw a distinction BOTH implementations can make.** Hence no
  `trailing_bytes` token: `ciborium` performs no EOF check, so Rust's parse
  discards them before the §4.3 comparison and it can only say `Unclassified`.
- **The repeated-array-value rules stay ordered.** §4.2's widened sentence covers
  the five array **sort** disciplines only, because both designs check repeats
  during interpretation.
- **#635 is untouched** — the crate-internal mapping works *around* `pub(crate)`.

---

## (3) What is next — with acceptance criteria

**(a) #644 — mutation testing has no verification step.** *Filed by this slice and
the most valuable thing in it.* Several load-bearing CLAUDE.md claims rest on
mutation results that nothing verified actually ran. **Acceptance:** a shared
harness in `scripts/` that (1) proves the mutation is live in a fresh interpreter
before running anything, (2) builds in the `__pycache__`/`PYTHONDONTWRITEBYTECODE`
discipline, (3) sha256-verifies every restore, (4) restores under `trap`/`atexit`
— a `finally` is skipped by a kill, which this session demonstrated — and (5)
distinguishes "did not red" from "did not run". A working prototype exists in this
session's scratchpad; it is not committed.

**(b) #612 — `manifest_uniqueness_kat.rs` (848 lines).** Reopened once already, so
it will be lost again if not taken soon. `80c3c488` is the worked example.
**Acceptance:** under 500, sharing `Case`/`Verdict`/surgery helpers through a
`_helpers/`, committed as a behaviour-preserving move with the name set diffed.

**(c) #641 — widen the token comparison to the five ordinary targets.** The
machinery now exists; each target needs its own exhaustive `rule_token()` and
typed Python exceptions. **Acceptance** is written out per-target in the issue.
`record` and `block_file` first — they carry decrypted user content.

**(d) #633 — writer-side encode refusals reach users as "try again".**
Unchanged from the last baton; the cheap half is one bridge test plus a comment.

**(e) #642 — the freshness script.** Cheap, and it currently makes a documented
command un-runnable to a clean exit.

**(f) #625 / #596 / #623 / #628 / #626 / #603 / #630 / #619 / #620 / #643 / #635
stay open and untouched.**

### Issues this slice closes — verify against the code, not this document

**#634 and #621.** Per the `(#N)`-not-`Closes #N` convention they stay open until
a human closes them. Checkable in four commands:

```bash
# 1. The comparison is live and its unit tests pass.
cargo test --release -p secretary-core --features differential-replay --test differential_replay  # 4 passed
# 2. The witness is replayed (39, not 38).
cargo test --release -p secretary-core --features differential-replay --test differential_replay -- --nocapture | grep manifest_body
# 3. Section RTV is registered.
uv run core/tests/python/conformance.py | grep "section registry"   # 29/29
# 4. The spec says it.
grep -c "five array sort disciplines" docs/vault-format.md          # >= 1
```

---

## (4) Open decisions and risks

### The finding that generalises furthest: sharing an enum is not sharing a granularity

`manifest_file` was scoped in on my recommendation, on the argument that it shares
`ManifestError` so the mapping is written once. That is true and irrelevant. What
matters is whether the two implementations can draw the **same distinctions** —
and Python collapses every envelope fault into one `ParseError` while Rust names
eight. **Generalise it:** before reusing a mapping across two consumers, check
that both can observe the distinctions it draws, not that both can name the type.

### Four plan defects, every one producing a green that proved nothing

Written down because the ratio is the point: **four of nine plan steps were
wrong**, and each would have reported success.

1. A mutation spliced `token = ''` after a class header, where the real
   assignment **after the docstring** silently overrode it. Hit **four** times
   before the harness started asserting the observed value.
2. A step asserted a directory that did not exist, where `corpus_dirs` skips a
   missing directory **silently** — the witness would never have been replayed.
3. A step wrote documentation **inside** a corpus directory, where every file is
   fed to both decoders as input bytes.
4. A step planned to rebuild `main` in a temp dir for a baseline that was already
   capturable from the branch while it was docs-only.

### Two mutations were live simultaneously, and it corrupted the measurements

A stalled worker left `M7` applied to `token.rs` while the controller's harness
had `M8` applied to `manifest_decode.py`. Any result in that window was
meaningless, and it also explains a >600s timeout: every `cargo test` was
rebuilding `secretary-core`. Both restored, sha256-verified. **Check
`git status` between tasks; a stall does not clean up after itself.**

### The subagent that could not finish

The final task was dispatched four times, burned **368k tokens**, and produced
**no durable output** — each attempt backgrounded a build and stopped waiting for
a notification that never came. The controller took the work over directly. The
mutation work produces **no diff to review** (the restore leaves the tree
byte-identical), so the usual objection to controller-side work did not apply.
**If a worker stalls twice the same way, change the shape of the work, not the
prompt.**

### Standing risks this slice does not remove

- **`cargo fmt --all --check` was failing on this branch** until `67fa49bf`, and
  the task review that should have caught it did not re-run fmt. Surfaced only
  because a post-mutation `git diff` showed rustfmt reflowing rather than a
  mutation.
- **The machine is heavily contended** — other projects' cargo builds were
  running throughout, competing for CPU and cargo's package-cache lock. A
  blocked run sits at 0% CPU and looks wedged.
- **Five of the six PEP 723 deps remain unbounded**, and `ed25519_verify` still
  has the "no exception means success" shape whose failure direction is
  fail-**open** (#544 / #550).
- **The `unknown`-subtree residual is untouched.**
- **`card.rs` (1264), `manifest_uniqueness_kat.rs` (848), `canonical/value.rs`
  (1082)** are all past the 500-line guideline — #625 / #612 / #603.

---

## (5) How to resume — the exact commands

```bash
# FIRST, before reading this file — it has fired twice in three sessions:
git fetch origin && git log --oneline main..origin/main

cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
pwd && git branch --show-current && git worktree list

# --- the gates this slice is about ---
cargo test --release -p secretary-core --features differential-replay --test differential_replay
uv run core/tests/python/conformance.py            # 29 sections; REG 29/29

# --- the rest of the gate set ---
cargo fmt --all --check
cargo build --release --workspace                  # separate from the test run ON PURPOSE
cargo test --release --workspace > /tmp/suite.txt 2>&1; echo "CARGO EXIT: $?"
grep -E "^test result" /tmp/suite.txt | awk '{p+=$4; f+=$6; i+=$8} END {print NR, p, f, i}'
cargo clippy --release --workspace --tests -- -D warnings
# NOT redundant — this is the one that lints differential_replay.rs at all:
cargo clippy --release --workspace --tests --features differential-replay -- -D warnings
touch core/src/lib.rs                              # rustdoc caches; a ~5s run did nothing
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace

# SLOW, and it holds cargo's package-cache lock — run BEFORE the fuzz check.
cargo test --release --workspace --features differential-replay
cd core/fuzz && PATH="$HOME/.rustup/toolchains/nightly-2026-04-29-aarch64-apple-darwin/bin:$PATH" cargo check
cd -

# --- six hygiene guards, --self-test FIRST every time, as literal commands ---
# (zsh does not word-split an unquoted variable, so a `for g in "bash x.sh"` loop FAILs all of them)
bash ffi/scripts/check-lean-binding.sh --self-test         && bash ffi/scripts/check-lean-binding.sh
bash ios/scripts/check-public-log-hygiene.sh --self-test   && bash ios/scripts/check-public-log-hygiene.sh
bash android/scripts/check-log-hygiene.sh --self-test      && bash android/scripts/check-log-hygiene.sh
bash scripts/check-secret-slot-hygiene.sh --self-test      && bash scripts/check-secret-slot-hygiene.sh
uv run scripts/check-error-payload-hygiene.py --self-test  && uv run scripts/check-error-payload-hygiene.py
uv run scripts/check-test-support-placement.py --self-test && uv run scripts/check-test-support-placement.py

# --- EXPECTED to exit 1: 90 pre-existing false positives, byte-identical to main (#642) ---
uv run core/tests/python/spec_test_name_freshness.py

# --- format invariants: seeds + UDL EMPTY; data/ is three ADDED and zero modified ---
git diff origin/main...HEAD --stat -- core/fuzz/seeds/
git diff origin/main...HEAD -- ffi/secretary-ffi-uniffi/src/secretary.udl
git diff origin/main...HEAD --name-status -- core/tests/data/
git diff origin/main...HEAD --stat -- docs/ ':!docs/handoffs/' ':!docs/manual/' ':!docs/superpowers/'
```

Re-proving the divergence this slice made visible — the fastest way to see what
#634 was. Make the tolerance strict and watch the one committed witness red:

```bash
# In core/tests/differential_replay.rs, change tokens_agree's last line to `r == p`.
cargo test --release -p secretary-core --features differential-replay --test differential_replay
# -> arraysort_plus_indefinite.bin: rust=array_sort_order python=rule2_indefinite_length
# RESTORE IT AFTERWARDS AND VERIFY WITH shasum -a 256.
```

---

## (6) Where this document lives

`NEXT_SESSION.md` at the repo root is a **symlink**, retargeted this session to
`docs/handoffs/2026-09-10-rule-token-agreement-shipped.md`. This file is the
single authored baton — do not create a second copy at the root, and do not sync
it to `main` during a pause window (that produces an add/add conflict).
