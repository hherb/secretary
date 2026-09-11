# NEXT_SESSION.md — mutation results are now CHECKED, not assumed (#644)

Branch `feature/mutation-harness`, worktree `.worktrees/mutation-harness`,
base `27b7b0ca` (`main`, immediately after PR #645 merged).

This slice is **(a)** from the previous baton's §(3) queue, chosen by the user
options-plus-recommendation. It builds the harness #644 asked for.

**Four issues filed:** [#649](https://github.com/hherb/secretary/issues/649),
[#651](https://github.com/hherb/secretary/issues/651), and from the PR #652
review's fix wave [#653](https://github.com/hherb/secretary/issues/653),
[#654](https://github.com/hherb/secretary/issues/654). The slice closes **#644**.

**The headline: on its first real spec the harness contradicted a shipped
handoff, and the handoff was wrong.** That is §(1)'s last subsection, and it is
the only evidence that matters for whether this thing works.

---

## (0) The starting-state check FIRED — third session in four

`git fetch origin && git log --oneline main..origin/main` returned `27b7b0ca`.
`main` had moved, so `NEXT_SESSION.md` resolved to the 2026-09-09 baton — the
slice *before* the current one — and read as a completely coherent, current
document. I had read all of it before the fetch landed. **Run the fetch first.**

Housekeeping: `.worktrees/rule-token-agreement` removed and
`feature/rule-token-agreement` deleted (merged as PR #645; two-dot diff against
`main` EMPTY, so `-D` was safe rather than judged). Three older local branches
deliberately left alone, unchanged ruling.

---

## (1) What shipped

23 commits before the PR #652 review, plus the fix wave in §(1b).
`docs/superpowers/specs/2026-09-11-mutation-harness-design.md` is
the binding spec; `docs/superpowers/plans/2026-09-11-mutation-harness.md` is
the plan.

| SHA | What |
|---|---|
| `17d27526` | design spec |
| `e4c06ff4` | implementation plan |
| `19bbeb9e` | **five pre-flight plan defects**, found before Task 1 dispatched |
| `99c7d944` `91339112` `9e48b11e` | Task 1 — types + fail-closed TOML parsing |
| `fa16a89b` `d4c0d137` | Task 2 — the durable journal |
| `b1808116` `2a6aa631` | Task 3 — the two liveness proofs |
| `a789a721` `0ff12a6e` `98615cdd` | Task 4 — gate + classification |
| `9123c26d` `2eafc261` | Task 5 — runner state machine + report |
| `d34deea0` `178a2fbd` `30c9bbae` | Task 6 — control table, `--self-test`, entrypoint |
| `602dff30` `3fe6a93d` | Task 7 — prove in practice + CLAUDE.md/ROADMAP |
| `67f2fdba` | **final-review fix wave** — 8 findings, 2 blocking |
| `237b8a24` | the last three Minors |
| *(this)* | the baton — a commit cannot cite its own SHA |

### The defect

This repo cites mutation results as load-bearing evidence in `CLAUDE.md` and in
every handoff. **Nothing checked that the mutation took effect.** Three
mechanisms had each produced a GREEN that proved nothing: stale `.pyc` bytecode
on a size-preserving edit; a `token = ''` splice after a `class X:` header
silently overridden by the real assignment below the docstring; and a mutation
left applied by a stalled worker. All three were caught only because a human
found a result *surprising* — which stops working the moment a mutation is
expected to be green **by design**, where a false green and a true green are
indistinguishable by inspection.

### What landed

`scripts/mutate.py` over `scripts/mutation_harness/`, matching the existing
`check-error-payload-hygiene.py` / `payload_guard/` shape. A slice declares
mutations as declarative TOML in its scratchpad; the harness owns all control
flow and emits the markdown result table the handoff pastes.

- **Ten outcomes, not a boolean.** `NOT_LIVE` and `UNEXPECTED_GREEN` can never
  render as the same row. That distinction is the whole of #644.
- **Two liveness proofs, both before/after.** Python probes the value a fresh
  interpreter BINDS, before and after, requiring it to change AND to land on
  the declared value. Rust compares the CONTENT hash of the artifacts cargo's
  JSON names. Never a source hash, never an mtime.
- **A durable journal, not a `finally`.** A `finally` is skipped by a kill.
  Original bytes and their sha256 are fsynced before the first byte changes,
  the index is written with `os.replace` + directory fsync, and an undrained
  journal **blocks the next invocation** rather than waiting to be noticed.
- **`--self-test`, 20 checks** (RE-MEASURE), reproducing false greens 1 and 2
  as `Control` rows and false green 3 as the standalone check C3, with every
  one of the ten outcomes covered.
- **238 unit tests** (RE-MEASURE).

### The result that matters: it contradicted a shipped handoff on first use

Task 7 ran the harness against mutation **M8** from the 2026-09-10 slice, which
that baton recorded as **"GREEN, by design … nothing catches it and nothing
should."**

```
| # | Mutation | Live | Outcome | Reds |
|---|---|---|---|---|
| M8-verify | handoff 2026-09-10 recorded this as GREEN by design | yes (interpreter) | UNEXPECTED_RED | — |
```

Section RTV's check 4 asserts strict set equality over the tokens the corpus
produces; flipping `ArraySortOrderViolation.token` removes `array_sort_order`
from that set. The handoff's claim is **true of the gate it was measured
against** (`differential_replay`'s per-token `tokens_agree` tolerance) and was
generalised to "nothing". **Controller-verified independently** by re-running
the spec: same `UNEXPECTED_RED`, tree clean, restore sha256-verified. Filed as
**#651**. Neither implementation is wrong; only the documentation
over-generalises.

### Every task had a real defect found by review — that ratio IS the finding

Seven tasks, seven rounds of findings, plus five in the plan before Task 1 ran.
The four worth carrying:

- **A control for one of the three founding false greens was ITSELF a false
  green.** C3 exercised the `Journal` API, not the entrypoint's refusal —
  deleting the refusal block entirely left C3 PASSING and 62/62 green. Caught
  only by mutation-testing the control.
- **A gate TIMEOUT was credited as a catch.** `exit_code=124` satisfies
  `is_red`, so for an `expect="red"` row with no named tests a timeout
  classified `RED_AS_EXPECTED`. Closed by a tenth outcome keyed on a flag, never
  on the exit code.
- **A test asserted nothing** because the outcome name `NOT_LIVE` lowercases to
  contain the substring `"no"` it checked for.
- **The Python liveness proof checked a POST-CONDITION, not a CHANGE** — found
  by the final whole-branch review. A no-op mutation with `equals` copied from
  the `old` side reported `GREEN_AS_EXPECTED, live=True`. A false green of
  #644's own class, emitted by the harness. Now a before/after comparison.

### The measured gate set

| Gate | Result |
|---|---|
| `uv run scripts/mutate.py --self-test` | 0 — **20/20** |
| `uv run --with pytest python3 -m pytest scripts/mutation_harness -q` | 0 — **238 passed** |
| `uv run core/tests/python/conformance.py` | 0 — 0 FAIL, REG **29/29** |
| six hygiene guards, `--self-test` first | all 0 |

**Branch scope, verified:** `CLAUDE.md`, `ROADMAP.md`, the `NEXT_SESSION.md`
symlink, this handoff, two `docs/superpowers/` files, and `scripts/`. **No Rust, no FFI, no `core/`, no crypto, no on-disk
format.** `scripts/` is not a workspace member, so `check-secret-slot-hygiene.sh`'s
manifest census is untouched. README checked and deliberately NOT edited — none
of the six hygiene guards is named there either, so the split is established
rather than inferred. Every file under 500 lines (largest 486, `controls.py`;
RE-MEASURE).

---

## (1b) The PR #652 review fix wave

Five review agents (code, tests, silent failures, types, comments) over the
branch above, every finding verified by execution before it was acted on. One
Critical and seventeen Importants; all closed in code except the four
type-shape suggestions now in #654 and the `rglob` limit in #653.

**The Critical was a false green inside the harness.** `compare_rust_artifacts`
recognised the `BUILD_TIMED_OUT` sentinel and not `BUILD_FAILED`, so a baseline
build that FAILED fell through to the set comparison and two differently-
failing builds scored `live=True` — while `liveness.py`'s own comment said
both sentinels were recognised. The reading is now a typed `RustObservation`
whose `kind` the comparison must dispatch on before it can reach a hash, and
the language asymmetry is pinned in both directions (a build the mutation
broke is live; a module it made unimportable is `NOT_LIVE`).

**The rest, by mechanism:**

- The value types refuse every self-contradictory row (`MutationResult`),
  `expect` is an `Expect` enum (a typo'd `"Red"` used to classify a live green
  as `GREEN_AS_EXPECTED`, exit 0), `GateResult.is_red` raises on a timed-out
  result, and `--json` carries `timed_out` beside `exit_code`.
- `expect_red` counts a name only on a line carrying `FAIL` (libtest names
  passing tests too); control **C14** pins it — self-test is now 20 checks.
- `Journal.restore` verifies the blob BEFORE overwriting the target, converts a
  target write/re-read `OSError` to `RestoreFailed`, and removes entries by
  identity rather than by blob name; `drain()` attempts every entry; an index
  without an `entries` key is corrupt, not clean; signal dispositions are
  handed back after every run and the handler is re-entrancy-guarded.
- Every abort carries its partial table as a typed `RunAborted`: exit 3 (a
  restore could not be trusted, tree may be dirty) is kept apart from exit 4
  (harness error, tree restored, traceback on stderr) — a typo'd `path` used to
  be a bare traceback with exit 1 and no table. `parse_spec` now also rejects a
  non-existent `path`, a non-existent `probe.syspath`, and a stray
  document-level key.
- One `subproc.run_bounded` for the gate and both probes: the whole process
  group is killed on timeout, output is decoded with `errors="replace"`, the
  gate runs under `bash -o pipefail`, and the probe interpreter is
  `sys.executable`. A cargo-named artifact that cannot be read is
  `ARTIFACT_MISSING`, a changed artifact SET is not a measurement, and the
  package-id match is exact in both cargo spellings.
- Non-success rows print a diagnostic block to stderr; the substitution works
  on bytes (CRLF and non-UTF-8 files survive); the baseline cache is keyed on
  `(gate, timeout)`; `PYTHONPYCACHEPREFIX` is stripped from every subprocess.
- Tests: the target's BYTES are asserted after every control and unit run
  (moving `journal.record` after the substitution used to leave both layers
  green with the file mutated); the 20 labels are pinned by name; `run_self_test`
  itself has pytests (exit code, a raising check, the census call); cargo's
  JSON parsing, `BUILD_FAILED` on both sides, the kill window between blob and
  index, and `_validate_timeout` all have tests for the first time.
- Docs: ROADMAP's "18/18" and "63 tests", CLAUDE.md's "108 tests", the design
  spec's two-value exit contract, its `C7` row, its C1 mechanism and its
  `GREEN_AS_EXPECTED` M8 example — all corrected against measurement.

**Verified by the harness itself before being believed** — three rows, each
undoing one fix, gate = the unit suite:

```
| # | Mutation | Live | Outcome | Reds |
|---|---|---|---|---|
| FW1 | undo the Critical: a BUILD_FAILED baseline compared as a measurement | yes (interpreter) | RED_AS_EXPECTED | test_a_failed_baseline_build_is_an_absent_baseline_whatever_the_mutated_build_does |
| FW2 | undo the expect_red fix: any line names a red | yes (interpreter) | RED_AS_EXPECTED | test_a_claimed_test_that_passes_while_another_fails_is_wrong_tests_red |
| FW3 | undo MutationResult's shape check: every contradictory row constructs | yes (interpreter) | RED_AS_EXPECTED | test_a_self_contradictory_row_is_unrepresentable |
```

Exit 0, tree clean afterwards, restores sha256-verified.

**A second review round over the fix wave itself found three more Importants
and eight suggestions, all closed with tests** — the ratio this document
records for every task held for the fix wave too:

- `subproc.run_bounded` had dropped `subprocess.run`'s kill-on-ANY-exception,
  so the `SystemExit` the journal's signal handler raises on Ctrl-C left the
  gate running against a tree the handler was restoring underneath it — the
  hazard the module's own docstring claimed to close, reintroduced on the
  signal path. Now `with Popen(...)` plus `except BaseException: killpg`;
  `test_subproc.py` interrupts a real gate with an alarm and asserts the
  grandchild is dead.
- `names_a_red` had scoped the MARKER to a line but left the NAME a substring,
  so `…_names_that_key_at_the_top_level` failing credited a claim on
  `…_names_that_key`. The name is now a whole token (not adjacent to an
  identifier character, dot, slash or hyphen; `mod::name` and `name[case]`
  still accepted). The `cargo test -q` limit — no per-test lines, so a
  genuine catch reports `WRONG_TESTS_RED` — is documented as fail-closed.
- The `RESTORE_FAILED` row had REPLACED the aborting row's own measurement,
  contradicting `RunAborted`'s docstring; the measured row is now kept ahead
  of it (`test_a_restore_failure_keeps_the_rows_own_measurement`).
- Smaller: control gates run under `sys.executable` like the probes;
  `RustObservation` is hashable; the "no baseline" message no longer blames
  the baseline for an empty post-mutation reading; `package_id_names` strips
  a git query string and percent-decodes; the census failure is reported
  beside the count rather than folded into a numerator that could go
  negative; the signal handler's `SIG_IGN` now survives the unwind through
  `run_mutations`'s `finally`; the post-`record` abort path has a test; three
  stale comments corrected.

---

## (2) What this slice does **not** claim

- **It does not run in CI.** No workflow invokes it; it is a per-slice
  investigative tool enforced by review. `CLAUDE.md` now says so plainly.
- **The two liveness proofs are not of equal strength**, and the report names
  which was used. Python observes an interpreter binding change; Rust observes
  that the compiler emitted different bytes.
- **No same-file textual edit to a file the crate compiles can EVER be
  `NOT_LIVE`.** Measured twice: `rustc` embeds a whole-file content checksum in
  `.rmeta`, so artifact bytes are a content function of the source. This is a
  real limit of the Rust proof and lives in `liveness.py`'s module doc. It was
  the plan's one DECLARED uncertainty and it resolved by falsifying the plan —
  the C10 fixture was changed to mutate a file the build graph never reads,
  **not** weakened to fit.
- ~~**`execution_census` has a terminal turtle**~~ — closed in the fix wave: a
  pytest substitutes a recording census and asserts `run_self_test` calls it.
- ~~**A dropped registry entry signals via a MOVING COUNT, not a red**~~ — closed
  in the fix wave: the 20 labels are pinned by name. (The rendering this bullet
  quoted, "18/19", was never reachable — a dropped row shrinks the denominator
  too, so it printed "18/18", exit 0; the review measured it.)
- **It does not make a mutation SET complete.** Choosing which mutations to run
  is still a design act; the harness makes each row's result trustworthy.

---

## (3) What is next — with acceptance criteria

**(a) #651 — the M8 documentation error this slice found.** Cheapest real item
and fully diagnosed. **Acceptance:** correct the M8 row and its paragraph in
`docs/handoffs/2026-09-10-rule-token-agreement-shipped.md` to name the gate the
result was measured against and record that Section RTV reds the same mutation;
sweep `CLAUDE.md` for the same unscoped claim. Consider requiring a mutation row
to NAME ITS GATE — a mutation result without its gate is under-specified
whenever more than one gate exists, which is now normal here.

**(b) #612 — `manifest_uniqueness_kat.rs` (measured 848 lines).** Reopened once
already. `80c3c488` is the worked example. **Acceptance:** under 500, sharing
`Case`/`Verdict`/surgery helpers through a `_helpers/`, committed as a
behaviour-preserving move with the test name set diffed against a MEASURED
baseline.

**(c) #649 — `differential_replay.rs` (measured 541 lines), filed this slice.**
Its `_helpers/` already exists, so the destination is not in question. Split
along the seams #641 and #646 will each edit, so those two do not collide in one
file.

**(d) #641 — widen the token comparison to `record` and `block_file`**, the two
targets carrying decrypted user content. Larger; scope it to those two.

**(e) #633, #642** unchanged from the last baton.

**(f) #623 / #624 / #625 / #626 / #628 / #629 / #630 / #635 / #640 / #643 /
#646 / #647 / #648 stay open and untouched.**

### Issues this slice closes — verify against the code, not this document

**#644.** Per the `(#N)`-not-`Closes #N` convention it stays open until a human
closes it. Checkable in four commands:

```bash
uv run scripts/mutate.py --self-test                                   # 20/20, exit 0
uv run --with pytest python3 -m pytest scripts/mutation_harness -q     # 238 passed
grep -c "execution_census" scripts/mutation_harness/selftest.py        # >= 1
grep -c "did NOT change" scripts/mutation_harness/liveness.py          # >= 1
grep -c "is_measurement" scripts/mutation_harness/liveness.py          # >= 1 (the Critical's fix)
```

---

## (4) Open decisions and risks

### The finding that generalises furthest: a denominator is not a census

The final review found `--self-test`'s accounting fail-open — deleting a check
INVOCATION printed "18/18 checks passed" with 17 run. I prescribed deriving the
total from a registry. **The implementer measured that this was only half the
fix**: with the total so derived, deleting the whole invocation LOOP still
printed "19/19 passed", exit 0, having run 14.

**A denominator read off a DECLARATION says nothing about what RAN.** Closed by
`execution_census`, which compares executed labels against declared ones in both
directions. Generalise it: whenever you fix a count, ask whether the new count
is derived from what happened or from what was supposed to happen.

### The trap this session hit that is already in memory

Running the six hygiene guards through a zsh `for g in "bash x.sh"; do $g; done`
loop reported **FAIL on all four bash guards**. zsh does not word-split an
unquoted variable. The previous baton warns about this in its own §(5). Run each
as a literal command. It cost one cycle and a moment of genuine alarm.

### The process rule this session added

**Do not dispatch a MUTATING re-review while the implementer is still live on
the same worktree.** During Task 3 the re-reviewer's mutate/restore cycle raced
the implementer's own verification of the same file. Neither lost data, because
BOTH sha256-verified their restores — an accidental end-to-end demonstration of
the discipline this harness exists to enforce — but the race was the
controller's error. From Task 4 on, reviews that modify files waited for the
implementer's final return, and every later proof ran on a COPY outside the repo.

### `uv run --with pytest pytest` intermittently HANGS on this machine

Two agents and the controller each hit it at 0% CPU; one isolated it to the
freshly-generated `<tmp-venv>/bin/pytest` console-script wrapper uv rebuilds per
invocation, reproduced on a trivial unrelated file and with `--offline`. The
controller saw the bare form succeed earlier in the same session, so it is
intermittent rather than broken — which is worse, because it fails as a HANG.
**`uv run --with pytest python3 -m pytest` is now canonical** and is what
`CLAUDE.md` documents.

### Standing risks this slice does not remove

- **The baton was resolved from a stale checkout for the third time in four
  sessions.** Nothing structural has changed; the symlink gives no signal.
- **The harness is not in CI**, so nothing stops a future slice hand-rolling one
  again. Adoption is a plan-authoring convention enforced by review.
- **Five of the six PEP 723 deps remain unbounded**, and `ed25519_verify` still
  has the "no exception means success" shape whose failure direction is
  fail-**open** (#544 / #550).
- **The `unknown`-subtree residual is untouched.**
- **`card.rs` (1264), `manifest_uniqueness_kat.rs` (848), `canonical/value.rs`
  (1082), `manifest/encode/tests.rs` (620), `sync/state.rs` (570),
  `differential_replay.rs` (541)** are all past the 500-line guideline —
  #625 / #612 / #603 / #630 / #626 / #649.

---

## (5) How to resume — the exact commands

```bash
# FIRST, and BEFORE reading this file — it has now fired three times in four sessions:
git fetch origin && git log --oneline main..origin/main

cd /Users/hherb/src/secretary/.worktrees/mutation-harness
pwd && git branch --show-current && git worktree list

# --- the gates this slice is about ---
uv run scripts/mutate.py --self-test                                 # 20/20, exit 0
uv run --with pytest python3 -m pytest scripts/mutation_harness -q   # 238 passed

# NOTE the module form. `uv run --with pytest pytest` intermittently HANGS here.

# --- prove the harness against a real mutation, end to end ---
SCRATCH=$(mktemp -d)
cat > "$SCRATCH/m8.toml" <<'EOF'
[[mutation]]
id = "M8-verify"
lang = "python"
path = "core/tests/python/conformance_lib/codec/manifest_decode.py"
old = 'token = "array_sort_order"'
new = 'token = "rule2_indefinite_length"'
gate = "uv run core/tests/python/conformance.py"
expect = "green"
note = "handoff 2026-09-10 recorded this as GREEN by design"
probe = { module = "conformance_lib.codec.manifest_decode", expr = "ArraySortOrderViolation.token", equals = "rule2_indefinite_length", syspath = "core/tests/python" }
EOF
uv run scripts/mutate.py "$SCRATCH/m8.toml"   # UNEXPECTED_RED, exit 1 — that is #651
git status --short                             # MUST be empty; the restore is sha256-verified

# --- the rest of the gate set ---
uv run core/tests/python/conformance.py        # 29/29, 0 FAIL

# --- six hygiene guards, --self-test FIRST, as LITERAL commands ---
# (zsh does not word-split an unquoted variable; a `for g in "bash x.sh"` loop
#  reports FAIL on all four bash guards. This bit me again this session.)
bash ffi/scripts/check-lean-binding.sh --self-test         && bash ffi/scripts/check-lean-binding.sh
bash ios/scripts/check-public-log-hygiene.sh --self-test   && bash ios/scripts/check-public-log-hygiene.sh
bash android/scripts/check-log-hygiene.sh --self-test      && bash android/scripts/check-log-hygiene.sh
bash scripts/check-secret-slot-hygiene.sh --self-test      && bash scripts/check-secret-slot-hygiene.sh
uv run scripts/check-error-payload-hygiene.py --self-test  && uv run scripts/check-error-payload-hygiene.py
uv run scripts/check-test-support-placement.py --self-test && uv run scripts/check-test-support-placement.py

# --- branch scope: scripts/ + docs ONLY, no Rust, no FFI, no core/ ---
git diff origin/main...HEAD --name-only | grep -E "^(core|ffi|desktop|ios|android|cli|browser)/" || echo "clean"
```

Re-proving the headline fix — that a no-op mutation is now caught:

```bash
uv run --no-project python3 -c "
import sys; sys.path.insert(0, 'scripts')
from mutation_harness.liveness import compare_python_probe, PythonObservation
from mutation_harness.types import PythonProbe
ok = lambda v: PythonObservation(ok=True, value=repr(v), error='')
p = PythonProbe(module='m', expr='TOKEN', equals='real', syspath='.')
print(compare_python_probe(p, ok('real'), ok('real')).detail)
"
# -> the bound value did NOT change ... so this mutation measured nothing

# And the PR #652 Critical — a failed BASELINE build is an absent baseline:
uv run --no-project python3 -c "
import sys; sys.path.insert(0, 'scripts')
from mutation_harness.liveness import compare_rust_artifacts
from mutation_harness.types import RustObservation, RustReadingKind
failed = lambda d: RustObservation(RustReadingKind.BUILD_FAILED, detail=d)
print(compare_rust_artifacts(failed('exit 101, stderr a'), failed('exit 101, stderr b')).live)
"
# -> False  (it printed True before the fix)
```

---

## (6) Where this document lives

`NEXT_SESSION.md` at the repo root is a **symlink**, retargeted this session to
`docs/handoffs/2026-09-11-mutation-harness-shipped.md`. This file is the single
authored baton — do not create a second copy at the root, and do not sync it to
`main` during a pause window (that produces an add/add conflict).
