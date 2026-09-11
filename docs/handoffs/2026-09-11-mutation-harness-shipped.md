# NEXT_SESSION.md — mutation results are now CHECKED, not assumed (#644)

Branch `feature/mutation-harness`, worktree `.worktrees/mutation-harness`,
base `27b7b0ca` (`main`, immediately after PR #645 merged).

This slice is **(a)** from the previous baton's §(3) queue, chosen by the user
options-plus-recommendation. It builds the harness #644 asked for.

**Two issues filed:** [#649](https://github.com/hherb/secretary/issues/649),
[#651](https://github.com/hherb/secretary/issues/651). The slice closes **#644**.

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

22 commits. `docs/superpowers/specs/2026-09-11-mutation-harness-design.md` is
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
- **`--self-test`, 19 checks**, reproducing all three founding false greens as
  controls, with every one of the ten outcomes covered.
- **110 unit tests.**

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
| `uv run scripts/mutate.py --self-test` | 0 — **19/19** |
| `uv run --with pytest python3 -m pytest scripts/mutation_harness -q` | 0 — **110 passed** |
| `uv run core/tests/python/conformance.py` | 0 — 0 FAIL, REG **29/29** |
| six hygiene guards, `--self-test` first | all 0 |

**Branch scope, verified:** `CLAUDE.md`, `ROADMAP.md`, two `docs/superpowers/`
files, and `scripts/`. **No Rust, no FFI, no `core/`, no crypto, no on-disk
format.** `scripts/` is not a workspace member, so `check-secret-slot-hygiene.sh`'s
manifest census is untouched. README checked and deliberately NOT edited — none
of the six hygiene guards is named there either, so the split is established
rather than inferred. Every file under 500 lines (largest 438).

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
- **`execution_census` has a terminal turtle**: nothing inside `run_self_test`
  verifies it calls the census. Disclosed in its docstring and in `CLAUDE.md`.
- **A dropped registry entry signals via a MOVING COUNT, not a red** — exit 0,
  "18/19". A reader who does not know the expected number gets nothing.
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
uv run scripts/mutate.py --self-test                                   # 19/19, exit 0
uv run --with pytest python3 -m pytest scripts/mutation_harness -q     # 110 passed
grep -c "execution_census" scripts/mutation_harness/selftest.py        # >= 1
grep -c "did NOT change" scripts/mutation_harness/liveness.py          # >= 1
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
uv run scripts/mutate.py --self-test                                 # 19/19, exit 0
uv run --with pytest python3 -m pytest scripts/mutation_harness -q   # 110 passed

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
```

---

## (6) Where this document lives

`NEXT_SESSION.md` at the repo root is a **symlink**, retargeted this session to
`docs/handoffs/2026-09-11-mutation-harness-shipped.md`. This file is the single
authored baton — do not create a second copy at the root, and do not sync it to
`main` during a pause window (that produces an add/add conflict).
