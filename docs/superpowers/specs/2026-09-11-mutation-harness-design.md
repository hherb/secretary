# Design: a verified mutation harness (#644)

**Date:** 2026-09-11
**Issue:** [#644](https://github.com/hherb/secretary/issues/644)
**Status:** approved for implementation

---

## 1. The problem, stated exactly

This repo leans on mutation testing to prove a test is non-vacuous. `CLAUDE.md`
carries measured mutation results as load-bearing claims, and several handoffs
record a mutation as the evidence for a slice's central argument.

**Every one of those results rests on an assumption nothing checks: that the
mutation actually took effect.** The workflow is apply, run, believe.

Three distinct mechanisms have now produced a GREEN that proved nothing:

1. **Stale bytecode.** CPython invalidates a `.pyc` on `(source_mtime, size)`
   with the mtime stored in whole **seconds**. A size-preserving Python mutation
   applied and reverted inside one second is served from cache and never runs.
   Documented in the 2026-09-09 handoff, then hit again during #634 — which is
   the point: a documented trap is not a mechanism.
2. **A later assignment overriding an earlier splice.** A probe inserting
   `token = ''` immediately after a `class X:` header is silently overridden by
   the class's real `token = "..."` assignment further down, after the docstring.
   The file changed, the interpreter loaded it, the attribute did not move.
   Diagnosed only because a human found the green surprising.
3. **A mutation left applied.** A worker stalled with a mutation still in a
   tracked file. Not a false green in itself, but the same root cause — nothing
   confirms the tree's mutation state — and it would have shipped as a landmine.

### Why "be careful" is not the fix

All three were caught by someone noticing a result was *surprising*. That works
only while the expected outcome is a red. When a mutation is expected to be
**green by design** — #634's M8, where a phase-dependent token swapped for
another phase-dependent one is tolerated deliberately — a false green and a true
green are indistinguishable by inspection. A false green in that position
silently converts "this test is non-vacuous" into an unfounded claim.

### The second-order problem: transcription

Every mutation table in every handoff so far was **hand-transcribed from
terminal scrollback**. That is an unverified step sitting between the
measurement and the published claim, and it is invisible to review because the
scrollback is gone by the time anyone reads the table.

---

## 2. Scope

**In scope.** A harness in `scripts/`, invoked per slice against a declarative
spec, covering both Python and Rust mutations, that makes the mutation's effect
*checked* rather than assumed and emits its own result table.

**Out of scope, deliberately.**

- **CI integration.** No workflow runs this. Mutation runs are slow (a Rust
  mutation costs a rebuild) and are a per-slice investigative act, not a gate.
- **Committed per-slice specs re-run as a regression suite.** That is
  mutation-testing-as-CI: every refactor invalidates historical `old` text, and
  the accumulated set costs a rebuild per row. A larger project than #644 asks
  for. The spec format is designed so this remains a pure addition later.
- **Computed or conditional mutations.** The spec is data. Control flow lives in
  the harness, because control flow in the caller is exactly how "did not run"
  and "did not red" came to be rendered identically in the ad-hoc harnesses.
- **Mutating anything outside the repo**, and writing probe files into the source
  tree. Probes and specs live in the session scratchpad (#516: probe residue in a
  live tree races parallel sessions and hides itself from `git status`).

---

## 3. Placement and shape

Following the established in-tree pattern — a thin entrypoint over a package,
with a mandatory two-sided `--self-test` that runs before any real work:

```
scripts/mutate.py                 entrypoint; argument parsing, exit codes
scripts/mutation_harness/
    __init__.py
    types.py       Outcome, MutationSpec, MutationResult, GateResult
    spec.py        tomllib parse + validation (fail-closed on unknown keys)
    journal.py     crash-safe original-bytes journal; apply / restore / drain
    liveness.py    the two liveness proofs, per language
    gate.py        run a gate command; classify red/green; match expected tests
    report.py      the markdown result table
    selftest.py    the controls
```

Python, run via `uv run` (never `pip`). `tomllib` for the spec, with precedent
in `scripts/check-test-support-placement.py`. Every file well under 500 lines.

---

## 4. The spec format

One TOML block per mutation, written by the slice to its scratchpad:

```toml
[[mutation]]
id     = "M8"
lang   = "python"                  # "python" | "rust"
path   = "core/tests/python/conformance_lib/codec/manifest_rules.py"
old    = 'token = "array_sort_order"'
new    = 'token = "rule2_indefinite_length"'
gate   = "uv run core/tests/python/conformance.py"
expect = "green"                   # "red" | "green"
note   = "§4.2 frees this order; a by-design green"

probe  = { module  = "conformance_lib.codec.manifest_rules",
           expr    = "ArraySortOrderViolation.token",
           equals  = "rule2_indefinite_length",
           syspath = "core/tests/python" }
```

```toml
[[mutation]]
id     = "R1"
lang   = "rust"
path   = "core/src/vault/manifest/decode/slot.rs"
old    = "set(field, index, take_u64(v, KEY)?)"
new    = "set_eager(field, index, take_u64(v, KEY)?)"
gate   = "cargo test --release -p secretary-core --lib"
expect = "red"
expect_red = ["a_duplicate_key_outranks_a_malformed_second_copy"]

probe  = { package = "secretary-core" }
```

### Rules the parser enforces, fail-closed

- `old` must occur **exactly once** in `path`. Zero occurrences and two or more
  are both errors. There is no first-wins guess — an ambiguous mutation is
  precisely the shape that produced false-green mechanism 2.
- Unknown top-level or `probe` keys are an **error**, not ignored. A typo'd key
  that silently degrades a check is the failure mode `ControlExpectation`
  already records for the payload guard.
- `expect_red` is optional but, when present, holds strings that MUST each
  appear in the gate's combined stdout+stderr **when the gate is red**. Matching
  is a plain substring test, uniform across languages, because the two gate
  families report differently: `cargo test` prints failing test names, while
  `conformance.py` prints one `FAIL: <reason>` line per failed section. A
  substring is the only predicate that spans both without the spec having to
  declare which parser to use. Without `expect_red` a mutation passes on
  "something red", which is not the claim a mutation table makes.
- `path` must resolve inside the repository root after `realpath`.

---

## 5. The five properties and their mechanisms

### 5.1 Prove the mutation is live before running anything

The two languages get **different mechanisms of different strength**, and the
harness reports which one it used rather than implying they are equivalent.

**Python — strong.** Spawn a fresh interpreter, put `probe.syspath` on
`sys.path`, import `probe.module`, evaluate `probe.expr`, and require it to
equal `probe.equals`. This observes the value **the interpreter sees**, not the
bytes in the file, which is exactly what mechanism 2 defeated. A fresh process
is mandatory: a hash salt and a module cache cannot be varied from inside a
running interpreter.

**Rust — weaker, and named as such.** `cargo build --message-format=json` emits
a `compiler-artifact` message naming the exact `filenames` produced for the
package. The harness hashes those files' **contents** before and after the
mutation and requires the hash to change.

Verified during design: for `-p secretary-core` the message names
`libsecretary_core.rlib` at a stable path, so the artifact set needs no globbing
against the 13,000 files in `target/release/deps/`.

Never a source hash and never an mtime — both are what the issue rules out, and
mtime is the mechanism behind false green 1.

### 5.2 Bytecode discipline, built in rather than per-caller

The harness clears `__pycache__` under the mutated file's tree and exports
`PYTHONDONTWRITEBYTECODE=1` for every Python step — the probe, the gate, and the
post-restore confirmation. It is applied uniformly and is not a per-mutation
judgement call, because the mutation whose green must not be believed is
precisely the size-preserving one nobody flags as risky.

### 5.3 Restore verified by hash

The pre-mutation sha256 is recorded before the first byte changes. After
restore, the file is re-hashed and must match. A mismatch **aborts the entire
run** rather than continuing into a poisoned next mutation. This is the one part
of the ad-hoc harnesses that never failed; it is kept unchanged.

### 5.4 Guaranteed restore on abnormal exit

A `finally` is skipped by a kill, which is why this is a **journal** rather than
a cleanup block.

Before any file is modified, the harness writes a journal to the scratchpad
recording, per file: the absolute path, the original bytes, and their sha256.
Restoration is then driven from durable state rather than from live process
state:

- Normal exit, `atexit`, and SIGINT/SIGTERM handlers all drain the journal.
- A SIGKILL leaves the journal on disk with entries unrestored.
- **The next invocation refuses to run** while an undrained journal exists,
  naming each dirty file and offering `--drain` to restore them.

That last clause is the structural fix for mechanism 3: a mutation left applied
can no longer be discovered by a routine `git status` happening to be run — the
harness itself will not proceed.

### 5.5 Distinguish "did not red" from "did not run"

The outcome is a ten-member enum, not a boolean. These are opposite
conclusions and the current workflow renders them identically.

| Outcome | Meaning |
|---|---|
| `RED_AS_EXPECTED` | Declared `red`; gate failed; every `expect_red` name present |
| `GREEN_AS_EXPECTED` | Declared `green`; gate passed; mutation proven live |
| `UNEXPECTED_GREEN` | Mutation proven live, gate passed anyway — **a finding** |
| `UNEXPECTED_RED` | Declared `green`, gate failed |
| `WRONG_TESTS_RED` | Gate failed, but an `expect_red` name did not appear |
| `NOT_APPLIED` | `old` absent, or matched more than once |
| `NOT_LIVE` | Applied, but the probe did not observe it — **proves nothing** |
| `BASELINE_DIRTY` | The gate already failed on the clean tree |
| `RESTORE_FAILED` | Post-restore sha256 mismatch; run aborted |
| `GATE_TIMEOUT` | The gate did not finish; nothing was measured. |

`NOT_LIVE` and `UNEXPECTED_GREEN` are the pair that matters, and they can never
render as the same row. `GATE_TIMEOUT` is the same shape one step later: a
timed-out gate's exit code (124) satisfies the same "the gate failed" test a
genuine catch does, so it must be distinguished from `RED_AS_EXPECTED` by an
explicit flag on the result, never inferred from the exit code alone — a real
gate command is free to exit 124 on its own.

### 5.6 The per-mutation state machine

1. **Baseline.** Run the gate on the clean tree; require green. Otherwise
   `BASELINE_DIRTY` and abort — a red baseline makes every subsequent row
   meaningless. Cached across mutations sharing a gate command.
2. **Journal**, then apply the substitution.
3. **Liveness probe.** On failure: `NOT_LIVE`, restore, continue to the next row.
4. **Run the gate**, capturing exit code and output. A timeout short-circuits
   classification: it is recorded as `GATE_TIMEOUT` and never reasoned about
   as a red or green gate result, even though its exit code would otherwise
   satisfy "the gate failed."
5. **Classify** against `expect` and `expect_red`.
6. **Restore**, sha256-verify, drain the journal entry.

Step 1 before step 3 is deliberate. A baseline that is already red and a
mutation that did not run produce the same gate output, and separating them is
half of requirement 5.

---

## 6. `--self-test`: two-sided, and it reproduces all three false greens

The repo's guards run `--self-test` first so a green is never vacuous. This
harness has a stronger obligation than a matcher: it must be proven to **detect
the three mechanisms that have actually fooled this project**.

Controls operate on fixtures under a `mktemp -d`, never the source tree.

**Positive controls — the harness must catch these:**

| ID | Control | Required outcome |
|---|---|---|
| `C1` | Size-preserving Python mutation, applied and reverted inside one second | reported **live** (mechanism 1 defeated) |
| `C2` | `token = ''` spliced after a `class X:` header, overridden by the real assignment below the docstring | **`NOT_LIVE`** (mechanism 2) |
| `C3` | A journal left undrained by a simulated kill | next invocation **refuses to run** and names the file (mechanism 3) |
| `C4` | `old` matching twice | `NOT_APPLIED` |
| `C5` | `old` matching zero times | `NOT_APPLIED` |
| `C6` | Gate red on the clean fixture | `BASELINE_DIRTY` |
| `C7` | Restored bytes altered behind the harness | `RESTORE_FAILED` and abort |
| `C8` | Live mutation, gate green, declared `red` | `UNEXPECTED_GREEN` |
| `C9` | Gate red but no `expect_red` name present | `WRONG_TESTS_RED` |
| `C10` | Rust mutation leaving the artifact byte-identical | `NOT_LIVE` |
| `C11` | Live mutation declared `green` whose gate goes red | `UNEXPECTED_RED` |

**Negative controls — the harness must stay silent:**

| ID | Control | Required outcome |
|---|---|---|
| `N1` | A genuinely live Python mutation reddening its gate | `RED_AS_EXPECTED`, never `NOT_LIVE` |
| `N2` | A by-design green, proven live | `GREEN_AS_EXPECTED`, never `UNEXPECTED_GREEN` |
| `N3` | A clean tree with a passing gate | no `BASELINE_DIRTY` |
| `N4` | A genuinely live Rust mutation | `RED_AS_EXPECTED`, never `NOT_LIVE` |

`C2` is the control this harness exists for. No ad-hoc harness caught that
shape, and it was diagnosed only by a human finding a green surprising.

---

## 7. Output

A markdown table on stdout in the column shape the handoffs already use, so a
slice pastes **generated** evidence rather than re-typing scrollback:

```markdown
| # | Mutation | Live | Outcome | Reds |
|---|---|---|---|---|
| M1 | tokens_agree returns `r == p` | yes (artifact) | RED_AS_EXPECTED | tolerance_admits_only_phase_dependent_pairs |
| M8 | ArraySortOrderViolation.token swapped | yes (interpreter) | GREEN_AS_EXPECTED | — |
```

The **Live** column names the mechanism, because the Rust and Python proofs are
not of equal strength and a reader weighing the evidence deserves the split.

Exit status: `0` when every outcome matches its declaration, `1` otherwise.
`--json` emits the same data machine-readably.

---

## 8. What this design does NOT claim

- **It does not make Rust liveness as strong as Python's.** An artifact hash
  proves the compiler produced different bytes; it does not prove the mutated
  expression was reached at runtime. The report labels the mechanism rather than
  flattening the two.
- **It does not verify that a mutation is *semantically* the one intended.** A
  spec saying `old = "a"`, `new = "b"` is applied as written. The harness checks
  that the edit took effect, not that it expresses the reviewer's intent.
- **It does not prevent a mutation set from being incomplete.** Choosing which
  mutations to run remains a design act; the harness makes each row's result
  trustworthy, not the set exhaustive.
- **It does not run in CI**, so nothing prevents a future slice from skipping it
  and hand-rolling a harness again. Adoption is a plan-authoring convention,
  enforced by review.
- **A `NOT_LIVE` verdict is not proof the test is vacuous.** It is proof the row
  measured nothing, which is a different and previously unrepresentable state.

---

## 9. Success criteria

1. `uv run scripts/mutate.py --self-test` exits 0, with every positive and
   negative control asserting its specific outcome — not merely "something
   fired".
   **Outcome coverage is the criterion, and it is stated as a requirement on
   the finished harness rather than as a claim about the current tree.** Each
   of the ten outcomes in §5.5 must have at least one control by the time this
   spec is satisfied; an outcome reachable in code but unasserted is exactly
   the vacuity this harness exists to remove. `GATE_TIMEOUT` is the tenth,
   added after a review found that a timed-out gate was being credited as a
   catch, and the task that builds the control table owns its control.
   The earlier wording of this criterion asserted universal coverage and
   admitted an exception to it in the same sentence — the overclaim shape this
   project keeps re-finding, reproduced inside its own success criteria. Do not
   restore it: say what must hold, or say what does hold, never both at once.
2. Each of `C1`, `C2`, `C3` is **mutation-proven**: disabling the corresponding
   harness mechanism reds exactly that control.
3. A real spec covering a known mutation from a shipped slice reproduces that
   slice's recorded result, run end to end.
4. An undrained journal blocks the next invocation, and `--drain` clears it with
   sha256 verification.
5. Every file under 500 lines, and no source-tree probe residue after any run,
   including an interrupted one — verified by `git status` being clean after a
   simulated kill. (This repo configures no Python linter, so none is claimed.)
6. The five numbered requirements in #644 each map to a named mechanism in §5.
