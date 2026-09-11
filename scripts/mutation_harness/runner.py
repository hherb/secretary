"""The per-mutation state machine. Spec §5.6.

Step ordering is load-bearing:

1. Baseline the gate on the CLEAN tree. A baseline that is already red and a
   mutation that did not run produce the same gate output; separating them is
   half of requirement 5. A baseline that TIMED OUT is a third thing again —
   `GATE_TIMEOUT`, not `BASELINE_DIRTY`: a gate that did not finish is not a
   gate that failed, and collapsing the two is the same class of error `C12`
   exists to prevent one step later (final whole-branch review, Finding 7).
2. Observe the probe on the CLEAN tree, then journal, then apply. BOTH
   languages take a before-reading now; see `_observe`.
3. Observe again and COMPARE. A row whose observed value did not move
   measured NOTHING and says so.
4. Run the gate — only if step 3 proved the mutation live. The short-circuit
   lives here, not only in `classify`: a gate that runs for a dead mutation
   burns the run's most expensive step to produce a result that must be
   discarded. Pinned by `test_runner.py`'s
   `test_a_not_live_row_never_executes_its_gate`.
5. Classify.
6. Restore and sha256-verify.

`spec.timeout` is threaded to BOTH `run_gate` calls made for a spec — the
baseline run and the post-mutation run — because it names a property of the
gate command, not of one particular invocation. A spec that never sets it
gets `run_gate`'s prior hardcoded default (3600s) on both calls, so this is
additive: no existing spec's behaviour changes. Two calls sharing one
`spec.gate` string but different `timeout` values would share a cached
baseline keyed only on the command text; no control in this tree does that,
and it is not otherwise exercised.

A `RestoreFailed` raised from the `finally` block below carries the PARTIAL
`results` list as `exc.partial_results`, attached just before the re-raise.
Without it, the row this function itself builds for `RESTORE_FAILED` was
unreachable by any caller — the `raise` propagates past this function's own
`return results`, so `mutate.py` could only see the bare exception, never a
result to render (fix round 2, Finding 4).
"""

from __future__ import annotations

from pathlib import Path

from mutation_harness.gate import classify, run_gate
from mutation_harness.journal import Journal, RestoreFailed
from mutation_harness.liveness import (
    clear_pycache, compare_python_probe, compare_rust_artifacts, observe_python,
    rust_artifact_hashes,
)
from mutation_harness.types import (
    GateResult, Lang, LivenessResult, MutationResult, MutationSpec, Outcome,
    PythonObservation,
)

# One reading of whichever probe a spec declares: a `PythonObservation` for
# `Lang.PYTHON`, cargo's artifact-hash map for `Lang.RUST`. Deliberately
# opaque to `run_mutations`, which only ever hands a pair back to `_compare`.
Observation = PythonObservation | dict[str, str]


def apply_substitution(path: Path, old: str, new: str) -> bool:
    """Replace `old` with `new` iff it occurs EXACTLY once.

    Zero and two-or-more are both refusals. There is no first-wins guess: an
    ambiguous mutation is precisely the shape that produced false green 2.
    """
    text = path.read_text()
    if text.count(old) != 1:
        return False
    path.write_text(text.replace(old, new, 1))
    return True


def _observe(spec: MutationSpec, repo_root: Path) -> Observation:
    """Take ONE reading for `spec`'s probe. Called twice: before the
    substitution and after it. The two branches are symmetric — each is a
    reading with no verdict attached, and `_compare` owns the verdict."""
    if spec.lang is Lang.PYTHON:
        # This call and the baseline `clear_pycache(repo_root)` in
        # `run_mutations` are BOTH defences against false-green mechanism 1
        # (stale bytecode), and mutation-testing them individually shows the
        # baseline call alone always suffices in this pipeline: it sweeps the
        # WHOLE `repo_root` unconditionally, fires before any spec's probe,
        # and nothing this harness spawns ever writes NEW bytecode (every
        # subprocess runs under `python_env()`'s `PYTHONDONTWRITEBYTECODE=1`)
        # — so nothing can repopulate a stale `.pyc` for this call to still
        # need to clear. Kept anyway as defence in depth against a future
        # change to either assumption (e.g. a scoped baseline sweep, or a
        # subprocess that regains bytecode writing) — see `controls.py`'s
        # `C1` docstring for the measured claim that control actually pins.
        clear_pycache(repo_root / Path(spec.path).parent)
        return observe_python(spec.probe, repo_root)
    return rust_artifact_hashes(spec.probe.package, repo_root)


def _compare(
    spec: MutationSpec, before: Observation, after: Observation
) -> LivenessResult:
    """Turn a before/after pair of readings into the row's liveness verdict."""
    if spec.lang is Lang.PYTHON:
        return compare_python_probe(spec.probe, before, after)
    return compare_rust_artifacts(before, after)


def run_mutations(
    specs: tuple[MutationSpec, ...], repo_root: Path, journal_dir: Path
) -> list[MutationResult]:
    journal = Journal(journal_dir)
    journal.install_handlers()
    results: list[MutationResult] = []
    # The whole `GateResult`, not a bool: `is_red` alone cannot tell a gate
    # that FAILED apart from one that never FINISHED, and `timed_out` is the
    # only thing that can (see `GateResult.timed_out`). Collapsing them here
    # would report a baseline that never ran as `BASELINE_DIRTY`, an outcome
    # a reader would act on by fixing tests that may be perfectly green.
    baselines: dict[str, GateResult] = {}

    for spec in specs:
        target = (repo_root / spec.path).resolve()

        if spec.gate not in baselines:
            clear_pycache(repo_root)
            baselines[spec.gate] = run_gate(spec.gate, repo_root, timeout=spec.timeout)
        baseline = baselines[spec.gate]
        if baseline.timed_out:
            results.append(
                MutationResult(spec=spec, outcome=Outcome.GATE_TIMEOUT, gate=baseline)
            )
            continue
        if baseline.is_red:
            results.append(
                MutationResult(spec=spec, outcome=Outcome.BASELINE_DIRTY, gate=baseline)
            )
            continue

        before = _observe(spec, repo_root)

        entry = journal.record(target)
        try:
            if not apply_substitution(target, spec.old, spec.new):
                results.append(MutationResult(spec=spec, outcome=Outcome.NOT_APPLIED))
                continue

            liveness = _compare(spec, before, _observe(spec, repo_root))
            if not liveness.live:
                results.append(
                    MutationResult(spec=spec, outcome=Outcome.NOT_LIVE, liveness=liveness)
                )
                continue

            gate = run_gate(spec.gate, repo_root, timeout=spec.timeout)
            outcome, missing = classify(spec, gate, liveness)
            results.append(
                MutationResult(
                    spec=spec, outcome=outcome, liveness=liveness,
                    gate=gate, missing_reds=missing,
                )
            )
        finally:
            try:
                journal.restore(entry)
            except RestoreFailed as exc:
                results.append(
                    MutationResult(spec=spec, outcome=Outcome.RESTORE_FAILED)
                )
                # Attach the PARTIAL results so a caller catching this
                # exception (mutate.py) can still render what was measured
                # before the abort, RESTORE_FAILED row included. Without
                # this, `results` — including the row two lines up — is
                # unreachable: the `raise` below propagates past this
                # function's own `return results` (fix round 2, Finding 4).
                exc.partial_results = results
                raise

    return results
