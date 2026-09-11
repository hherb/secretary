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
gate command, not of one particular invocation. The baseline cache is keyed
on `(gate, timeout)`: keyed on the command text alone, a spec with
`timeout = 1` that timed out poisoned a later spec sharing the command but
allowing the full budget into `GATE_TIMEOUT` (PR #652 review).

**Every abort carries what was measured before it** (PR #652 review). Only
`RestoreFailed` used to: it had `partial_results` bolted on as an undeclared
attribute, read back with a `getattr` default, and every OTHER exception —
a spec `path` that does not exist, a probe interpreter that is not on `PATH`,
`PycacheNotCleared` — escaped `mutate.main` as a bare traceback that dropped
every row already measured and exited 1, the code documented for "a rendered
table with an unsuccessful row". `run_mutations` now raises ONE typed
`RunAborted` for either, with the partial results as a declared field and a
`restore_failed` flag telling the caller which exit code the abort is (3: the
tree may be dirty; 4: the tree was restored, the harness itself failed).
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
    PythonObservation, RustObservation,
)

# One reading of whichever probe a spec declares. Deliberately opaque to
# `run_mutations`, which only ever hands a pair back to `_compare`.
Observation = PythonObservation | RustObservation


class RunAborted(Exception):
    """`run_mutations` stopped before finishing every row.

    `partial_results` is every row measured before the abort. When the cause
    is a `RestoreFailed`, that includes the aborting row's OWN measurement if
    it completed (a four-hour gate's verdict is not thrown away because the
    restore after it failed — fix-wave review), followed by a
    `RESTORE_FAILED` row for the same spec. `restore_failed` is True iff the
    cause was a `RestoreFailed`, i.e. the tree may still be mutated;
    otherwise the restore succeeded and the failure is the harness's own
    (the original exception is `__cause__`).
    """

    def __init__(
        self, reason: str, partial_results: tuple[MutationResult, ...], *, restore_failed: bool
    ) -> None:
        super().__init__(reason)
        self.partial_results = partial_results
        self.restore_failed = restore_failed


def apply_substitution(path: Path, old: str, new: str) -> bool:
    """Replace `old` with `new` iff it occurs EXACTLY once.

    Zero and two-or-more are both refusals. There is no first-wins guess: an
    ambiguous mutation is precisely the shape that produced false green 2.

    Works on BYTES, encoding `old`/`new` as UTF-8: `read_text()` /
    `write_text()` used the locale encoding and universal newlines, so a
    CRLF file was silently rewritten LF-only — every line changed, which the
    Rust artifact proof then reported as "live" for the wrong reason — and a
    non-UTF-8 file raised out of the run (PR #652 review). The journal
    hashes bytes; the substitution now edits the same thing it hashes.
    """
    data = path.read_bytes()
    needle, replacement = old.encode(), new.encode()
    if data.count(needle) != 1:
        return False
    path.write_bytes(data.replace(needle, replacement, 1))
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


def _baseline_verdict(
    spec: MutationSpec, repo_root: Path, baselines: dict[tuple[str, int], GateResult]
) -> MutationResult | None:
    """Step 1. A row decided by the baseline alone, or `None` to proceed."""
    key = (spec.gate, spec.timeout)
    if key not in baselines:
        clear_pycache(repo_root)
        baselines[key] = run_gate(spec.gate, repo_root, timeout=spec.timeout)
    baseline = baselines[key]
    # The whole `GateResult`, not a bool: `is_red` alone cannot tell a gate
    # that FAILED apart from one that never FINISHED — and now refuses to
    # try. Collapsing them here would report a baseline that never ran as
    # `BASELINE_DIRTY`, an outcome a reader would act on by fixing tests
    # that may be perfectly green.
    if baseline.timed_out:
        return MutationResult(spec=spec, outcome=Outcome.GATE_TIMEOUT, gate=baseline)
    if baseline.is_red:
        return MutationResult(spec=spec, outcome=Outcome.BASELINE_DIRTY, gate=baseline)
    return None


def _mutate_and_measure(
    spec: MutationSpec, target: Path, repo_root: Path, before: Observation
) -> MutationResult:
    """Steps 3-5, on a target the caller has already journaled."""
    if not apply_substitution(target, spec.old, spec.new):
        return MutationResult(spec=spec, outcome=Outcome.NOT_APPLIED)

    liveness = _compare(spec, before, _observe(spec, repo_root))
    if not liveness.live:
        return MutationResult(spec=spec, outcome=Outcome.NOT_LIVE, liveness=liveness)

    gate = run_gate(spec.gate, repo_root, timeout=spec.timeout)
    outcome, missing = classify(spec, gate, liveness)
    return MutationResult(
        spec=spec, outcome=outcome, liveness=liveness, gate=gate, missing_reds=missing,
    )


def run_mutations(
    specs: tuple[MutationSpec, ...], repo_root: Path, journal_dir: Path
) -> list[MutationResult]:
    journal = Journal(journal_dir)
    journal.install_handlers()
    results: list[MutationResult] = []
    baselines: dict[tuple[str, int], GateResult] = {}
    current = "<no row started>"
    try:
        for spec in specs:
            current = spec.id
            decided = _baseline_verdict(spec, repo_root, baselines)
            if decided is not None:
                results.append(decided)
                continue

            before = _observe(spec, repo_root)
            target = (repo_root / spec.path).resolve()
            entry = journal.record(target)
            measured: MutationResult | None = None
            try:
                measured = _mutate_and_measure(spec, target, repo_root, before)
            finally:
                try:
                    journal.restore(entry)
                except RestoreFailed as exc:
                    # Step 6 failed. Keep what step 5 measured, then say the
                    # tree may be dirty. Raised from inside the `finally` so
                    # it also wins over any exception step 3-5 raised — a
                    # restore that cannot be trusted is the more urgent fact.
                    if measured is not None:
                        results.append(measured)
                    results.append(MutationResult(spec=spec, outcome=Outcome.RESTORE_FAILED))
                    raise RunAborted(str(exc), tuple(results), restore_failed=True) from exc
            results.append(measured)
    except RunAborted:
        raise
    except Exception as exc:  # noqa: BLE001 - re-raised typed, with the partial table
        raise RunAborted(
            f"row {current}: {type(exc).__name__}: {exc}", tuple(results), restore_failed=False
        ) from exc
    finally:
        # The `atexit` drain stays registered for the life of the process
        # (see journal.py); the SIGNAL dispositions are process-global state
        # this run borrowed and now hands back, so a signal after the run —
        # in a test process, in a `--self-test` that runs thirty of these —
        # reaches whatever handled it before, not a `Journal` whose
        # directory is gone.
        journal.restore_signal_dispositions()
    return results
