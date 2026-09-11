"""The per-mutation state machine. Spec §5.6.

Step ordering is load-bearing:

1. Baseline the gate on the CLEAN tree. A baseline that is already red and a
   mutation that did not run produce the same gate output; separating them is
   half of requirement 5.
2. Journal, then apply.
3. Probe liveness. A row that fails here measured NOTHING and says so.
4. Run the gate.
5. Classify.
6. Restore and sha256-verify.
"""

from __future__ import annotations

from pathlib import Path

from mutation_harness.gate import classify, run_gate
from mutation_harness.journal import Journal, RestoreFailed
from mutation_harness.liveness import (
    clear_pycache, compare_rust_artifacts, probe_python, rust_artifact_hashes,
)
from mutation_harness.types import (
    Lang, LivenessResult, MutationResult, MutationSpec, Outcome,
)


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


def _probe(spec: MutationSpec, repo_root: Path, rust_before: dict) -> LivenessResult:
    if spec.lang is Lang.PYTHON:
        clear_pycache(repo_root / Path(spec.path).parent)
        return probe_python(spec.probe, repo_root)
    after = rust_artifact_hashes(spec.probe.package, repo_root)
    return compare_rust_artifacts(rust_before, after)


def run_mutations(
    specs: tuple[MutationSpec, ...], repo_root: Path, journal_dir: Path
) -> list[MutationResult]:
    journal = Journal(journal_dir)
    journal.install_handlers()
    results: list[MutationResult] = []
    baselines: dict[str, bool] = {}

    for spec in specs:
        target = (repo_root / spec.path).resolve()

        if spec.gate not in baselines:
            clear_pycache(repo_root)
            baselines[spec.gate] = not run_gate(spec.gate, repo_root).is_red
        if not baselines[spec.gate]:
            results.append(MutationResult(spec=spec, outcome=Outcome.BASELINE_DIRTY))
            continue

        rust_before: dict[str, str] = {}
        if spec.lang is Lang.RUST:
            rust_before = rust_artifact_hashes(spec.probe.package, repo_root)

        entry = journal.record(target)
        try:
            if not apply_substitution(target, spec.old, spec.new):
                results.append(MutationResult(spec=spec, outcome=Outcome.NOT_APPLIED))
                continue

            liveness = _probe(spec, repo_root, rust_before)
            if not liveness.live:
                results.append(
                    MutationResult(spec=spec, outcome=Outcome.NOT_LIVE, liveness=liveness)
                )
                continue

            gate = run_gate(spec.gate, repo_root)
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
            except RestoreFailed:
                results.append(
                    MutationResult(spec=spec, outcome=Outcome.RESTORE_FAILED)
                )
                raise

    return results
