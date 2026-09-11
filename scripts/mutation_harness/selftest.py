"""Drive every control through the REAL pipeline. Spec §6.

`--self-test` runs before any real spec, matching the discipline every other
guard in this repo follows: a green is never vacuous because the matcher is
first shown to fire on a known positive and stay silent on a known negative.

This harness carries a stronger obligation than a matcher. Its whole claim is
detection, so it must be proven to detect the three mechanisms that actually
fooled this project. C2 is the one it exists for.

`GATE_TIMEOUT` coverage (spec §9 criterion 1's tenth outcome) comes from
`controls.C12`, exercised through the same `POSITIVE_CONTROLS` loop as every
other control below — there is no separate code path for it here. The
outcome-coverage check at the end of `run_self_test` is what makes that
"genuinely covered" rather than an unchecked claim: it fails if any control
table stops mentioning an `Outcome` member, `GATE_TIMEOUT` included.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from mutation_harness.controls import NEGATIVE_CONTROLS, POSITIVE_CONTROLS, Control
from mutation_harness.journal import Journal
from mutation_harness.runner import run_mutations
from mutation_harness.types import Lang, MutationSpec, Outcome, PythonProbe


def run_control(control: Control) -> tuple[bool, str]:
    """Build the control's fixture in a temp dir and run it end to end."""
    with tempfile.TemporaryDirectory(prefix="mutate-selftest-") as tmp:
        root = Path(tmp)
        spec = control.build(root)
        results = run_mutations((spec,), root, root / ".journal")
        if len(results) != 1:
            return False, f"expected 1 result, got {len(results)}"
        actual = results[0].outcome
        if actual is not control.expect:
            return False, f"expected {control.expect.value}, got {actual.value}"
        if Journal(root / ".journal").is_dirty():
            return False, "journal left dirty after a completed control"
        return True, actual.value


def check_clean_baseline() -> tuple[bool, str]:
    """N3: a clean tree whose gate passes must not report BASELINE_DIRTY."""
    with tempfile.TemporaryDirectory(prefix="mutate-n3-") as tmp:
        root = Path(tmp)
        (root / "m.py").write_text('TOKEN = "real"\n')
        spec = MutationSpec(
            id="N3", lang=Lang.PYTHON, path="m.py",
            old='"real"', new='"mutated"', gate="true", expect="green",
            probe=PythonProbe("m", "TOKEN", "mutated", "."),
        )
        (result,) = run_mutations((spec,), root, root / ".journal")
        if result.outcome is Outcome.BASELINE_DIRTY:
            return False, "a passing gate on a clean tree was reported BASELINE_DIRTY"
        return True, result.outcome.value


def check_journal_refusal() -> tuple[bool, str]:
    """C3: an undrained journal must be visible to the NEXT invocation.

    This is the structural fix for false green 3 — a mutation left applied by
    a stalled worker, previously caught only by a routine `git status`.
    """
    with tempfile.TemporaryDirectory(prefix="mutate-c3-") as tmp:
        root = Path(tmp)
        target = root / "f.txt"
        target.write_text("original\n")
        Journal(root / ".journal").record(target)
        target.write_text("mutated\n")

        reopened = Journal(root / ".journal")
        if not reopened.is_dirty():
            return False, "a reopened journal did not see the outstanding entry"
        if reopened.dirty_paths() != [str(target.resolve())]:
            return False, "dirty_paths did not name the mutated file"
        reopened.drain()
        if target.read_text() != "original\n":
            return False, "drain did not restore the original bytes"
        return True, "refusal state visible and drainable"


def run_self_test() -> int:
    failures = 0
    print("mutation harness self-test")
    print("=" * 60)

    for control in POSITIVE_CONTROLS:
        ok, detail = run_control(control)
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {control.label}: {control.why} -> {detail}")
        failures += 0 if ok else 1

    ok, detail = check_journal_refusal()
    print(f"  [{'PASS' if ok else 'FAIL'}] C3: journal refusal -> {detail}")
    failures += 0 if ok else 1

    ok, detail = check_clean_baseline()
    print(f"  [{'PASS' if ok else 'FAIL'}] N3: clean baseline -> {detail}")
    failures += 0 if ok else 1

    for control in NEGATIVE_CONTROLS:
        ok, detail = run_control(control)
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {control.label}: {control.why} -> {detail}")
        failures += 0 if ok else 1

    total = len(POSITIVE_CONTROLS) + len(NEGATIVE_CONTROLS) + 2  # +C3 +N3
    covered = {c.expect for c in POSITIVE_CONTROLS} | {c.expect for c in NEGATIVE_CONTROLS}
    uncovered = sorted(o.value for o in Outcome if o not in covered)
    if uncovered:
        # RESTORE_FAILED is covered by test_journal.py rather than by a
        # control here (it needs a backup corrupted BEHIND the harness,
        # which is a white-box test, not a fixture `run_mutations` can be
        # pointed at). Every other outcome, GATE_TIMEOUT included since
        # C12, is reached through this file's own control loops above.
        if uncovered != ["RESTORE_FAILED"]:
            print(f"  [FAIL] outcome coverage: no control reaches {uncovered}")
            failures += 1
        else:
            print("  [PASS] outcome coverage: all but RESTORE_FAILED (see test_journal.py)")

    print("=" * 60)
    print(f"{total - failures}/{total} checks passed")
    return 1 if failures else 0
