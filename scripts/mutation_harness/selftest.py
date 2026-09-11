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

Fix round 2 closed a real vacuity here (Finding 1): `check_journal_refusal`
used to exercise only the `Journal` API, never `mutate.py`'s own refusal
block — deleting that block left this control PASSING. It now imports and
calls `mutate.main` directly, capturing stdout/stderr so the self-test's own
output stays clean. A deferred (function-local) import is required rather
than a module-level one: `mutate.py` imports `run_self_test` FROM this
module, so a module-level `import mutate` here would be circular whenever
`mutate.py` is the one doing the importing (running as `__main__`) — by the
time `check_journal_refusal` is actually CALLED, both modules have finished
initializing, so the import is safe there.
"""

from __future__ import annotations

import hashlib
import io
import tempfile
from contextlib import redirect_stderr, redirect_stdout
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

    Must drive the REAL entrypoint (`mutate.main`), not just the `Journal`
    API it is built on top of: `Journal.is_dirty()`/`drain()` working
    correctly proves nothing about whether `mutate.py` actually CONSULTS
    them before starting a run. An earlier version of this function called
    those methods directly and stayed PASSING even with `mutate.py`'s own
    refusal block (the `if journal.is_dirty(): ... return 2` in `main()`)
    deleted entirely — see the fix report for the exact mutation and output.
    """
    import mutate  # deferred: see module docstring for why

    with tempfile.TemporaryDirectory(prefix="mutate-c3-") as tmp:
        root = Path(tmp)
        journal_dir = root / ".journal"
        target = root / "f.txt"
        target.write_text("original\n")
        Journal(journal_dir).record(target)
        target.write_text("mutated\n")

        # argparse requires a spec PATH before the journal-dirty refusal
        # fires (it is checked ahead of `parse_spec`, so the file's content
        # is never read on this path) — an empty placeholder is enough.
        spec_path = root / "spec.toml"
        spec_path.write_text("")

        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = mutate.main([str(spec_path), "--journal-dir", str(journal_dir)])
        if code != 2:
            return False, f"expected exit 2 on an undrained journal, got {code}"
        if str(target.resolve()) not in err.getvalue():
            return False, "refusal output did not name the dirty file"

        out2, err2 = io.StringIO(), io.StringIO()
        with redirect_stdout(out2), redirect_stderr(err2):
            drain_code = mutate.main(["--drain", "--journal-dir", str(journal_dir)])
        if drain_code != 0:
            return False, f"--drain exited {drain_code}, expected 0"
        if target.read_text() != "original\n":
            return False, "--drain did not restore the original bytes"
        if Journal(journal_dir).is_dirty():
            return False, "journal still dirty after --drain"
        return True, "refusal blocks the next invocation; --drain restores"


def check_no_bytecode_written() -> tuple[bool, str]:
    """Spec §5.2's `PYTHONDONTWRITEBYTECODE=1` discipline, the OTHER half.

    `C1` (and `clear_pycache`) prove a PRE-EXISTING stale `.pyc` is ignored.
    Nothing previously checked the complementary claim: that a probe or gate
    subprocess never WRITES a fresh one in the first place. Verified absent
    before this fix — replacing `liveness.py`'s `_NO_BYTECODE` with `{}` left
    every Python control and the whole pytest suite green, because nothing
    ever inspected a fixture tree AFTER a run for leftover bytecode.
    """
    with tempfile.TemporaryDirectory(prefix="mutate-bytecode-") as tmp:
        root = Path(tmp)
        (root / "m.py").write_text('TOKEN = "real"\n')
        spec = MutationSpec(
            id="NB1", lang=Lang.PYTHON, path="m.py",
            old='"real"', new='"mutated"', gate="true", expect="green",
            probe=PythonProbe("m", "TOKEN", "mutated", "."),
        )
        (result,) = run_mutations((spec,), root, root / ".journal")
        if result.outcome is not Outcome.GREEN_AS_EXPECTED:
            return False, f"setup failed: expected GREEN_AS_EXPECTED, got {result.outcome.value}"
        leftover = sorted(str(p) for p in root.rglob("__pycache__"))
        if leftover:
            return False, f"a probe or gate subprocess wrote bytecode: {leftover}"
        return True, "no __pycache__ written by any probe or gate subprocess"


def check_restore_failed_is_observable() -> tuple[bool, str]:
    """RESTORE_FAILED must reach a CALLER, not just get raised past one.

    Until this fix, `run_mutations`'s `finally` block built a `MutationResult`
    row for this outcome and then immediately lost it: the `raise`
    immediately after `results.append(...)` propagates past the function's
    own `return results`, so no caller — `mutate.main` included — could ever
    observe the row, only the bare `RestoreFailed` exception. `runner.py` now
    attaches the partial results list to the exception before re-raising
    (`exc.partial_results`), and `mutate.main` renders it and exits 3.

    Corrupting a backup needs reaching BEHIND the harness — neither
    `apply_substitution` nor `journal.record` has a failure path a spec can
    drive on its own, the same reason `test_journal.py`'s sha256 test
    corrupts a backup file directly rather than through any public API. This
    control does the same corruption through the one seam `run_mutations`
    exposes to an arbitrary command: the GATE. It runs strictly between
    `journal.record()` and the `finally` block's `journal.restore()`, so a
    gate that deletes the backup blob `record()` just wrote reproduces the
    same failure end to end, through the real `mutate.main` path.

    `mutate.REPO_ROOT` is a module-level global (not a CLI argument) that
    every spec `path` resolves against, and `main()` looks it up by name at
    CALL time — so it is patched to this fixture root for the duration of
    the one `mutate.main(...)` call below and restored immediately after,
    the same technique pytest's own `monkeypatch` fixture uses elsewhere in
    this tree. That touches WHICH DIRECTORY counts as "the repo" for this
    call; it does not touch or bypass any of `main`'s own logic — the
    refusal check, `parse_spec`, `run_mutations`, the `RestoreFailed`
    handler, rendering, and the exit code all still run exactly as written.
    `check_journal_refusal` above needs no such patch: it never gets past
    the early refusal check, which never touches `REPO_ROOT`.
    """
    import mutate  # deferred: see module docstring for why

    with tempfile.TemporaryDirectory(prefix="mutate-restorefail-") as tmp:
        root = Path(tmp)
        journal_dir = root / ".journal"
        original = 'TOKEN = "real"\n'
        (root / "m.py").write_text(original)
        digest = hashlib.sha256(original.encode()).hexdigest()
        backup_path = journal_dir / f"{digest[:16]}-m.py.orig"

        spec_path = root / "spec.toml"
        spec_path.write_text(
            "[[mutation]]\n"
            'id = "RF1"\n'
            'lang = "python"\n'
            'path = "m.py"\n'
            'old = \'"real"\'\n'
            'new = \'"mutated"\'\n'
            f'gate = "rm -f {backup_path}"\n'
            'expect = "green"\n'
            'probe = { module = "m", expr = "TOKEN", equals = "mutated", syspath = "." }\n'
        )

        saved_repo_root = mutate.REPO_ROOT
        mutate.REPO_ROOT = root
        try:
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = mutate.main([str(spec_path), "--journal-dir", str(journal_dir)])
        finally:
            mutate.REPO_ROOT = saved_repo_root

        # `run_mutations()` (inside `mutate.main`) constructed its OWN
        # `Journal(journal_dir)` internally and called `install_handlers()`
        # on it — this control never gets a direct reference to that
        # instance, only the directory it used, so `Journal.installed_for`
        # is how it is found. This journal is left dirty BY DESIGN (the
        # backup this control's own gate deleted can never be restored), so
        # its atexit hook would otherwise fire at INTERPRETER shutdown, long
        # after this function has already made its assertion, printing a
        # `JOURNAL DRAIN FAILED` line after an otherwise-green summary (fix
        # round 3, the finding that motivated `uninstall_handlers`). In a
        # `finally` so it runs even if an assertion below fails. This is
        # the ONLY call site in the tree — see `journal.py`'s module
        # docstring for why a real `RestoreFailed` must never take this
        # path: the control's actual claim (exit 3, RESTORE_FAILED rendered,
        # ABORTED on stderr) is asserted first, unchanged by this cleanup.
        installed = Journal.installed_for(journal_dir)
        try:
            if code != 3:
                return False, f"expected exit 3 on a restore failure, got {code}"
            if "RESTORE_FAILED" not in out.getvalue():
                return False, "rendered output did not include a RESTORE_FAILED row"
            if "ABORTED" not in err.getvalue():
                return False, "stderr did not report the abort"
            return True, "RESTORE_FAILED reaches mutate.main, renders, and exits 3"
        finally:
            if installed is not None:
                installed.uninstall_handlers()


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

    ok, detail = check_no_bytecode_written()
    print(f"  [{'PASS' if ok else 'FAIL'}] no-bytecode: PYTHONDONTWRITEBYTECODE -> {detail}")
    failures += 0 if ok else 1

    ok, detail = check_restore_failed_is_observable()
    print(f"  [{'PASS' if ok else 'FAIL'}] RESTORE_FAILED: observable via mutate.main -> {detail}")
    failures += 0 if ok else 1

    for control in NEGATIVE_CONTROLS:
        ok, detail = run_control(control)
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {control.label}: {control.why} -> {detail}")
        failures += 0 if ok else 1

    # +C3 +N3 +no-bytecode +RESTORE_FAILED-check +this coverage line itself
    # (fix round 2, Finding 6 — the coverage line is a counted check too,
    # not a free pass omitted from the denominator).
    total = len(POSITIVE_CONTROLS) + len(NEGATIVE_CONTROLS) + 5
    covered = (
        {c.expect for c in POSITIVE_CONTROLS}
        | {c.expect for c in NEGATIVE_CONTROLS}
        # Proven above by check_restore_failed_is_observable rather than by
        # a Control row (it needs a backup corrupted behind the harness, not
        # a fixture `run_mutations` can be pointed at directly) — a REAL
        # assertion now, not an excuse (fix round 2, Finding 4).
        | {Outcome.RESTORE_FAILED}
    )
    uncovered = sorted(o.value for o in Outcome if o not in covered)
    if uncovered:
        print(f"  [FAIL] outcome coverage: no control or check reaches {uncovered}")
        failures += 1
    else:
        print("  [PASS] outcome coverage: every outcome has a control or check")

    print("=" * 60)
    print(f"{total - failures}/{total} checks passed")
    return 1 if failures else 0
