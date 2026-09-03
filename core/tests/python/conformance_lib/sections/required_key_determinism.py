"""Section DET -- a missing required key is reported deterministically (#597).

THE DEFECT. THREE of this verifier's seven required-key presence checks were
written as `for k in SOME_REQUIRED_SET: if k not in decoded: raise` -- the other
four already wrote `sorted(...)` by hand, which is the whole argument for putting
the rule in one named helper rather than in seven independent copies. A Python
`set`/`frozenset` of strings iterates in hash order, and CPython salts string
hashing once per PROCESS, so when an input omitted more than one required key
those three named whichever key they happened to reach first -- a different one from
run to run. #597 records six consecutive runs over one fuzz seed alternating
between `self_sig_ed` and `self_sig_pq`.

The verdict was never affected (`{"status": "reject", "error_class":
"KeyError"}` every time, and `core/tests/differential_replay.rs` scores
reject-vs-reject as agreement without comparing `detail`), so no gate was
flaky. What it cost was reproducibility: a byte-exact `--diff-replay` baseline
could not be taken without pinning `PYTHONHASHSEED`, which is a trap for
exactly the task that found it -- proving a refactor changed nothing.

WHAT THIS SECTION PINS, in three independent checks.

  1. SEED AGREEMENT. `required_key_probe` is spawned once per seed in
     `_HASH_SEEDS` and every run's stdout must be byte-identical. This is
     #597's own reproduction, run as an assertion. It needs subprocesses
     because a process's hash salt is fixed at interpreter start and cannot
     be varied from within.

  2. THE DOCUMENTED CHOICE, with an ambiguity control. Determinism alone is
     satisfied by reporting a constant, so each case also asserts the
     rejection names the LEXICOGRAPHICALLY FIRST absent key -- and names no
     OTHER absent key, which is what rules out a message that happens to
     mention several. The control against a vacuous fixture is the probe's
     second decode: restoring `missing[0]` must move the rejection onto
     `missing[1]`. Two different keys from two nearly identical inputs is
     the ambiguity the bug needed, demonstrated by the decoder rather than
     asserted about the table.

  3. STRUCTURE, both directions. `first_missing_key_in_sorted_order` is the
     one place the rule lives, so every call site of it under `codec/` must
     have a case (a new site with no case reds), and NO `for` loop under
     `codec/` may iterate a required-key set directly (a new site that
     bypasses the helper reds). Check 3 is what makes checks 1 and 2 more
     than a snapshot of seven inputs.

LIMITS, stated rather than implied. Check 3 scans `codec/` only, matches by
NAME SHAPE (a bare `for` over a set literal, or over a name containing
`REQUIRED` / ending `_KEYS` / `_FIELDS`), and reads TEXT rather than resolved
identities -- a decoder placed outside `codec/`, or one iterating a required
set bound to some other name, is invisible to it. `wire/card.py` deliberately
does not use the helper: it reports the WHOLE missing set, already sorted, so
it has no first-key choice to make.
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path

from conformance_lib.required_key_probe import CASES

# Eight fixed seeds, not `random`: a fixed set makes a regression a
# deterministic red rather than an intermittent one. Measured against the
# pre-fix decoders, these eight produce SEVEN distinct outputs, so the check
# is not relying on a lucky pair.
_HASH_SEEDS = ("0", "1", "2", "3", "4", "5", "6", "7")

_PROBE_MODULE = "conformance_lib.required_key_probe"
_HELPER = "first_missing_key_in_sorted_order"
# The module that DEFINES the helper; excluded from the call-site census so
# the definition does not count as a use.
_HELPER_MODULE = "required_keys.py"
# A `for` target whose name matches one of these is a required-key set being
# iterated raw -- the shape the defect had. Matched CASE-INSENSITIVELY: two of
# the seven live sites bind their required set to the lowercase PARAMETER
# `required_keys` (`manifest_schema.py`), so a case-sensitive matcher would miss
# the ordinary-Python-naming half of the very shape it exists to catch. Verified
# by execution: a new decoder written as `required_keys = {...}` /
# `for required in required_keys:` scanned GREEN before this.
_REQUIRED_SET_MARKERS = ("REQUIRED",)
_REQUIRED_SET_SUFFIXES = ("_KEYS", "_FIELDS")

_PACKAGE_ROOT = Path(__file__).resolve().parents[1]
_CODEC_DIR = _PACKAGE_ROOT / "codec"


def _run_probe_under(seed: str) -> tuple[str, str | None]:
    """Spawn the probe with `PYTHONHASHSEED=seed`; return `(stdout, error)`."""
    env = dict(os.environ)
    env["PYTHONHASHSEED"] = seed
    # The probe is spawned as a MODULE, so the package's parent must be on the
    # path. `sys.executable` is the interpreter already running this verifier,
    # so the PEP 723 dependencies resolved for it are available to the child.
    parent = str(_PACKAGE_ROOT.parent)
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = f"{parent}{os.pathsep}{existing}" if existing else parent
    try:
        completed = subprocess.run(
            [sys.executable, "-m", _PROBE_MODULE],
            capture_output=True, text=True, env=env, timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as e:
        return "", f"probe under PYTHONHASHSEED={seed} could not run: {e}"
    if completed.returncode != 0:
        return "", (
            f"probe under PYTHONHASHSEED={seed} exited {completed.returncode}: "
            f"{completed.stderr.strip()}"
        )
    return completed.stdout, None


def _codec_modules() -> list[Path]:
    """The `codec/` modules both structural checks read.

    `rglob`, not `glob`: this repo splits a module into a DIRECTORY module once
    it passes 500 lines (`codec/record.py` is already 355), and a non-recursive
    glob would make the first such split silently invisible to both checks.
    Verified by execution -- a `codec/sub/thing.py` carrying the verbatim #597
    shape scanned GREEN, and the PASS line counted 13 modules against a
    14-module tree.

    Returned rather than re-globbed per check so the two cannot end up
    scanning different sets, and so an EMPTY result is visible to the caller:
    a glob that matches nothing would let both checks report "no violations"
    having read no source at all.
    """
    return sorted(_CODEC_DIR.rglob("*.py"))


def _enclosing_function_names(tree: ast.AST) -> dict[ast.AST, str | None]:
    """Each node's nearest enclosing `def` name, or `None` at module level."""
    enclosing: dict[ast.AST, str | None] = {}

    def visit(node: ast.AST, current: str | None) -> None:
        for child in ast.iter_child_nodes(node):
            inner = (
                child.name
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                else current
            )
            enclosing[child] = inner
            visit(child, inner)

    visit(tree, None)
    return enclosing


def _helper_call_sites(modules: list[Path]) -> dict[str, list[int]]:
    """Every `codec/` call of the helper, keyed `codec/<path>::<function>`.

    Keyed by ENCLOSING FUNCTION rather than counted, because a count is not a
    mapping: with `len(call_sites) != len(CASES)` as the whole check, adding an
    eighth call site no case exercises AND an eighth case duplicating an
    existing one scanned GREEN, under a PASS line reading "8 call sites, one
    case each" that was false in that state (verified by execution). The key
    matches `Case.site`'s spelling so the two sets can be compared directly.

    Read through `ast`, not by line matching, so a comment or docstring naming
    the helper cannot inflate the count into a false red either.
    """
    hits: dict[str, list[int]] = {}
    for path in modules:
        if path.name == _HELPER_MODULE:
            continue
        tree = ast.parse(path.read_text())
        enclosing = _enclosing_function_names(tree)
        relative = path.relative_to(_CODEC_DIR)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not (isinstance(node.func, ast.Name) and node.func.id == _HELPER):
                continue
            function = enclosing.get(node) or "<module>"
            hits.setdefault(f"codec/{relative}::{function}", []).append(node.lineno)
    return hits


def _is_required_set_name(name: str) -> bool:
    upper = name.upper()
    return any(m in upper for m in _REQUIRED_SET_MARKERS) or upper.endswith(
        _REQUIRED_SET_SUFFIXES
    )


def _raw_required_set_iterations(modules: list[Path]) -> list[str]:
    """Every `codec/` `for` loop iterating a required-key set directly.

    A `for k in sorted(X)` is an `ast.Call`, not a bare name, so this reports
    only the unmediated shape -- which after #597 should be none at all,
    because the sort belongs in the helper where one name carries it.
    """
    hits: list[str] = []
    for path in modules:
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.For):
                continue
            iterated = node.iter
            relative = path.relative_to(_CODEC_DIR)
            if isinstance(iterated, (ast.Set, ast.SetComp)):
                hits.append(f"codec/{relative}:{node.lineno} (set literal)")
            elif isinstance(iterated, ast.Name) and _is_required_set_name(iterated.id):
                hits.append(f"codec/{relative}:{node.lineno} ({iterated.id})")
    return hits


def _check_case_outcome(
    label: str, site: str, which: str, outcome: dict, expected: str,
    other_absent: tuple[str, ...],
) -> list[str]:
    """`outcome` must be a rejection naming `expected` and no key in
    `other_absent`."""
    issues: list[str] = []
    if not outcome["error_class"]:
        return [
            f"{label} ({which}): the input was ACCEPTED -- the fixture no "
            f"longer reaches {site}'s required-key check, so this case tests "
            "nothing"
        ]
    detail = outcome["detail"]
    if repr(expected) not in detail:
        issues.append(
            f"{label} ({which}): rejection does not name the lexicographically "
            f"first absent key {expected!r} -- {site} reported: {detail}"
        )
    for other in other_absent:
        if repr(other) in detail:
            issues.append(
                f"{label} ({which}): rejection also names {other!r}, which is "
                f"absent but not the one the contract selects -- {detail}"
            )
    return issues


def section_required_key_determinism() -> tuple[bool, list[str]]:
    issues: list[str] = []
    lines: list[str] = []

    for case in CASES:
        if len(case.missing) < 2:
            issues.append(
                f"{case.label}: declares {len(case.missing)} absent key(s); a "
                "case with fewer than 2 cannot distinguish a sorted decoder "
                "from an unsorted one"
            )
        if list(case.missing) != sorted(case.missing):
            issues.append(
                f"{case.label}: `missing` is not lexicographically sorted, so "
                "`missing[0]`/`missing[1]` do not mean first/second"
            )

    outputs: dict[str, str] = {}
    for seed in _HASH_SEEDS:
        stdout, error = _run_probe_under(seed)
        if error is not None:
            issues.append(error)
            continue
        outputs[seed] = stdout

    if len(outputs) == len(_HASH_SEEDS):
        distinct = sorted(set(outputs.values()))
        if len(distinct) != 1:
            differing = sorted(s for s in outputs if outputs[s] != outputs["0"])
            issues.append(
                f"probe output is NOT identical across {len(_HASH_SEEDS)} hash "
                f"seeds: {len(distinct)} distinct outputs, seeds differing from "
                f"seed 0: {differing} -- a rejection detail still depends on set "
                "iteration order (#597)"
            )
        else:
            lines.append(
                f"PASS  probe output byte-identical across "
                f"{len(_HASH_SEEDS)} PYTHONHASHSEED values"
            )

    report: dict[str, dict] = {}
    if outputs:
        # A probe that exits 0 while printing something unparseable is a probe
        # failure, reported as one. Letting `json.loads` raise here would abort
        # the whole verifier with a traceback instead of a `FAIL:` line -- still
        # fail-closed, but illegible.
        raw = outputs[sorted(outputs)[0]]
        try:
            report = {row["label"]: row for row in json.loads(raw)}
        except (ValueError, KeyError, TypeError) as e:
            issues.append(f"probe stdout is not the expected JSON shape: {e}")

    if report:
        for case in CASES:
            row = report.get(case.label)
            if row is None:
                issues.append(f"{case.label}: probe emitted no row for this case")
                continue
            if len(case.missing) < 2:
                continue
            first, second = case.missing[0], case.missing[1]
            case_issues = _check_case_outcome(
                case.label, case.site, "base", row["base"], first,
                tuple(k for k in case.missing if k != first),
            )
            case_issues += _check_case_outcome(
                case.label, case.site, "missing[0] restored", row["restored"], second,
                tuple(k for k in case.missing if k != second),
            )
            issues.extend(case_issues)
            if not case_issues:
                lines.append(
                    f"PASS  {case.label}: {len(case.missing)} absent, reports "
                    f"{first!r}, then {second!r} once {first!r} is restored"
                )

    modules = _codec_modules()
    if not modules:
        issues.append(
            f"no *.py under {_CODEC_DIR} -- both structural checks below would "
            "report no violations having read nothing"
        )

    call_sites = _helper_call_sites(modules)
    declared = [case.site for case in CASES]
    duplicates = sorted({s for s in declared if declared.count(s) > 1})
    for duplicate in duplicates:
        issues.append(
            f"two or more cases declare site {duplicate!r} -- a duplicate hides "
            "an uncovered site behind a set comparison that still balances"
        )

    uncovered = sorted(set(call_sites) - set(declared))
    for site in uncovered:
        issues.append(
            f"{site} calls `{_HELPER}` (line(s) {call_sites[site]}) but no case "
            "exercises it -- a new required-key check this section does not cover"
        )
    orphaned = sorted(set(declared) - set(call_sites))
    for site in orphaned:
        issues.append(
            f"a case declares site {site!r}, which no longer calls `{_HELPER}` "
            "-- the case has drifted off the check it was written for"
        )

    if not (duplicates or uncovered or orphaned):
        lines.append(
            f"PASS  {len(call_sites)} required-key call sites under codec/, "
            f"each matched to its own case by enclosing function"
        )

    raw = _raw_required_set_iterations(modules)
    if raw:
        issues.append(
            f"required-key set(s) iterated directly rather than through "
            f"`{_HELPER}`: {raw} -- set iteration order is what #597 was"
        )
    else:
        lines.append(
            f"PASS  no required-key set iterated directly in "
            f"{len(modules)} codec/ module(s)"
        )

    if issues:
        return False, issues
    return True, lines
