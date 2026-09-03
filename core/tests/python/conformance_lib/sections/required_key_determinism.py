"""Section DET -- a missing required key is reported deterministically (#597).

THE DEFECT. THREE of this verifier's seven `codec/` required-key presence
checks were written as `for k in SOME_REQUIRED_SET: if k not in decoded: raise`
-- the other four already wrote `sorted(...)` by hand, which is the whole
argument for putting the rule in one named helper rather than in seven
independent copies. A Python `set`/`frozenset` of strings iterates in hash
order, and CPython salts string hashing once per PROCESS, so when an input
omitted more than one required key those three named whichever key they
happened to reach first -- a different one from run to run. #597 records six
consecutive runs over one fuzz seed alternating between `self_sig_ed` and
`self_sig_pq`.

Say `codec/` and not "this verifier": there is an EIGHTH required-key check,
`wire/card.py`, deliberately outside the helper and outside this section's
table, because it reports the whole missing set already sorted and so has no
first-key choice to make.

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

  3. STRUCTURE, both directions -- `required_key_structure`. Every `codec/`
     call site of the helper must have a case (a new site with no case reds),
     and no `codec/` construct may select a key from a required-key set
     without imposing an order first (a new site that bypasses the helper
     reds). Check 3 is what makes checks 1 and 2 more than a snapshot of
     seven inputs. Read that module's LIMITS block for what its two scans do
     and do not see -- the gaps are enumerated there rather than summarised
     here, so the two cannot drift.

WHAT MAKES EACH CHECK NON-VACUOUS, since the #605 review found four ways this
section could report PASS having verified less than it claims:

  * Check 1 compares eight outputs for equality and would be satisfied by one
    output compared with itself, so `_HASH_SEEDS` is asserted to hold at least
    two DISTINCT seeds. It would also be satisfied by eight identical
    catastrophes, which is why check 2 is not optional (below).
  * The probe reports which package it actually imported, and that must be the
    package this section scanned. `python -m` puts the child's CWD on
    `sys.path[0]`, AHEAD of the `PYTHONPATH` `_run_probe_under` sets, so
    running the verifier from a directory holding another `conformance_lib`
    used to have the probe verify one tree while the structural scans read
    another -- measured GREEN on a tree carrying the verbatim #597 defect.
  * The report must carry a row for EXACTLY the declared cases. A probe
    emitting `[]` used to skip check 2 in full, with no issue and no
    diagnostic line: PASS, three lines, the seven per-case lines simply gone.
  * Each case's site must be unique AND hold exactly one helper call, so two
    checks in one function cannot share a case.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from conformance_lib.required_key_probe import (
    CASES,
    OUTCOME_KEYS,
    PACKAGE_KEY,
    ROW_KEYS,
    ROWS_KEY,
)
from conformance_lib.sections.required_key_structure import (
    CODEC_DIR,
    HELPER,
    helper_call_sites,
    parse_codec_modules,
)
from conformance_lib.sections.required_key_structure import (
    unmediated_required_selections,
)

# Eight fixed seeds, not `random`: a fixed set makes a regression a
# deterministic red rather than an intermittent one. Measured against the
# pre-fix decoders, these eight produce SEVEN distinct outputs, so the check
# is not relying on a lucky pair. That measurement lives in this comment; what
# the code enforces is the weaker precondition it depends on -- that the seeds
# differ at all -- because `_HASH_SEEDS = ("0",)` used to pass, printing
# `PASS probe output byte-identical across 1 PYTHONHASHSEED values`.
_HASH_SEEDS = ("0", "1", "2", "3", "4", "5", "6", "7")

_PROBE_MODULE = "conformance_lib.required_key_probe"
_PACKAGE_ROOT = CODEC_DIR.parent


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
            capture_output=True,
            text=True,
            env=env,
            # LOAD-BEARING, not tidiness. `python -m` prepends the child's CWD
            # to `sys.path` ahead of every `PYTHONPATH` entry, so without this
            # the probe imports whichever `conformance_lib` the caller happened
            # to be standing in. Pinning the CWD to the package's own parent
            # makes that prepended entry the right one. The probe also reports
            # the package it loaded, which is what actually PROVES this.
            cwd=parent,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as e:
        return "", f"probe under PYTHONHASHSEED={seed} could not run: {e}"
    if completed.returncode != 0:
        return "", (
            f"probe under PYTHONHASHSEED={seed} exited {completed.returncode}: "
            f"{completed.stderr.strip()}"
        )
    return completed.stdout, None


def _parse_report(raw: str) -> tuple[dict[str, dict], list[str]]:
    """The probe's rows keyed by label, or the issues that stopped the parse.

    Every shape assumption is checked HERE. Letting one raise instead would
    abort the whole verifier with a traceback rather than a `FAIL:` line --
    still fail-closed, but illegible, and `conformance.py`'s documented exit
    codes promise one failure line per failed section.
    """
    issues: list[str] = []
    try:
        payload = json.loads(raw)
    except ValueError as e:
        return {}, [f"probe stdout is not valid JSON: {e}"]

    if not isinstance(payload, dict):
        return {}, [f"probe stdout is a {type(payload).__name__}, not a JSON object"]
    if PACKAGE_KEY not in payload or ROWS_KEY not in payload:
        return {}, [
            f"probe stdout is missing {PACKAGE_KEY!r} or {ROWS_KEY!r} -- the "
            "probe and this section disagree on the contract between them"
        ]

    reported = payload[PACKAGE_KEY]
    if reported != str(_PACKAGE_ROOT):
        issues.append(
            f"the probe imported {reported!r} but this section scanned "
            f"{str(_PACKAGE_ROOT)!r} -- checks 1 and 2 measured a different "
            "tree from check 3"
        )

    rows = payload[ROWS_KEY]
    if not isinstance(rows, list):
        return {}, issues + [f"probe {ROWS_KEY!r} is not a list"]

    report: dict[str, dict] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or not ROW_KEYS <= set(row):
            issues.append(f"probe row {index} is not {sorted(ROW_KEYS)}: {row!r}")
            continue
        malformed = False
        for which in ("base", "restored"):
            outcome = row[which]
            if not isinstance(outcome, dict) or not OUTCOME_KEYS <= set(outcome):
                issues.append(
                    f"probe row {index} {which!r} is not "
                    f"{sorted(OUTCOME_KEYS)}: {outcome!r}"
                )
                malformed = True
        # A row that failed validation must not reach `_check_case_outcome`,
        # which indexes both outcomes directly. Recording the issue and then
        # handing the row on anyway would raise the very `KeyError` this
        # function exists to turn into a `FAIL:` line. The row's absence is
        # itself reported, by the label-set comparison in the caller.
        if not malformed:
            report[row["label"]] = row
    return report, issues


def _check_case_outcome(
    label: str,
    site: str,
    which: str,
    outcome: dict,
    expected: str,
    other_absent: tuple[str, ...],
) -> list[str]:
    """`outcome` must be a rejection naming `expected` and no key in
    `other_absent`.

    `other_absent` is the keys STILL absent on this decode besides the expected
    one -- for the restored decode that excludes `missing[0]`, which is present
    again. Passing the whole tail would make the diagnostic claim a restored key
    was "absent but not the one the contract selects".
    """
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


def _check_case_table() -> list[str]:
    """The table's own preconditions, before any decoding."""
    issues: list[str] = []
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
    for field in ("site", "label"):
        declared = [getattr(case, field) for case in CASES]
        for duplicate in sorted({d for d in declared if declared.count(d) > 1}):
            issues.append(
                f"two or more cases declare {field} {duplicate!r} -- a duplicate "
                "hides an uncovered check behind a comparison that still balances"
            )
    if len(set(_HASH_SEEDS)) < 2:
        issues.append(
            f"_HASH_SEEDS holds {len(set(_HASH_SEEDS))} distinct value(s); "
            "check 1 would compare a run with itself and pass over any decoder"
        )
    return issues


def _check_structure(call_sites: dict[str, list[int]]) -> tuple[list[str], list[str]]:
    """The two-way census between helper call sites and declared cases."""
    issues: list[str] = []
    declared = [case.site for case in CASES]

    for site in sorted(set(call_sites) - set(declared)):
        issues.append(
            f"{site} calls `{HELPER}` (line(s) {call_sites[site]}) but no case "
            "exercises it -- a new required-key check this section does not cover"
        )
    for site in sorted(set(declared) - set(call_sites)):
        issues.append(
            f"a case declares site {site!r}, which no longer calls `{HELPER}` "
            "-- the case has drifted off the check it was written for"
        )
    for site, lines in sorted(call_sites.items()):
        if len(lines) > 1:
            issues.append(
                f"{site} calls `{HELPER}` {len(lines)} times (lines {lines}), "
                "but a case is keyed by enclosing function -- one of these "
                "checks would be covered only by the other's fixture"
            )

    lines: list[str] = []
    if not issues:
        lines.append(
            f"PASS  {len(call_sites)} required-key call sites under codec/, "
            f"each matched one-to-one to its own case by enclosing function"
        )
    return issues, lines


def section_required_key_determinism() -> tuple[bool, list[str]]:
    issues: list[str] = _check_case_table()
    lines: list[str] = []

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
        report, parse_issues = _parse_report(outputs[sorted(outputs)[0]])
        issues.extend(parse_issues)

    # Unconditional, and NOT guarded by `if report:` -- an empty report is a
    # probe that verified nothing, which is a failure rather than a reason to
    # skip the only check that reads the decoders' actual messages.
    expected_labels = {case.label for case in CASES}
    if set(report) != expected_labels:
        issues.append(
            f"probe reported rows for {sorted(report)} but the table declares "
            f"{sorted(expected_labels)} -- check 2 cannot run on this report"
        )
    for case in CASES:
        row = report.get(case.label)
        if row is None or len(case.missing) < 2:
            continue
        first, second = case.missing[0], case.missing[1]
        case_issues = _check_case_outcome(
            case.label, case.site, "base", row["base"], first, case.missing[1:]
        )
        case_issues += _check_case_outcome(
            case.label,
            case.site,
            "missing[0] restored",
            row["restored"],
            second,
            case.missing[2:],
        )
        issues.extend(case_issues)
        if not case_issues:
            lines.append(
                f"PASS  {case.label}: {len(case.missing)} absent, reports "
                f"{first!r}, then {second!r} once {first!r} is restored"
            )

    modules, scan_issues = parse_codec_modules()
    issues.extend(scan_issues)

    census_issues, census_lines = _check_structure(helper_call_sites(modules))
    issues.extend(census_issues)
    lines.extend(census_lines)

    unmediated = unmediated_required_selections(modules)
    if unmediated:
        issues.append(
            f"required-key set(s) read without an imposed order rather than "
            f"through `{HELPER}`: {unmediated} -- set iteration order is what "
            "#597 was"
        )
    else:
        lines.append(
            f"PASS  no required-key set selected from without an imposed order "
            f"in {len(modules)} codec/ module(s)"
        )

    if issues:
        return False, issues
    return True, lines
