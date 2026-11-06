"""`--self-test` for the CI-wiring guard: controls on an in-memory fixture."""

from __future__ import annotations

import contextlib
import io
import tempfile
from pathlib import Path

from ci_wiring import rules
from ci_wiring.rules import (
    ALL_REASONS, CONTINUE_ON_ERROR, ENV, JOB_CONDITION, NEEDS, NO_JOB, NO_LINUX_RUNNER,
    NO_STEP, NO_WORKFLOW, RUN_OVERRIDE, STEP_CONDITION, TRIGGER,
    UNPARSEABLE, WORKFLOW_DIR, RequiredStep, check_all, run_check,
)

# ---------------------------------------------------------------------------
# --self-test: every control is an edit to a GOOD in-memory fixture, checked
# in memory; the end-to-end checks write that fixture only into a mktemp dir
# (cf. #516). The real workflows are never read.
# ---------------------------------------------------------------------------

FIXTURE_FILE = "fixture.yml"
FIXTURE_LINUX_CMD = "cargo test --features x --test y"
FIXTURE_ENV_CMD = "cargo doc --workspace"
FIXTURE_ON = """\
on:
  push:
    branches: [main]
  pull_request:
"""
FIXTURE_ENV = "    env:\n      FLAGS: -D warnings\n"
FIXTURE = f"""\
name: Fixture
{FIXTURE_ON}jobs:
  matrixed:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-26]
    runs-on: ${{{{ matrix.os }}}}
    steps:
      - uses: actions/checkout@v4
      - name: 'replay'
        if: runner.os == 'Linux'
        run: >-
          cargo test --features x
          --test y
  plain:
    runs-on: ubuntu-latest
{FIXTURE_ENV}    steps:
      - name: 'doc'
        run: cargo doc --workspace
"""
FIXTURE_ROWS = (
    RequiredStep(FIXTURE_FILE, "matrixed", FIXTURE_LINUX_CMD, linux_only=True),
    RequiredStep(FIXTURE_FILE, "plain", FIXTURE_ENV_CMD, {"FLAGS": "-D warnings"}),
)

REPLAY_STEP = """\
      - name: 'replay'
        if: runner.os == 'Linux'
        run: >-
          cargo test --features x
          --test y
"""
LINUX_IF = "if: runner.os == 'Linux'"
PLAIN = "  plain:\n"
PLAIN_RUN = "        run: cargo doc"
PR = "  pull_request:\n"
JOBS = "jobs:\n"
BAD_SHELL = "{run: {shell: 'true {0}'}}"
# Spelled out rather than read from SKIPPING_TRIGGER_KEYS, so dropping a key
# there reds its control here instead of silently dropping the control too.
PINNED_SKIPPING_KEYS = ("branches", "branches-ignore", "paths", "paths-ignore", "types")
Edit = tuple[tuple[str, str], ...]


def one(old: str, new: str) -> Edit:
    return ((old, new),)


# (label, edits -- a sequence of exact-once (old, new) replacements, or None to
# delete the file -- and the expected reason; None = must pass with no finding).
CONTROLS: tuple[tuple[str, Edit | None, str | None], ...] = (
    ("N1 the fixture as written passes", (), None),
    ("N2 one runnable copy among disabled ones passes",
     one(REPLAY_STEP, REPLAY_STEP + REPLAY_STEP.replace(LINUX_IF, "if: false")), None),
    ("N3 Linux gate with extra spaces on a linux_only row", one(LINUX_IF, "if: runner.os  ==  'Linux'"), None),
    ("N4 `on:` as a bare string", one(FIXTURE_ON, "on: pull_request\n"), None),
    ("N5 env set at workflow level", ((FIXTURE_ENV, ""), (JOBS, "env:\n  FLAGS: -D warnings\n" + JOBS)), None),
    ("N6 one-line `|` literal block", one(PLAIN_RUN + " --workspace", "        run: |\n          cargo doc --workspace"), None),
    ("P1 step deleted", one(REPLAY_STEP, ""), NO_STEP),
    ("P2 step commented out", one(REPLAY_STEP, "".join("#" + l + "\n" for l in REPLAY_STEP.splitlines())), NO_STEP),
    ("P3 command renamed", one("--test y", "--test z"), NO_STEP),
    ("P4 command only echoed", one("cargo test --features x\n", "echo cargo test --features x\n"), NO_STEP),
    ("P5 step `if: false`", one(LINUX_IF, "if: false"), STEP_CONDITION),
    ("P6 Linux gate on a row that is not linux_only", one(PLAIN_RUN, f"        {LINUX_IF}\n{PLAIN_RUN}"), STEP_CONDITION),
    ("P7 step continue-on-error expression",
     one(LINUX_IF + "\n", LINUX_IF + "\n        continue-on-error: ${{ matrix.x }}\n"), CONTINUE_ON_ERROR),
    ("P8 job continue-on-error", one(PLAIN, PLAIN + "    continue-on-error: true\n"), CONTINUE_ON_ERROR),
    ("P9 job-level `if` expression", one(PLAIN, PLAIN + "    if: github.event_name == 'push'\n"), JOB_CONDITION),
    ("P10 job-level `if: false`", one(PLAIN, PLAIN + "    if: false\n"), JOB_CONDITION),
    ("P11 job `needs:`", one(PLAIN, PLAIN + "    needs: matrixed\n"), NEEDS),
    ("P12 matrix lost its Linux leg", one("os: [ubuntu-latest, macos-26]", "os: [macos-26]"), NO_LINUX_RUNNER),
    ("P13 matrix shape we cannot evaluate",
     one("os: [ubuntu-latest, macos-26]\n", "os: [ubuntu-latest, macos-26]\n        include: [{os: windows-latest}]\n"),
     NO_LINUX_RUNNER),
    ("P14 runs-on is not Linux", one("runs-on: ubuntu-latest", "runs-on: macos-26"), NO_LINUX_RUNNER),
    ("P15 no pull_request trigger", one(PR, ""), TRIGGER),
    ("P16 `on:` list without pull_request", one(FIXTURE_ON, "on: [push]\n"), TRIGGER),
    ("P17 unrecognised pull_request value", one(PR, "  pull_request: [opened]\n"), TRIGGER),
    *((f"P18 pull_request filtered by `{key}`", one(PR, f"{PR}    {key}: [x]\n"), TRIGGER)
      for key in PINNED_SKIPPING_KEYS),
    ("P19 required env dropped", one(FIXTURE_ENV, ""), ENV),
    ("P20 required env overridden on the step", one(PLAIN_RUN, f"        env: {{FLAGS: ''}}\n{PLAIN_RUN}"), ENV),
    ("P21 env that is not a mapping", one(FIXTURE_ENV, "    env: FLAGS\n"), ENV),
    ("P22 step `shell:`", one(PLAIN_RUN, f"        shell: 'true {{0}}'\n{PLAIN_RUN}"), RUN_OVERRIDE),
    ("P23 step `working-directory:`", one(PLAIN_RUN, f"        working-directory: core/fuzz\n{PLAIN_RUN}"), RUN_OVERRIDE),
    ("P24 job `defaults.run.shell`", one(PLAIN, f"{PLAIN}    defaults: {BAD_SHELL}\n"), RUN_OVERRIDE),
    ("P25 workflow `defaults.run.shell`", one(JOBS, f"defaults: {BAD_SHELL}\n{JOBS}"), RUN_OVERRIDE),
    ("P26 job deleted", one(PLAIN, "  renamed:\n"), NO_JOB),
    ("P27 workflow file missing", None, NO_WORKFLOW),
    ("P28 workflow unparseable", one(JOBS, "jobs: [\n"), UNPARSEABLE),
    ("P29 workflow has no `jobs:`", one(JOBS, "steps:\n"), UNPARSEABLE),
)


def apply_edit(edits: Edit | None) -> str | None:
    """The fixture after its edits. An edit that matches nothing is a broken
    control, not a pass: a no-op mutation proves nothing (#644)."""
    if edits is None:
        return None
    text = FIXTURE
    for old, new in edits:
        if text.count(old) != 1:
            raise AssertionError(f"control edit matches {text.count(old)} times, want 1: {old!r}")
        text = text.replace(old, new)
    return text


def run_check_on(text: str, rows: tuple[RequiredStep, ...]) -> int:
    """`run_check` on a throwaway tree holding the fixture text, output swallowed."""
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / WORKFLOW_DIR).mkdir(parents=True)
        (Path(tmp) / WORKFLOW_DIR / FIXTURE_FILE).write_text(text, encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()):
            return run_check(Path(tmp), rows)


def main_reaches_real_check() -> bool:
    """`main([])` must dispatch to `run_real_check`; swap in a recorder to see it."""
    sentinel, real = 97, rules.run_real_check
    rules.run_real_check = lambda: sentinel
    try:
        return rules.main([]) == sentinel
    finally:
        rules.run_real_check = real


def rejects_bogus_argument() -> bool:
    with contextlib.redirect_stderr(io.StringIO()):
        return rules.main(["--bogus"]) == 2


# The real-run path end to end: exit codes, the "checked nothing" floor, and
# the CLI dispatch. Without these, `if findings:` -> `if False:` stayed green.
END_TO_END: tuple[tuple[str, object], ...] = (
    ("E1 clean tree exits 0", lambda: run_check_on(FIXTURE, FIXTURE_ROWS) == 0),
    ("E2 broken tree exits 1", lambda: run_check_on(apply_edit(one(REPLAY_STEP, "")), FIXTURE_ROWS) == 1),
    ("E3 empty table exits 1", lambda: run_check_on(FIXTURE, ()) == 1),
    ("E4 unknown argument exits 2", rejects_bogus_argument),
    ("E5 no argument runs the real check", main_reaches_real_check),
)


def run_self_test() -> int:
    failures, ran = [], 0
    for label, edit, want in CONTROLS:
        ran += 1
        try:
            findings, _ = check_all(FIXTURE_ROWS, {FIXTURE_FILE: apply_edit(edit)})
        except Exception as e:  # a crashing control is a named FAIL, not an abort
            failures.append(f"{label}: raised {e!r}")
            continue
        reasons = {f.reason for f in findings}
        if want is None and findings:
            failures.append(f"{label}: want no finding, got {sorted(reasons)}")
        elif want is not None and want not in reasons:
            failures.append(f"{label}: want [{want}], got {sorted(reasons) or 'nothing'}")
    for label, check in END_TO_END:
        ran += 1
        try:
            if not check():
                failures.append(f"{label}: wrong result")
        except Exception as e:
            failures.append(f"{label}: raised {e!r}")
    uncovered = ALL_REASONS - {want for _, _, want in CONTROLS}
    if uncovered:
        failures.append(f"no positive control for reason(s) {sorted(uncovered)}")
    total = len(CONTROLS) + len(END_TO_END)
    for line in failures:
        print(f"FAIL: {line}")
    if failures or ran != total:
        print(f"FAIL: self-test ({ran}/{total} checks ran, {len(failures)} failed)")
        return 1
    # ALL_REASONS is hand-listed; Finding refuses any reason not in it.
    print(f"OK: self-test, {ran}/{total} checks, every reason in ALL_REASONS has a control")
    return 0
