#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     # Exact pin, the convention for a dependency on a gate's path: a parser
#     # change is a deliberate edit, never a `uv` resolution drifting under us.
#     "pyyaml==6.0.3",
# ]
# ///
r"""Assert that CI still RUNS the gates this repo relies on (#657).

WHY THIS EXISTS
---------------
`test.yml` gained a step running the cross-language differential replay
(#647), and deleting it red nothing: no test, guard or `--self-test` read a
workflow file, and `actionlint` checks syntax, not step presence. That is the
failure #647 itself was -- a gate that exists and does not run -- and it is
not specific to that step. A required JOB that is deleted is loud (its
required status check never reports and the PR cannot merge); a STEP removed
from inside a required job is silent, because the job still goes green.

WHAT IT CHECKS
--------------
For every row of `REQUIRED_STEPS` -- (workflow file, job id, command, env):

1. The workflow parses, and runs on `pull_request` with no `branches` /
   `paths` filter that could skip it.
2. The job exists, has no job-level `if:` and no `continue-on-error`.
3. The job can run on a Linux runner: `runs-on` is an `ubuntu-*` label, or
   `${{ matrix.os }}` over a plain list holding one. Any other shape
   (`include`/`exclude`, an expression we cannot evaluate) FAILS CLOSED.
4. Some `run:` step in that job equals the command exactly, after collapsing
   whitespace (so a folded `>-` block matches its one-line form, and
   `echo <command>` or a commented-out step does not).
5. That step has no `continue-on-error` and its `if:` is absent or exactly
   one of `ALLOWED_STEP_CONDITIONS`.
6. Every `env` pair the row names is set on that step, job or workflow.

The YAML is PARSED, never grepped: a grep finds a commented-out step, and an
unquoted ` #` in a scalar silently truncates it while staying valid YAML (#470).

LIMITS
------
- Only Linux reachability is checked. Dropping the macOS leg of a matrix is
  not caught; no row here needs macOS to be meaningful.
- Steps BEFORE the pinned one (checkout, toolchain install) are not checked.
  Removing one breaks the pinned step loudly, so it is not a silent gap.
- The guard cannot pin its own invocation: if its step is deleted, nothing
  runs to notice. Its two rows below are checked whenever it does run; what
  keeps the job itself present is listing `ci wiring` as a required status
  check on `main`, where a deleted or renamed job blocks every merge.
- Platform jobs (Swift, Kotlin, Android, desktop vitest) are not rows. They
  are required status checks, so deleting the JOB is caught; emptying its
  steps is not.

Usage:
    uv run scripts/check-ci-wiring.py --self-test   # controls, no files read
    uv run scripts/check-ci-wiring.py               # the real workflows
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW_DIR = Path(".github/workflows")

LINUX_LABEL_PREFIX = "ubuntu-"
MATRIX_OS_EXPR = "${{ matrix.os }}"
ALLOWED_STEP_CONDITIONS = frozenset({"runner.os == 'Linux'"})
# A trigger filter that can make a PR skip the workflow entirely.
SKIPPING_TRIGGER_KEYS = frozenset({"branches", "branches-ignore", "paths", "paths-ignore"})


@dataclass(frozen=True)
class RequiredStep:
    workflow: str
    job: str
    command: str
    env: dict[str, str] = field(default_factory=dict)


TEST_YML = "test.yml"
LINT_YML = "rust-lint.yml"

REQUIRED_STEPS: tuple[RequiredStep, ...] = (
    # --- test.yml: the behaviour gate ---
    RequiredStep(TEST_YML, "rust-test", "cargo build --release --locked --workspace"),
    RequiredStep(TEST_YML, "rust-test", "cargo test --release --locked --workspace"),
    RequiredStep(
        TEST_YML,
        "rust-test",
        "cargo test --release --locked -p secretary-core"
        " --features differential-replay --test differential_replay",
    ),
    RequiredStep(TEST_YML, "clean-room-conformance", "uv run core/tests/python/conformance.py"),
    RequiredStep(TEST_YML, "swift-log-hygiene", "bash ios/scripts/check-public-log-hygiene.sh --self-test"),
    RequiredStep(TEST_YML, "swift-log-hygiene", "bash ios/scripts/check-public-log-hygiene.sh"),
    RequiredStep(TEST_YML, "kotlin-log-hygiene", "bash android/scripts/check-log-hygiene.sh --self-test"),
    RequiredStep(TEST_YML, "kotlin-log-hygiene", "bash android/scripts/check-log-hygiene.sh"),
    RequiredStep(TEST_YML, "rust-error-payload-hygiene", "uv run scripts/check-error-payload-hygiene.py --self-test"),
    RequiredStep(TEST_YML, "rust-error-payload-hygiene", "uv run scripts/check-error-payload-hygiene.py"),
    RequiredStep(TEST_YML, "rust-error-payload-hygiene", "uv run scripts/check-test-support-placement.py --self-test"),
    RequiredStep(TEST_YML, "rust-error-payload-hygiene", "uv run scripts/check-test-support-placement.py"),
    RequiredStep(TEST_YML, "rust-secret-slot-hygiene", "bash scripts/check-secret-slot-hygiene.sh --self-test"),
    RequiredStep(TEST_YML, "rust-secret-slot-hygiene", "bash scripts/check-secret-slot-hygiene.sh"),
    RequiredStep(TEST_YML, "ci-wiring", "uv run scripts/check-ci-wiring.py --self-test"),
    RequiredStep(TEST_YML, "ci-wiring", "uv run scripts/check-ci-wiring.py"),
    # --- rust-lint.yml: fmt / clippy / doc and two tripwires ---
    RequiredStep(LINT_YML, "fmt", "cargo fmt --all --check"),
    RequiredStep(LINT_YML, "clippy", "cargo clippy --release --locked --workspace --tests -- -D warnings"),
    RequiredStep(
        LINT_YML,
        "clippy",
        "cargo clippy --release --locked -p secretary-core"
        " --features differential-replay --tests -- -D warnings",
    ),
    # Without the env pair this step documents and denies nothing.
    RequiredStep(LINT_YML, "doc", "cargo doc --no-deps --locked --workspace", {"RUSTDOCFLAGS": "-D warnings"}),
    RequiredStep(LINT_YML, "lean-binding", "bash ffi/scripts/check-lean-binding.sh --self-test"),
    RequiredStep(LINT_YML, "lean-binding", "bash ffi/scripts/check-lean-binding.sh"),
    RequiredStep(
        LINT_YML,
        "deps-script-selftest",
        "RETRY_SLEEP=0 bash .github/scripts/install-tauri-linux-deps.sh --self-test",
    ),
)

# Finding reasons. Each is a stable token the self-test asserts on, never
# message text.
NO_WORKFLOW = "no_workflow"
UNPARSEABLE = "unparseable"
TRIGGER = "trigger"
NO_JOB = "no_job"
JOB_CONDITION = "job_condition"
NO_LINUX_RUNNER = "no_linux_runner"
NO_STEP = "no_step"
STEP_CONDITION = "step_condition"
CONTINUE_ON_ERROR = "continue_on_error"
ENV = "env"
ALL_REASONS = frozenset(
    {NO_WORKFLOW, UNPARSEABLE, TRIGGER, NO_JOB, JOB_CONDITION, NO_LINUX_RUNNER,
     NO_STEP, STEP_CONDITION, CONTINUE_ON_ERROR, ENV}
)


@dataclass(frozen=True)
class Finding:
    row: RequiredStep
    reason: str
    detail: str

    def render(self) -> str:
        r = self.row
        return f"FAIL [{self.reason}] {r.workflow} / {r.job} / `{r.command}`: {self.detail}"


def normalize(command: str) -> str:
    """Collapse all whitespace, so a folded `>-` block equals its one-line form."""
    return " ".join(command.split())


def parse_workflow(text: str) -> dict:
    """Parse one workflow; raise ValueError unless it is a mapping with `jobs`."""
    doc = yaml.safe_load(text)
    if not isinstance(doc, dict) or not isinstance(doc.get("jobs"), dict):
        raise ValueError("not a mapping with a `jobs` mapping")
    return doc


def trigger_problem(doc: dict) -> str | None:
    """Why this workflow might not run on a pull request, or None."""
    # YAML 1.1 reads the bare key `on` as boolean True.
    on = doc.get("on", doc.get(True))
    if isinstance(on, str):
        on = [on]
    if isinstance(on, list):
        return None if "pull_request" in on else "no `pull_request` trigger"
    if not isinstance(on, dict) or "pull_request" not in on:
        return "no `pull_request` trigger"
    pr = on["pull_request"]
    if pr is None:
        return None
    if not isinstance(pr, dict):
        return f"unrecognised `pull_request` value {pr!r}"
    skipping = sorted(SKIPPING_TRIGGER_KEYS & pr.keys())
    return f"`pull_request` filtered by {skipping}" if skipping else None


def runner_labels(job: dict) -> list[str] | None:
    """The runner labels a job can land on, or None if we cannot tell."""
    runs_on = job.get("runs-on")
    if isinstance(runs_on, str) and "${{" not in runs_on:
        return [runs_on]
    if runs_on == MATRIX_OS_EXPR:
        matrix = (job.get("strategy") or {}).get("matrix")
        if isinstance(matrix, dict) and set(matrix) == {"os"} and isinstance(matrix["os"], list):
            return [label for label in matrix["os"] if isinstance(label, str)]
    return None


def is_set_true(value: object) -> bool:
    """`continue-on-error` is off only when absent or literally false."""
    return value is not None and value is not False


def job_problems(job: dict) -> list[tuple[str, str]]:
    problems = []
    if "if" in job:
        problems.append((JOB_CONDITION, f"job-level `if: {job['if']}`"))
    if is_set_true(job.get("continue-on-error")):
        problems.append((CONTINUE_ON_ERROR, "job-level `continue-on-error`"))
    labels = runner_labels(job)
    if labels is None:
        problems.append((NO_LINUX_RUNNER, f"cannot evaluate `runs-on: {job.get('runs-on')!r}`"))
    elif not any(label.startswith(LINUX_LABEL_PREFIX) for label in labels):
        problems.append((NO_LINUX_RUNNER, f"no `{LINUX_LABEL_PREFIX}*` runner in {labels}"))
    return problems


def step_problems(row: RequiredStep, doc: dict, job: dict, step: dict) -> list[tuple[str, str]]:
    problems = []
    condition = step.get("if")
    if condition is not None and normalize(str(condition)) not in ALLOWED_STEP_CONDITIONS:
        problems.append((STEP_CONDITION, f"step `if: {condition}`"))
    if is_set_true(step.get("continue-on-error")):
        problems.append((CONTINUE_ON_ERROR, "step-level `continue-on-error`"))
    for key, want in row.env.items():
        # Innermost scope wins, as in GitHub Actions.
        scopes = (step.get("env") or {}, job.get("env") or {}, doc.get("env") or {})
        got = next((s[key] for s in scopes if key in s), None)
        if got != want:
            problems.append((ENV, f"`{key}` is {got!r}, want {want!r}"))
    return problems


def check_row(row: RequiredStep, workflows: dict[str, str | None]) -> list[Finding]:
    """All findings for one row. `workflows` maps file name -> text (None = absent)."""
    text = workflows.get(row.workflow)
    if text is None:
        return [Finding(row, NO_WORKFLOW, "workflow file not found")]
    try:
        doc = parse_workflow(text)
    except (yaml.YAMLError, ValueError) as e:
        return [Finding(row, UNPARSEABLE, str(e).splitlines()[0])]
    findings = []
    if (why := trigger_problem(doc)) is not None:
        findings.append(Finding(row, TRIGGER, why))
    job = doc["jobs"].get(row.job)
    if not isinstance(job, dict):
        return findings + [Finding(row, NO_JOB, "job not found")]
    findings += [Finding(row, r, d) for r, d in job_problems(job)]
    steps = [s for s in job.get("steps") or [] if isinstance(s, dict)]
    candidates = [s for s in steps if isinstance(s.get("run"), str) and normalize(s["run"]) == row.command]
    if not candidates:
        return findings + [Finding(row, NO_STEP, "no `run:` step with exactly this command")]
    per_candidate = [step_problems(row, doc, job, s) for s in candidates]
    if all(per_candidate):  # every copy is disabled somehow; report the first
        findings += [Finding(row, r, d) for r, d in per_candidate[0]]
    return findings


def check_all(rows: tuple[RequiredStep, ...], workflows: dict[str, str | None]) -> list[Finding]:
    return [f for row in rows for f in check_row(row, workflows)]


def read_workflows(root: Path, rows: tuple[RequiredStep, ...]) -> dict[str, str | None]:
    out = {}
    for name in sorted({r.workflow for r in rows}):
        path = root / WORKFLOW_DIR / name
        out[name] = path.read_text(encoding="utf-8") if path.is_file() else None
    return out


def run_real_check() -> int:
    if not REQUIRED_STEPS:
        print("FAIL: REQUIRED_STEPS is empty; the guard would check nothing")
        return 1
    findings = check_all(REQUIRED_STEPS, read_workflows(REPO_ROOT, REQUIRED_STEPS))
    for f in findings:
        print(f.render())
    if findings:
        print(f"FAIL: {len(findings)} finding(s); a gate CI relies on is no longer run")
        return 1
    files = len({r.workflow for r in REQUIRED_STEPS})
    print(f"OK: {len(REQUIRED_STEPS)} required steps wired across {files} workflows")
    return 0


# ---------------------------------------------------------------------------
# --self-test: every control is an edit to a GOOD in-memory fixture, so no file
# is written (cf. #516) and the real workflows are not read.
# ---------------------------------------------------------------------------

FIXTURE_FILE = "fixture.yml"
FIXTURE_LINUX_CMD = "cargo test --features x --test y"
FIXTURE_ENV_CMD = "cargo doc --workspace"
FIXTURE = """\
name: Fixture
on:
  push:
    branches: [main]
  pull_request:
jobs:
  matrixed:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-26]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - name: 'replay'
        if: runner.os == 'Linux'
        run: >-
          cargo test --features x
          --test y
  plain:
    runs-on: ubuntu-latest
    env:
      FLAGS: -D warnings
    steps:
      - name: 'doc'
        run: cargo doc --workspace
"""
FIXTURE_ROWS = (
    RequiredStep(FIXTURE_FILE, "matrixed", FIXTURE_LINUX_CMD),
    RequiredStep(FIXTURE_FILE, "plain", FIXTURE_ENV_CMD, {"FLAGS": "-D warnings"}),
)

REPLAY_STEP = """\
      - name: 'replay'
        if: runner.os == 'Linux'
        run: >-
          cargo test --features x
          --test y
"""
NO_EDIT = ("", "")
# (label, (old, new) text edit or None to delete the file, expected reason;
# None = must pass with no finding).
CONTROLS: tuple[tuple[str, tuple[str, str] | None, str | None], ...] = (
    ("N1 the fixture as written passes", NO_EDIT, None),
    ("N2 one runnable copy among disabled ones passes",
     (REPLAY_STEP, REPLAY_STEP + REPLAY_STEP.replace("runner.os == 'Linux'", "false")), None),
    ("N3 step `if` may be the Linux gate with extra spaces",
     ("if: runner.os == 'Linux'", "if: runner.os  ==  'Linux'"), None),
    ("P1 step deleted", (REPLAY_STEP, ""), NO_STEP),
    ("P2 step commented out", (REPLAY_STEP, "".join("#" + l + "\n" for l in REPLAY_STEP.splitlines())), NO_STEP),
    ("P3 command renamed", ("--test y", "--test z"), NO_STEP),
    ("P4 command only echoed", ("cargo test --features x\n", "echo cargo test --features x\n"), NO_STEP),
    ("P5 step `if: false`", ("if: runner.os == 'Linux'", "if: false"), STEP_CONDITION),
    ("P6 step continue-on-error", ("if: runner.os == 'Linux'\n", "if: runner.os == 'Linux'\n        continue-on-error: true\n"), CONTINUE_ON_ERROR),
    ("P7 job continue-on-error", ("  plain:\n", "  plain:\n    continue-on-error: true\n"), CONTINUE_ON_ERROR),
    ("P8 job-level `if`", ("  plain:\n", "  plain:\n    if: github.event_name == 'push'\n"), JOB_CONDITION),
    ("P9 matrix lost its Linux leg", ("os: [ubuntu-latest, macos-26]", "os: [macos-26]"), NO_LINUX_RUNNER),
    ("P10 matrix shape we cannot evaluate", ("os: [ubuntu-latest, macos-26]\n", "os: [ubuntu-latest, macos-26]\n        include: [{os: windows-latest}]\n"), NO_LINUX_RUNNER),
    ("P11 runs-on is not Linux", ("runs-on: ubuntu-latest", "runs-on: macos-26"), NO_LINUX_RUNNER),
    ("P12 no pull_request trigger", ("  pull_request:\n", ""), TRIGGER),
    ("P13 pull_request path-filtered", ("  pull_request:\n", "  pull_request:\n    paths: ['ios/**']\n"), TRIGGER),
    ("P14 required env dropped", ("    env:\n      FLAGS: -D warnings\n", ""), ENV),
    ("P15 required env overridden on the step", ("        run: cargo doc", "        env: {FLAGS: ''}\n        run: cargo doc"), ENV),
    ("P16 job deleted", ("  plain:\n", "  renamed:\n"), NO_JOB),
    ("P17 workflow file missing", None, NO_WORKFLOW),
    ("P18 workflow unparseable", ("jobs:\n", "jobs: [\n"), UNPARSEABLE),
)


def apply_edit(edit: tuple[str, str] | None) -> str | None:
    """The fixture after one edit. An edit that matches nothing is a broken
    control, not a pass: a no-op mutation proves nothing (#644)."""
    if edit is None:
        return None
    old, new = edit
    if edit == NO_EDIT:
        return FIXTURE
    if FIXTURE.count(old) != 1:
        raise AssertionError(f"control edit matches {FIXTURE.count(old)} times, want 1: {old!r}")
    return FIXTURE.replace(old, new)


def run_self_test() -> int:
    failures, ran = [], 0
    for label, edit, want in CONTROLS:
        ran += 1
        try:
            findings = check_all(FIXTURE_ROWS, {FIXTURE_FILE: apply_edit(edit)})
        except Exception as e:  # a crashing control is a named FAIL, not an abort
            failures.append(f"{label}: raised {e!r}")
            continue
        reasons = {f.reason for f in findings}
        if want is None and findings:
            failures.append(f"{label}: want no finding, got {sorted(reasons)}")
        elif want is not None and want not in reasons:
            failures.append(f"{label}: want [{want}], got {sorted(reasons) or 'nothing'}")
    uncovered = ALL_REASONS - {want for _, _, want in CONTROLS}
    if uncovered:
        failures.append(f"no positive control for reason(s) {sorted(uncovered)}")
    for line in failures:
        print(f"FAIL: {line}")
    if failures or ran != len(CONTROLS):
        print(f"FAIL: self-test ({ran}/{len(CONTROLS)} controls ran, {len(failures)} failed)")
        return 1
    print(f"OK: self-test, {ran}/{len(CONTROLS)} controls, every finding reason covered")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        return run_self_test()
    if argv:
        print(f"usage: check-ci-wiring.py [--self-test]; got {argv}", file=sys.stderr)
        return 2
    return run_real_check()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
