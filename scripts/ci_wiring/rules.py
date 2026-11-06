"""The REQUIRED_STEPS table and the checks over it. See `scripts/check-ci-wiring.py`."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
WORKFLOW_DIR = Path(".github/workflows")

LINUX_LABEL_PREFIX = "ubuntu-"
MATRIX_OS_EXPR = "${{ matrix.os }}"
ALLOWED_STEP_CONDITIONS = frozenset({"runner.os == 'Linux'"})
# A trigger filter that can make a PR skip the workflow entirely.
SKIPPING_TRIGGER_KEYS = frozenset({"branches", "branches-ignore", "paths", "paths-ignore", "types"})
# Keys that change how a `run:` step executes; any value can neuter it.
RUN_OVERRIDE_KEYS = ("shell", "working-directory")


@dataclass(frozen=True)
class RequiredStep:
    workflow: str
    job: str
    command: str
    env: dict[str, str] = field(default_factory=dict)
    # May the step carry `if: runner.os == 'Linux'`? Only where the gate is
    # deliberately Linux-only; elsewhere that condition silently drops the
    # macOS leg.
    linux_only: bool = False


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
        linux_only=True,
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
        linux_only=True,
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
NEEDS = "needs"
RUN_OVERRIDE = "run_override"
ALL_REASONS = frozenset(
    {NO_WORKFLOW, UNPARSEABLE, TRIGGER, NO_JOB, JOB_CONDITION, NO_LINUX_RUNNER,
     NO_STEP, STEP_CONDITION, CONTINUE_ON_ERROR, ENV, NEEDS, RUN_OVERRIDE}
)


@dataclass(frozen=True)
class Finding:
    row: RequiredStep
    reason: str
    detail: str

    def __post_init__(self) -> None:
        # An undeclared reason would escape the self-test's coverage census.
        if self.reason not in ALL_REASONS:
            raise AssertionError(f"undeclared finding reason {self.reason!r}")

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
    if "needs" in job:
        problems.append((NEEDS, f"`needs: {job['needs']}`; a skipped dependency skips this job green"))
    labels = runner_labels(job)
    if labels is None:
        problems.append((NO_LINUX_RUNNER, f"cannot evaluate `runs-on: {job.get('runs-on')!r}`"))
    elif not any(label.startswith(LINUX_LABEL_PREFIX) for label in labels):
        problems.append((NO_LINUX_RUNNER, f"no `{LINUX_LABEL_PREFIX}*` runner in {labels}"))
    return problems


def run_overrides(scope: object, where: str) -> list[tuple[str, str]]:
    """`shell` / `working-directory` set in one `defaults.run` or step mapping."""
    if not isinstance(scope, dict):
        return [(RUN_OVERRIDE, f"cannot evaluate {where} {scope!r}")]
    return [(RUN_OVERRIDE, f"{where} sets `{k}: {scope[k]}`") for k in RUN_OVERRIDE_KEYS if k in scope]


def defaults_run(owner: dict) -> object:
    defaults = owner.get("defaults")
    if defaults is None:
        return {}
    return (defaults.get("run") or {}) if isinstance(defaults, dict) else defaults


def step_problems(row: RequiredStep, doc: dict, job: dict, step: dict) -> list[tuple[str, str]]:
    problems = []
    condition = step.get("if")
    allowed = ALLOWED_STEP_CONDITIONS if row.linux_only else frozenset()
    if condition is not None and normalize(str(condition)) not in allowed:
        problems.append((STEP_CONDITION, f"step `if: {condition}`"))
    if is_set_true(step.get("continue-on-error")):
        problems.append((CONTINUE_ON_ERROR, "step-level `continue-on-error`"))
    problems += run_overrides(step, "step")
    problems += run_overrides(defaults_run(job), "job `defaults.run`")
    problems += run_overrides(defaults_run(doc), "workflow `defaults.run`")
    # Innermost scope wins, as in GitHub Actions.
    scopes = [step.get("env") or {}, job.get("env") or {}, doc.get("env") or {}]
    if not all(isinstance(s, dict) for s in scopes):
        return problems + [(ENV, f"cannot evaluate an `env:` that is not a mapping: {scopes!r}")]
    for key, want in row.env.items():
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


def check_all(rows: tuple[RequiredStep, ...], workflows: dict[str, str | None]) -> tuple[list[Finding], int]:
    """All findings, plus how many rows were actually checked."""
    findings, ran = [], 0
    for row in rows:
        findings += check_row(row, workflows)
        ran += 1
    return findings, ran


def read_workflows(root: Path, rows: tuple[RequiredStep, ...]) -> dict[str, str | None]:
    out = {}
    for name in sorted({r.workflow for r in rows}):
        path = root / WORKFLOW_DIR / name
        out[name] = path.read_text(encoding="utf-8") if path.is_file() else None
    return out


def run_check(root: Path, rows: tuple[RequiredStep, ...]) -> int:
    findings, ran = check_all(rows, read_workflows(root, rows))
    for f in findings:
        print(f.render())
    if findings:
        print(f"FAIL: {len(findings)} finding(s); a gate CI relies on is no longer run")
        return 1
    if ran == 0 or ran != len(rows):  # the count below is what RAN, never the table size
        print(f"FAIL: checked {ran} of {len(rows)} rows; the guard would check nothing")
        return 1
    files = len({r.workflow for r in rows})
    print(f"OK: {ran} required steps wired across {files} workflows")
    return 0


def run_real_check() -> int:
    return run_check(REPO_ROOT, REQUIRED_STEPS)


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        from ci_wiring.selftest import run_self_test  # lazy: selftest imports this module

        return run_self_test()
    if argv:
        print(f"usage: check-ci-wiring.py [--self-test]; got {argv}", file=sys.stderr)
        return 2
    return run_real_check()
