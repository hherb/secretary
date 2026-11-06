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
For every row of `REQUIRED_STEPS` -- (workflow file, job id, command, env,
linux_only):

1. The workflow parses, and runs on `pull_request` with no `branches` /
   `paths` / `types` filter (`SKIPPING_TRIGGER_KEYS`) that could skip it.
2. The job exists and has no job-level `if:`, no `continue-on-error` and no
   `needs:` (a job whose dependency is skipped is skipped too, and a skipped
   job passes its required check).
3. The job can run on a Linux runner: `runs-on` is an `ubuntu-*` label, or
   `${{ matrix.os }}` over a plain list holding one. Any other shape
   (`include`/`exclude`, an expression we cannot evaluate) FAILS CLOSED.
4. Some `run:` step in that job equals the command after collapsing
   whitespace (so a folded `>-` or one-line `|` block matches its one-line
   form, and `echo <command>` or a commented-out step does not). The step's
   `name:` is not read.
5. That step has no `continue-on-error`. Its `if:` is absent, or -- on a
   `linux_only` row only -- equal (after collapsing whitespace) to one of
   `ALLOWED_STEP_CONDITIONS`.
6. No `shell:` or `working-directory:` is set on the step, in the job's
   `defaults.run`, or in the workflow's: `shell: 'true {0}'` turns any step
   into a green no-op.
7. Every `env` pair the row names is set on that step, job or workflow; an
   `env:` that is not a mapping fails closed.

The YAML is PARSED, never grepped: a grep finds a commented-out step, and an
unquoted ` #` in a scalar silently truncates it while staying valid YAML (#470).

LIMITS
------
- Only `test.yml` and `rust-lint.yml` are read. `audit.yml`, `codeql.yml`,
  `macos-host.yml` and `ios-tsan.yml` are out of scope.
- The table checks the workflows, nothing checks the table: deleting a row
  together with its step is silent. Adding a CI gate worth keeping means
  adding a row here.
- Only the Linux leg is checked. Dropping a matrix leg is caught only by that
  leg's required status check never reporting.
- Steps BEFORE the pinned one (checkout, toolchain install) are not checked;
  an earlier `$GITHUB_ENV` write could override a row's env. Removing a setup
  step breaks the pinned step loudly, so that half is not a silent gap.
- The guard cannot pin its own invocation: if its job is deleted, nothing
  runs to notice. Its two rows below are checked whenever it does run. What
  will keep the job itself present is `ci wiring` being a required status
  check on `main`, and that is NOT yet the case: it must be added to the
  `protect_main` ruleset after this guard merges (adding it earlier would
  block every PR branched before the job existed).
- Platform jobs (`desktop-test`, `swift-conformance`, `kotlin-conformance`,
  `ios-host`, `android-host`) are not rows. They are required status checks,
  so deleting the JOB is caught; emptying its steps is not.

The code lives in `scripts/ci_wiring/` (`rules.py`: the table and checks;
`selftest.py`: the controls).

Usage:
    uv run scripts/check-ci-wiring.py --self-test   # controls; writes only to a mktemp dir
    uv run scripts/check-ci-wiring.py               # the real workflows
"""

import sys

from ci_wiring.rules import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
