---
name: finalcheck
description: final pre-merge pass on the current PR — review, fix everything, then drive GitHub CI to green
disable-model-invocation: false
allowed-tools: Bash(git *), Bash(gh *), Bash(cargo *), Bash(uv *), Bash(pnpm *), Bash(bash *), Bash(actionlint *)
---
Run these steps in order on the PR for the current branch. Sessions here span several `git worktree`s, so
first run `pwd && git branch --show-current && git worktree list` and `cd` into the PR's worktree under
`.worktrees/`. Then find the PR with `gh pr view --json number,url,headRefOid`. If there is none, stop and
tell me.

1. **Review.** Invoke the `pr-review-toolkit:review-pr` skill via the Skill tool and let it finish.
2. **Fix.** Invoke the `fixall` skill via the Skill tool on that review's findings. It merges `origin/main`
   first and ends by committing and pushing into the PR. Before moving on, confirm the push landed:
   `git fetch origin && git status -sb` must show no `ahead`, and the PR's `headRefOid` must equal
   `git rev-parse HEAD`. Any edit to the baton goes into the handoff doc under `docs/handoffs/`. Never edit
   through the `NEXT_SESSION.md` symlink.
3. **Drive CI to green.** Loop:
   - Watch the checks for the pushed head commit with `gh pr checks --watch --fail-fast`. Checks can take a
     minute to register, so wait if it reports none yet. Path-gated workflows (`macos-host.yml`,
     `ios-tsan.yml`, `audit.yml`) post no check at all when their paths are untouched. A missing check
     there is normal, not stuck.
   - All green → done. Report the PR URL and the final check list. "All green" means every required
     context in the `protect_main` ruleset passed: `gh api repos/hherb/secretary/rules/branches/main`.
     `branches/main/protection` returns 404 by design.
   - A check failed → read the cause: `gh run list --branch "$(git branch --show-current)" --limit 5`, then
     `gh run view <run-id> --log-failed`. Reproduce it locally with the command the failing job runs
     (see `.github/workflows/`):
     - `cargo fmt --check` → `cargo fmt --all --check`
     - `cargo clippy` → `cargo clippy --release --locked --workspace --tests -- -D warnings`, plus the same
       with `-p secretary-core --features differential-replay --tests`
     - `cargo doc` → `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked --workspace`
     - `cargo test` → `cargo build --release --locked --workspace`, `cargo test --release --locked --workspace`,
       and `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay`
     - `desktop vitest` → `cd desktop && pnpm install --frozen-lockfile && pnpm test && pnpm svelte-check && pnpm lint`
     - `clean-room conformance` → `uv run core/tests/python/conformance.py`
     - a hygiene job → its script, `--self-test` first (`ffi/scripts/check-lean-binding.sh`,
       `ios/scripts/check-public-log-hygiene.sh`, `android/scripts/check-log-hygiene.sh`,
       `scripts/check-secret-slot-hygiene.sh`, `uv run scripts/check-error-payload-hygiene.py`,
       `uv run scripts/check-test-support-placement.py`)
     - swift/kotlin conformance → `bash ffi/secretary-ffi-uniffi/tests/{swift,kotlin}/run_conformance.sh`
     - `cargo audit` → `cargo audit --deny warnings`
     - a workflow file changed → `actionlint`

     Judge each command by its **exit code**, never by filtered output: `cmd | tail` reports `tail`'s
     status. Fix the root cause, using TDD where it is a code bug. Confirm the fix passes locally, commit
     with a message naming the CI failure, push, and loop again.
   - **Linux-only failures** (CI is ubuntu-24.04 and macOS passes locally): reproduce in Docker
     (`ubuntu:24.04` or `rust:1.97.0-bookworm`; start the daemon with `open -a Docker`). Don't guess.
   - **A job that is CANCELLED with no log** means the runner was killed, not that a test was slow
     (PR #662's `kill(-1)`). Treat it as a code bug: find what killed the runner. Do not rerun it as a
     flake.
   - If the failure is not caused by the code (runner/infra outage, network flake, missing secret), rerun
     once with `gh run rerun <run-id> --failed`. If it fails the same way again, stop and report rather
     than changing code to work around it. The Actions API returns empty or stale data during an outage,
     so re-query before concluding a run never happened.
   - Never "fix" CI by skipping, `#[ignore]`-ing or deleting tests, by weakening lint/CI config, guards or
     allowlists, or by adding an allowlist entry, without my explicit permission. Allowlist entries here are
     security decisions. If the same failure survives three fix attempts, stop and report what you tried.
4. **Not covered by CI.** `browser/extension/` has no CI job. If the PR touches it, run
   `cd browser/extension && pnpm install --frozen-lockfile && pnpm typecheck && pnpm lint && pnpm test`
   locally and include the result in the report.
