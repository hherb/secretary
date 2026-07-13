# Design — CI hardening follow-on: `rust-lint.yml`/`audit.yml` timeouts + macOS pins + hardened `apt-get` step (#427)

**Date:** 2026-07-13
**Issue:** [#427](https://github.com/hherb/secretary/issues/427) — *CI hardening follow-on: rust-lint.yml/audit.yml timeouts + macOS pins + harden the apt-get step against hangs*
**Branch:** `feature/ci-hardening-427` off `main` @ `2ee3dc63`
**Scope class:** CI/config only. Files changed: [.github/workflows/rust-lint.yml](../../../.github/workflows/rust-lint.yml), [.github/workflows/audit.yml](../../../.github/workflows/audit.yml), [.github/workflows/test.yml](../../../.github/workflows/test.yml), and one **new** shell script [.github/scripts/install-tauri-linux-deps.sh](../../../.github/scripts/install-tauri-linux-deps.sh). **No** `core` / crypto / FFI / on-disk-format change; no new error variant; `#![forbid(unsafe_code)]` intact; no production code. Additive/hardening — no job's *observable result* changes, only its runner determinism, its runaway ceiling, and its resilience to a transient apt blip.

## Problem

The #424 / PR #426 review found the `test.yml` hardening (pinned macOS images + Xcode, uniform `timeout-minutes`) did not reach the remaining two workflow files, and a third gap surfaced live during #426's own CI:

1. **`rust-lint.yml` has no runaway cap and two nondeterministic macOS legs.** None of its four jobs (`fmt`, `clippy`, `doc`, `lean-binding`) set `timeout-minutes` — a hung clippy or rustdoc runs to the GitHub 6h default. The `clippy` and `doc` jobs each carry a `macos-latest` matrix leg; unlike the Swift jobs these are **Rust** builds (toolchain pinned via `rust-toolchain.toml`), so they are *not* exposed to the macos-15/26 Swift-literal flake — but the `macos-latest` label is still nondeterministic, and #424's stated goal was that **no** `macos-latest` label survive anywhere in the repo's workflows.
2. **`audit.yml` has no runaway cap.** Its single ubuntu `cargo audit` job is short and low-risk, but the missing `timeout-minutes` is an inconsistency with the rest of the CI.
3. **The Tauri-Linux `apt-get` step can stall the whole job.** During #426's CI, the `cargo test (ubuntu-latest)` job's *"Install Tauri Linux system dependencies"* step **hung ~30 min** on a transient apt mirror / network / dpkg-lock blip and was only killed by the job-level `timeout-minutes: 30`; a plain re-run passed in 3m37s. The job-level timeout is the correct *backstop*, but a transient blip should not burn the whole 30-min budget and turn the job red — a per-attempt `timeout` + bounded retry would fail-fast-and-retry in seconds. This exact `apt-get update && apt-get install …` step appears **3×** (`test.yml` `rust-test` Linux leg; `rust-lint.yml` `clippy` + `doc` Linux legs), currently byte-identical.

None of these is a correctness bug today; all three are reproducibility / cost / resilience hardening. Left unfixed they re-introduce the class of flake #424 exists to close (nondeterministic runner labels; unbounded hangs) and leave a known transient-apt stall unmitigated.

## Goals

1. **Every job in `rust-lint.yml` and `audit.yml` bounded by `timeout-minutes`.** No job on the 6h default.
2. **No `macos-latest` label anywhere in any repo workflow.** The two `rust-lint.yml` macOS legs pinned `macos-latest → macos-26` (image-only; Rust builds need no `setup-xcode`), completing the goal #424 set for the whole `.github/workflows/` tree.
3. **The `apt-get` dependency install fails fast and retries, but still fails red on a genuine outage.** A per-attempt `timeout` caps a hung `apt-get`; a bounded retry absorbs a transient blip; an all-attempts-exhausted outage still `exit 1`s the step — never green-with-missing-deps into a broken build.
4. **The apt hardening cannot drift between its three sites.** Extract the logic into a single shared script so the three legs are guaranteed identical, its constants live in one place (no scattered magic numbers), and it is independently self-testable.
5. **Follow CI discipline:** shell-only (no new third-party action), named constants over inline magic numbers, prove-the-guard-fires before trusting a green (the #231 anti-vacuous-check lesson).

## Non-goals (out of scope, documented not done)

- **`test.yml` timeouts / macOS pins.** Already landed in #424 / PR #426. This PR only *re-wires* `test.yml`'s one inline apt block to the shared script (Change 4); its timeouts and image pin are untouched.
- **`ios-tsan.yml`.** Already pinned to `macos-26` + Xcode 26.5 in #426 (commit `fd6097db`). It runs no apt step. Untouched.
- **A shellcheck CI step.** The repo does not currently shellcheck any script in CI; adding a lone shellcheck job for this one script would be inconsistent. `shellcheck` is run locally as part of verification, not wired into CI.
- **Emulator instrumented job / `:app`+`:kit` compile-gate.** Separate roadmap items (carried from #424's non-goals).
- **The deferred iOS `UInt64` test-literal hardening** (from #424) — unrelated to this file set.

## Design

### Change 1 — New shared script `.github/scripts/install-tauri-linux-deps.sh`

A single `bash` script (uses arrays + `(( ))`, so `bash`, not POSIX `sh`) that installs the GTK3/WebKitGTK dev libs the Tauri desktop crate needs to compile on Linux, wrapped in a bounded retry with a per-attempt `timeout`.

**Named tunables (no inline magic numbers; env-overridable so the self-test can zero the sleep):**

```bash
readonly MAX_ATTEMPTS="${MAX_ATTEMPTS:-3}"       # total apt tries before the step fails red
readonly UPDATE_TIMEOUT="${UPDATE_TIMEOUT:-120}" # seconds — cap a hung `apt-get update`
readonly INSTALL_TIMEOUT="${INSTALL_TIMEOUT:-300}" # seconds — cap a hung `apt-get install`
readonly RETRY_SLEEP="${RETRY_SLEEP:-15}"        # seconds between attempts (let a transient blip clear)
readonly PACKAGES=(libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev)
```

**Retry semantics.** One attempt is `sudo timeout $UPDATE_TIMEOUT apt-get update && sudo timeout $INSTALL_TIMEOUT apt-get install -y --no-install-recommends "${PACKAGES[@]}"`. A generic `run_with_retries` helper runs a passed command up to `MAX_ATTEMPTS` times: on first success it returns 0; on each failure it emits a `::warning::` and sleeps `RETRY_SLEEP` (skipped after the final attempt); if all attempts are exhausted it emits a `::error::` and returns 1. The real path calls `run_with_retries apt_install`.

**Fail-red invariant (load-bearing).** The naive `for … && break` loop the issue sketches has a trap under `bash -e`: after the last failed attempt the final executed command is the `sleep`, which succeeds, so the *step* exits 0 — a green-with-missing-deps that then fails the build opaquely somewhere downstream. The helper closes this by returning an explicit non-zero after the loop, so a genuine all-attempts apt outage turns the job **red at the install step**, not green.

**`--self-test` mode (no apt, fast).** Proves the two behaviours that matter, so a green guard is never vacuous (the #231 lesson, mirroring `ffi/scripts/check-lean-binding.sh --self-test`):
- an always-failing command (`false`) exhausts `MAX_ATTEMPTS` and `run_with_retries` returns non-zero (the fail-red path), **and**
- a fail-once-then-succeed command returns 0 (transient recovery).

The self-test is invoked with `RETRY_SLEEP=0` so it runs in well under a second.

**File-size / structure.** One focused script, ≈70–90 lines including the header comment — well under the 500-line guidance; no split needed.

### Change 2 — `rust-lint.yml`: `timeout-minutes` on every job + pin the two macOS legs

- Add `timeout-minutes: 30` at job level to all four jobs (`fmt`, `clippy`, `doc`, `lean-binding`). Uniform `30` matches `test.yml` — a runaway safety cap, not a performance target; being generous relative to real durations (all these legs finish in a few minutes) is correct.
- `clippy` and `doc` matrix: `os: [ubuntu-latest, macos-latest]` → `os: [ubuntu-latest, macos-26]`. Image-only pin; **no** `setup-xcode` (Rust builds, toolchain via `rust-toolchain.toml`), identical reasoning to `test.yml`'s `rust-test` macOS leg. A short comment records why (mirrors the existing `rust-test` comment).
- Replace both inline `apt-get` blocks (in `clippy` and `doc`) with `run: bash .github/scripts/install-tauri-linux-deps.sh` (Change 1). The `if: runner.os == 'Linux'` guard and step name are preserved.

### Change 3 — `audit.yml`: `timeout-minutes` on the one job

Add `timeout-minutes: 15` to `cargo-audit`. Lower than the `30` on the workspace-compiling jobs (the issue notes "audit can be lower"): the job's dominant cost is a cold `cargo install --locked cargo-audit` compile (~3–5 min; near-instant once `rust-cache` warms), so `15` gives ≥3× headroom over a cold build while still bounding a runaway. As with every timeout here the value is provisional — a clip fails **loud**, and the one constant is bumped.

### Change 4 — `test.yml`: re-wire the one inline apt block to the shared script

Replace `rust-test`'s inline `apt-get` block with `run: bash .github/scripts/install-tauri-linux-deps.sh`. Its `timeout-minutes: 30` and `macos-26` pin (from #424) are untouched. This is the third and final apt call-site, so after this change **all three** are the shared script and cannot drift.

### Change 5 — `rust-lint.yml`: add a fast `deps-script-selftest` guard job

A tiny ubuntu-only job (no cargo, no rust-cache) that runs `RETRY_SLEEP=0 bash .github/scripts/install-tauri-linux-deps.sh --self-test`. It proves the shared script's fail-red-on-outage and retry-recovery invariants on every CI run, so the guard cannot silently rot into a vacuous check (the concern the smoke-runners-rot experience and #231 both flag). Gets its own `timeout-minutes: 30` (uniform), completing "every job bounded".

### Job/step matrix after the change

| File · Job | `runs-on` | `timeout-minutes` | apt step |
|---|---|:---:|---|
| `rust-lint` · `fmt` | `ubuntu-latest` | 30 ⬅ | — |
| `rust-lint` · `clippy` (ubuntu) | `ubuntu-latest` | 30 ⬅ | shared script ⬅ |
| `rust-lint` · `clippy` (macos) | `macos-26` ⬅ | 30 ⬅ | — |
| `rust-lint` · `doc` (ubuntu) | `ubuntu-latest` | 30 ⬅ | shared script ⬅ |
| `rust-lint` · `doc` (macos) | `macos-26` ⬅ | 30 ⬅ | — |
| `rust-lint` · `lean-binding` | `ubuntu-latest` | 30 ⬅ | — |
| `rust-lint` · `deps-script-selftest` | `ubuntu-latest` ⬅ | 30 ⬅ | self-test ⬅ |
| `audit` · `cargo-audit` | `ubuntu-latest` | 15 ⬅ | — |
| `test` · `rust-test` (ubuntu) | `ubuntu-latest` | 30 (kept) | shared script ⬅ |

(⬅ = changed/added this PR. `test.yml`'s other jobs are unchanged.)

## Verification strategy

CI-config changes cannot be fully exercised locally — runner-image selection only exists on GitHub-hosted runners — but the shared script's *logic* is fully local-testable (unlike #424's Xcode-pin behaviour). Verification is staged, TDD-analog: the script's `--self-test` and the grep/actionlint assertions are the "tests", written and passing before the change is trusted.

- **Locally verifiable (the tests):**
  - `shellcheck .github/scripts/install-tauri-linux-deps.sh` — clean.
  - `RETRY_SLEEP=0 bash .github/scripts/install-tauri-linux-deps.sh --self-test` — passes (proves fail-red + retry-recovery). This is the primary behavioural test, runnable on the dev machine.
  - `grep -c 'timeout-minutes' .github/workflows/rust-lint.yml` → 5 (four original jobs + the self-test job); `.github/workflows/audit.yml` → 1.
  - `grep -rnE '(runs-on:|os:).*macos-latest' .github/workflows/` → none.
  - `grep -rc 'install-tauri-linux-deps.sh' .github/workflows/` → `test.yml`:1, `rust-lint.yml`:3 (clippy wiring + doc wiring + the self-test invocation) = 4 total references; the three apt call-sites now all use the shared script.
  - `actionlint .github/workflows/*.yml` — clean.
- **CI-only (the real gate):** the `clippy`/`doc` macOS legs green on `macos-26`; the Linux legs' apt install succeeds through the shared script; the `deps-script-selftest` job green; every job's summary shows its `timeout-minutes`. Confirmed on the PR's own Actions run. The real apt path is exercised live every run; the self-test job proves the fail-red path without needing to stage an outage.

### Acceptance criteria (from #427)

- [ ] Every job in `rust-lint.yml` and `audit.yml` sets `timeout-minutes`.
- [ ] No `macos-latest` label remains in any repo workflow.
- [ ] The `apt-get` dependency step retries with a per-attempt `timeout` in all three sites (via the shared script), and still fails the job on a genuine (all-attempts) apt outage.
- [ ] The shared script is self-testable and its self-test is guarded in CI (non-vacuous).
- [ ] Live CI green on the PR; `actionlint` clean; no existing job's behaviour changes beyond the hardening.

## Risks

- **`15` too tight for a cold `cargo install cargo-audit`.** Low: `rust-cache` restores cargo-audit across runs, and a from-scratch build is well under 15 min on GitHub runners. A clip fails **loud** (never a silent wrong result) → bump the one constant. Explicitly provisional.
- **The `run_with_retries` fail-red path regresses into a silent green.** Mitigated structurally: the `--self-test` (Change 1) asserts `false` exhausts retries and returns non-zero, and Change 5 runs that self-test in CI on every run, so a regression turns the guard job red.
- **`bash -e` interaction inside the retry loop.** The command under retry runs as an `if` condition, where `set -e` is suppressed, so a failed attempt does not abort the script mid-loop; the explicit post-loop `return 1` is the only exit path on total failure. Covered by the self-test's always-fail case.
- **`macos-26` drift.** These legs are Rust-only (no Xcode pin), so an image refresh can only change the OS image, not the compiler (pinned by `rust-toolchain.toml`). Lower risk than the Swift jobs; if the `macos-26` label were ever retired the leg fails loud and the image string is bumped deliberately. **Never** revert to `macos-latest`.
- **Scope creep.** Guarded: only the three workflow files named in #427 plus the one new script; `test.yml` gets *only* the apt re-wire (its #424 hardening untouched); all other items are explicit non-goals.

## Rollout

Single PR off `feature/ci-hardening-427`. The Linux apt path and the self-test job are proven on the PR's own Actions run. No README/ROADMAP change — internal CI infrastructure, no user-facing feature (consistent with #288/#289/#423/#424, none of which appear in README/ROADMAP).
