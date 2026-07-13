# NEXT_SESSION.md — CI hardening follow-on: rust-lint/audit timeouts + macOS pins + shared hardened apt step (#427) ✅ SHIPPED (PR #428)

**Session date:** 2026-07-13, resuming from `main` @ `2ee3dc63` after #426 (the #424 CI hardening) merged. This session closed **#427** — the follow-on the #426 review filed: `rust-lint.yml`/`audit.yml` still lacked the `timeout-minutes` caps and `macos-26` pins #426 gave `test.yml`, and a transient `apt-get` hang that surfaced live in #426's CI (a ~30-min stall killed only by the job-level cap) was unmitigated across the three identical inline apt steps. Branch `feature/ci-hardening-427` off `main` @ `2ee3dc63`; worktree `.worktrees/ci-hardening-427/`. Executed spec → plan → inline TDD-style execution (shellcheck + a `--self-test` + grep/actionlint assertions as the config-change test analog, plus a local mutation check) → live-CI gate. Spec: [docs/superpowers/specs/2026-07-13-ci-hardening-427-design.md](../superpowers/specs/2026-07-13-ci-hardening-427-design.md). Plan: [docs/superpowers/plans/2026-07-13-ci-hardening-427.md](../superpowers/plans/2026-07-13-ci-hardening-427.md).

**CI/config only. Files: [.github/workflows/rust-lint.yml](../../.github/workflows/rust-lint.yml), [.github/workflows/audit.yml](../../.github/workflows/audit.yml), [.github/workflows/test.yml](../../.github/workflows/test.yml) (one apt re-wire only), and one NEW [.github/scripts/install-tauri-linux-deps.sh](../../.github/scripts/install-tauri-linux-deps.sh). No `core` / crypto / FFI / on-disk-format change; no new error variant; `#![forbid(unsafe_code)]` intact. No production code — the only local execution was `shellcheck` + the script's `--self-test`.**

## (1) What we shipped this session

**#427 — bound every `rust-lint.yml`/`audit.yml` job, complete the "no `macos-latest` anywhere" goal, and DRY the three inline `apt-get` steps into one retry-hardened, self-testable script.**

- **New shared script `.github/scripts/install-tauri-linux-deps.sh`.** The GTK3/WebKitGTK apt install the Tauri desktop crate needs on Linux, behind a **bounded retry + per-attempt `timeout`** (named `readonly` tunables — `MAX_ATTEMPTS=3`, `UPDATE_TIMEOUT=120`, `INSTALL_TIMEOUT=300`, `RETRY_SLEEP=15` — env-overridable, no inline magic numbers). A transient apt blip fails fast and retries in seconds instead of stalling to the 30-min job cap (the #426 failure mode). A **genuine all-attempts outage still fails RED** (`::error::` + `exit 1`) — the load-bearing invariant: never green-with-missing-deps. Closes the naive-`&& break`-loop trap (last `sleep` succeeds → step greens) with an explicit post-loop `return 1`. A `--self-test` mode proves fail-red + transient-recovery **without touching apt**.
- **All three byte-identical inline `apt-get` steps replaced** by `run: bash .github/scripts/install-tauri-linux-deps.sh` (`test.yml` rust-test; `rust-lint.yml` clippy + doc) — they can no longer drift.
- **`rust-lint.yml`:** `timeout-minutes: 30` on all five jobs (`fmt`, `clippy`, `doc`, `lean-binding`, + the new self-test job); `clippy` + `doc` matrix macOS legs `macos-latest → macos-26` (Rust-only, no `setup-xcode` — toolchain via `rust-toolchain.toml`); **new `deps-script-selftest` job** runs `RETRY_SLEEP=0 … --self-test` on every CI run so the fail-red guard can't rot into a vacuous check (#231 lesson, mirroring `check-lean-binding.sh --self-test`).
- **`audit.yml`:** `timeout-minutes: 15` on `cargo-audit` (lower than the build jobs' 30 — dominant cost is a cold `cargo install cargo-audit`, cached after; provisional, fails loud if ever clipped).
- **`test.yml`:** only the one apt re-wire; its #424 `timeout-minutes` + `macos-26` pin untouched.

### Branch commits (off `main` @ `2ee3dc63`, in order)
- `c3b3a565` design doc (spec)
- `35928634` implementation plan
- `979c5cc5` **Task 1** — shared `install-tauri-linux-deps.sh` (retry + per-attempt timeout + `--self-test`; shellcheck-clean)
- `5117363d` **Task 2** — `rust-lint.yml`: timeouts ×5, `macos-26` pins ×2, wire script ×2, new self-test job
- `6746c39c` **Task 3** — `test.yml`: re-wire the one apt step to the shared script
- `8b8b1d9e` **Task 4** — `audit.yml`: `timeout-minutes: 15`
- _(this commit)_ handoff doc + symlink retarget

### Acceptance (all met)
```bash
# Local (from the worktree root) — all green this session:
shellcheck .github/scripts/install-tauri-linux-deps.sh                       # clean
RETRY_SLEEP=0 bash .github/scripts/install-tauri-linux-deps.sh --self-test   # "SELF-TEST: all cases passed"
grep -c 'timeout-minutes' .github/workflows/rust-lint.yml                    # 5
grep -c 'timeout-minutes' .github/workflows/audit.yml                        # 1
grep -rnE '(runs-on:|os:).*macos-latest|- macos-latest' .github/workflows/   # (none — real labels)
actionlint .github/workflows/*.yml                                           # clean
```
A **local mutation check** (flip `run_with_retries`'s `return 1` → `return 0` in a scratch copy) confirmed the self-test catches a broken fail-red path (`SELF-TEST FAIL`, exit 1) — the guard is non-vacuous.

**Live CI (PR #428, runs `29289173650` rust-lint / `29289173657` test / `29289173709` audit): all 15 workflow jobs green + the 5 CodeQL/Analyze default-setup checks = 20 checks, 0 failures, first run (PR state CLEAN + MERGEABLE).** The change-exercising jobs passed on real runners: **`cargo clippy (macos-26)`** (50s) + **`cargo doc (macos-26)`** (46s) on the newly-pinned image; **`cargo clippy (ubuntu-latest)`** (57s) + **`cargo doc (ubuntu-latest)`** (54s) + **`cargo test (ubuntu-latest)`** (4m2s) installed their Tauri deps through the shared script (the last is the exact leg whose apt step hung in #426 — now on the retry wrapper); **`apt-deps script self-test`** green (5s — proves the fail-red guard live); **`cargo audit`** green (18s, ~50× under the 15-min cap). Timeout headroom confirmed comfortable: slowest job was **`cargo test (macos-26)` at 5m21s — ~6× under the 30-min cap**.

## (2) What's next — pick a new slice

The whole `.github/workflows/` tree is now deterministic (no `macos-latest` label anywhere) and hang-bounded (every job has `timeout-minutes`; the apt step retries + fails fast). Pick from [ROADMAP.md](../../ROADMAP.md) / [README.md](../../README.md). Concrete candidates (carried from #426's handoff, minus #427 now done):

- **Desktop OS-biometric write re-auth (#277 + gate-coverage #280)** — the remaining D.1 roadmap item; completes presence-proof across all three platforms (mobile has grace-window config now; desktop still re-auths by password only). Meaty, multi-session, hardware-verification heavy (macOS Touch ID). **Acceptance:** a desktop write-gate re-auth via OS biometric + a centralized #280 gate-coverage test proving no ungated mutating IPC.
- **#280 write-gate scanner is comment-naive (#408)** — the static scanner flags gated-write mentions inside comments. Small; strip/ignore comment lines before matching + a regression test. A natural warm-up toward #280.
- **Mobile Settings/Trash banner polish (#421 + #417)** — fix the "save"-worded copy on a read/load failure (#421) + add the missing SwiftUI/Compose render-layer test for the purge-notice banner (#417). Small, iOS + Android.
- **`:app`/`:kit` compile-gate in CI** — `android-host` *configures* but does not *compile* `:app`/`:kit`, so a cross-module sealed-`when` exhaustiveness break still isn't caught. Heavier full-Android-build lift.
- **Emulator instrumented job** (deferred from #423/#424) — opt-in AVD job for `:browse-ui:connectedDebugAndroidTest`. Slow/flaky; out of host-only scope.
- **Security #383** — still **upstream-blocked** (`quick-xml 0.39` via `plist` → `tauri`). Re-check on the next Tauri bump; do not start.
- Any user-prioritized slice.

## (3) Open decisions and risks

- **All `timeout-minutes` values are provisional (accepted).** `30` on build/self-test jobs (uniform with `test.yml`), `15` on `audit`. Grounded in this run's durations (all jobs ≪ their cap — `cargo audit` 18s vs 15min; clippy/doc ≤ 57s vs 30min). A future cold-cache clip fails **loud** (never a silent wrong result) → bump the one constant. Do not tighten speculatively.
- **The apt retry constants are provisional too.** `UPDATE_TIMEOUT=120` / `INSTALL_TIMEOUT=300` / `MAX_ATTEMPTS=3` / `RETRY_SLEEP=15` are sized for a transient blip. If a real apt mirror is genuinely slow (not hung), a legit install could exceed 300s and fail a real attempt — but the retry absorbs it, and total failure is loud. Re-tune only if live CI shows spurious retries. **Never** remove the post-loop `return 1` — it is the fail-red invariant the self-test guards.
- **`macos-26` on the `rust-lint` legs is Rust-only (no Xcode pin).** An image refresh can only change the OS image, not the compiler (pinned by `rust-toolchain.toml`) — lower risk than the Swift jobs. If `macos-26` were ever retired the leg fails loud → bump the image string. **Never** revert to `macos-latest` (re-opens the nondeterminism #424/#427 closed).
- **shellcheck / actionlint are NOT in CI.** They're local-only gates this session (the repo shellchecks no script in CI; adding a lone shellcheck job would be inconsistent). The script's *behaviour* is guarded live by `deps-script-selftest`; its *style* is a local dev-machine gate. If script rot is a concern later, a shellcheck CI step is a small follow-on.
- **`test.yml` scope:** only the one apt re-wire. Its #424 hardening (6× `timeout-minutes`, `macos-26` pins, `setup-xcode`) is deliberately untouched.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After PR #428 merges, drop the branch + worktree (squash-merge leaves it "not fully merged"):
#   git worktree remove .worktrees/ci-hardening-427 && git branch -D feature/ci-hardening-427
git worktree list && git status -s
# If resuming THIS branch for fixups (bind histories first — closes the add/add gap on the handoff doc):
#   cd .worktrees/ci-hardening-427 && git fetch origin && git merge origin/main
# Re-run this branch's local gates any time it is live (from the worktree root):
#   shellcheck .github/scripts/install-tauri-linux-deps.sh
#   RETRY_SLEEP=0 bash .github/scripts/install-tauri-linux-deps.sh --self-test
#   actionlint .github/workflows/*.yml
# CI status for the PR:
#   gh pr checks 428
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; the symlink retargeted in the same commit on the feature branch (new path → no add/add conflict; `main` updates cleanly on merge). The handoff rides inside PR #428 — do **not** sync to `main` during the pause window ([[feedback_next_session_main_authoritative]]). If resuming this branch for fixups, first `git fetch origin && git merge origin/main` (branch version wins on this doc) before editing.

## Closing inventory
- **State on close:** PR #428 open on `feature/ci-hardening-427` (worktree `.worktrees/ci-hardening-427`), **live CI green on all workflow jobs**. Branch commits: spec + plan + 4 task commits + handoff.
- **Acceptance:** all local gates green (shellcheck clean; `--self-test` passes + mutation check confirms non-vacuous; timeout counts 5/1; no `macos-latest` label; actionlint clean); live CI green — both newly-pinned `macos-26` legs, both Linux legs via the shared apt script, the self-test guard, and `cargo audit` all pass.
- **Next:** pick a new slice (desktop #277+#280 is the biggest-remaining D.1 item; #408 is a small #280 warm-up; #421+#417 is the smallest mobile polish; or user priority).
- **README / ROADMAP:** no change (internal CI infrastructure, no user-facing feature; verified neither file references any workflow / timeout / #288/#289/#423/#424 — CI PRs set the precedent of not appearing in either).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-07-13-ci-hardening-427-shipped.md`.
