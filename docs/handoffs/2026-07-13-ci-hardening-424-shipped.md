# NEXT_SESSION.md — CI hardening: pin macOS toolchain + universal timeouts (#424) ✅ SHIPPED (PR #426)

**Session date:** 2026-07-13, resuming from `main` @ `e0f47586` after #425 (mobile host-test CI wiring) merged. This session closed **#424** — the CI-hardening follow-on that the #423 final review filed: the macOS jobs ran on a nondeterministic `macos-latest` image with an unpinned Xcode (the exact class of flake that cost a cycle last session), and no job had a `timeout-minutes` cap (a hang would burn the 6h GitHub default). Branch `feature/ci-hardening-424` off `main` @ `e0f47586`; worktree `.worktrees/ci-hardening-424/`. Executed spec → plan → inline TDD-style execution (grep/actionlint assertions as the config-change test analog) → live-CI gate. Spec: [docs/superpowers/specs/2026-07-13-ci-hardening-424-design.md](../superpowers/specs/2026-07-13-ci-hardening-424-design.md). Plan: [docs/superpowers/plans/2026-07-13-ci-hardening-424.md](../superpowers/plans/2026-07-13-ci-hardening-424.md).

**CI/config only. Only `.github/workflows/test.yml` changed. No `core` / crypto / FFI / on-disk-format change; no new error variant; `#![forbid(unsafe_code)]` intact. No production code touched — the only local build run was `swift test` on the two FFI-free host packages (read-only verification that the pinned Xcode 26.5 builds the code).**

## (1) What we shipped this session

**#424 — pin the macOS toolchain + a uniform runaway cap on every job in [.github/workflows/test.yml](../../.github/workflows/test.yml).** Pin depth was user-approved as **Image + Xcode (both)** — fully deterministic, satisfying #424's "pinned-SHA action" literally.

- **Xcode pin on both Swift jobs.** `swift-conformance` moved `macos-latest` → **`macos-26`** (matching `ios-host`, already pinned last session), and both gained a first-step `maxim-lobanov/setup-xcode@ed7a3b1fda3918c0306d1b724322adc0b8cc0a90 # v1.7.0` selecting **`xcode-version: '26.5'`** (Swift 6.3 — the `macos-26` image default *and* the code's target). SHA independently verified to resolve to the `v1.7.0` tag. Fails **loud** (never a false green) if a future image drops 26.5 → bump deliberately (kotlin-snap-pin discipline, #367).
- **`rust-test` macOS matrix leg** pinned `macos-latest` → **`macos-26`** (no `setup-xcode` — it's Rust-only, toolchain via `rust-toolchain.toml`). **No `macos-latest` label remains anywhere** in the file.
- **Uniform `timeout-minutes: 30`** on **all six** jobs (was: the 6h default). A single value — satisfies "no per-job drift"; a **provisional runaway cap**, not a perf target.
- Refreshed the stale `#424 tracks…` forward-reference comment in the `ios-host` block (now: "#424 (this file) now pins Xcode 26.5…").
- **Post-review add-on:** also pinned **`ios-tsan.yml`** (SecretaryKit under ThreadSanitizer — the one *other* macOS Swift job, exposed to the same flake) to `macos-26` + Xcode 26.5 via the same `setup-xcode` step; its existing 60-min TSan timeout kept. That workflow is path-gated to `ios/**` + its own file, so editing it re-triggers the job → the pin is CI-validated on this PR.

### Branch commits (off `main` @ `e0f47586`, in order)
- `138b42e3` design doc (spec)
- `a173ef15` implementation plan
- `176b214d` **Task 1** — pin macos-26 + Xcode 26.5 on `swift-conformance` + `ios-host`
- `df711c39` **Task 2** — uniform `timeout-minutes: 30` on all jobs + pin `rust-test` macOS leg
- `d477fdb0` handoff doc + symlink retarget
- `fd6097db` **review add-on** — pin `ios-tsan.yml` to macos-26 + Xcode 26.5 (#424)
- _(this commit)_ handoff doc correction (scope: `ios-tsan.yml` pinned; `rust-lint.yml`/`audit.yml` → #427)

### Acceptance (all met)
```bash
# Local (from the worktree root) — all green this session:
grep -c 'maxim-lobanov/setup-xcode' .github/workflows/test.yml   # 2
grep -c 'timeout-minutes: 30'       .github/workflows/test.yml   # 6
grep -nE '(runs-on:|os:).*macos-latest' .github/workflows/test.yml   # (none)
actionlint .github/workflows/test.yml                            # clean
( cd ios/SecretaryDeviceUnlock && swift test )   # 46/46  under Xcode 26.5
( cd ios/SecretaryVaultAccess  && swift test )   # 276/276 under Xcode 26.5
```
**Live CI (PR #426, run `29239546514`): all 7 jobs green on the first run.** The pinned macOS Swift jobs passed on real runners — `swift conformance` (1m51s) + `ios host` (1m03s) on `macos-26` with `setup-xcode` selecting 26.5, and `cargo test (macos-26)` (3m56s) on the pinned image. **Timeout headroom confirmed comfortable:** slowest job was `cargo test (ubuntu-latest)` at **4m16s** — ~7× under the 30-min cap. (`setup-xcode` added negligible time; `ios host` was actually *faster* than last run's baseline, within noise.)

## (2) What's next — pick a new slice

The `test.yml` CI is now deterministic (pinned images + Xcode) and hang-bounded. Pick from [ROADMAP.md](../../ROADMAP.md) / [README.md](../../README.md). Concrete candidates (carried from #425's handoff, minus #424 now done):

- **Desktop OS-biometric write re-auth (#277 + gate-coverage #280)** — the remaining D.1 roadmap item; completes presence-proof across all three platforms (mobile has grace-window config now; desktop still re-auths by password only). Meaty, multi-session. **Acceptance:** a desktop write-gate re-auth via OS biometric (macOS Touch ID first) + a centralized #280 gate-coverage test proving no ungated mutating IPC.
- **#417's remaining iOS render sliver** — a literal SwiftUI render assertion for `settings-error` / `purge-notice` (ViewInspector or an XCUITest target). Small, focused; closes #417's iOS half. **Acceptance:** a render-layer test that fails if the banner does not render.
- **Emulator instrumented job (deferred from #423/#424):** an opt-in AVD job for `:browse-ui:connectedDebugAndroidTest` (the #417 render guards). Slow/flaky; out of the host-only scope. **Acceptance:** an opt-in (label- or manual-triggered) job that boots an AVD and runs the connected tests green.
- **`:app`/`:kit` compile-gate in CI:** `android-host` *configures* but does not *compile* `:app`/`:kit`, so a cross-module sealed-`when` exhaustiveness break (see the Android sealed-`when` memory) still isn't caught. Heavier full-Android-build lift; separate enhancement.
- **Optional micro-follow-on (from #424's non-goal):** harden the fragile iOS test literals `[N * 86_400_000]` to explicit `UInt64` so the host suites compile under *any* Swift, not just 6.3. **Obviated** by the pin (they compile fine on 26.5) and un-verifiable without a `macos-15` runner — file only if a paper trail is wanted; do not treat as blocking.
- **Security #383** — still **upstream-blocked** (last verified #425 session: `quick-xml 0.39.4` via `plist 1.9.0` → `tauri 2.11.2`). Re-check on the next Tauri bump; do not start.
- Any user-prioritized slice.

## (3) Open decisions and risks

- **`timeout-minutes: 30` is provisional (accepted, user-flagged).** Grounded in this run's observed durations (max 4m16s, ~7× headroom), so it comfortably absorbs a cold cargo cache. If a future full-cache-miss `cargo test` ever clips it, the failure is a **loud** timeout (never a silent wrong result) — bump the one constant. A single uniform value (not per-job) is deliberate: "no per-job drift" + one number to justify. Re-tune only if live CI shows it's tight.
- **`macos-26` could drop Xcode 26.5 in a future image refresh.** Then `setup-xcode` hard-fails loud → bump the `xcode-version` string on **both** Swift jobs deliberately (and re-confirm the Swift host literals compile under the new toolchain, or apply the deferred `UInt64` hardening). **Never** revert to `macos-latest` / `latest-stable` — that re-opens the nondeterminism this PR closed.
- **Scope: `test.yml` + `ios-tsan.yml` hardened; `rust-lint.yml`/`audit.yml` tracked in #427.** The PR review found the flake was NOT confined to `test.yml` (my first-pass handoff wrongly called the rest "Linux-only" — it is not): **`ios-tsan.yml`** builds SecretaryKit under `xcodebuild` on `macos-latest` → exposed to the *same* macos-15/26 Swift-toolchain flake, so it was pinned in this PR (commit `fd6097db`). Still out of scope, filed as **#427**: `rust-lint.yml` has **two `macos-latest` matrix legs** (Rust — clippy + rustdoc/#92 gate — so NOT the Swift-literal flake, but nondeterministic image) and **no `timeout-minutes` on any job**; `audit.yml` (ubuntu) has no timeout. Lower value (no Swift flake), hence deferred not done.
- **Deferred non-goal:** the iOS test-literal `UInt64` hardening (see §2). Documented, not dropped; safe to leave.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After PR #426 merges, drop the branch + worktree (squash-merge leaves it "not fully merged"):
#   git worktree remove .worktrees/ci-hardening-424 && git branch -D feature/ci-hardening-424
git worktree list && git status -s
# If resuming THIS branch for fixups (bind histories first — closes the add/add gap on the handoff doc):
#   cd .worktrees/ci-hardening-424 && git fetch origin && git merge origin/main
# Re-run this branch's local gates any time it is live (from the worktree root):
#   actionlint .github/workflows/test.yml
#   ( cd ios/SecretaryDeviceUnlock && swift test ) && ( cd ios/SecretaryVaultAccess && swift test )
# CI status for the PR:
#   gh pr checks 426
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; the symlink retargeted in the same commit on the feature branch (new path → no add/add conflict; `main` updates cleanly on merge). The handoff rides inside PR #426 — do **not** sync to `main` during the pause window ([[feedback_next_session_main_authoritative]]). If resuming this branch for fixups, first `git fetch origin && git merge origin/main` (branch version wins on this doc) before editing.

## Closing inventory
- **State on close:** PR #426 open on `feature/ci-hardening-424` (worktree `.worktrees/ci-hardening-424`), **live CI green on all 7 jobs** (run `29239546514`). Branch commits: spec + plan + 2 task commits + handoff.
- **Acceptance:** all local assertions green (setup-xcode ×2, timeout ×6, no `macos-latest`, actionlint clean, both iOS host packages 46+276 under Xcode 26.5); live CI green first run, timeout headroom ~7×.
- **Next:** pick a new slice (desktop #277+#280 is the biggest-remaining D.1 item; #417 iOS render sliver is the smallest; or user priority).
- **README / ROADMAP:** no change (internal CI infrastructure, no user-facing feature; verified README/ROADMAP mention neither #288/#289/#423 nor `test.yml` — CI PRs set the precedent of not appearing in either).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-07-13-ci-hardening-424-shipped.md`.
