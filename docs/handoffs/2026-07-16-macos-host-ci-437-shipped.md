# NEXT_SESSION.md — macos-host CI job (#437) ✅ SHIPPED (PR #439)

**Session date:** 2026-07-16, resuming from `main` @ `2ec8930f` (after #435/#436/#438 all merged). This session shipped **#437** — wiring `ios/scripts/run-macos-tests.sh` into CI as a **`macos-host`** job, closing the CI-coverage gap that PR #438 explicitly deferred for the just-shipped D.5.1 native macOS client. Branch `ci/wire-macos-host-437`; worktree `.worktrees/macos-host-ci-437`. Executed brainstorm → spec → plan → inline execution (3 tasks). Spec: [docs/superpowers/specs/2026-07-16-macos-host-ci-437-design.md](../superpowers/specs/2026-07-16-macos-host-ci-437-design.md). Plan: [docs/superpowers/plans/2026-07-16-macos-host-ci-437.md](../superpowers/plans/2026-07-16-macos-host-ci-437.md).

**CI config only. No `core` / crypto / FFI / Swift / on-disk-format change; no change to any `ios/scripts/*` script (`run-macos-tests.sh` used verbatim). One new workflow file + a one-clause ROADMAP flip.**

## (1) What we shipped this session

### #437 — a `macos-host` CI job running `run-macos-tests.sh`
Before this, `test.yml`'s `ios-host` job covered only **step 1** of `run-macos-tests.sh` (the two FFI-free host packages, which are platform-agnostic). **Steps 2–4 were CI-uncovered:** the xcframework build (incl. the `macos-arm64` slice), the `SecretaryKit` macOS **host** test (the D.5.1 headline — SecretaryKit builds without a simulator), and the `SecretaryMac.app` compile proof. A regression (e.g. a future SecretaryKit adapter importing UIKit, or an ffi UDL change altering the generated Swift API so SecretaryKit no longer compiles) would have gone unnoticed until the next manual macOS run. #437 closes that.

**Architecture — mirror `ios-tsan.yml`.** The repo already had the exact precedent: an expensive, macOS-only, Rust-cross-compiling job in its **own** path-gated workflow file, so it doesn't gate `test.yml`'s must-run legs and needs no third-party changed-files action (GitHub `paths:` filters are per-workflow). The new `.github/workflows/macos-host.yml` clones that structure.

**Design decisions (user-approved in brainstorm; do NOT re-litigate):**
- **Separate workflow file**, not a `test.yml` job — `test.yml`'s jobs all run unconditionally; this is the single heaviest leg (4-triple Apple cross-compile + host cdylib + uniffi-bindgen + 2 `xcodebuild` runs), so it must be path-gated.
- **Path filter `ios/** + ffi/** + core/**`** (+ the workflow file) — deliberately **broader** than `ios-tsan.yml`'s `ios/**`, because this job's differentiator vs `ios-host` is precisely the Rust→Swift integration, so an ffi/core break is exactly what it must catch.
- **`brew install xcodegen`** — `build-macos-app.sh` hard-requires `xcodegen` and it had never run in this repo's CI; explicit provisioning gives deterministic presence over relying on undocumented runner-image contents.
- **`runs-on: macos-26` + `setup-xcode 26.5`** (both SHA-pinned actions, same as every macOS leg, #424); **`timeout-minutes: 45`** (provisional — heavier than any 30-min `test.yml` leg, lighter than `ios-tsan.yml`'s 60); `concurrency` cancel-in-progress; `permissions: contents: read`.

### Branch commits (off `main` @ `2ec8930f`, in order)
- `99fc886e` design spec
- `dd6a64ac` implementation plan
- `7ed61d0d` **Task 1** — `.github/workflows/macos-host.yml` (actionlint-clean; pins/knobs verified identical to `ios-tsan.yml` except the deliberate `timeout-minutes: 45`)
- `e15d3ce1` **Task 2** — ROADMAP: flip the D.5.1 "CI wiring … deferred (#437)" note to ✅ shipped (README unchanged — CI jobs aren't tracked in its status table; matches #426/#428 precedent)
- _(this commit)_ **Task 3** — handoff doc + symlink retarget

### Acceptance (local gates met; hosted run is the terminal gate — see §3)
```bash
cd .worktrees/macos-host-ci-437
actionlint .github/workflows/macos-host.yml   # clean (also: bare `actionlint` over the whole dir = clean, no regression)
```
The real acceptance — the first hosted-`macos-26` run going **green** (and going red if the SecretaryKit macOS host test or the app compile breaks) — is observed on **PR #439** via `gh pr checks 439`. It cannot be run locally (it needs a GitHub-hosted macOS runner). `run-macos-tests.sh` itself is already a known-good runner (it is the D.5.1 acceptance entry point, proven on-hardware this repo).

## (2) What's next — pick a new slice

**Verify liveness first** ([[project_secretary_stale_but_done_issues]] — grep/git-log each candidate before starting). Genuinely-open candidates (all re-verified OPEN at the start of THIS session — re-verify again next time):

- **#277 — desktop OS-biometric write re-auth (macOS Touch ID)** — the biggest-remaining D.1 item; desktop still re-auths by password only. `authorizeWrite` is the single injection point. Meaty, multi-session, hardware-verification heavy — brainstorm/spec deliberately. **Acceptance:** LocalAuthentication `LAContext` gate at the desktop `authorizeWrite`, falling back to password where biometry is unavailable; typed error surface; a host-testable gate abstraction (mirror the iOS `WriteReauthGate`) so the logic isn't stranded in the Tauri shell.
- **#417 — mobile Trash purge-notice render-layer test (Compose/SwiftUI)** — the iOS render-assertion infra gap. More tractable on iOS since #435's `BlockNameSheet` is a plain custom SwiftUI view; deciding the infra (ViewInspector host dep vs a SecretaryApp XCUITest target) would ALSO backfill a render test for #434's sheet. **Acceptance:** one render test proving the purge-notice banner shows/hides on the retention state; document the chosen infra.
- **#90 — Rust test-helper dedup** — ~13 files each define `copy_dir_recursive`; consolidate into one shared helper. Low-risk Rust-module practice. **Acceptance:** single shared helper, all duplicates removed, `cargo test --release --workspace` green.
- **#437 follow-up (this PR): re-tune `timeout-minutes`** — after the first few `macos-host` runs, replace the provisional `45` with a value matched to observed cold/warm durations (mirrors the "provisional, re-tune vs live CI" comments already in `test.yml`/`ios-tsan.yml`).
- Security **#383** — still upstream-blocked (`quick-xml 0.39` via `plist` → `tauri`; the dependabot moderate on push is this); re-check on the next Tauri bump; do not start.
- Any user-prioritized slice.

## (3) Open decisions and risks
- **The hosted-macOS run is the only real acceptance and it is NOT locally reproducible.** `actionlint` proves the YAML; it does not prove the job runs green on a GitHub `macos-26` runner. **Watch PR #439's `macos-host` check** (`gh pr checks 439 --watch`). If it goes red, that is the first-ever CI exercise of `build-xcframework.sh` + `build-macos-app.sh` on a hosted runner — debug per systematic-debugging (likely culprits: an image tool the scripts assume, or the multi-minute build exceeding 45 min).
- **`timeout-minutes: 45` is provisional.** First-run cold duration is unknown (4-triple cross-compile + 2 `xcodebuild`); if a healthy run exceeds 45 min, bump it. `rust-cache` should make warm runs much faster.
- **`brew install xcodegen` installs the latest formula version** (not pinned). Acceptable for a non-security project-file generator on a compile-proof path; if a future XcodeGen release changes generated settings and breaks the compile proof, pin the formula then. Also: `xcodegen` may already be preinstalled on `macos-26`, in which case `brew install` is a cheap no-op/upgrade — still correct, keeps the dependency explicit.
- **Path filter is broader than `ios-tsan.yml`'s on purpose** (`ios/** + ffi/** + core/**`). Do not "simplify" it back to `ios/**` — an ffi/core change that breaks the macOS build is exactly this job's reason to exist.
- **Stale merged worktrees to clean up** (both fully merged, tree-clean, remote branches deleted): `.worktrees/ios-block-name-guard-269` (#435) and `.worktrees/d5-macos-native` (#438). Safe to `git worktree remove` + `git branch -D` once you're on a fresh session. This session created + will leave `.worktrees/macos-host-ci-437` (drop it after PR #439 merges).
- **Other in-flight worktrees exist** (parallel sessions — do NOT touch): `.worktrees/d4-browser-autofill`, `.worktrees/desktop-block-crud-ui`, `.worktrees/timer-poison-147`, plus two detached `.claude/worktrees/*`.
- **README: no change** — CI jobs are not tracked in the README status table (precedent: CI-hardening PRs #426/#428 touched neither README nor ROADMAP). ROADMAP got a one-clause flip because it carried the explicit "deferred to #437" note.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After PR #439 merges, drop the branch + worktree (squash-merge leaves it "not fully merged"):
#   git worktree remove .worktrees/macos-host-ci-437 && git branch -D ci/wire-macos-host-437
# Also clean the two already-merged stale worktrees:
#   git worktree remove .worktrees/ios-block-name-guard-269 && git branch -D feature/ios-block-name-guard-269
#   git worktree remove .worktrees/d5-macos-native         && git branch -D fix/d5-macos-review-followups
git worktree list && git status -s
# If resuming THIS branch for fixups (bind histories first — closes the add/add gap on the handoff doc):
#   cd .worktrees/macos-host-ci-437 && git fetch origin && git merge origin/main
# Local gate for this branch (fast, no hosted runner):
#   cd .worktrees/macos-host-ci-437 && actionlint .github/workflows/macos-host.yml
# The terminal acceptance — the hosted macOS run:
#   gh pr checks 439 --watch
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; the symlink retargeted in the same commit on the feature branch (new path → no add/add conflict; `main` updates cleanly on merge). The handoff rides inside the PR — do **not** sync to `main` during the pause window ([[feedback_next_session_main_authoritative]]). If resuming this branch for fixups, first `git fetch origin && git merge origin/main` (branch version wins on this doc) before editing.

## Closing inventory
- **State on close:** PR **#439** open on `ci/wire-macos-host-437` (worktree `.worktrees/macos-host-ci-437`), tracking issue **#437**. Branch commits: spec + plan + workflow + ROADMAP + handoff. Local `actionlint` clean; hosted `macos-host` run watching on the PR at handoff.
- **Acceptance:** `actionlint` clean (new file + whole dir); pins/knobs verified identical to `ios-tsan.yml` except the deliberate `timeout-minutes: 45`. Terminal acceptance = the first `macos-26` run going green on PR #439 (`gh pr checks 439`).
- **Next:** pick a new slice — #277 (biggest D.1), #417 (iOS render-infra, backfills #434), #90 (Rust dedup), or re-tune this job's timeout after live runs, or user priority. **Verify liveness first.**
- **README:** no change. **ROADMAP:** one-clause D.5.1 flip (deferred → shipped).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-07-16-macos-host-ci-437-shipped.md`.
