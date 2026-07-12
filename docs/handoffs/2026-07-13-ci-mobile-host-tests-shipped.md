# NEXT_SESSION.md — Wire mobile host-test suites into CI (#423) ✅ SHIPPED (PR #425)

**Session date:** 2026-07-13, resuming from `main` @ `4ade2bd4` after #422 (settings/trash render consolidation) merged. With the mobile per-vault settings slice and its render loose ends complete, this session closed the **systemic CI gap** that review surfaced: the mobile app-layer host-test suites had **never** run in CI, so a copy/logic regression (e.g. the #421 Settings banner reverting "update"→"save") stayed green. Branch `feature/ci-mobile-host-tests` off `main` @ `4ade2bd4`; worktree `.worktrees/ci-mobile-host-tests/`. Executed plan-first (spec → plan → subagent-driven inline TDD execution → final whole-branch review). Spec: [docs/superpowers/specs/2026-07-13-ci-mobile-host-tests-design.md](../superpowers/specs/2026-07-13-ci-mobile-host-tests-design.md). Plan: [docs/superpowers/plans/2026-07-13-ci-mobile-host-tests.md](../superpowers/plans/2026-07-13-ci-mobile-host-tests.md).

**CI/config only. No `core` / crypto / FFI / on-disk-format change; no new error variant; `#![forbid(unsafe_code)]` intact. No committed production code change — the only Rust/Swift/Kotlin edits were throwaway deliberate-regression flips (source copy → run suite → confirm red → revert) that proved each newly-wired suite actually guards the #421 copy.**

## (1) What we shipped this session

**#423 — two additive host-only jobs in [.github/workflows/test.yml](../../.github/workflows/test.yml).** Both chosen scopes were user-approved: **host-only** (emulator instrumented job deferred), and **provision the SDK in CI** (vs a divergent standalone sub-build).

- **`ios-host` (pinned `macos-26`)** — `swift test` in the two FFI-free Swift packages `ios/SecretaryDeviceUnlock` (46 tests) + `ios/SecretaryVaultAccess` (276 tests), as two named steps on one runner (mirrors `run-ios-tests.sh` Step 1). No Rust / xcframework build → the cheapest job in the file. Guards the app-layer view-model / formatter logic (the #421 `SettingsErrorMessageTests`, `TrashViewModelTests`, `SettingsViewModelTests`) that the uniffi conformance jobs don't cover. **Pinned to `macos-26`, not `macos-latest` — a real flake forced it; see the CI-flake note in (3).**
- **`android-host` (ubuntu-latest)** — `./gradlew :vault-access:test` (412 tests) with a provisioned Android SDK (`android-actions/setup-android` pinned to `40fd30fb8d7440372e1316f5d1809ec01dcd3699` **# v4.0.1**, SHA independently confirmed to resolve to that tag) + JDK temurin 21 (matches `jvmToolchain(21)`) with `cache: gradle`. The root `settings.gradle.kts` includes the AGP modules, so Gradle configures them even for a pure-JVM test task — hence the SDK. Guards `SettingsErrorMessageTest`, `TrashFormattingTest`, `SettingsModelTest`, etc.

**Regression-bite proven locally during implementation (TDD "test the test"):** flipping the #421 fallback copy back to "save" failed exactly `SettingsErrorMessageTests.testGenericLoadOrSaveErrorUsesNeutralUpdateCopyNotSave` (iOS) and `SettingsErrorMessageTest.genericLoadOrSaveError_usesNeutralUpdateCopy_notSave` (Android); reverted, re-confirmed green, never committed.

### Branch commits (off `main` @ `4ade2bd4`, in order)
- `d20d9c64` design doc (spec)
- `2852f76c` implementation plan
- `8bf5e345` #423 `ios-host` job (swift test × 2 FFI-free packages)
- `4927eabd` #423 `android-host` job (`:vault-access:test` + provisioned SDK, `setup-android` pinned SHA)
- `eb600ba9` handoff doc + symlink retarget
- `77819765` **fixup** — pin `ios-host` to `macos-26` (resolves the macos-latest nondeterminism flake; see (3))

### Acceptance (local verification; live-CI is the gate for the Android provisioning path)
```bash
# iOS — both FFI-free host packages (verifiable locally; macOS toolchain present)
( cd ios/SecretaryDeviceUnlock && swift test )   # 46/46
( cd ios/SecretaryVaultAccess && swift test )    # 276/276
# Android — pure-JVM host suite (local run proves the command; the "no SDK" provisioning path is CI-only)
( cd android && ./gradlew :vault-access:test )   # 412/412
```
**Live CI (PR #425):** `android-host` green on the first run (2m1s; **SDK auto-provisioned, no `sdkmanager` fallback**). `ios-host` initially passed on run 1 (macos-26) but **failed on run 2 (macos-15)** — see the CI-flake note in (3); fixed by pinning `ios-host` to `macos-26` (commit `77819765`), then green on the pinned runner.

## (2) What's next — pick a new slice

The mobile host-test suites now run on every PR. Pick from [ROADMAP.md](../../ROADMAP.md) / [README.md](../../README.md). Concrete candidates (carried + refined from last session):

- **#424 — CI hardening (filed this session; scope expanded after the flake below):** `ios-host` is already pinned to `macos-26` in this PR, but `swift-conformance` still runs on the nondeterministic `macos-latest` — pin its runner *image* too; pin the Xcode toolchain *within* the image (`maxim-lobanov/setup-xcode`, pinned SHA); add `timeout-minutes` uniformly (none set it; a hung `swift test` burns the paid macOS runner to the 6h default). Small, self-contained. **Acceptance:** every macOS job pins a fixed runner image + Xcode; every job sets `timeout-minutes`; applied uniformly.
- **Emulator instrumented job (deferred here):** an opt-in AVD job for `:browse-ui:connectedDebugAndroidTest` (the #417 render guards). Pairs with #414 / the #417 iOS sliver. Deferred as slow/flaky, out of #423's host-only scope.
- **`:app`/`:kit` compile-gate in CI:** `android-host` *configures* but does not *compile* `:app`/`:kit`, so a cross-module sealed-`when` exhaustiveness break (see the Android sealed-`when` memory) still isn't caught. A heavier full-Android-build lift; separate enhancement.
- **Desktop OS-biometric write re-auth (#277 + gate-coverage #280)** — the remaining D.1 roadmap item; completes presence-proof across all three platforms (mobile has grace-window config now; desktop still re-auths by password only). Meaty, multi-session.
- **#417's remaining iOS sliver** — a literal SwiftUI render assertion for `settings-error` / `purge-notice` (ViewInspector or an XCUITest target).
- **Security #383** — still **upstream-blocked** (verified this session: `quick-xml 0.39.4` still resolves via `plist 1.9.0` → `tauri 2.11.2`; exit criteria unmet). Re-check on the next Tauri bump; do not start.
- Any user-prioritized slice.

## (3) Open decisions and risks

- **Android live-CI provisioning (the one real risk, per spec + final review).** With no configuration-on-demand, AGP configures all modules (`compileSdk = 36`) even for `:vault-access:test`, so the SDK location + `android-36` platform/build-tools must resolve at configure time. `setup-android` sets `ANDROID_HOME`/accepts licenses; AGP's `sdkDownload=true` then auto-fetches missing components — most likely green on first run. If not, the failure is **loud** ("SDK location not found" / missing-platform — never a false green), and the documented fallback is a `sdkmanager "platforms;android-36" "build-tools;36.0.0"` step. **Resolved in practice: the auto-download path worked on the first CI run (2m1s) — the fallback was not needed and is not in the shipped job.**
- **CI-flake resolved — `macos-latest` is nondeterministic (macos-15 ↔ macos-26).** During this PR the *same commit* compiled green on `macos-26` (Swift 6.3, run 1) and red on `macos-15` (Swift 6.0, run 2), both requesting `macos-latest` — GitHub is mid-migration of that label. The failure: Swift 6.0 rejects the integer-literal inference (`[N * 86_400_000]` array literals in generic `XCTAssertEqual`) that Swift 6.3 accepts. **Fix: pinned `ios-host` to `macos-26`** (the dev toolchain, Xcode 26.5 / Swift 6.3 — the whole suite already compiled green there in run 1), commit `77819765`. This is the review's #3 (unpinned toolchain) realized. **Follow-on in #424** (scope expanded via comment): pin the runner *image* on the remaining `swift-conformance` macOS job too, pin Xcode-within-image, add `timeout-minutes` uniformly. Optional code-hygiene: make the fragile test literals explicitly `UInt64` so they compile under any Swift (not needed once the runner is pinned; can't be verified without a macos-15 to test on).
- **Xcode/Swift toolchain unpinned + no `timeout-minutes` on the remaining jobs** — accepted here as **pre-existing repo-wide conventions** (the existing `swift-conformance` job is also unpinned; no job sets a timeout). Fixing them all uniformly is **#424** (scope now includes the runner-image pin surfaced above).
- **Non-goals documented, not dropped:** emulator instrumented job; `:app` compile-gate; the iOS literal-SwiftUI render sliver.
- **Android host job needs the SDK provisioned** — do not "optimize" it into a standalone JVM-only sub-build (rejected in the spec: a divergent build graph could pass while the real included build breaks).

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After PR #425 merges, drop the branch + worktree (squash-merge leaves it "not fully merged"):
#   git worktree remove .worktrees/ci-mobile-host-tests && git branch -D feature/ci-mobile-host-tests
git worktree list && git status -s
# Re-run this branch's local gates any time it is live (from the worktree root):
#   ( cd ios/SecretaryDeviceUnlock && swift test ) && ( cd ios/SecretaryVaultAccess && swift test )
#   ( cd android && ./gradlew :vault-access:test )
# CI status for the PR:
#   gh pr checks 425 | grep -E "ios host|android host"
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; the symlink retargeted in the same commit on the feature branch (new path → no add/add conflict; `main` updates cleanly on merge). The handoff rides inside PR #425 — do **not** sync to `main` during the pause window ([[feedback_next_session_main_authoritative]]). If resuming this branch for fixups, first `git fetch origin && git merge origin/main` (branch version wins on this doc) before editing.

## Closing inventory
- **State on close:** PR #425 open on `feature/ci-mobile-host-tests` (worktree `.worktrees/ci-mobile-host-tests`). Branch commits: spec + plan + 2 task + handoff + 1 CI-flake fixup (`77819765`, pin `ios-host` to `macos-26`).
- **Review pass:** subagent-driven — per-task review (both spec ✅ + quality Approved, 0 issues) + final whole-branch review (Ready to merge = Yes; 0 Critical/Important, 4 Minor → #1 = this PR's CI gate, #2 = doc note only, #3+#4 → #424).
- **Acceptance:** iOS both packages green locally (46 + 276); Android `:vault-access:test` green locally (412). Live CI (PR #425): `android-host` green first run (2m1s, SDK auto-provisioned); `ios-host` flaked on a macos-15 runner (macos-latest nondeterminism), fixed by pinning to `macos-26` (`77819765`) → green on the pinned runner.
- **Next:** pick a new slice (#424 CI hardening is the smallest/most-adjacent; or desktop #277, or user priority).
- **README / ROADMAP:** no change (internal CI infrastructure, no user-facing feature; README "Testing and hardening" covers only fuzzing, ROADMAP tracks feature slices — CI jobs #288/#289 set the precedent of not appearing in either).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-07-13-ci-mobile-host-tests-shipped.md`.
