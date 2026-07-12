# Design — Wire mobile host-test suites into CI (#423)

**Date:** 2026-07-13
**Issue:** [#423](https://github.com/hherb/secretary/issues/423) — *CI: wire the mobile host-test suites into test.yml*
**Branch:** `feature/ci-mobile-host-tests` off `main` @ `4ade2bd4`
**Scope class:** CI/config only. **No** `core` / crypto / FFI / on-disk-format change; no new error variant; `#![forbid(unsafe_code)]` intact. No production code changes at all — the only Rust/Swift/Kotlin touched is a *throwaway* deliberate-regression edit used to prove the guard bites, then reverted.

## Problem

`.github/workflows/test.yml` runs four jobs: `cargo test` (Linux + macOS), desktop `vitest`, and the Swift + Kotlin uniffi **conformance KAT replays** (raw `swiftc`/`kotlinc`, no Gradle, no Android SDK). **None of the mobile app-layer test suites run in CI:**

- Android host unit tests — `:vault-access:test` (`SettingsErrorMessageTest`, `TrashFormattingTest`, `SettingsModelTest`, …).
- iOS Swift-package host tests — `SecretaryVaultAccess` / `SecretaryDeviceUnlock` `swift test`.
- Android instrumented Compose tests — `:browse-ui:connectedDebugAndroidTest` (the #417 render guards).

Consequence surfaced during the #422 review: the new host + render-binding tests were green **locally** that session, but a regression — e.g. the Settings banner copy reverting from "update" to "save" (#421) — would keep CI green. These guards silently rot. The gap is **pre-existing and systemic**: the mobile suites have never been in CI.

## Goals

1. A copy/logic regression in the mobile app-layer host suites turns a **CI** job red, not just a local run.
2. Wire in the **two fast, host-only** suites (no emulator, no xcframework, no Rust build for iOS).
3. Follow the repo's CI discipline: **pinned action SHAs**, minimal third-party actions, additive-only (no existing job touched).

## Non-goals (out of scope, documented not done)

- **Emulator instrumented job** (`:browse-ui:connectedDebugAndroidTest`). Deferred as an opt-in follow-up (pairs with #414 / the remaining #417 iOS sliver). Emulator CI is slow (AVD boot) and flaky; the issue explicitly scopes it as "Stretch / separate".
- **`:app:assembleDebug` compile-gate in CI.** Would catch the cross-module sealed-`when` breakage (`:vault-access` adding an arm silently breaks no-`else` `when`s in `:kit`/`:app`), but that is a heavier full-Android-build lift — a separate future enhancement. `:vault-access:test` *configures* but does not *compile* `:app`/`:kit`.
- **The iOS literal-SwiftUI render sliver (#417 remainder).** Unrelated; tracked separately.

## Design

Two new jobs appended to the existing `jobs:` map in `.github/workflows/test.yml`. No change to the four existing jobs, the `on:` triggers, `concurrency`, `permissions`, or `env`.

### Job 1 — `ios-host` (macos-latest)

Mirrors `ios/scripts/run-ios-tests.sh` Step 1. Both packages are FFI-free (`swift-tools-version: 6.0`, `platforms: [.macOS(.v13), .iOS(.v17)]`, **no** `binaryTarget`/xcframework, no Rust), so they build + test standalone on a plain macOS runner. **No cargo build, no `rust-cache`** — the cheapest job in the file.

Steps:
- `actions/checkout` — pinned SHA (same `34e114876b0b11c390a56381ad16ebd13914f8d5` as the existing jobs).
- `swift test` in `ios/SecretaryDeviceUnlock` (covers `SecretaryDeviceUnlockTests` / `…UITests` — the device-unlock coordinator logic).
- `swift test` in `ios/SecretaryVaultAccess` (covers `SecretaryVaultAccessTests` / `…UITests` — the #421 `SettingsErrorMessageTests`, `TrashViewModelTests`, `SettingsViewModelTests`).

**Two named steps, not a package matrix** — one macOS runner spin-up (macOS minutes are the scarcest), and each failure is attributable to its package. If `SecretaryDeviceUnlock` fails, the step stops and the job is red — acceptable for a gate.

### Job 2 — `android-host` (ubuntu-latest)

`:vault-access` is a pure `kotlin("jvm")` module (`jvmToolchain(21)`), **but** the root `android/settings.gradle.kts` `include`s the Android modules (`:app` = `com.android.application`; `:kit`/`:browse-ui`/`:sync-ui` = `com.android.library`, all `compileSdk = 36`). Gradle configures **every** included project even for `./gradlew :vault-access:test`, so AGP (8.13.2) is applied and an Android SDK must be present, or configuration fails with **"SDK location not found."**

Steps:
- `actions/checkout` — pinned SHA.
- `actions/setup-java` — distribution `temurin`, java-version **21** (matches `jvmToolchain(21)`; AGP 8.13 runs on JDK 21), `cache: gradle` (built-in Gradle cache — avoids adding a second third-party caching action).
- `android-actions/setup-android` — **pinned SHA**, licenses accepted; provisions the command-line tools so AGP auto-downloads `platforms;android-36` on first configure.
- `./gradlew :vault-access:test` (working-directory `android`) — covers `SettingsErrorMessageTest`, `TrashFormattingTest`, `SettingsModelTest`, etc.

**Fallback (only if the auto-download path fails in CI):** add an explicit `sdkmanager "platforms;android-36" "build-tools;36.0.0"` step before the Gradle run. The workflow ships minimal first; this is added only if a live run proves it necessary — recorded here so the follow-up isn't a surprise.

## Verification strategy

The two jobs differ sharply in how confidently they can be verified before merge:

- **iOS job — fully verifiable locally.** The macOS toolchain is available on the dev machine; `swift test` in both packages is the exact command the job runs. A locally-green run proves the wrapper. (`run-ios-tests.sh` already runs both every iOS session.)
- **Android job — needs a live CI run.** The "SDK location not found" failure mode **cannot be reproduced locally** (the dev machine already has an SDK). Confirming the `setup-android` provisioning path is therefore inherently CI-driven — the iteration the issue flagged. Flow: push branch → open PR → watch the `android-host` job → iterate the SDK step (apply the `sdkmanager` fallback if needed) until green.

### Acceptance criteria

- [ ] `ios-host` green on `macos-latest` — `swift test` passes for both `SecretaryDeviceUnlock` and `SecretaryVaultAccess`.
- [ ] `android-host` green on `ubuntu-latest` — `./gradlew :vault-access:test` passes with a provisioned SDK.
- [ ] Both jobs wired into `test.yml` with **pinned action SHAs**; no existing job modified.
- [ ] **Regression bite proven:** flipping the #421 fallback copy back to "save" makes the relevant suite fail (demonstrated locally for `:vault-access:test` and the iOS `SettingsErrorMessageTests`, then reverted). The PR's own green Actions run is the CI evidence that the jobs execute the suites.

## Risks

- **AGP first-configure SDK components.** If `setup-android`'s default install lacks a component AGP 8.13.2 needs at configure time, the Android job fails until the `sdkmanager` fallback is added. Mitigated by the documented fallback; caught by the live CI run.
- **`setup-android` SHA freshness.** Pinning to a SHA (not a moving tag) is required by repo discipline; the SHA is looked up from the action's release at implementation time and recorded with a version comment (cf. the pinned kotlin snap revision in `kotlin-conformance`).
- **macOS runner minutes.** The `ios-host` job adds a macOS runner to every PR. Kept cheap by running only pure-Swift `swift test` (no Rust, no xcframework) and a single runner (two steps, not a matrix).
- **No new coverage of `:app`/`:kit` compile.** Accepted (non-goal). A cross-module `when`-exhaustiveness break still would not be caught by CI; that remains a known separate gap.

## Rollout

Single PR off `feature/ci-mobile-host-tests`. Since the Android job needs live-CI iteration, the PR is where it is proven green; the iOS job is verifiable pre-push. No README/ROADMAP change (internal CI infrastructure, no user-facing feature).
