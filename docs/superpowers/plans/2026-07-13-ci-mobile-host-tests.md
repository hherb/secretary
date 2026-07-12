# Wire Mobile Host-Test Suites into CI — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add two additive jobs to `.github/workflows/test.yml` so the mobile app-layer host-test suites (iOS `swift test` × 2 FFI-free packages; Android `:vault-access:test`) run on every PR, closing the systemic gap where a copy/logic regression stays green in CI (#423).

**Architecture:** Purely additive CI config. Two new jobs appended to the existing `jobs:` map — `ios-host` (macos-latest, pure `swift test`, no Rust/xcframework) and `android-host` (ubuntu-latest, `setup-android` + JDK 21, `:vault-access:test`). No existing job, trigger, or production code changes. The only non-YAML edits are *throwaway* deliberate-regression flips (source copy → run suite → confirm red → revert) that prove each newly-wired suite actually guards the #421 copy.

**Tech Stack:** GitHub Actions YAML; `swift test` (Swift 6 packages); Gradle 8.14.3 + AGP 8.13.2 + Kotlin 2.2.10, JDK 21; `android-actions/setup-android`.

## Global Constraints

- **Pinned action SHAs only** — no moving tags. Reuse the repo's existing pins: `actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5` (v4), `actions/setup-java@c1e323688fd81a25caa38c78aa6df2d33d3e20d9` (v4). `android-actions/setup-android` is looked up + pinned in Task 2 with a version comment.
- **Additive only** — do not modify the four existing jobs (`rust-test`, `desktop-test`, `swift-conformance`, `kotlin-conformance`), the `on:`/`concurrency:`/`permissions:`/`env:` blocks.
- **No `core`/crypto/FFI/on-disk-format change; no new error variant; `#![forbid(unsafe_code)]` intact.** No committed production code change.
- **Working directory:** all work in the worktree `/Users/hherb/src/secretary/.worktrees/ci-mobile-host-tests` on branch `feature/ci-mobile-host-tests`. Edit/Write/Read MUST use the full `.worktrees/ci-mobile-host-tests/...` path (a bare main-repo path silently hits `main`).
- **JDK version** — `android-host` uses temurin **21** (matches `:vault-access` `jvmToolchain(21)`); the existing `kotlin-conformance` uses 17 for a different purpose — do not "align" them.
- **iOS job = two packages** — `swift test` in both `ios/SecretaryDeviceUnlock` and `ios/SecretaryVaultAccess`, as two named steps (mirrors `run-ios-tests.sh` Step 1), one runner.

---

### Task 1: `ios-host` job (macos-latest, `swift test` × 2)

**Files:**
- Modify: `.github/workflows/test.yml` (append one job to the `jobs:` map)
- Regression-bite (throwaway, reverted): `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/SettingsErrorMessage.swift:20`

**Interfaces:**
- Consumes: nothing (first task).
- Produces: a job named `ios-host` in `test.yml`. Task 3 relies on that exact name when watching CI.

- [ ] **Step 1: Establish baseline — run both host suites locally, expect PASS**

Run:
```bash
( cd /Users/hherb/src/secretary/.worktrees/ci-mobile-host-tests/ios/SecretaryDeviceUnlock && swift test ) \
&& ( cd /Users/hherb/src/secretary/.worktrees/ci-mobile-host-tests/ios/SecretaryVaultAccess && swift test )
```
Expected: both packages build and **all tests pass** (`Test Suite '…' passed`). This is the green baseline the CI job wraps. If either fails on host, STOP — the premise is broken; investigate before wiring CI.

- [ ] **Step 2: Prove the guard bites — flip the #421 neutral copy, expect FAIL**

Edit `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/SettingsErrorMessage.swift` line 20, changing the fallback from:
```swift
        return "Couldn’t update settings. Please try again."
```
to (note "save"):
```swift
        return "Couldn’t save settings. Please try again."
```
Run:
```bash
( cd /Users/hherb/src/secretary/.worktrees/ci-mobile-host-tests/ios/SecretaryVaultAccess && swift test )
```
Expected: **FAIL** — `SettingsErrorMessageTests` asserts the neutral "update" copy. This proves the wired suite guards the #421 fix.

- [ ] **Step 3: Revert the regression**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/ci-mobile-host-tests && git checkout ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/SettingsErrorMessage.swift
( cd ios/SecretaryVaultAccess && swift test )
```
Expected: green again (`git status` clean for that file; tests pass).

- [ ] **Step 4: Add the `ios-host` job to `test.yml`**

Append to the `jobs:` map in `.github/workflows/test.yml` (after `kotlin-conformance`):
```yaml
  ios-host:
    name: ios host (swift test)
    # The two mobile host packages are FFI-free (no xcframework, no Rust), so
    # they build + test standalone on a plain macOS runner — no cargo build,
    # no rust-cache. Mirrors run-ios-tests.sh Step 1; guards the app-layer
    # view-model + formatter logic (e.g. the #421 neutral settings copy) that
    # the uniffi conformance jobs do NOT cover.
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      - name: swift test — SecretaryDeviceUnlock (FFI-free host)
        run: swift test
        working-directory: ios/SecretaryDeviceUnlock
      - name: swift test — SecretaryVaultAccess (FFI-free host)
        run: swift test
        working-directory: ios/SecretaryVaultAccess
```

- [ ] **Step 5: Validate the YAML parses**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/ci-mobile-host-tests && python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/test.yml')); print('YAML OK')"
```
Expected: `YAML OK` (no parse error).

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/ci-mobile-host-tests
git add .github/workflows/test.yml
git commit -m "ci: add ios-host job (swift test for SecretaryVaultAccess + SecretaryDeviceUnlock) (#423)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: `android-host` job (ubuntu-latest, `:vault-access:test`)

**Files:**
- Modify: `.github/workflows/test.yml` (append one more job)
- Regression-bite (throwaway, reverted): `android/vault-access/src/main/kotlin/org/secretary/browse/SettingsErrorMessage.kt:16`

**Interfaces:**
- Consumes: the `test.yml` from Task 1 (append after `ios-host`).
- Produces: a job named `android-host`. Task 3 relies on that exact name.

- [ ] **Step 1: Establish baseline — run `:vault-access:test` locally, expect PASS**

Run:
```bash
( cd /Users/hherb/src/secretary/.worktrees/ci-mobile-host-tests/android && ./gradlew :vault-access:test )
```
Expected: `BUILD SUCCESSFUL`, `SettingsErrorMessageTest` + `TrashFormattingTest` + `SettingsModelTest` etc. pass. (Locally the SDK is present, so configuration succeeds — this proves the *command*; the "no SDK" provisioning path is proven only in CI, Task 3.)

- [ ] **Step 2: Prove the guard bites — flip the #421 neutral copy, expect FAIL**

Edit `android/vault-access/src/main/kotlin/org/secretary/browse/SettingsErrorMessage.kt` line 16, changing:
```kotlin
    else -> "Couldn't update settings: ${error::class.simpleName}"
```
to (note "save"):
```kotlin
    else -> "Couldn't save settings: ${error::class.simpleName}"
```
Run:
```bash
( cd /Users/hherb/src/secretary/.worktrees/ci-mobile-host-tests/android && ./gradlew :vault-access:test )
```
Expected: **FAIL** — `SettingsErrorMessageTest` asserts `"Couldn't update settings: CorruptVault"`.

- [ ] **Step 3: Revert the regression**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/ci-mobile-host-tests && git checkout android/vault-access/src/main/kotlin/org/secretary/browse/SettingsErrorMessage.kt
( cd android && ./gradlew :vault-access:test )
```
Expected: green again; `git status` clean for that file.

- [ ] **Step 4: Look up and pin the `android-actions/setup-android` SHA**

Run (resolve the latest release tag → commit SHA to pin):
```bash
gh api repos/android-actions/setup-android/git/ref/tags/v3 --jq '.object.sha'   # if annotated tag, deref:
gh api repos/android-actions/setup-android/git/refs/tags/v3 --jq '.[].object.sha'
```
Take the resolved **commit** SHA (deref annotated tags to the commit) and its human version (e.g. `v3.2.x`) for the pin comment. Record it as `SETUP_ANDROID_SHA` for Step 5.

- [ ] **Step 5: Add the `android-host` job to `test.yml`**

Append after `ios-host` (substitute `<SETUP_ANDROID_SHA>` / `<version>` from Step 4):
```yaml
  android-host:
    name: android host (:vault-access:test)
    # `:vault-access` is pure kotlin(jvm), but the root settings.gradle.kts
    # includes the AGP modules (:app/:kit/:browse-ui/:sync-ui), which Gradle
    # configures even for a :vault-access-only test task — so an Android SDK
    # must be provisioned or configuration fails with "SDK location not found".
    # JDK 21 matches the module's jvmToolchain(21). Guards the app-layer host
    # logic (e.g. the #421 neutral settings copy) uncovered by kotlin-conformance.
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: android
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      - name: Install JDK
        uses: actions/setup-java@c1e323688fd81a25caa38c78aa6df2d33d3e20d9 # v4
        with:
          distribution: temurin
          java-version: 21
          cache: gradle
      - name: Provision Android SDK
        uses: android-actions/setup-android@<SETUP_ANDROID_SHA> # <version>
      - name: ':vault-access:test'
        run: ./gradlew :vault-access:test
```

- [ ] **Step 6: Validate the YAML parses**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/ci-mobile-host-tests && python3 -c "import yaml; d=yaml.safe_load(open('.github/workflows/test.yml')); print('jobs:', list(d['jobs']))"
```
Expected: `jobs: ['rust-test', 'desktop-test', 'swift-conformance', 'kotlin-conformance', 'ios-host', 'android-host']`.

- [ ] **Step 7: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/ci-mobile-host-tests
git add .github/workflows/test.yml
git commit -m "ci: add android-host job (:vault-access:test with provisioned SDK) (#423)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Push, open PR, drive both jobs green in live CI

**Files:** none (CI iteration + optional `android-host` fallback edit to `test.yml`).

**Interfaces:**
- Consumes: jobs `ios-host` + `android-host` from Tasks 1–2.
- Produces: a green Actions run on the PR; the merge evidence for #423 acceptance.

- [ ] **Step 1: Author the handoff + retarget the symlink, then push**

(Per the session's handoff model — do this on the branch before opening the PR. The handoff doc content is finalized in the wrap-up; this step just ensures the branch carries it.) Then:
```bash
cd /Users/hherb/src/secretary/.worktrees/ci-mobile-host-tests
git push -u origin feature/ci-mobile-host-tests
```

- [ ] **Step 2: Open the PR**

```bash
cd /Users/hherb/src/secretary/.worktrees/ci-mobile-host-tests
gh pr create --title "ci: wire mobile host-test suites into test.yml (#423)" \
  --body "Adds two additive host-only jobs to test.yml — ios-host (swift test × 2 FFI-free packages) and android-host (:vault-access:test with provisioned SDK). Closes the systemic gap where a mobile app-layer copy/logic regression stayed green in CI. Emulator instrumented job + :app compile-gate documented as non-goals. Fixes #423.

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
```

- [ ] **Step 3: Watch the run**

```bash
cd /Users/hherb/src/secretary/.worktrees/ci-mobile-host-tests
gh run watch "$(gh run list --branch feature/ci-mobile-host-tests --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
```
Expected (target): all jobs pass, including `ios-host` and `android-host`.

- [ ] **Step 4: If `android-host` fails with a missing SDK component — apply the fallback**

If the log shows AGP could not find `platforms;android-36` / build-tools, add a provisioning step to the `android-host` job in `test.yml`, immediately before the `:vault-access:test` step:
```yaml
      - name: Install SDK platform + build-tools
        run: |
          yes | sdkmanager "platforms;android-36" "build-tools;36.0.0" || true
          sdkmanager --licenses <<< y || true
```
Commit (`ci: provision android-36 platform for :vault-access:test config (#423)`), push, re-watch. Iterate until green. If instead the failure is a *test* failure (not provisioning), STOP — that is a real regression, not a CI-wiring problem; investigate.

- [ ] **Step 5: Confirm the acceptance evidence**

```bash
cd /Users/hherb/src/secretary/.worktrees/ci-mobile-host-tests
gh run list --branch feature/ci-mobile-host-tests --limit 1 --json conclusion,displayTitle
gh pr checks
```
Expected: `ios-host` + `android-host` both `success`. Record the green run URL in the handoff. The regression-bite (Tasks 1–2 Steps 2) already proved locally that a bad copy turns the suites red; the green run proves CI executes them.

---

## Self-Review

**1. Spec coverage:**
- Goal 1 (regression turns CI red) → Tasks 1–2 Step 2 (local bite proof) + Task 3 (CI executes suites). ✅
- Goal 2 (two host-only suites) → Task 1 (iOS ×2) + Task 2 (Android). ✅
- Goal 3 (pinned SHAs, minimal actions, additive) → Global Constraints + reused pins + Task 2 Step 4 (setup-android pin). ✅
- Non-goals (emulator, `:app` gate, iOS sliver) → not planned; documented in spec. ✅
- Verification asymmetry (iOS local, Android CI) → Task 1 fully local; Task 2 local command + Task 3 CI provisioning. ✅
- Acceptance criteria (4 boxes) → Task 3 Steps 3–5. ✅
- Risk: AGP first-configure fallback → Task 3 Step 4. ✅

**2. Placeholder scan:** No TBD/TODO. `<SETUP_ANDROID_SHA>`/`<version>` are explicit lookup outputs from Task 2 Step 4, not placeholders-to-guess. ✅

**3. Type/name consistency:** Job names `ios-host`/`android-host` used identically in Tasks 1–2 (definition) and Task 3 (watch). File paths for the regression-bite match the `grep` outputs. Reused SHAs match the existing `test.yml`. ✅
