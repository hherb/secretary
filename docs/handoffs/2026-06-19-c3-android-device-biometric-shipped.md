# NEXT_SESSION.md — C.3 Android real biometric device open, slice 2 ✅ (SHIPPED — on-device biometric proof PASSED on NX809J / Android 16)

**Session date:** 2026-06-19. Flow: `/nextsession` → prior baton (device-open slice 1, "push + open PR") was already **squash-merged by a parallel session** (PR #262, `main` @ `c923be6a`) → housekeeping (removed the merged `c3-android-device-open-core` worktree + branch; left `hardcore-robinson` / `d4-browser-autofill` untouched) → chose **slice 2 (real biometric device open)** → brainstormed 4 decisions (minimal e2e round-trip; enroll-via-unlock-screen-checkbox; split enclave with an injected `BiometricGate`; `MainActivity`→`FragmentActivity`) → spec → 7-task TDD plan → **subagent-driven execution** (fresh implementer + spec/quality review per task; all review items fixed in-task) → final whole-branch review (opus, READY-WITH-MINORS) → 4 minor fixes → this handoff.

**Status:** ✅ **SHIPPED — all gates green INCLUDING the on-device biometric proof.** Branch `feature/c3-android-device-biometric` pushed; **PR [#263](https://github.com/hherb/secretary/pull/263) open + MERGEABLE** (awaiting your squash-merge). **Android-only — `core` / `ffi` / `ios` / on-disk-format / UDL all untouched** (both guardrails verified empty). **Real-biometric on-device proof PASSED on an NX809J (Android 16, 2026-06-19):** enrol (with enroll-time biometric) → force-stop → "Unlock with biometrics" released the device secret behind a real `BiometricPrompt` and opened the vault to `BrowseWithSyncScreen`; a cancelled prompt returned cleanly to the unlock screen with no crash. README/ROADMAP flipped 🚧 → ✅.

## (1) What we shipped this session

**The central idea:** an enrolled Android device opens `golden_vault_001` via its per-device wrap slot, with the 32-byte device secret released only behind a real `BiometricPrompt`. Slice 1 (#262) gave the pure coordinator + ports + FFI adapter with FAKE enclave/metadata; slice 2 swaps in the REAL Android implementations + UI + wiring. The device-secret credential flows through the SAME `openWithCredential` → `openBrowseWithSync` pipeline as password/recovery (same manifest verify-before-decrypt — never a weaker open).

| Layer | What landed | Commit (pre-squash) |
|---|---|---|
| **Spec + plan** | design doc + 7-task TDD plan | `be31381` `7469575` |
| **Task 1 — `DeviceUnlockViewModel`** | pure state machine (`Unenrolled`/`Enrolled`/`Prompting`/`Failed`) in `:vault-access`, host-tested over the slice-1 fakes (+ a fix: idiomatic unused-param + test name) | `a0f62e1` `77710d6` |
| **Task 2 — `FileDeviceEnrollmentMetadataStore`** | non-secret `vaultId`+uuid file store in `:kit`, host-tested (+ a fix: temp-cleanup-on-rename-failure + boundary tests) | `ef2bcdc` `000bc87` |
| **Task 3 — `KeystoreDeviceSecretEnclave` + `BiometricGate`** | real AES-256-GCM Keystore enclave (`release` gated by an injected `BiometricGate` via `CryptoObject`; PRODUCTION = auth-required + StrongBox-best-effort + `invalidatedByBiometricEnrollment`), instrumented round-trip (+ a **security fix**: invalidated-key & corrupt/truncated-blob → typed `Enclave`/`WrappedSecretCorrupt`, never untyped) | `ae5f9ab` `6e71404` |
| **Task 4 — `BiometricPromptGate` + `mapBiometricError` + `FragmentActivity`** | the real `:app` gate (CryptoObject prompt → suspend bridge), pure host-tested error mapping, `MainActivity` `ComponentActivity`→`FragmentActivity` + `androidx.biometric` dep (+ a fix: `ERROR_CANCELED` test) | `c58ef10` `02a72fd` |
| **Task 5 — `UnlockScreen` affordances** | "Remember this device with biometrics" checkbox + "Unlock with biometrics" button, instrumented Compose UI tests (+ a fix: rename a `remember`-shadowing var + negative-visibility tests) | `795c687` `ea03532` |
| **Task 6 — `AppRoot` wiring** | construct coordinator once; enroll-on-password-unlock-with-remember (non-fatal); biometric unlock → existing pipeline (+ a **functional fix**: bridge the pure VM's plain-`var` state into a Compose-observable mirror, else the enrolled button never appears) | `bc50bfe` `792b89c` |
| **Task 7 — docs** | README + ROADMAP rows (slice 2 🚧) | `f5235c7` |
| **Final-review fixes** | 2 `IOException` typed-mapping edges + drop dead `_folder` param + doc reword | `5cc1811` |

Branch from `main` @ `c923be6a`. **Squash-merge collapses 16 commits → one on `main`.**

### Architecture (where the pieces live)
- `:vault-access` (pure, host-tested) — `DeviceUnlockViewModel` + `DeviceUnlockState`.
- `:kit` (Android lib) — `KeystoreDeviceSecretEnclave` + `BiometricGate` typealias + `KeystoreKeyConfig` (instrumented; PRODUCTION default), `FileDeviceEnrollmentMetadataStore` (host-tested).
- `:app` — `BiometricPromptGate` + pure `mapBiometricError`, `MainActivity` (now `FragmentActivity`), `UnlockScreen` affordances, `AppRoot` wiring.

### Acceptance (automated — green this session)
```
cd android && ./gradlew :vault-access:test :kit:test :app:testDebugUnitTest :browse-ui:test        → BUILD SUCCESSFUL (host)
cd android && ANDROID_SERIAL=emulator-5554 ./gradlew :kit:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.browse.KeystoreDeviceSecretEnclaveTest    → 4/4 (enclave round-trip/corrupt/truncated/enrolled)
cd android && ANDROID_SERIAL=emulator-5554 ./gradlew :app:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.app.UnlockScreenDeviceUiTest             → 4/4 (UI affordances incl. negative-visibility)
cd android && ANDROID_SERIAL=emulator-5554 ./gradlew :app:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.app.OpenWithDeviceSecretSmokeTest        → 1/1 (slice-1 device-secret pipeline REGRESSION clean)
git diff main...HEAD --name-only | grep -E 'core/|ffi/|crypto-design|vault-format'                          → empty
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md)'                         → empty (NO ios/)
```
App installs + launches cleanly to `MainActivity` on emulator-5554 (FragmentActivity migration sound; no crash).

### Deliberate design decisions (so a future reader doesn't "fix" them)
- **Injectable `KeystoreKeyConfig`** — an auth-required Keystore key CANNOT be exercised headlessly (`doFinal` throws `UserNotAuthenticatedException` without a live biometric), so the instrumented test injects `TEST_NO_AUTH` to prove the wrap/unwrap/blob mechanics; the secure `PRODUCTION` default is proven by the manual proof (§4). Same honest split iOS used (its simulator test used a fake enclave). **Don't "add a PRODUCTION-config automated test" — it's not possible.**
- **One enroll-time biometric prompt** — Android can't scope key-auth to decryption-only for a symmetric key, so `store` also routes through the gate. Acceptable (enroll is deliberate); two-key-wrap fallback documented in the spec if it proves awkward.
- **Device-secret session syncs like recovery** (status-only) — Android sync is password-keyed; the `dispatchPostOpenSync` `DeviceSecret`→`onRecovery` arm shipped in slice 1; unchanged.
- **Pure VM state bridged to Compose in AppRoot** — `DeviceUnlockViewModel.state` is a plain `var` (the module has no Compose dependency, so it's host-testable). AppRoot mirrors it into a `mutableStateOf` refreshed on entering the Unlock route. **Don't read `deviceVm.state` directly in a composable** — it won't recompose.
- **Typed errors only** — invalidated-key/corrupt-blob/IO failures map to the existing `Enclave(...)`/`WrappedSecretCorrupt` arms; NO new `DeviceUnlockError` variant added this slice.

## (2) What's next

- **Merge PR [#263](https://github.com/hherb/secretary/pull/263)** (your squash-merge), then housekeeping (§4 step 1). The on-device biometric proof is DONE — slice 2 is fully shipped.
- **Polished enrollment/settings UI + disenroll-from-UI** — deferred from this minimal slice (the coordinator's `disenroll` exists from slice 1; no UI yet).
- **#261 (root-cause secret residue)** — UDL `take_secret()` `sequence<u8>?` → `bytes?` so bindings return a zeroizable `ByteArray`/`Data`. Cross-platform; needs the Swift+Kotlin conformance harness re-run.
- **Block create/rename + record move-between-blocks** — next CRUD tier.
- **iOS biometric re-auth before a write** — separate follow-up (ROADMAP C.3 remaining).
- **On-device sync veto round-trip** still needs a seeded concurrent state ([[project_secretary_sync_veto_needs_seeded_state]]).

**Open follow-up issues (carried):** #224 / #234 / #192 / #193 / #190 / #189 / #186 / #161 / #162 / #167 / #202 / #251 / #252 / #255 / #261. **None filed this session** (all review findings fixed in-task).

## (3) Open decisions and risks
- **Manual biometric proof DONE** — passed on NX809J / Android 16 (2026-06-19). Slice is ✅. No outstanding risks for this slice.
- **`:kit` enclave + `:app` gate/wiring have no host test** — they need the real Keystore / Activity; the instrumented enclave round-trip (4/4) + the manual proof are the behavioral evidence. The pure logic (VM, mapping, metadata store) is fully host-tested.
- **Final review verdict (opus, whole-branch):** READY-WITH-MINORS; 0 Critical, 0 Important. Verified against actual code: end-to-end secret-hygiene trace (zeroize on every path, enclave retains no plaintext), no secrets in logs/exception messages, the cryptographic `CryptoObject` gate (not a bypassable guard), no silent auth downgrade in the StrongBox fallback, the device open reusing verify-before-decrypt, guardrails empty, and test honesty. All 4 Minors fixed (`5cc1811`).

## (4) Exact commands to resume
```bash
# 0) ALREADY DONE this session: branch pushed, PR #263 opened (MERGEABLE), on-device biometric proof PASSED.
#    Your next action is simply to squash-merge PR #263.

# 1) After the PR merges, housekeeping (from the MAIN checkout, not this worktree):
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/c3-android-device-biometric && git branch -D feature/c3-android-device-biometric
git worktree prune && git worktree list   # leaves hardcore-robinson + d4-browser-autofill untouched

# Re-run the gauntlet (emulator must be running; TWO devices attached — PIN emulator-5554):
cd /Users/hherb/src/secretary/.worktrees/c3-android-device-biometric/android && \
  ./gradlew :vault-access:test :kit:test :app:testDebugUnitTest :browse-ui:test                 # host green
cd /Users/hherb/src/secretary/.worktrees/c3-android-device-biometric/android && \
  ANDROID_SERIAL=emulator-5554 PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :kit:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.browse.KeystoreDeviceSecretEnclaveTest
# NOTE: connectedAndroidTest rejects --tests; use -Pandroid.testInstrumentationRunnerArguments.class=<FQN>.
# NOTE: a physical device (912607710061) AND emulator-5554 are attached — always set ANDROID_SERIAL.

# Guardrails (core/ffi/format AND ios/ all empty this slice):
git diff main...HEAD --name-only | grep -E 'core/|ffi/|crypto-design|vault-format'                   # empty
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md)'                  # empty
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Authored once; the symlink is the pointer. `origin/main` did NOT move during this session relative to the branch point (`c923be6a`), so the symlink retarget merges cleanly. Both this handoff + the retargeted symlink are committed on the feature branch ([[feedback_next_session_in_pr]]). If you resume this branch for fixups, first `git fetch origin && git merge origin/main` (branch-version-wins on the handoff path) before editing ([[feedback_next_session_main_authoritative]]).

## Closing inventory
- **Branch on close:** `main` @ `c923be6a`; `feature/c3-android-device-biometric` pushed; **PR #263 open + MERGEABLE.** Carries spec + plan + 7 task commits (with per-task fixes) + 1 final-fix commit + handoff + this proof-result commit. Squash-merge → one commit on `main`.
- **Acceptance:** green — host suites + `:kit` enclave 4/4 + `:app` UI 4/4 + slice-1 device-secret smoke 1/1 regression; both guardrails empty (incl. no `ios/`). **Real-biometric on-device proof PASSED on NX809J / Android 16.**
- **Process note:** subagent-driven (fresh implementer + spec/quality review per task; all per-task review items fixed in-task). Final whole-branch review (opus) = READY-WITH-MINORS; all 4 Minors fixed.
- **README.md / ROADMAP.md:** updated — device-open slice 2 ✅ (real biometric, on-device proof passed on NX809J/Android 16), 2026-06-19.
- **NEXT_SESSION.md:** symlink retargeted to this file.
