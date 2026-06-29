# Design — Android biometric cloud-vault OPEN (#337)

**Date:** 2026-06-30
**Issue:** [#337](https://github.com/hherb/secretary/issues/337) — follow-up to #333 (cloud-vault device enrollment + biometric write-reauth)
**Scope:** Android `app/` (Kotlin/Compose) only. **No** `core` / `ffi` / `:kit` / `:vault-access` / on-disk-format / spec / conformance / conflict-KAT change.

## Goal

An enrolled device opens a **cloud (SAF) vault** by biometric, mirroring the existing demo/local biometric-open path. Today (post #333) a device can be *enrolled* against a cloud vault and *write-reauth* is biometric, but **cloud open is still password-only**. This wires biometric **open**.

## Why this is small (the heavy lifting already shipped in #333)

- The cloud device slot `devices/<uuid>.wrap` is already minted into the cloud vault on enrollment, and survives materialize (proven by `CloudEnrollSafRoundTripInstrumentedTest`).
- The per-cloud-vault device secret (keyed Keystore enclave, alias `secretary.devicesecret.cloud.<cloudKey>`) and enrollment metadata (vaultId + deviceUuid) are already stored locally, keyed by `cloudKey(treeUri)`.
- The FFI boundary `openWithDeviceSecret` is complete end-to-end and **already used** by the demo biometric-open path.
- `isUnlocking` (the #332 spinner flag) already wraps the biometric path.

The remaining gap is **purely Android UI orchestration**.

## Chosen approach — A (query state at screen entry; rebuild coordinator in the callback)

Rejected alternatives:
- **B — hoist a retained cloud `DeviceUnlockViewModel` into `AppRoot` keyed by target.** More symmetric with the demo path, but adds a retained, target-keyed object whose lifecycle must track `cloudTarget` changes (retention pitfalls, more state to get wrong) for no functional gain — the coordinator is cheap to rebuild.
- **C — auto-prompt biometric on screen entry.** Surprising UX; fights the button-driven demo pattern; hostile when the user wants to type a password.

Approach A reuses the entire existing cloud-open pipeline unchanged, holds the least state, and concentrates new logic in pure, host-testable helpers.

## Architecture & data flow (the new biometric-cloud-open path)

1. User lands on `Route.Unlock(cloudTarget)` with `cloudTarget != null`.
2. `LaunchedEffect(cloudTarget)` computes the per-cloud **enrollment state** via a cheap local read (keyed metadata + enclave alias for `cloudKey(treeUri)`). **No biometric prompt, no SAF I/O.**
3. If enrolled → `UnlockScreen` shows the biometric-unlock button (today gated to `cloudTarget == null`).
4. Tap → `onBiometricUnlock` **cloud branch**: rebuild `cloudDeviceUnlockCoordinator(activity, noBackupBase, cloudKey(treeUri))`, call its biometric unlock → releases the keyed Keystore secret behind `BiometricPrompt` → returns `UnlockCredential.DeviceSecret(uuid, secret)`.
5. Route that credential through the **existing** `openCloudTarget(..., enrollThisDevice=false)` → `openExisting()` materializes cloud→working (so `devices/<uuid>.wrap` is present locally) → `openCloudBrowse` → `openWithCredential` dispatches `DeviceSecret` → FFI `openWithDeviceSecret`.
6. `isUnlocking` (shipped #332) already wraps the biometric path, so the spinner shows during the multi-second open.

**Why it works with zero core change:** materialize-before-open already runs in `openExisting()`, so the device slot is on disk before the FFI open; the write-reauth gate decision (`cloudReauthRoute`) already reads the local metadata that enrollment wrote.

## Components & files touched

### New pure helpers — `android/app/src/main/kotlin/org/secretary/app/CloudBiometric.kt`
Free functions, no Compose/Android types in their bodies (per the project's pure-functions preference); keeps `AppRoot.kt` under the 500-line threshold.

- `cloudBiometricButtonVisible(cloudTarget, cloudEnrollState): Boolean` — total mapping: `true` iff a cloud target is present **and** its enrollment state is `Enrolled`. (The demo-path equivalent inlines `cloudTarget == null && state is Enrolled`; this extracts and names the cloud half.)
- An enrollment-state derivation wrapper is added **only if** the metadata-load result needs branching worth pinning; if it is a one-liner delegating to the existing coordinator query, it is skipped (YAGNI).

### `CloudVaultOpen.kt` — the one real behavioral fix
`openCloudBrowse()` already takes `credential: UnlockCredential` but hard-codes `openWithPassword`. Change that single open call to `openWithCredential(openPort, workingDir.path, credential)` (the same dispatch the demo path uses). Enroll-after-open stays gated to `credential is Password`, so the biometric path (`DeviceSecret`) correctly skips re-enroll.

### `AppRoot.kt` — wiring (Approach A)
- Add `cloudDeviceState` derived in `LaunchedEffect(cloudTarget)` (cheap local read).
- Screen `isEnrolled` = demo case **OR** `cloudBiometricButtonVisible(...)`.
- Split `onBiometricUnlock` into a demo branch (existing) and a cloud branch (rebuild cloud coordinator → `DeviceSecret` → `openCloudTarget(..., enrollThisDevice=false)`).

### Unchanged
`CloudDeviceUnlock.kt`, `BrowseSession.kt`, `UnlockCredential.kt`, all of `:kit` / `:vault-access` / `core` / FFI. No on-disk-format / spec / conformance / conflict-KAT change.

## Error handling

- **Biometric cancel / non-match:** the cloud coordinator's biometric unlock surfaces the same typed `DeviceUnlockError` as the demo path; cancel funnels to a cancel error (not a corruption error). On cancel, `isUnlocking` resets in the existing `finally`, the screen stays on Unlock, no Toast (cancel is not a failure).
- **Open failure after successful biometric** (e.g. stale working copy missing `devices/<uuid>.wrap` → FFI `DeviceSlotNotFound`, or wrong-secret/corrupt): surfaces via the cloud path's **existing** failure Toast — **no silent return to Unlock**. (Re-plumbing the cloud path to the typed `unlockFailureMessage` stays out of scope, consistent with #332/#333.)
- **Not-enrolled / stale enrollment:** the button simply does not show (the `LaunchedEffect` state read returns not-`Enrolled`); the user falls back to password, which still works. No failure path.
- **Offline / un-materialized cloud:** `openExisting()` already handles pending-flush + materialize; a genuinely-behind cloud copy missing the slot folds into the open-failure Toast above. Documented risk, not a new code path.

## Testing (acceptance bar: host gate + emulator instrumented)

- **Host unit tests** (`:app/src/test`): `cloudBiometricButtonVisible` totality — enrolled-cloud → true; unenrolled-cloud → false; null-target → false; demo-OR composition if extracted. Pure, fast.
- **Instrumented UI test** (`:app`, emulator-5554): new `CloudBiometricUnlockUiTest` — render `UnlockScreen` for an enrolled cloud target, assert the biometric button (existing testTag) is shown + enabled and that tapping it routes through the cloud branch (existing fake/injected coordinator pattern, no real Keystore); assert the button is **absent** for an unenrolled cloud target.
- **Host gate green:** `:app:testDebugUnitTest :kit:testDebugUnitTest :vault-access:test :app:compileDebugKotlin :app:compileDebugAndroidTestKotlin`.
- **On-device biometric cloud-open** on the RedMagic: deferred to a manual follow-up.
- **No conformance/KAT impact** (no FFI/format change) — the Swift/Kotlin conformance scripts are not in this gate.

## Out of scope (explicit)

- Settings-screen enroll/disenroll toggle (separate #333 follow-up).
- Cloud password-path error-message re-plumbing to the typed `unlockFailureMessage`.
- Recovery-phrase cloud open.

## Risks

- A stale/un-materialized cloud working copy could miss `devices/<uuid>.wrap` and fail the device-secret open; mitigated by `openExisting()`'s materialize/pending-flush and surfaced via the existing failure Toast.
- `:app` Compose-UI instrumented tests can intermittently fail on the RedMagic ("No compose hierarchies found") — pre-existing, device-specific; the merge gate is the host suite + emulator-5554, not the RedMagic.
