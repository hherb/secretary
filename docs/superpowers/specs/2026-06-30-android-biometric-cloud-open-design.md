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

> **Correction during plan authoring (post-approval):** verifying the code showed the credential dispatch is **already generic**. `openCloudBrowse → openBrowseWithSync → openWithCredential` (`BrowseSession.kt:63`, `UnlockCredential.kt:30-34`) already routes a `DeviceSecret` credential to `openPort.openWithDeviceSecret`. And `UnlockScreen` (`UnlockScreen.kt:79-85`) already renders the biometric button for any `isEnrolled == true`, demo or cloud. So **`CloudVaultOpen.kt` and `UnlockScreen.kt` need ZERO changes** — the earlier "one behavioral fix to `openCloudBrowse`" is unnecessary. The change is strictly smaller: `AppRoot.kt` wiring + one new pure helper + tests.

### New pure helper — `android/app/src/main/kotlin/org/secretary/app/CloudBiometric.kt`
Free function, no Compose/Android types in its body (per the project's pure-functions preference).

- `unlockBiometricEnrolled(isCloudTarget: Boolean, demoEnrolled: Boolean, cloudEnrolled: Boolean): Boolean` — total mapping that replaces the inline `r.cloudTarget == null && deviceState is Enrolled` at `AppRoot.kt:287`: returns `cloudEnrolled` for a cloud target, `demoEnrolled` for the demo target. This is the one genuinely new decision and is host-tested for totality.

### `AppRoot.kt` — wiring (Approach A), the only production change
- Add `var cloudEnrolled by remember { mutableStateOf(false) }`.
- In `LaunchedEffect(route)`: when `route is Route.Unlock` with a non-null `cloudTarget`, build `cloudDeviceUnlockCoordinator(activity, context.noBackupFilesDir, cloudVaultKey(cloudTarget.location.treeUri))` and set `cloudEnrolled = it.coordinator.isEnrolled` (cheap, prompt-free; `isEnrolled` = enclave blob **and** metadata present). For a demo target the existing `deviceVm.refresh()` path is unchanged.
- Screen `isEnrolled = unlockBiometricEnrolled(isCloudTarget = r.cloudTarget != null, demoEnrolled = deviceState is DeviceUnlockState.Enrolled, cloudEnrolled = cloudEnrolled)`.
- Split `onBiometricUnlock` into a demo branch (existing, unchanged) and a **cloud branch** (when `r.cloudTarget != null`): rebuild the cloud coordinator, wrap it in a throwaway `DeviceUnlockViewModel`, call `unlockWithBiometrics(vaultId = cdu.metadataVaultId ?: "", reason = "Unlock your vault") { credential -> route = openCloudTarget(context, activity, r.cloudTarget, credential, enrollThisDevice = false, locationStore, selectionVm) }`, surface the same "couldn't open" Toast on a returned `Route.Unlock`, then recompute `cloudEnrolled = cdu.coordinator.isEnrolled` so a cancel keeps the button. `isUnlocking` wraps it in the existing `try/finally`.

**Why `vaultId = cdu.metadataVaultId`:** `DeviceUnlockCoordinator.unlock` (`DeviceUnlockCoordinator.kt:56-61`) guards `enrollment.vaultId == vaultId` (else `VaultSlotMismatch`) **before** the biometric prompt. The enrolled vault id is exactly `cdu.metadataVaultId`; the location's `vaultUuidHex` may be empty (a SAF-picked vault not yet opened) or differ, so the enrolled id is the correct guard value. The actual open uses the `deviceUuid` carried in the returned credential, independent of this id.

### Unchanged
`CloudVaultOpen.kt`, `UnlockScreen.kt`, `CloudDeviceUnlock.kt`, `BrowseSession.kt`, `UnlockCredential.kt`, all of `:kit` / `:vault-access` / `core` / FFI. No on-disk-format / spec / conformance / conflict-KAT change.

## Error handling

- **Biometric cancel / non-match:** the cloud coordinator's biometric unlock surfaces the same typed `DeviceUnlockError` as the demo path; cancel funnels to a cancel error (not a corruption error). On cancel, `isUnlocking` resets in the existing `finally`, the screen stays on Unlock, no Toast (cancel is not a failure).
- **Open failure after successful biometric** (e.g. stale working copy missing `devices/<uuid>.wrap` → FFI `DeviceSlotNotFound`, or wrong-secret/corrupt): surfaces via the cloud path's **existing** failure Toast — **no silent return to Unlock**. (Re-plumbing the cloud path to the typed `unlockFailureMessage` stays out of scope, consistent with #332/#333.)
- **Not-enrolled / stale enrollment:** the button simply does not show (the `LaunchedEffect` state read returns not-`Enrolled`); the user falls back to password, which still works. No failure path.
- **Offline / un-materialized cloud:** `openExisting()` already handles pending-flush + materialize; a genuinely-behind cloud copy missing the slot folds into the open-failure Toast above. Documented risk, not a new code path.

## Testing (acceptance bar: host gate + emulator instrumented)

- **Host unit test** (`:app/src/test`, JUnit 5): `UnlockBiometricEnrolledTest` for `unlockBiometricEnrolled` totality — cloud-target+cloudEnrolled → true; cloud-target+!cloudEnrolled → false; demo-target follows `demoEnrolled` (true and false); and that the cloud branch ignores `demoEnrolled` and the demo branch ignores `cloudEnrolled` (no cross-talk). Pure, fast. This is the one genuinely new decision.
- **Instrumented UI test** (`:app`, emulator-5554): new `CloudBiometricUnlockUiTest` — render `UnlockScreen` with a **cloud** title (`"Secretary — My Cloud Vault"`) and `isEnrolled = true`; assert the `biometric-unlock` button is displayed + enabled and tapping it fires `onBiometricUnlock`; and with `isEnrolled = false` assert the button is **absent**. This pins that the biometric affordance is available on the cloud-titled unlock screen (the #332 per-target title and this biometric change coexist).
- **Already-covered, not re-tested here:** the credential-release orchestration (`DeviceUnlockViewModel.unlockWithBiometrics` over `DeviceUnlockCoordinator`) and the `VaultSlotMismatch`/`NotEnrolled` guards are host-tested in `:vault-access`; the gate-route decision in `CloudReauthRouteTest`. The cloud `onBiometricUnlock` glue in `AppRoot` (real Keystore + SAF + FFI) is covered by compile (`:app:compileDebugKotlin`) + the deferred on-device run.
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
