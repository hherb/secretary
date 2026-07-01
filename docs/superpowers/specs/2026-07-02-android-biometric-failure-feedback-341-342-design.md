# Design — Android biometric-unlock feedback parity (#341 + #342)

**Date:** 2026-07-02
**Scope:** Android only — `:vault-access` (type) + `:app` (classifier, wiring). No Rust / FFI / spec / on-disk-format change. Mirrors the iOS fixes shipped last session (PR #346, `deviceUnlockFailureDisplay` + `rememberDevice` reset on route entry).

## Problem

Two pre-existing UX defects on the Android Unlock screen, made routine to hit by #339 (per-cloud-vault biometric open):

- **#341** — When a biometric unlock fails with a non-cancel `DeviceUnlockError` (e.g. `NotEnrolled` / `VaultSlotMismatch` from a stale-enrollment or metadata race, `WrappedSecretCorrupt`), neither the demo nor the cloud path surfaces feedback. Both branches in `AppRoot.kt` discard the ephemeral `DeviceUnlockViewModel`'s terminal `Failed(err)` state — the button silently disappears or the screen stays put. `UserCancelled` is intentionally silent; every other error should surface.
- **#342** — `rememberDevice` (`AppRoot.kt`) is a single app-level `mutableStateOf(false)` never reset on `Route.Unlock` entry. Tick it on vault A, back out, open vault B → checkbox is still ticked → an unintended first enroll against vault B on the next password open. Worst case bounded (an accidental first enroll; repeat enroll is a no-op via `alreadyEnrolledForThisVault`); UX surprise, not a security regression.

## #341 — surface non-cancel biometric-unlock failures

### New pure classifier (host-tested)

Mirror of the iOS `deviceUnlockFailureDisplay` (`SecretaryDeviceUnlockUI`). Exhaustive `when` over the sealed `DeviceUnlockError`; only `UserCancelled` is silent.

```kotlin
sealed interface DeviceUnlockFailureDisplay {
    data object Silent : DeviceUnlockFailureDisplay
    data class Message(val text: String) : DeviceUnlockFailureDisplay
}

fun deviceUnlockFailureDisplay(error: DeviceUnlockError): DeviceUnlockFailureDisplay
```

**Location:** `:app`, next to the existing sibling `mapBiometricError` (both map `DeviceUnlockError`; both host-tested in `app/src/test`). Keeps the two error/Toast mappers together instead of splitting one into `:vault-access`. (iOS placed its analog in the pure package's UI product; Android's closest structural match is the app-local sibling.)

Message copy mirrors the iOS strings, adapted to Android's `DeviceUnlockError` arms (no `wrongDeviceSecretOrCorrupt` / `vault(e)` — those open-time failures surface as `VaultBrowseError` from the shared pipeline, not here):

| arm | display |
|---|---|
| `UserCancelled` | `Silent` |
| `BiometryUnavailable` | "Biometric unlock is unavailable on this device." |
| `BiometryNotEnrolled` | "No biometrics are enrolled on this device." |
| `BiometryLockout` | "Biometrics are locked out. Use your PIN/password, then try again." |
| `AuthenticationFailed` | "Biometric authentication failed. Try again or use your password." |
| `NotEnrolled` | "This device isn't set up for biometric unlock of this vault." |
| `VaultSlotMismatch` | "This device's biometric enrollment is for a different vault." |
| `WrappedSecretCorrupt` | "The device key couldn't be used. Unlock with your password." |
| `Enclave(detail)` | "Secure hardware error. Unlock with your password. ($detail)" |

### Wiring in `AppRoot.kt` (symmetric, both paths)

After `unlockWithBiometrics` returns in each biometric branch, inspect the VM's terminal `state`; on `Failed(err)` run it through `deviceUnlockFailureDisplay` and `Toast` on `Message` (`LENGTH_LONG`). `Silent` → nothing (deliberate-cancel UX preserved). The open-stage failure Toast added in #332 (via `openCloudTarget` → `Route.Unlock`) is untouched and complementary — it covers the *post-credential* open failure; this covers the *pre-credential* `DeviceUnlockError`.

- **Demo branch:** `deviceVm` is already a stable local; after `unlockWithBiometrics(...)` + `deviceVm.refresh()`, read `deviceVm.state`.
- **Cloud branch:** currently `DeviceUnlockViewModel(cdu.coordinator).unlockWithBiometrics(...)` is constructed inline and its state thrown away. Bind it to a local (`val cloudVm = DeviceUnlockViewModel(cdu.coordinator)`) so `.state` is readable post-call.

Both are inside `scope.launch { … }` on the main scope; `Toast` on main is correct. On the success path the VM state is `Enrolled` (not `Failed`) so no Toast fires.

## #342 — reset "Remember this device" on Unlock route entry

One line in the existing `LaunchedEffect(route)` block, in the `current is Route.Unlock` arm: `rememberDevice = false`. Fires on every entry to an Unlock screen (demo or any cloud target), clearing carryover. Mirrors iOS resetting `rememberDevice` on every `.unlock` route entry.

## Testing (TDD, host-only — no emulator)

1. **`DeviceUnlockFailureDisplayTest`** (`app/src/test`) — full matrix: `UserCancelled` → `Silent`; each of the 8 other arms → `Message` with non-blank text. Written first (fails to compile → drives the classifier). Mirror of the iOS `DeviceUnlockFailureDisplayTest`.
2. **#342 reset** — the reset lives in a Compose `LaunchedEffect`; the decidable content is a trivial assignment. Its behavioural assertion (checkbox does not carry across targets) belongs in the emulator androidTest UI suite (`UnlockScreenDeviceUiTest`). Consistent with the accepted repo-wide limitation that Compose/biometric app-wiring is compile + on-device covered, not host-unit covered. Documented as such; no host unit test is possible for a `LaunchedEffect` side effect without an emulator.

**Verify:** `./gradlew :app:testDebugUnitTest :vault-access:test` (host) + a `:app` assembleDebug compile (catches the `AppRoot.kt` wiring). The classifier is app-local, so no cross-module sealed-`when` break — but `:app` is built in the same task regardless per the standing rule.

## Non-goals / accepted limitations

- No new coverage of the Compose app-wiring itself (Toast dispatch, the `rememberDevice` reset) beyond compile + emulator UI — same accepted limitation as every biometric path in this repo.
- #347 (Face ID button shown vault-agnostically) is out of scope — a `DeviceEnrollment` data-model change.
- The Android `DeviceUnlockError` taxonomy is unchanged; the classifier is purely additive.
