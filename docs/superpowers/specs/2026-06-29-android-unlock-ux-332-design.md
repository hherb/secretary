# Design — Android UnlockScreen UX polish (#332)

**Date:** 2026-06-29
**Issue:** [#332](https://github.com/hherb/secretary/issues/332)
**Scope:** `android/app` Kotlin/Compose only. No `:vault-access` / `:kit` change, no crypto/on-disk-format/FFI/spec/conformance impact. Pure UX polish on the walking-skeleton unlock flow.

## Problem

Three pre-existing gaps in the walking-skeleton `UnlockScreen` / open flow, found during on-device testing of the cloud-vault work (#321 follow-ups):

1. **No progress / disabled state during open.** The vault open runs Argon2id (m=256 MiB, t=3) — several seconds on a phone — but the "Unlock & Sync" button shows no spinner and stays enabled, so a correct unlock looks like a frozen/dead button.
2. **Silent failure on the demo/password path.** `unlockAndOpen` failures (wrong password, etc.) route back to the Unlock screen with no message. (The cloud path shows a Toast as of `4f2bdbc`; the demo path does not.) The open port already throws a typed `VaultBrowseError`, but `unlockAndOpen`'s `catch` swallows it.
3. **Hardcoded screen title.** `UnlockScreen` always renders `"Secretary — demo vault"` even for a cloud target, so the user can't tell which vault they're unlocking.

## Goals / non-goals

- **Goal:** loading indicator + disabled controls while the open is in flight; a typed error message on failed demo/password unlock; a target-specific title.
- **Non-goal:** re-plumbing the cloud path's error message (its internal `catch` in `openCloudTarget` doesn't expose the throwable; it keeps its existing folder-reachability Toast). No change to crypto, sync, or the open ports.

## Components

### 1. Two pure presentation helpers (`app/src/main`, host-tested)

Both are free functions (no side effects, no Compose/Android types in the body beyond the input enum), per the project's pure-functions preference, and each is host-tested in `app/src/test`.

#### `unlockScreenTitle(cloudTarget: CloudVaultTarget?): String`
- `null` → `"Secretary — demo vault"`
- non-null → `"Secretary — ${cloudTarget.location.displayName}"`

The shared prefix (`"Secretary — "`) and the demo suffix (`"demo vault"`) are `private const` — no magic strings.

#### `unlockFailureMessage(error: Throwable): String`
`when` over the sealed `VaultBrowseError` (defined in `:vault-access`, thrown by the open port and surfaced through `unlockAndOpen`'s `catch`):

| Error arm | Message |
|---|---|
| `VaultBrowseError.WrongPasswordOrCorrupt` | `Wrong password, or the vault is damaged.` |
| `VaultBrowseError.WrongRecoveryOrCorrupt` | `Wrong recovery phrase, or the vault is damaged.` |
| `VaultBrowseError.InvalidRecoveryPhrase` (carries `detail`) | `Invalid recovery phrase: ${error.detail}` |
| anything else (IO / SAF / unknown) | `Couldn't open the vault. Please try again.` |

The wrong-password/corrupt conflation is intentional and matches the threat model (`VaultBrowseError.WrongPasswordOrCorrupt` already conflates the two) — no secret leak. Each message string is a `private const`.

### 2. `UnlockScreen` composable changes (`app/src/main/kotlin/org/secretary/app/UnlockScreen.kt`)

New parameters:
- **`title: String`** — replaces the hardcoded `Text("Secretary — demo vault")`.
- **`isUnlocking: Boolean`** — the in-flight flag.

When `isUnlocking` is true:
- The unlock button renders a `CircularProgressIndicator` (testTag `unlock-progress`) **instead of** its text label, and is disabled.
- The password field, recovery field, mode toggle (both segmented buttons), the biometric-unlock button, and the remember-device checkbox are all disabled (`enabled = !isUnlocking`).

The unlock-button enable condition becomes `!isUnlocking && <field-non-empty>` (the existing per-mode non-empty check, AND-ed with not-unlocking). On a failed open the caller resets `isUnlocking` to false, so the button re-enables.

### 3. `AppRoot` wiring (`app/src/main/kotlin/org/secretary/app/AppRoot.kt`)

- New `var isUnlocking by remember { mutableStateOf(false) }`.
- Pass `title = unlockScreenTitle(r.cloudTarget)` and `isUnlocking = isUnlocking` to `UnlockScreen`.
- Wrap **all three** open entry points so `isUnlocking = true` on launch and is reset in a `finally` (each runs the multi-second open, so each exhibits the frozen-button symptom):
  - the **password/demo** branch (`unlockAndOpen`),
  - the **cloud** branch (`openCloudTarget`),
  - the **biometric** branch (`onBiometricUnlock` → `deviceVm.unlockWithBiometrics` → `unlockAndOpen`).
- Demo-path error surfacing: inside `unlockAndOpen`'s existing `catch (e: Exception)` (which already logs and returns `Route.Unlock()`), add
  `Toast.makeText(context, unlockFailureMessage(e), Toast.LENGTH_LONG).show()`.
  This mirrors the cloud Toast but is typed. The cloud path is unchanged.

On success the open routes to `Route.Browse`; the `isUnlocking = false` reset in the `finally` is then harmless (the composition is leaving the Unlock route anyway). On failure the screen stays on Unlock with the button re-enabled and the Toast shown.

## Data flow

```
user taps Unlock
  → AppRoot.onUnlock: isUnlocking = true
      → (password)  unlockAndOpen(...)   ── failure → catch: Toast(unlockFailureMessage(e)); return Route.Unlock()
      → (cloud)     openCloudTarget(...) ── failure → Route.Unlock + existing folder Toast
  → finally: isUnlocking = false
  → success → route = Route.Browse  |  failure → stays Route.Unlock, button re-enabled
```

## Error handling

- `unlockFailureMessage` is total over `Throwable` (sealed-type arms + `else`), so an unexpected exception type still yields the generic message rather than crashing.
- Resetting `isUnlocking` in a `finally` guarantees the button never stays stuck-disabled even if the open throws a non-`Exception` `Throwable` (the `finally` runs regardless; the demo Toast is in the `Exception` catch, consistent with the existing handler).

## Testing

- **Host** (`app/src/test`, the merge gate — `:app:testDebugUnitTest`):
  - `unlockScreenTitle`: `null` → demo title; a cloud target → `"Secretary — <displayName>"`.
  - `unlockFailureMessage`: each `VaultBrowseError` arm → its expected message (incl. `InvalidRecoveryPhrase` detail interpolation); a plain `RuntimeException` → the generic message.
- **Instrumented** (`app/src/androidTest`, run on `emulator-5554`; per prior batons new `:app` instrumented tests are **not** the merge gate — RedMagic-flaky "No compose hierarchies found" — but are run on the emulator):
  - `isUnlocking = true` → unlock button disabled, `unlock-progress` node present, password field disabled.
  - `title` parameter is rendered.
  - Existing `UnlockScreenRecoveryUiTest` / `UnlockScreenDeviceUiTest` updated for the new required params (default `isUnlocking = false`, a demo `title`).

## Acceptance criteria

1. During an open, the unlock button shows a spinner and is disabled; the input fields/toggle are disabled; on failure they re-enable.
2. A failed demo/password unlock shows a typed Toast (wrong-password / wrong-recovery / invalid-phrase / generic) instead of silently returning.
3. The Unlock screen title reflects the target: `"demo vault"` for the demo path, the cloud folder display name for a cloud target.
4. `:app:testDebugUnitTest` green (host gate); `:app:testDebugUnitTest :app:compileDebugKotlin :app:compileDebugAndroidTestKotlin` BUILD SUCCESSFUL.

## Out of scope / deferred

- Cloud-path typed error message (would require plumbing the throwable out of `openCloudTarget`'s internal catch).
- Any change to the open ports, sync, or crypto.
