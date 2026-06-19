# Android device-management Settings surface — design

**Date:** 2026-06-19
**Scope:** C.3 Android — the deferred "polished enrollment/settings UI + disenroll-from-UI" follow-up to PR #263 (real biometric device open, slice 2).
**Platform:** Android only. `core` / `ffi` / on-disk format / UDL / `ios` are untouched.

## Problem

After PR #263, an Android device can enroll for biometric unlock — but only implicitly, via the
"Remember this device with biometrics" checkbox on the unlock screen. There is:

- **No way to disenroll from the UI.** `DeviceUnlockCoordinator.disenroll(folder)` exists (shipped in
  slice 1) but no view-model method and no screen call it.
- **No device-management surface at all.** `AppRoot` has only two routes (`Unlock`, `Browse`); a user
  cannot see whether this device is enrolled, nor enroll/disenroll deliberately.

This slice adds a device-management **Settings** surface, reachable while unlocked, exposing
enrollment **status**, **enroll**, and **disenroll**.

## Non-goals

- No new FFI / core / format work — this is pure Android UI + a thin pure view-model over the
  existing `DeviceUnlockCoordinator`.
- No multi-device management list (this surface is about *this* device only).
- No change to the unlock-screen checkbox enroll path — it stays as-is.

## Decisions (brainstormed 2026-06-19)

1. **Scope = status + disenroll + enroll** (all three), not status-only.
2. **Navigation = a Settings sub-view of the unlocked route** reached from the Browse screen, not a
   sibling AppRoot branch (so the session is never locked by a Settings excursion).
3. **Enroll re-prompts the password** (enrollment needs `addDeviceSlot(folder, password)`); the
   re-prompted password is *unverified*, so the settings view-model must handle a wrong-password error.

## Architecture

### 1. Navigation & route model

The unlocked session MUST survive a Browse → Settings excursion. Today the `DisposableEffect(r.session)`
that calls `browse.lock()` is keyed to the `Route.Browse` branch, so leaving that branch wipes the
session. To avoid re-opening the vault on every Settings visit, Settings is a **sub-view of the unlocked
route**, not a sibling branch.

Extend the route:

```kotlin
data class Browse(
    val session: BrowseSession,
    val folder: File,
    val showSettings: Boolean = false,
)
```

- The `DisposableEffect(session)` stays keyed on the *session instance*, unchanged when `showSettings`
  flips — so navigating to Settings and back never re-opens and never locks.
- Only `ON_STOP` (background) → `Route.Unlock` disposes + locks, exactly as today.
- `folder` is captured into the route at unlock time (returned from `unlockAndOpen`) so Settings does
  not depend on `BrowseSession` internals (the session does not carry the folder).
- Entry: a "Manage device" / gear affordance on `BrowseWithSyncScreen` (new `onOpenSettings` lambda)
  flips `showSettings = true`; a back affordance flips it false.

### 2. State machine & view-model (pure, host-tested, `:vault-access`)

A new focused `DeviceSettingsViewModel`, separate from `DeviceUnlockViewModel` (single responsibility;
the unlock VM's `Prompting`/`Failed` states are unlock-flow-shaped). Both are thin wrappers over the
*same* `DeviceUnlockCoordinator`, which already holds all three pure operations.

```kotlin
sealed interface DeviceSettingsState {
    data object Enrolled : DeviceSettingsState     // offer "Disable biometric unlock"
    data object Unenrolled : DeviceSettingsState   // offer "Enable biometric unlock"
    data object Working : DeviceSettingsState        // enroll/disenroll in flight — disable buttons
    data class Failed(val message: String) : DeviceSettingsState  // user-safe text; returns to Enrolled/Unenrolled
}

class DeviceSettingsViewModel(private val coordinator: DeviceUnlockCoordinator) {
    var state: DeviceSettingsState = DeviceSettingsState.Unenrolled
        private set
    fun refresh()                                       // recompute Enrolled vs Unenrolled
    suspend fun enroll(folder: String, vaultId: String, password: ByteArray)  // → Working → Enrolled | Failed
    suspend fun disenroll(folder: String)               // → Working → Unenrolled | Failed
}
```

**Error handling (the important bit).** The settings *enroll* re-prompts the password, and that password
is **unverified** (unlike the unlock-time path where the open already validated it). `coordinator.enroll`
→ `addDeviceSlot` throws `VaultBrowseError.WrongPasswordOrCorrupt` on a bad password. So
`DeviceSettingsViewModel.enroll` catches **both** `DeviceUnlockError` *and* `VaultBrowseError` (the
unlock VM catches only `DeviceUnlockError` — insufficient here) and maps to a user-safe `Failed`
message. Per threat-model §13 (anti-oracle), wrong-password and corruption stay **conflated** — the
message is e.g. *"Couldn't enable biometric unlock — wrong password, or biometrics unavailable."*
Disenroll only touches folder/enclave/metadata (no password); its failure modes are `VaultBrowseError`
(non-`DeviceSlotNotFound`) → `Failed`. `DeviceSlotNotFound` is already swallowed inside the coordinator
(idempotent), so disenroll-when-not-enrolled is a success.

`password` is caller-owned (forwarded to the coordinator, not zeroized in the VM) — same contract as
`DeviceUnlockViewModel.enroll`.

### 3. SettingsScreen composable (`:app`) + data flow

A new `DeviceSettingsScreen.kt` in `:app`, rendering from `DeviceSettingsState`:

- **Status line** — "This device **is** enrolled for biometric unlock" / "**is not** enrolled"
  (testTag `device-status`).
- **Enrolled →** "Disable biometric unlock" button (testTag `disenroll-button`) → a **confirm dialog**
  (deliberate revocation: the next open needs the password) → `vm.disenroll(folder)`.
- **Unenrolled →** "Enable biometric unlock" button (testTag `enroll-button`) → a **password re-prompt
  dialog** (masked field, Confirm/Cancel) → `vm.enroll(folder, vaultId, pwBytes)`.
- **Working →** buttons disabled.
- **Failed →** the conflated user-safe message inline (testTag `device-error`).
- **Back** affordance (testTag `settings-back`) → `showSettings = false`.

**Secret hygiene (the re-prompt password):** the dialog's `String`-backed field carries the same
documented demo-skeleton tradeoff as `UnlockScreen` (the typed `String` lingers until GC). The derived
`ByteArray` handed to `vm.enroll` is **zeroized in a `finally`** in the AppRoot lambda after enroll
returns — mirroring `unlockAndOpen`'s discipline. The enroll triggers the **one enroll-time biometric
prompt** (the Keystore `store` routes through the gate — unchanged slice-2 decision).

**AppRoot wiring:** construct `DeviceSettingsViewModel` once (over the existing `coordinator`); bridge
its plain-`var` `state` into a Compose `mutableStateOf` mirror (same pattern the slice-2 handoff calls
out — *don't read `vm.state` directly in a composable, it won't recompose*), refreshed on entering the
Settings sub-view. Enroll/disenroll lambdas: `scope.launch { vm.xxx(...); mirror = vm.state }`. On
enroll/disenroll completion, also refresh so the status line and which-button-shows update.

## Error handling summary

| Operation | Failure | Surfaced as |
|---|---|---|
| enroll | wrong password / corrupt (`VaultBrowseError.WrongPasswordOrCorrupt`) | `Failed` (conflated message) |
| enroll | no strong biometric enrolled / Keystore rejects the auth-required key (`DeviceUnlockError.*`, e.g. `BiometryNotEnrolled` or `Enclave`) | `Failed` (biometrics-unavailable message) |
| disenroll | slot already gone (`DeviceSlotNotFound`) | success (swallowed in coordinator) |
| disenroll | other `VaultBrowseError` | `Failed` |

## Testing

- **Host (`:vault-access`):** `DeviceSettingsViewModel` full matrix over the slice-1 in-memory fakes
  (`FakeDeviceSlotPort` / `FakeEnclave` / `FakeMetadataStore`): enroll-success → Enrolled,
  enroll-wrong-password → Failed, disenroll-success → Unenrolled, disenroll-when-not-enrolled
  (idempotent) → Unenrolled, and the `Working` transitions.
- **Instrumented (`:app`, Compose UI):** `DeviceSettingsScreenUiTest` over a fake state driver — status
  text per state, disenroll confirm dialog shows + invokes, enroll password dialog shows + invokes,
  error text renders, back invokes. No real Keystore/biometric (same honest split as slice 2; the real
  release was proven manually there and the Keystore mechanics are already instrumented-tested).
- **Manual on-device proof (NX809J / Android 16):** enroll-from-settings, disenroll, then confirm a
  disenrolled device falls back to password-only on the next open.
- **Guardrails:** `git diff main...HEAD --name-only` shows nothing under `core/`, `ffi/`,
  `crypto-design`, `vault-format`, or `ios/` (Android-only).

## File inventory (new / changed)

| File | Module | Change |
|---|---|---|
| `vault-access/.../DeviceSettingsViewModel.kt` | `:vault-access` | NEW — pure VM + state |
| `vault-access/.../DeviceSettingsViewModelTest.kt` | `:vault-access` (host test) | NEW — full matrix |
| `app/.../DeviceSettingsScreen.kt` | `:app` | NEW — Compose surface + dialogs |
| `app/.../DeviceSettingsScreenUiTest.kt` | `:app` (instrumented) | NEW — UI matrix |
| `app/.../AppRoot.kt` | `:app` | route extended (`folder`, `showSettings`), settings VM wired |
| `app/.../BrowseWithSyncScreen.kt` | `:app` | `onOpenSettings` entry affordance |
| `README.md` / `ROADMAP.md` | — | device-settings row |

Each new file is focused and well under 500 lines; tests written first per task (TDD); no magic numbers
(testTags and copy are named constants where shared).
