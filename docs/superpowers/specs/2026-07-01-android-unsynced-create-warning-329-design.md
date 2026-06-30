# Android cloud: surface `PendingFlushNotPersisted` as an Unlock-screen banner (#329)

**Date:** 2026-07-01
**Issue:** [#329](https://github.com/hherb/secretary/issues/329)
**Branch:** `feature/android-unsynced-create-banner-329` (off `main` @ `be84775`)

## Problem

When an offline-created cloud vault fails to push **and** its pending-flush marker cannot be
persisted, `VaultWorkingCopyCoordinator.createThenOpen` raises `PendingFlushNotPersisted` (#327).
`openCloudTarget` ([CloudVaultOpen.kt](../../../android/app/src/main/kotlin/org/secretary/app/CloudVaultOpen.kt))
routes this through `cloudOpenFailureRoute`, which sets `CloudOpenFailure.createdButNotSynced = true`.

The data-integrity protection is already sound: the `VaultMirror.materialize` no-clobber guard
preserves the un-pushed vault, and `isCreate` is preserved on the returned target so the next open
retries push-before-pull (never a materialize that could clobber the only copy). **But** `createdButNotSynced`'s
only current effect is choosing between two `Log.w` lines — both failure branches return the
identical `Route.Unlock(cloudTarget = failure.target)`. The user who just created a vault that lives
**only** in the local working copy sees the same Unlock screen as an ordinary retry — no indication
their only copy is at risk until it is successfully pushed.

The signal already rides forward in `CloudOpenFailure.createdButNotSynced` (host-tested in
`CloudCreateErrorRoutingTest`); it just needs a UI surface.

## Scope

`android/app` Kotlin/Compose **only**. No `:vault-access` / `:kit`, no `core` / `ffi`, no
on-disk-format / spec / `conformance.py` / conflict-KAT / observable-byte / FFI-surface change.
This adds **only** a user-facing warning — the integrity protection (materialize no-clobber guard +
`isCreate`-preserved push-before-pull retry) is untouched.

## Design

### 1. Data flow — thread the existing flag onto the route

The signal already exists. Today `openCloudTarget`'s failure branch drops `createdButNotSynced`:

```kotlin
val failure = cloudOpenFailureRoute(e, target)
// ... two Log.w branches ...
Route.Unlock(cloudTarget = failure.target)   // createdButNotSynced discarded here
```

The fix carries it through:

- Add a field to the route:
  `data class Unlock(val cloudTarget: CloudVaultTarget? = null, val unsyncedCreateWarning: Boolean = false)`.
  The default keeps every other `Route.Unlock(...)` construction site (demo path, ON_STOP re-target,
  Selection → Unlock, create-wizard → Unlock) unchanged.
- A tiny **pure** helper makes the route construction host-testable without a `Context`:
  `internal fun unsyncedCreateRoute(failure: CloudOpenFailure): Route.Unlock =
   Route.Unlock(cloudTarget = failure.target, unsyncedCreateWarning = failure.createdButNotSynced)`.
- `openCloudTarget`'s failure branch returns `unsyncedCreateRoute(failure)`. The two `Log.w` lines stay.

### 2. Render — `UnlockScreen` banner

- New param `unsyncedCreateWarning: Boolean` on `UnlockScreen`, defaulted `false` so other call
  sites and existing tests are unaffected.
- When `true`, render a `Text` at the **top** of the screen `Column` (above the title / biometric
  button), `color = MaterialTheme.colorScheme.error`, `testTag("unsynced-create-warning")`:

  > **Vault created but not yet synced — keep this device online and reopen to finish the upload.
  > The vault currently exists only on this device.**

  This follows the existing inline-error convention (`wizard-error`, `device-error` are plain `Text`
  with a `testTag`); no new `Card` / `Surface`.
- `AppRoot`'s `is Route.Unlock ->` branch passes `unsyncedCreateWarning = r.unsyncedCreateWarning`.

### 3. Persistence / clearing semantics (the one subtlety)

The banner rides the **failed-attempt flag** on `Route.Unlock`, **not** durable marker state — by
construction: `PendingFlushNotPersisted` is precisely the case where the marker *could not* be
persisted, so there is nothing durable to read on a cold entry. Consequences, all acceptable and
within issue scope:

- Shows immediately after a create-open attempt that raised `PendingFlushNotPersisted`.
- A retry that **succeeds** → `Route.Browse` → banner gone.
- A retry that **fails again** with `PendingFlushNotPersisted` → new `Route.Unlock` re-carries the
  flag → banner persists.
- A retry that fails with an **ordinary** error (e.g. the marker persisted this time) →
  `unsyncedCreateWarning = false` → banner clears. This is correct: the vault is now marked, so
  push-before-pull protects it — the dangerous-and-*unmarked* condition is gone.
- Backgrounding (ON_STOP → `Route.Unlock(cloudTarget)` with no flag) or a process restart drops the
  banner. Data is still protected by the materialize guard; the warning re-raises on the next failed
  create-open. **This is a documented limitation, not a gap to fix** — durable marker state does not
  exist for this case by construction.

### 4. Error handling

No new failure modes. The flag is a pure boolean already derived from the exception type; no new
throws, no secret-handling or zeroize path touched.

### 5. Testing (TDD)

- **Host (unit):** extend `CloudCreateErrorRoutingTest` to assert `unsyncedCreateRoute` carries the
  flag through — `unsyncedCreateWarning == true` for a `PendingFlushNotPersisted`-derived
  `CloudOpenFailure`, `false` for an ordinary one. (The underlying `cloudOpenFailureRoute` decision
  is already host-tested; this pins the route projection.)
- **Instrumented (emulator-5554):** new `UnsyncedCreateWarningUiTest` —
  (a) `UnlockScreen(unsyncedCreateWarning = true)` shows the `unsynced-create-warning` node;
  (b) `unsyncedCreateWarning = false` → the node is absent.
  Mirrors the existing `CloudBiometricUnlockUiTest` structure. Merge gate = host suite +
  emulator-5554 (RedMagic Compose-UI flakiness, per prior handoffs).

## Files touched

| File | Change |
|---|---|
| `android/app/.../AppRoot.kt` | `Route.Unlock.unsyncedCreateWarning` field; pass-through to `UnlockScreen` |
| `android/app/.../CloudVaultOpen.kt` | `unsyncedCreateRoute` pure helper; failure branch carries the flag |
| `android/app/.../UnlockScreen.kt` | new `unsyncedCreateWarning` param + banner `Text` |
| `android/app/src/test/.../CloudCreateErrorRoutingTest.kt` | extend — assert route projection |
| `android/app/src/androidTest/.../UnsyncedCreateWarningUiTest.kt` | new instrumented UI test |
| `README.md` / `ROADMAP.md` | note cloud un-synced-create warning is now surfaced |

No file approaches the 500-line split threshold.

## Acceptance

```bash
cd .worktrees/android-unsynced-create-banner-329/android
./gradlew :app:testDebugUnitTest :kit:testDebugUnitTest :vault-access:test \
  :app:compileDebugKotlin :app:compileDebugAndroidTestKotlin            # host gate green
# Instrumented (emulator-5554 online):
./gradlew :app:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.app.UnsyncedCreateWarningUiTest
```

- Host: `CloudCreateErrorRoutingTest` asserts the flag rides onto `Route.Unlock`.
- Instrumented: banner shown for `unsyncedCreateWarning = true`, absent for `false`.
