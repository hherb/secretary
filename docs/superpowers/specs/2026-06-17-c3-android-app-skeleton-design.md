# C.3 Android slice 6 — `:app` walking skeleton + real lifecycle wiring

**Date:** 2026-06-17
**Status:** Design approved; ready for implementation plan.
**Branch:** `feature/c3-android-app-skeleton` (worktree `.worktrees/c3-android-app-skeleton`)
**Predecessor:** C.3 Android slice 5 (Compose sync render, `:sync-ui`, #245, `cbf1adf`).

## Purpose

Deliver the first runnable Android application target: a Compose `:app` module that wires the
real `makeVaultSync` factory into a genuine unlock/lock lifecycle over a staged copy of the
`golden_vault_001` reference vault, and hosts the slice-5 `SyncScreen`. The slice closes the one
host-untested seam left by slices 4–5 — `makeVaultSync` (which needs an Android `Looper` + the
native `.so`) and `VaultSyncModel.syncAtUnlock` over the *real* `SyncCoordinator` — with an
on-device instrumented smoke.

This mirrors the iOS `SecretaryApp` walking skeleton (`ios/SecretaryApp/`), scoped to what the
Android FFI surface actually exposes today.

## Scope decision: sync-only (no browse)

The iOS app does `select → unlock → browse → sync`. **Android has only the sync FFI surface**
(`syncStatus` / `syncVault` / `syncCommitDecisions` via `uniffi.secretary`) — there is no
open-vault / read-records port equivalent to iOS's `UniffiVaultOpenPort` / `VaultBrowseViewModel`.
Building one is a separate, larger effort (new `ffi/` + core surface). Therefore this slice is a
**sync-only walking skeleton**: the "unlock" is the sync-password entry that drives a pass; there
is no record browsing. Browse becomes its own future slice once an open port exists.

## Architecture

### Module & build

- New module `:app`, plugin `com.android.application`. `namespace` and `applicationId` =
  `org.secretary.app`. `minSdk` / `compileSdk` / `targetSdk` match the existing sibling modules.
- Depends on `:sync-ui`, `:kit`, `:vault-access`.
- Compose-enabled, reusing the Compose BOM + `resolutionStrategy` pattern `:sync-ui` already
  established (Compose BOM 2025.05.00; coroutines/Espresso forces only where the API-36 emulator
  requires them).
- **No cargo wiring of its own.** The arm64-v8a `libsecretary_ffi_uniffi.so` is built and staged
  into `:kit`'s `jniLibs` by `:kit`'s existing `cargoNdkBuildArm64` task and propagates into the
  `:app` APK transitively through the `:kit` dependency.
- A Gradle task stages `golden_vault_001/` and `golden_vault_001_inputs.json` from
  `core/tests/data` into `:app/src/main/assets/` (single source of truth in `core/tests/data`),
  excluding `.DS_Store`. The staged assets are untracked (`.gitignore`d), mirroring the
  `stageGoldenVaultForAndroidTest` pattern in `:kit`.

### Production provisioning — `AppVaultProvisioning`

Mirror of iOS `AppVaultProvisioning.swift`. Production code (not test-only), so the instrumented
smoke exercises the real provisioning path.

- `stageGoldenVault(context): File` — recursively copies `assets/golden_vault_001` into
  `filesDir/golden_vault_001` on first launch; idempotent (returns the existing staged dir if
  present). **Never mutates the bundled asset** — the app reads/writes only the staged copy, so the
  frozen KAT is never touched (honors the temp-copy discipline).
- `goldenVaultUuid(context): ByteArray` — reads the bundled `golden_vault_001_inputs.json` and
  parses the pinned `vault_uuid` (16 bytes). Single source of truth; no hardcoded uuid constant.
- The recursive asset-copy logic mirrors `:kit`'s `GoldenVaultStaging.copyAsset` (AssetManager
  `list()` empty-children == leaf-file heuristic; the pinned fixture has no empty directories, so
  the heuristic is exact here — documented as in `:kit`).

### Pure helpers (host-tested)

- **uuid hex→bytes parse** — a free function (no `Context`); given the dashed hex string, returns
  the 16-byte array. Host JUnit5 tested (valid parse + malformed-input rejection).
- **state-dir resolution** — `AppSyncStateDir`: a pure `fun syncStateDir(base: File): File`
  returning `base/sync-state`; the production caller passes `context.filesDir`, creating the dir if
  absent. The base→subdir mapping is host-tested; the `filesDir` lookup is the only `Context` touch.

### App flow, screens & lifecycle

A single `MainActivity` (`ComponentActivity`) sets a Compose root with a route state machine:

```
sealed interface Route {
    object Unlock : Route
    data class Sync(val viewModel: VaultSyncViewModel, val monitor: ChangeDetectionMonitor) : Route
}
```

- **Unlock screen** (new Compose surface): a masked password `TextField` + an "Unlock & Sync"
  button. On submit:
  1. `folder = AppVaultProvisioning.stageGoldenVault(context)`,
     `stateDir = syncStateDir(filesDir)`, `uuid = AppVaultProvisioning.goldenVaultUuid(context)`.
  2. `(model, monitor) = makeVaultSync(folder, stateDir, uuid)` — called on the **main thread**
     (the factory fast-fails otherwise).
  3. `monitor.start()` inside try/catch: a failed start logs and leaves detection advisory-blind
     (the badge falls back to manual "Sync now"); **not fatal** — mirrors iOS.
  4. `viewModel = VaultSyncViewModel(model)`; **await** `syncAtUnlock(password)` (trigger-1 silent
     sync), then zeroize the password (see hygiene below), then route to `Sync`.
- **Sync screen**: hosts the existing slice-5 `SyncScreen(viewModel)` **unchanged** (badge +
  password sheet + conflict sheet). Trigger-2 (interactive badge-tap) flows through it as built.
- **Lifecycle**: on `Lifecycle.Event.ON_STOP` (app backgrounded / locked) → `monitor.stop()` and
  route back to `Unlock`, dropping the model (mirrors iOS `scenePhase == .background`). The next
  foreground requires a fresh password entry — there is no session to resume (Android has no open
  port; the password is only ever transient per pass).
- **`FLAG_SECURE`** is set on the activity window: blocks screenshots and the app-switcher
  snapshot from capturing the password field. This is the cheap stand-in for iOS's `PrivacyCover`;
  a full privacy cover is deferred along with browse (no other secret content is on screen in this
  slice).

### Unlock-password hygiene

`VaultSyncViewModel.syncAtUnlock` is fire-and-forget and the VM deliberately does **not** zeroize
its password argument (the slice-5 contract: the interactive path reuses the same buffer for
`resolve`). The **silent unlock path drops the password and never reuses it**, so the app is the
owner of that buffer's lifetime and zeroizes it (`fill(0)`).

To avoid a use-after-zero race with the asynchronous Argon2id re-open inside the pass, the app
**awaits the pass to completion before zeroizing**. Concretely this requires a `suspend`-awaitable
unlock entry — either:
- a new `suspend fun syncAtUnlockAwaiting(password)` on `VaultSyncViewModel` that delegates to
  `model.syncAtUnlock` and returns when the pass settles, or
- the unlock screen launching `model.syncAtUnlock` in its own `rememberCoroutineScope` and
  zeroizing in the continuation.

The implementation plan picks one; the binding **requirement** is: the unlock password is zeroized
only after the pass completes, and is never retained on the VM or model. The interactive password
(entered later via the slice-5 `SyncPasswordSheet`) keeps its existing slice-5 hygiene unchanged.

## Data flow

```
Unlock screen
  └─ submit(password)
       ├─ stageGoldenVault(ctx) ─────────────► filesDir/golden_vault_001  (idempotent copy)
       ├─ goldenVaultUuid(ctx) ──────────────► 16-byte uuid (from bundled inputs JSON)
       ├─ makeVaultSync(folder, stateDir, uuid)  [main thread] ──► (VaultSyncModel, ChangeDetectionMonitor)
       ├─ monitor.start()                         [advisory; failure logged, non-fatal]
       ├─ await viewModel.syncAtUnlock(password)  [trigger-1 silent pass; conflict → review badge only]
       ├─ password.fill(0)                        [after completion]
       └─ route = Sync(viewModel, monitor)
Sync screen  = SyncScreen(viewModel)              [slice-5; trigger-2 interactive + conflict sheets]
ON_STOP      → monitor.stop(); route = Unlock     [drop model]
```

## Testing

### Host (JUnit5, `:app/src/test`)
- uuid hex→bytes parse: valid dashed-hex → 16 bytes; malformed input rejected.
- `syncStateDir(base)`: returns `base/sync-state`.

### Instrumented (emulator, `:app/src/androidTest`, real `.so`)
`MakeVaultSyncSmokeTest`:
1. **Happy path:** stage via the production `AppVaultProvisioning` → `makeVaultSync(...)` on the
   main thread → `monitor.start()` → await `syncAtUnlock("correct horse battery staple")` → assert
   `model.badge` reaches `Synced` and `model.lastError == null` (single-device golden vault →
   `AppliedAutomatically`, a clean advancing arm — characterized in `:kit`'s existing round-trip
   test) → `monitor.stop()`.
2. **Wrong-password path:** await `syncAtUnlock(<wrong bytes>)` → assert `model.lastError` is
   non-null (a `VaultSyncError`) and `model.badge` is not `Synced`.

This lands precisely on the seam the prior slices left untested: `makeVaultSync` itself + the
`VaultSyncModel` state machine (badge derivation, hook muting) over the **real** `SyncCoordinator`.
`:kit`'s existing `SyncRoundTripInstrumentedTest` proves only the raw port + bare coordinator
`runPass`, bypassing both the factory and the model. Per the slice-5 `SyncCoordinator`
single-`Mutex` caveat, status reads occur only before/after a pass, never during.

The new unlock-screen Compose UI is **not** separately UI-tested (the slice-5 `SyncScreen` is
already covered in `:sync-ui`; the unlock surface is thin routing). The genuinely-novel runtime
behavior — real FFI wiring — is what the instrumented smoke proves.

## File layout (each well under the 500-line guideline)

```
android/app/build.gradle.kts
android/app/.gitignore                              # staged assets (golden vault) untracked
android/app/src/main/AndroidManifest.xml            # MainActivity, LAUNCHER intent
android/app/src/main/kotlin/org/secretary/app/MainActivity.kt
android/app/src/main/kotlin/org/secretary/app/AppRoot.kt          # Compose routing + lifecycle observer
android/app/src/main/kotlin/org/secretary/app/UnlockScreen.kt     # Compose unlock surface
android/app/src/main/kotlin/org/secretary/app/AppVaultProvisioning.kt
android/app/src/main/kotlin/org/secretary/app/VaultUuidParsing.kt # pure hex→bytes
android/app/src/main/kotlin/org/secretary/app/AppSyncStateDir.kt  # pure syncStateDir(base)
android/app/src/test/kotlin/org/secretary/app/VaultUuidParsingTest.kt
android/app/src/test/kotlin/org/secretary/app/AppSyncStateDirTest.kt
android/app/src/androidTest/kotlin/org/secretary/app/MakeVaultSyncSmokeTest.kt
```
(`settings.gradle.kts` gains `include(":app")`. A staging Gradle task wires the golden-vault asset
copy, mirroring `:kit`.)

## Out of scope (deferred)

- Record browse/edit — needs a new open-vault FFI port; its own future slice.
- Create-vault wizard, multi-vault selection screen, device/biometric unlock — later client work.
- Full `PrivacyCover` (app-switcher cover beyond `FLAG_SECURE`) — deferred with browse.
- `armv7` / `x86_64` ABIs — arm64-v8a only (matches the existing `:kit` cross-build).
- WorkManager background detection — foreground-only per ADR-0003.
- Conflict round-trip stays fake-driven: a single-device golden vault never yields
  `ConflictsPending`; a real veto round-trip needs a seeded concurrent state (carried).

## Acceptance

```
cd android && ./gradlew :app:test :sync-ui:test :vault-access:test :kit:testDebugUnitTest   # host JUnit5 green
cd android && PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :app:connectedDebugAndroidTest    # MakeVaultSyncSmokeTest green on the arm64 emulator
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|.gitignore)'   # expect empty
git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'           # expect empty
```

Additive only — no change to `core/`, `ffi/`, `ios/`, or the on-disk format.
