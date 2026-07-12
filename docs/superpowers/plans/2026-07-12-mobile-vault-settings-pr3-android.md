# Mobile per-vault settings — PR 3 (Android Settings screen) — Implementation Plan

> **For agentic workers:** Every task is TDD — write the failing host test first (`:vault-access:test`, JVM, millisecond feedback), then the implementation. This is the **last** PR of the 3-PR mobile-settings slice; when it ships the feature is complete (flip README/ROADMAP).

**Goal:** Ship the native Jetpack Compose per-vault Settings screen on top of PR 1's shared FFI surface (`read_settings` / `write_settings` / `Settings` + bound-constant readers, on `main` @ #418) and mirroring the shipped iOS screen (#419). Two per-vault controls — **retention window (days)** and **re-auth grace (minutes)** — with the Trash retention path reading the persisted value and the live re-auth gate retargeting to a changed grace window. `auto_lock_timeout_ms` / `require_password_before_edits` get no UI but are round-tripped so they are never dropped.

**Design source:** [docs/superpowers/specs/2026-07-12-mobile-vault-settings-design.md](../specs/2026-07-12-mobile-vault-settings-design.md) — Components D + E (Android half). iOS reference: [docs/superpowers/plans/2026-07-12-mobile-vault-settings-pr2-ios.md](2026-07-12-mobile-vault-settings-pr2-ios.md) and the **shipped** iOS `SettingsViewModel` (mirror the shipped code, which has two refinements over the iOS plan — see "Mirror the shipped iOS VM" below).

## User-locked decisions (2026-07-12, this session)

1. **Effective re-auth grace default → 2 min on Android** (currently 30 s: `ReauthWindow.V1_DEFAULT_MS`). Align with iOS/desktop/the schema by seeding the gate from persisted settings at open (`readSettings().reauthGraceWindowMs`, which defaults to `REAUTH_WINDOW_DEFAULT_MS = 120_000` for a vault with no settings block). Same user-approved 30 s→2 min weakening iOS got (a longer unattended-write window); call it out in the PR body. `ReauthWindow.V1_DEFAULT_MS` (30 s, its own tests) is left untouched — the composition root passes the settings-derived window explicitly.
2. **Separate "Vault settings" entry.** The browse shell already surfaces a **"Device settings"** entry (biometric enrollment) via `testTag("open-settings")` + `Route.Browse.showSettings`. The new per-vault Settings screen gets its **own** distinct entry, route flag, and testTag (`open-vault-settings` / a new route flag e.g. `showVaultSettings`) — the existing device-settings screen/route is left untouched.

## Mirror the shipped iOS `SettingsViewModel` (two refinements over the iOS *plan*)

The shipped iOS VM (post-review) differs from its plan; mirror the **shipped** behavior:
- **Re-read at save time** for the two unedited fields (`autoLockTimeoutMs` / `requirePasswordBeforeEdits`): `save()` re-reads `readSettings()` *after* the gate passes and merges only retention+grace onto the freshly-read values (never a cached-from-`load()` placeholder). This is field-preservation **and** closes a load→save TOCTOU.
- **Retarget only when the grace window actually changed:** `if (newSettings.reauthGraceWindowMs != current.reauthGraceWindowMs) retarget(...)`. A retention-only save must NOT retarget (retarget reseeds presence to `now`, which would silently slide the unattended-write window on an edit that didn't touch grace).

## Global constraints

- **No `core` / crypto / on-disk-format / `manifest_version` change; no new `FfiVaultError` variant; `#![forbid(unsafe_code)]` intact.** PR 3 is Android-only (Kotlin + one additive method on `RetargetableReauthGate`) over the frozen PR-1 FFI surface. The generated uniffi Kotlin bindings for `readSettings`/`writeSettings`/bound readers already exist (Rust source on `main`); only `:kit` needs to regenerate them at build.
- **Kotlin interface conformance is in-class** ([[project_secretary_kotlin_interface_conformance_in_class]]): `UniffiVaultSession` gains `, SettingsPort` in its class header and implements the methods in the class body next to the `TrashPort` block, reusing the private handles (`identity`/`manifest`/`sessionLock`/`wiped`/`mapErrors`/`write {}`/`deviceUuid()`). NO Swift-style extension.
- **Sealed-`when` / cross-module exhaustiveness** ([[project_secretary_android_sealed_when_cross_module]]): no new `VaultBrowseError`/`DeviceUnlockError` arm is added, so no `when` breaks — but build `:app` in the SAME task as any shared-type touch, not later.
- **Value types use `Long`** (Kotlin idiom, matching `TrashPort.defaultRetentionWindowMs(): Long`). The `:kit` adapter converts the generated `ULong` at the FFI boundary (`.toLong()` / `.toULong()`), exactly like `ffiDefaultRetentionWindowMs().toLong()`.
- **Bound constants come from the FFI (one source):** the UI validates against the six generated readers surfaced through `SettingsPort.settingsBounds()` as a `SettingsBounds` value. `MS_PER_DAY` is reused from `TrashFormatting.kt`; `MS_PER_MINUTE = 60_000L` is a new named constant in the settings conversions file (frozen; no magic numbers). Auto-lock bounds are not projected and not needed (no UI); `write_settings` still rejects out-of-range auto-lock server-side.
- **Working directory:** all edits target `.worktrees/mobile-settings-android/…` on branch `feature/mobile-settings-android` ([[feedback_edit_tool_targets_main_not_worktree]]). Verify `pwd && git branch --show-current` before path-sensitive commands. Spell out the full worktree path in Edit/Write/Read.
- **Conversions (mirror desktop `SettingsDialog` + iOS exactly):**
  - Retention = **days**: display `daysFromMs(ms) = round(ms / MS_PER_DAY)` (reuse `msToDays`, round-half-up), save `msFromDays(days) = days * MS_PER_DAY`, clamp `1…3650`, default `90`.
  - Grace = **minutes**: display `minutesFromMs(ms) = round(ms / MS_PER_MINUTE)`, save `msFromMinutes(min) = min * MS_PER_MINUTE`, clamp `0…60`, default `2`.

## Acceptance gate (from the worktree root)

```bash
# Phase 1 (host, fast — JVM unit tests, no emulator/NDK):
./gradlew -p android :vault-access:test
# Phase 2 (multi-minute silent Rust→JNI build on a cold :kit daemon — warm once,
# [[project_secretary_android_instrumented_test_gotchas]] / [[project_secretary_ios_xcframework_build_watchdog]]):
./gradlew -p android :vault-access:test :kit:testDebugUnitTest :kit:lintDebug :browse-ui:compileDebugKotlin :app:assembleDebug
```

---

## File structure

**`:vault-access` (`org.secretary.browse`, host-tested — new):**
- `SettingsModels.kt` — `interface SettingsPort` + `data class VaultSettings` (4 fields, `Long`/`Boolean`) + `data class SettingsBounds` (6 bound fields, `Long`) + `SettingsBanner`. Mirror `TrashModels.kt`.
- `SettingsConversions.kt` — pure `daysFromMs`/`msFromDays`/`minutesFromMs`/`msFromMinutes`/`clampRetentionDays`/`clampGraceMinutes` + `const val MS_PER_MINUTE = 60_000L` (+ `settingsSavedBanner()`), reusing `MS_PER_DAY`/`msToDays` from `TrashFormatting.kt`.
- `SettingsModel.kt` — host-tested model: load / clamp / gated `suspend save()` / field-preservation / retarget-after-save. Mirror `TrashBrowseModel`'s `guardedWrite` discipline + the shipped iOS `SettingsViewModel` ordering.

**`:vault-access` (test — new):**
- `test/.../FakeSettingsPort.kt` — in-memory double: seeded `settings` + `bounds`, records `writtenSettings`, one-shot `failNextRead`/`failNextWrite`. Mirror `FakeTrashPort.kt`.

**`:vault-access` (modify):**
- `RetargetableReauthGate.kt` — **add** `fun retargetWindow(newGate: WriteReauthGate, nowMs: Long)` (swap delegate + seed the incoming gate at `nowMs`, not the stored open instant; set `seededAtMs = nowMs`). Existing `retarget`/`seed`/`reset`/`authorizeWrite` untouched (cloud-path ordering-independence preserved).
- `TrashBrowseModel.kt` — add an optional `settingsPort: SettingsPort?` ctor param; on `load()` cache `retentionWindowMs` = `settingsPort?.runCatching { readSettings().retentionWindowMs }?.getOrNull() ?: port.defaultRetentionWindowMs()`; replace the 3 `port.defaultRetentionWindowMs()` reads (accessor L41, `previewRetention` L56, `runRetention` L81) with the cached value. Keep `TrashPort.defaultRetentionWindowMs()` as the read-error fallback.

**`:kit` (`org.secretary.browse` — modify):**
- `UniffiVaultOpenPort.kt` — `UniffiVaultSession : … , SettingsPort` in-class: `readSettings()` (sync, `synchronized(sessionLock)` + wiped-guard + `mapErrors { ffi readSettings(identity, manifest) }` → `VaultSettings`); `suspend writeSettings(settings)` via the `write { deviceUuid, nowMs -> ffi writeSettings(identity, manifest, Settings(...), deviceUuid, nowMs) }` wrapper; `settingsBounds()` bundling the 6 generated readers (`toLong()`).

**`:app` (`org.secretary.app` — new + modify):**
- `SettingsScreen.kt` (new) — stateless `@Composable` mirroring `DeviceSettingsScreen.kt`: a retention-days field/stepper (`testTag("settings-retention-days")`), a grace-minutes field/stepper (`testTag("settings-grace-minutes")`), a Save button (`testTag("settings-save")`, disabled while writing), an inline banner (`testTag("settings-notice")`) + error line (`testTag("settings-error")`), back (`testTag("vault-settings-back")`).
- `BrowseWithSyncScreen.kt` (modify) — add a third entry `TextButton(onClick = onOpenVaultSettings, Modifier.testTag("open-vault-settings")) { Text("Vault settings") }` alongside the existing Trash / Device-settings buttons; new `onOpenVaultSettings` callback param.
- `AppRoot.kt` (modify) — add `showVaultSettings: Boolean` to `Route.Browse`; render `SettingsScreen` over a `SettingsModel` built from `(session as? SettingsPort)` when the flag is set; flip the flag from the new entry (mirror the `showTrash` route-flip). Switch the **local password/recovery** open to a shared `RetargetableReauthGate` (currently a plain `GraceWindowReauthGate`).
- `BrowseSession.kt` (modify) — `openBrowseWithSync` seeds the shared `RetargetableReauthGate` from persisted grace: after the session opens, read `(session as? SettingsPort)?.readSettings()?.reauthGraceWindowMs` (fallback `settingsBounds().reauthGraceDefaultMs`), install the real grace gate for that window via `gate.retargetWindow(makeGraceGate(graceMs), nowMs)` **or** the existing `retarget`+`seed` path, and attach the `SettingsModel`/screen from `(session as? SettingsPort)`. A read failure falls back to the 2-min default (it must never fail the unlock).

---

## Phase 1 — host-testable (`:vault-access:test`, no emulator/NDK/xcframework)

### Task 1 — Pure settings types + conversions (`:vault-access`)
- [ ] **Test first** (`test/.../SettingsConversionsTest.kt`): `daysFromMs`/`msFromDays` round-trip + round-half-up; `minutesFromMs`/`msFromMinutes` round-trip; `clampRetentionDays` (0→1, 9999→3650, in-range unchanged); `clampGraceMinutes` (-5→0, 999→60); `settingsSavedBanner()` equals expected.
- [ ] `data class VaultSettings(autoLockTimeoutMs: Long, requirePasswordBeforeEdits: Boolean, reauthGraceWindowMs: Long, retentionWindowMs: Long)` (field order mirrors the uniffi `Settings`).
- [ ] `data class SettingsBounds(retentionDefaultMs, retentionMinMs, retentionMaxMs, reauthGraceDefaultMs, reauthGraceMinMs, reauthGraceMaxMs: Long)`.
- [ ] `SettingsBanner` (reuse the `PurgeNotice`/success-idiom style) + `SettingsConversions.kt` with `MS_PER_MINUTE = 60_000L` and the pure conversions/clamps.
- [ ] `interface SettingsPort { fun readSettings(): VaultSettings; suspend fun writeSettings(settings: VaultSettings); fun settingsBounds(): SettingsBounds }` (`readSettings` may throw `VaultBrowseError` on a hard vault error; lenient defaults for absent/corrupt come from the bridge).

### Task 2 — `FakeSettingsPort` (`:vault-access` test)
- [ ] **Test first** (`test/.../FakeSettingsPortTest.kt`): read returns the seed; write appends to `writtenSettings` + updates the seed; `failNextRead`/`failNextWrite` throw once then clear; `settingsBounds()` returns the seed. Default bounds seed the real constant values (retention 90/1/3650 d in ms, grace 120_000/0/3_600_000).
- [ ] `class FakeSettingsPort : SettingsPort` — mirror `FakeTrashPort` (records + one-shot failures; optional `writeGate: CompletableDeferred<Unit>?` to hold a write in flight for ordering/race tests).

### Task 3 — `retargetWindow` on `RetargetableReauthGate` (`:vault-access`)
- [ ] **Test first** (append to `RetargetableReauthGateTest.kt`): after `retargetWindow(newGate, nowMs)`, `authorizeWrite` forwards to `newGate`, and `newGate` was seeded at `nowMs` (assert via a recording gate spy's `seed` arg) **not** the stored open instant; a subsequent `authorizeWrite` inside `[nowMs, nowMs+window)` is silent. Existing 5 tests stay green.
- [ ] Implement `fun retargetWindow(newGate: WriteReauthGate, nowMs: Long) { delegate = newGate; seededAtMs = nowMs; newGate.seed(nowMs) }` with a doc comment: mirror of iOS `retarget(window:)` — used **after** a successful gated save; seeds at `nowMs` (present-now) not the stored unlock instant; the security guard is the caller's after-save ordering.

### Task 4 — `SettingsModel` (`:vault-access`)
- [ ] **Test first** (`test/.../SettingsModelTest.kt`) with `FakeSettingsPort` + a real `RetargetableReauthGate` and a recording-gate factory `makeGraceGate` + a fake `nowMs` clock + a fake `BiometricAuthorizer`:
  - **load** populates `retentionDays` + `graceMinutes` from `readSettings()` (converted/clamped); load on a read error → bounds defaults (90 d / 2 min) + `error` set.
  - **clamp** on `setRetentionDays`/`setGraceMinutes` (0→1, 9999→3650; -5→0, 999→60).
  - **save success** → `writtenSettings.last` has the new retention+grace **and preserves** the loaded `autoLockTimeoutMs`/`requirePasswordBeforeEdits`; `notice == settingsSavedBanner()`; gate retargeted to the new grace window.
  - **retarget-after-save ordering** (security): a shared event log asserts `authorize → writeSettings → retargetWindow`; the delegate used for `authorize` still carries the **pre-save** window at the write instant (the new-window gate is built only by the post-success `retargetWindow`). A widening from outside the pre-save window still demands a proof.
  - **retarget only on grace change**: a retention-only save does **not** call `retargetWindow` (assert `makeGraceGate` uninvoked).
  - **re-read at save (field preservation + TOCTOU)**: seed the port with non-default auto-lock/require-password; the write preserves them even if `load()` never ran (or after a load-error); if another writer changed those between load and save, the saved value reflects the re-read.
  - **gate refusal** (`UserCancelled` → silent no-op; other `DeviceUnlockError` → `error`, no write, no retarget, no notice).
  - **re-entrancy guard**: a second `save()` while `writing` is a no-op.
- [ ] Implement `class SettingsModel(port, gate: RetargetableReauthGate, makeGraceGate: (Long) -> WriteReauthGate, nowMs: () -> Long)` — `StateFlow`s for `retentionDays`/`graceMinutes`/`writing`/`error`/`notice`; `bounds` from `port.settingsBounds()`. `save()` copies `TrashBrowseModel.guardedWrite`'s shape (set `writing` before the gate await; clear notice/error at start; gate → re-read → merge → `writeSettings` → on success `if grace changed: gate.retargetWindow(makeGraceGate(newGraceMs), nowMs())` + notice), preserving the two unedited fields from the re-read.

### Task 5 — Trash per-vault retention integration (`:vault-access`)
- [ ] **Test first** (`test/.../TrashBrowseModelTest.kt`): a new test seeds `FakeSettingsPort.settings.retentionWindowMs` to a non-default value and asserts `previewRetention()` + `runRetention()` use **that** window (via `FakeTrashPort`'s captured window arg), not the frozen 90-day default; a settings read-error case falls back to `defaultRetentionWindowMs()`.
- [ ] `TrashBrowseModel` gains `settingsPort: SettingsPort? = null`; cache the effective window on `load()`; swap the 3 reads. Update existing `TrashBrowseModelTest` construction sites (default `null` keeps them green).

**Checkpoint:** `./gradlew -p android :vault-access:test` fully green. Request a Phase-1 code review (ports/model/gate + the ordering + field-preservation + re-read tests) — the security-critical, novel piece is the retarget-after-save ordering; the review must confirm no path retargets before the gated save resolves (non-vacuous tests).

---

## Phase 2 — FFI adapter + composition + screen (`:kit` / `:app`; cold `:kit` triggers a multi-minute silent Rust→JNI build — warm once, run backgrounded with log-poll)

### Task 6 — `UniffiVaultSession : SettingsPort` in-class adapter (`:kit`)
- [ ] Add `, SettingsPort` to the `UniffiVaultSession` header; implement `readSettings`/`writeSettings`/`settingsBounds` in-class (§File structure), reusing `sessionLock`/`wiped`/`mapErrors`/`write {}`/`deviceUuid()`. Confirm the generated `readSettings`/`writeSettings`/bound-reader signatures (ULong; `deviceUuid` byte type) against `android/kit/build/generated/uniffi/…/secretary.kt` after a build; convert `ULong`↔`Long` at the boundary. A wiped session returns safe defaults for `readSettings` (mirror the wiped-handle contract [[project_secretary_bridge_wiped_handle_defaults]]) — surface `Settings::default()`-equivalent, not a throw.
- [ ] `:kit:testDebugUnitTest` compiles; add a smoke round-trip over the real FFI on a **temp copy** of the golden vault ([[feedback_smoke_test_temp_copy_golden_vault]]) if a `:kit` host-test harness exists for it (else defer to the existing conformance path — no protocol change here).

### Task 7 — Composition-root gate seeding (`:app`)
- [ ] `BrowseSession.openBrowseWithSync`: after the session opens, derive the grace window from persisted settings and install the real grace gate into the shared `RetargetableReauthGate` (seed from persisted grace; fallback to the 2-min bounds default on read error — must never fail the unlock). Attach the `SettingsModel`/route from `(session as? SettingsPort)`.
- [ ] `AppRoot.unlockAndOpen` (local password/recovery): switch the plain `GraceWindowReauthGate` to a shared `RetargetableReauthGate` + a `makeGraceGate` factory (`{ w -> GraceWindowReauthGate(authorizer, clock, w) }`), matching the cloud path (`CloudVaultOpen.openCloudBrowse` already uses `RetargetableReauthGate`). Verify both the biometric and cloud open paths route through the same seed.

### Task 8 — `SettingsScreen.kt` + separate Vault-settings entry (`:app`)
- [ ] `SettingsScreen.kt` (stateless, mirror `DeviceSettingsScreen`): retention-days + grace-minutes inputs (bounded by the model's ranges), Save (disabled while writing), inline notice + error, back. `testTag`s per §File structure.
- [ ] `BrowseWithSyncScreen.kt`: add the `open-vault-settings` entry + `onOpenVaultSettings` callback.
- [ ] `AppRoot.kt`: `Route.Browse.showVaultSettings` flag + render + route-flip; build the `SettingsModel` from the shared gate + `(session as? SettingsPort)`; DO NOT reuse the device-settings `showSettings`/`open-settings`.

### Task 9 — Full gate + docs
- [ ] `./gradlew -p android :vault-access:test :kit:testDebugUnitTest :kit:lintDebug :browse-ui:compileDebugKotlin :app:assembleDebug` green.
- [ ] Whole-branch review (security ordering + field preservation + wiped-handle + no cross-module `when` break).
- [ ] **Feature-complete flip:** README + ROADMAP → "mobile Settings screens shipped on iOS + Android"; mark the retention-window + re-auth-grace settings feature complete ([[feedback_readme_style]] — brief).
- [ ] Handoff doc + symlink retarget committed on the branch before pushing/opening the PR ([[feedback_next_session_in_pr]]).

---

## Risks / notes
- **Retarget-after-save ordering is the security guard** — the review must confirm no path retargets before the gated save resolves, and that a widening from outside the pre-save window still demands a proof (mirror iOS #419's confirmed-non-vacuous tests).
- **Seed-at-now on `retargetWindow`** (accepted, mirrors iOS): a grace-changing save reseeds presence to `now`. Bounded by the grace window's inherent trust; retarget-only-on-grace-change keeps a retention-only edit from sliding the window. Re-confirmed acceptable for Android (same semantics as iOS #419 §3).
- **Grace default 30 s → 2 min** is user-approved but user-visible; call it out in the PR body.
- **Screen render stays host-untested** (existing gap [#417](https://github.com/hherb/secretary/issues/417)); `testTag` hooks are added for a future instrumented/Compose assertion.
- **`:kit` cold build** is a multi-minute silent Rust→JNI compile ([[project_secretary_android_instrumented_test_gotchas]] / [[project_secretary_ios_xcframework_build_watchdog]]) — warm once, then run backgrounded with log-poll; do not let a subagent watchdog kill it.
- **Naming collision guard:** the existing `showSettings`/`open-settings` = *device* settings; the new per-vault screen MUST use distinct identifiers or the browse toolbar routes to the wrong screen.
