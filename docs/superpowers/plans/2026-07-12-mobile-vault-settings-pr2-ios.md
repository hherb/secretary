# Mobile per-vault settings — PR 2 (iOS Settings screen) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Every task is TDD: write the failing host test first, then the implementation.

**Goal:** Ship the native iOS Settings screen on top of PR 1's shared FFI surface (`read_settings` / `write_settings` / `Settings` + bound-constant readers, already on `main` @ #418). Two per-vault controls — **retention window (days)** and **re-auth grace (minutes)** — with the Trash retention path reading the persisted value and the live re-auth gate retargeting to a changed grace window. `auto_lock_timeout_ms` / `require_password_before_edits` get no UI but are round-tripped so they are never dropped.

**Design source:** [docs/superpowers/specs/2026-07-12-mobile-vault-settings-design.md](../specs/2026-07-12-mobile-vault-settings-design.md) — Components D + E.

**Locked design decision (user-approved 2026-07-12):** the **effective re-auth grace default is 2 min** (`REAUTH_WINDOW_DEFAULT_MS`), honored from persisted settings at vault open. This aligns iOS with the schema + desktop and fits the whole-minutes UI. It is a deliberate behavior change from today's mobile `ReauthWindow.v1Default = 30 s` (a slight weakening — a longer unattended-write window); flag it in the PR description. `ReauthWindow.v1Default` (30 s) is left untouched (shared constant with its own tests); the composition root passes the settings-derived window explicitly.

**Tech Stack:** Swift 6 (strict concurrency = hard error), SPM packages `SecretaryVaultAccess` (FFI-free ports/DTOs/pure logic), `SecretaryVaultAccessUI` (`@MainActor` VMs + gates), `SecretaryVaultAccessTesting` (fakes), `SecretaryKit` (uniffi adapters), `SecretaryApp` (SwiftUI + composition root). Host tests via `swift test`; xcframework-dependent code via `build-xcframework.sh` + `xcodebuild`.

## Global constraints

- **`#![forbid(unsafe_code)]` / no `core` / crypto / on-disk-format / `manifest_version` change / no new `FfiVaultError` variant.** PR 2 is Swift-only over the frozen PR-1 FFI surface.
- **Strict concurrency:** every port/gate/VM/value type crossing an actor boundary is `Sendable`. VMs are `@MainActor final class … : ObservableObject`. Fakes use `@unchecked Sendable` (single-threaded mutable spies), matching `FakeTrashPort` / `FakeWriteReauthGate`.
- **Load-bearing security invariant — retarget strictly AFTER a successful save.** The gated save (`gate.authorizeWrite`) is evaluated against the **current (pre-save)** grace window; the gate is retargeted to the new window **only after `writeSettings` succeeds**. A user at an unlocked-but-unattended session outside the current grace window cannot widen their own window to self-authorize the widening — the widening still demands biometric proof. Pinned by a dedicated ordering test. No path may retarget before the gated save resolves.
- **Field preservation:** every `writeSettings` serializes all four fields. The VM reads the full `VaultSettings` on load, mutates only retention/grace, and writes back — `auto_lock_timeout_ms` / `require_password_before_edits` are preserved by construction (bridge already serializes all four; the VM must not zero them). Pinned by a VM-level field-preservation test via the fake port's captured value.
- **Lenient / never-block-access:** `read_settings` on the bridge returns `Settings::default()` (never errors) for an absent or corrupt settings block. The iOS `readSettings()` therefore surfaces defaults on a missing block; a hard FFI error (corrupt vault) falls back to the frozen defaults on the retention path and to the 2-min grace default at open.
- **Bound constants come from the FFI (one source):** the UI validates against the projected readers (`retention_window_min/max_ms`, `reauth_window_default/min/max_ms`, `default_retention_window_ms`), surfaced through the port as a `SettingsBounds` value. `MS_PER_DAY` (86_400_000) and `MS_PER_MINUTE` (60_000) are **not** projected — define them as named Swift constants in the pure conversion module (frozen, no-magic-numbers). Auto-lock bounds are not projected and not needed (no auto-lock UI); `write_settings` still rejects an out-of-range auto-lock server-side via `validate_save_settings`.
- **Working directory:** all edits target `.worktrees/mobile-settings-ios/…` on branch `feature/mobile-settings-ios` ([[feedback_edit_tool_targets_main_not_worktree]]). Verify with `pwd && git branch --show-current` before path-sensitive commands.
- **Conversions (mirror desktop `SettingsDialog` exactly):**
  - Retention = **days**: display `daysFromMs(ms) = round(ms / MS_PER_DAY)`, save `msFromDays(days) = days * MS_PER_DAY`, clamp `1…3650`, default `90`.
  - Grace = **minutes**: display `minutesFromMs(ms) = round(ms / MS_PER_MINUTE)`, save `msFromMinutes(min) = min * MS_PER_MINUTE`, clamp `0…60`, default `2`.

## Acceptance gate (run from the worktree root)

```bash
# Phase 1 (host, fast — no xcframework):
( cd ios/SecretaryVaultAccess && swift test )                 # pure + UI VM/gate tests green
# Phase 2 (multi-minute xcframework regen; [[project_secretary_ios_xcframework_build_watchdog]]):
bash ios/scripts/run-ios-tests.sh                             # host tests → xcframework → SecretaryKit xctest → build-app
```

---

## File structure

**`SecretaryVaultAccess` (FFI-free — new):**
- `Sources/SecretaryVaultAccess/SettingsPort.swift` — `SettingsPort` protocol + `VaultSettings` + `SettingsBounds` value types.
- `Sources/SecretaryVaultAccess/SettingsConversions.swift` — pure `daysFromMs`/`msFromDays`/`minutesFromMs`/`msFromMinutes`/`clampRetentionDays`/`clampGraceMinutes` + `MS_PER_DAY`/`MS_PER_MINUTE` constants + `SettingsBanner` (text + severity, `Equatable`) + `settingsSavedBanner()`.

**`SecretaryVaultAccessUI` (`@MainActor` — new):**
- `Sources/SecretaryVaultAccessUI/RetargetableReauthGate.swift` — delegating gate wrapper with `retarget(window:)`.
- `Sources/SecretaryVaultAccessUI/SettingsViewModel.swift` — the VM.

**`SecretaryVaultAccessTesting` (new):**
- `Sources/SecretaryVaultAccessTesting/FakeSettingsPort.swift` — fake port (seeded settings + bounds, spies, one-shot `failNext…`).

**`SecretaryKit` (xcframework-dependent — new):**
- `Sources/SecretaryKit/VaultAccess/UniffiVaultSession+Settings.swift` — `UniffiVaultSession: SettingsPort` over generated `readSettings`/`writeSettings` + the 6 bound readers.

**`SecretaryApp` (new + modify):**
- `Sources/SettingsScreen.swift` — the SwiftUI screen (new; auto-picked by XcodeGen — no project.yml edit).
- `Sources/VaultBrowseScreen.swift` — add a Settings gear toolbar item (modify).
- `Sources/SecretaryApp.swift` — password-path composition: build `RetargetableReauthGate` seeded from persisted grace; pass `settingsPort` + `settingsGate` to the browse VM (modify).
- `Sources/DeviceUnlockOpen.swift` — biometric-path composition: same; change `.opened` gate type to `RetargetableReauthGate` (modify).

**Modify (host-testable):**
- `Sources/SecretaryVaultAccessUI/TrashViewModel.swift` — inject `SettingsPort`; replace the 3 `defaultRetentionWindowMs()` reads with the per-vault retention value (cached on `load()`, fallback to the frozen default on read error).
- `Sources/SecretaryVaultAccessUI/VaultBrowseViewModel.swift` — hold `settingsPort: SettingsPort?` + `settingsGate: RetargetableReauthGate?`; `makeTrashViewModel()` passes the settings port; add `makeSettingsViewModel()`.

---

## Phase 1 — host-testable (`swift test`, millisecond feedback, no xcframework)

### Task 1 — Pure settings types + conversions (`SecretaryVaultAccess`)
- [ ] **Test first** (`Tests/SecretaryVaultAccessTests/SettingsConversionsTests.swift`): `daysFromMs`/`msFromDays` round-trip + rounding (`round`, not floor), `minutesFromMs`/`msFromMinutes` round-trip, `clampRetentionDays` (below 1 → 1, above 3650 → 3650, in-range unchanged), `clampGraceMinutes` (below 0 → 0, above 60 → 60), `settingsSavedBanner()` equals the expected `SettingsBanner`.
- [ ] `VaultSettings` — `public struct` (`Sendable`, `Equatable`) with `autoLockTimeoutMs: UInt64`, `requirePasswordBeforeEdits: Bool`, `reauthGraceWindowMs: UInt64`, `retentionWindowMs: UInt64` (field order mirrors the uniffi memberwise init).
- [ ] `SettingsBounds` — `public struct` (`Sendable`, `Equatable`): `retentionDefaultMs`/`retentionMinMs`/`retentionMaxMs`/`reauthGraceDefaultMs`/`reauthGraceMinMs`/`reauthGraceMaxMs` (`UInt64`).
- [ ] `SettingsBanner` (`Equatable`, `Sendable`) reusing the `.success`/`.warning` severity idiom; `SettingsConversions.swift` holds `MS_PER_DAY = 86_400_000` / `MS_PER_MINUTE = 60_000` (named constants).
- [ ] `SettingsPort` protocol (`AnyObject, Sendable`): `func readSettings() throws -> VaultSettings`, `func writeSettings(_ settings: VaultSettings) throws`, `func settingsBounds() -> SettingsBounds`.

### Task 2 — `FakeSettingsPort` (`SecretaryVaultAccessTesting`)
- [ ] **Test first** (`Tests/SecretaryVaultAccessTests/SettingsPortFakesTests.swift`): read returns the seed; write appends to a spy + updates the seed; `failNextRead`/`failNextWrite` throw once then clear; `settingsBounds()` returns the seeded bounds.
- [ ] `FakeSettingsPort: SettingsPort, @unchecked Sendable` — `public var settings`, `public var bounds`, `public private(set) var writtenSettings: [VaultSettings]`, one-shot `public var failNextRead/failNextWrite: VaultAccessError?`. Default `bounds` seeds the real constant values (retention 90/1/3650 d in ms, grace 120_000/0/3_600_000).

### Task 3 — `RetargetableReauthGate` (`SecretaryVaultAccessUI`)
- [ ] **Test first** (`Tests/SecretaryVaultAccessUITests/RetargetableReauthGateTests.swift`), mirroring `RetargetableReauthGateTest.kt` + iOS specifics:
  - `authorizeWrite` forwards to the current delegate (spy delegate records the call).
  - After `retarget(window:)`, `authorizeWrite` forwards to the **new** delegate.
  - `retarget(window:)` builds the new delegate with the **new window** and a **seed-at-now** instant (assert the injected `makeDelegate` factory received `(newWindow, clock())`).
  - Initial delegate is built once from the ctor `(window, initialAuthAt)`.
- [ ] Implement (`@MainActor final class RetargetableReauthGate: WriteReauthGate`): stores `delegate`, `clock: () -> MonotonicInstant`, `makeDelegate: @escaping @MainActor (Duration, MonotonicInstant?) -> WriteReauthGate`. Ctor builds the initial delegate from `makeDelegate(window, initialAuthAt)`. `authorizeWrite` forwards. `retarget(window:)` → `delegate = makeDelegate(window, clock())`.
  - **Rationale (document in a doc comment):** the wrapper seeds the new window from `clock()` because `retarget` is only ever called after a successful gated save, so the user is genuinely authorized at that instant; the security guard is the caller's after-save ordering, not the seed value.

### Task 4 — `SettingsViewModel` (`SecretaryVaultAccessUI`)
- [ ] **Test first** (`Tests/SecretaryVaultAccessUITests/SettingsViewModelTests.swift`) with `FakeSettingsPort` + a real `RetargetableReauthGate` whose `makeDelegate` returns a recording delegate (+ `FakeBiometricAuthorizer`):
  - **load** populates `retentionDays` + `graceMinutes` from `readSettings()` (converted/clamped); load on a read error falls back to bounds defaults (90 d / 2 min).
  - **clamp**: `setRetentionDays(0)` → 1, `setRetentionDays(9999)` → 3650; `setGraceMinutes(-5)` → 0, `setGraceMinutes(999)` → 60.
  - **save success** → `writtenSettings.last` has the new retention+grace **and preserves** the loaded `autoLockTimeoutMs`/`requirePasswordBeforeEdits`; `banner == settingsSavedBanner()`; the gate was retargeted to the new grace window.
  - **retarget-after-save ordering** (security): using a shared event log, assert the sequence is `authorizeWrite` → `writeSettings` → `retarget`, and that the delegate used for `authorizeWrite` still carries the **pre-save** window at the moment of the write (the new-window delegate is built only by the post-success `retarget`).
  - **gate refusal** (`gate` delegate throws `.reauthFailed`): `error` set, **no** `writeSettings`, **no** retarget, **no** banner, list/state unchanged.
  - **guard**: a second `save()` while `isWriting` is a no-op.
- [ ] Implement `@MainActor public final class SettingsViewModel: ObservableObject`: `@Published private(set)` `retentionDays: Int`, `graceMinutes: Int`, `isWriting: Bool`, `error: VaultAccessError?`, `banner: SettingsBanner?`; private `loaded: VaultSettings` (holds the round-tripped fields); injected `port: SettingsPort`, `gate: RetargetableReauthGate`, `bounds` (from `port.settingsBounds()`). `save()` copies the `reauthedWrite` guard shape (guard-`isWriting`-before-`await`, clear banner at start, gate → `writeSettings` → on success update `loaded` + `gate.retarget(window:)` + set banner).

### Task 5 — Trash retention integration + browse-VM factories (`SecretaryVaultAccessUI`)
- [ ] **Test first** (`Tests/SecretaryVaultAccessUITests/TrashViewModelTests.swift`): a new test seeds `FakeSettingsPort.settings.retentionWindowMs` to a non-default value and asserts `previewRetention()` + `runRetention()` use **that** window (via the fake trash port's captured `autoPurgeWindows` / `expiredTrashEntries` arg), not the frozen 90-day default; a read-error case falls back to `defaultRetentionWindowMs()`.
- [ ] `TrashViewModel.init(port:settingsPort:gate:)` — add `settingsPort: SettingsPort`. On `load()`, cache `retentionWindowMs` = `(try? settingsPort.readSettings())?.retentionWindowMs ?? port.defaultRetentionWindowMs()`. Replace all 3 `defaultRetentionWindowMs()` reads (accessor, `previewRetention`, `runRetention`) with the cached value. Keep `TrashPort.defaultRetentionWindowMs()` only as the read-error fallback.
- [ ] Update the existing `TrashViewModelTests` construction sites for the new `settingsPort:` param.
- [ ] `VaultBrowseViewModel`: add `settingsPort: SettingsPort?` + `settingsGate: RetargetableReauthGate?` ctor params (default `nil`, mirroring `trashPort`); `makeTrashViewModel()` passes `settingsPort` (guarded — return `nil` if absent, or supply a defaulting no-op? Prefer: require both trashPort and settingsPort for Trash); add `makeSettingsViewModel()` → `nil` unless both `settingsPort` and `settingsGate` are present.
- [ ] Update `VaultBrowseViewModel` tests that build the VM / call `makeTrashViewModel()` for the new params.

**Checkpoint:** `( cd ios/SecretaryVaultAccess && swift test )` fully green before Phase 2. Request code review of Phase 1 (ports/VM/gate + the ordering + field-preservation tests).

---

## Phase 2 — xcframework-dependent (multi-minute regen; drive the build yourself, log-poll, [[project_secretary_ios_xcframework_build_watchdog]])

### Task 6 — `UniffiVaultSession+Settings` adapter (`SecretaryKit`)
- [ ] Conform `UniffiVaultSession: SettingsPort` in a new extension file. `readSettings()` → map generated `SecretaryKit.readSettings(identity:manifest:)` → `VaultSettings`; `writeSettings(_:)` → `writeTrash`-style helper resolving `(deviceUuid, nowMs)`, calling `SecretaryKit.writeSettings(identity:manifest:settings:deviceUuid:nowMs:)`, mapping `VaultError` → `VaultAccessError` (existing `.invalidArgument` arm covers out-of-range / wrong-length device UUID — no new mapping). `settingsBounds()` bundles the 6 generated readers (`defaultRetentionWindowMs`, `retentionWindowMinMs`, `retentionWindowMaxMs`, `reauthWindowDefaultMs`, `reauthWindowMinMs`, `reauthWindowMaxMs`).
- [ ] Regenerate bindings (`bash ios/scripts/build-xcframework.sh`) so `readSettings`/`writeSettings` exist in the generated `secretary.swift`; confirm `xcodebuild test -scheme SecretaryKit` compiles + passes (a smoke test round-tripping settings over the real FFI on a temp copy of the golden vault — [[feedback_smoke_test_temp_copy_golden_vault]]).

### Task 7 — Composition-root wiring (`SecretaryApp`)
- [ ] Password path (`SecretaryApp.swift`): after `session`, read persisted grace: `let graceMs = (try? (session as? SettingsPort)?.readSettings())?.reauthGraceWindowMs ?? (session as? SettingsPort)?.settingsBounds().reauthGraceDefaultMs ?? REAUTH_DEFAULT`; build `let gate = RetargetableReauthGate(window: .milliseconds(Int(graceMs)), initialAuthAt: nil, clock: MonotonicInstant.now, makeDelegate: { w, seed in GraceWindowReauthGate(authorizer: authorizer, window: w, clock: MonotonicInstant.now, initialAuthAt: seed) })`; pass `settingsPort: session as? SettingsPort`, `settingsGate: gate` to the browse VM.
- [ ] Biometric path (`DeviceUnlockOpen.swift`): same, with `initialAuthAt: reauthInitialAuthAt(biometricUnlock: true, now: MonotonicInstant.now())`. Change `.opened(VaultSession, gate: GraceWindowReauthGate)` → `gate: RetargetableReauthGate`; thread `settingsPort` + `settingsGate` through `handleBiometricResult` into the browse VM.

### Task 8 — `SettingsScreen.swift` + browse toolbar gear (`SecretaryApp`)
- [ ] `SettingsScreen.swift`: `@StateObject var viewModel: SettingsViewModel`, `init(viewModel:)`. A `Form`/`List` with a **retention days** stepper/number field (`accessibilityIdentifier("settings-retention-days")`) and a **grace minutes** stepper/number field (`"settings-grace-minutes"`); a Save button (`"settings-save"`, `.disabled(viewModel.isWriting)`) calling `await viewModel.save()`; an inline banner mirroring `TrashScreen`'s `purge-notice` (`accessibilityIdentifier("settings-notice")`, `.warning` orange / `.success` secondary) + an error line. `.onAppear { viewModel.load() }`. No `Resources/` dir (codesign gotcha) — no bundled assets.
- [ ] `VaultBrowseScreen.swift`: add a sibling `ToolbarItem(placement: .primaryAction)` — `if let settingsVM = viewModel.makeSettingsViewModel() { NavigationLink { SettingsScreen(viewModel: settingsVM) } label: { Label("Settings", systemImage: "gear") } .disabled(viewModel.isWriting) .accessibilityIdentifier("open-settings") }`.

### Task 9 — Full acceptance + docs
- [ ] `bash ios/scripts/run-ios-tests.sh` green (host tests → xcframework → SecretaryKit xctest → build-app compile).
- [ ] README: note the iOS Settings screen now exists (retention + re-auth grace) — but per [[feedback_readme_style]] keep it brief; the mobile-Settings feature is only **complete** when PR 3 (Android) ships, so the "feature complete" README/ROADMAP flip lands with PR 3. For PR 2, a minimal ROADMAP note (iOS Settings shipped; Android remaining) is enough.
- [ ] Handoff doc + symlink retarget committed on the branch before opening the PR.

---

## Risks / notes
- **iOS `RetargetableReauthGate` is genuinely new code** (highest-novelty piece); the retarget-after-save ordering is the security guard — a review must confirm no path retargets before the gated save resolves. Android has no retarget-after-save reference (its `retarget` fires only at cloud-open); iOS PR 2 is the first.
- **Grace default change (30 s → 2 min)** is user-approved but user-visible; call it out in the PR body.
- **Screen render stays host-untested** (existing gap #417); `accessibilityIdentifier` hooks are added for a future instrumented assertion.
- **Reading settings at open** adds one block read to the unlock path (negligible AEAD decrypt; on the main actor during route transition). If ever slow, offload — but a single settings-record decrypt does not run Argon2 ([[project_secretary_ios_value_types_sendable_offload]] is about the sync path, not this).
