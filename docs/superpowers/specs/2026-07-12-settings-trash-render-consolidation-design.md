# Design — Consolidate settings/trash render loose ends (#421 + #417; close #413)

**Date:** 2026-07-12
**Branch:** `feature/settings-trash-render-consolidation` off `main` @ `6b2b6e6f`
**Worktree:** `.worktrees/settings-trash-render-consolidation/`
**Status:** approved (brainstorming), pre-implementation

## Purpose

Tidy the render-layer loose ends left by the mobile per-vault Settings slice (#418/#419/#420)
and the Trash purge-notice slice (#411/#416). This is a **consolidation** session — no new
feature. Three tracked issues:

| Issue | Verdict | Work |
| --- | --- | --- |
| **#413** iOS Trash `formatTrashedWhen` renders UTC, not locale date | **Already fixed** by #415 (commit `4de849e2`) | Close with a pointer comment — no code |
| **#421** Settings error banner uses "save" copy on a load failure (iOS + Android) | Real, cosmetic, host-testable | Extract the error→message mapping into a pure host-tested function; neutralize the shared fallback arm |
| **#417** Mobile Trash/Settings render bindings unverified | Real, infra-asymmetric | Android instrumented Compose render test; iOS host-logic coverage (defer the literal SwiftUI render) |

## Non-goals / invariants preserved

- **No `core` / crypto / on-disk-format / `manifest_version` change.** No new `FfiVaultError` /
  `VaultBrowseError` / `VaultAccessError` variant. `#![forbid(unsafe_code)]` intact.
- **Android + iOS only.** No `.rs` / desktop change (desktop already has DOM-level render
  coverage: `TrashView.test.ts`).
- **No change to the reviewed security models.** `SettingsModel` (Android) /
  `SettingsViewModel` (iOS) — including the retarget-after-save ordering and the field-preservation
  re-read — are untouched. The `readSettings()` throw-on-wiped behaviour (parity with `readTrash`)
  is correct and stays.

## #413 — close as already-fixed (no code)

The #415 housekeeping sweep (commit `4de849e2`, merged 2026-07-11 20:15, hours *after* #413 was
filed at 03:19) already did exactly what the issue asks:

- `formatTrashedWhen(_ ms:)` → `formatTrashedWhen(_ ms:, timeZone:, locale:)` — injected zone/locale
  rather than hard-coded UTC / `en_US_POSIX`.
- Display switched from fixed `yyyy-MM-dd` to `.medium` **locale-aware** style, matching desktop's
  short-month `formatShortDate`.
- Call site `ios/SecretaryApp/Sources/TrashScreen.swift` passes `.current` / `.current`.
- Regression test asserts the injected zone changes output (`utcDay` vs `laDay` in
  `TrashFormattingTests.swift`).

**Action:** close #413 with a comment pointing at `4de849e2`. Verify (grep) at close time that the
current tree still carries the injected signature + `.current` call site before closing.

## #421 — correct + host-test the Settings error banner (both platforms)

### Root cause

Both platforms expose a **single** `error` state populated by **both** `load()` and `save()`. The
banner text is derived **inline in the view** (Android: inside the `SettingsErrorBanner` Composable
in `:browse-ui`; iOS: a `private func settingsErrorMessage` in the app-target `SettingsScreen.swift`),
so neither mapping is reachable from host tests today.

Only the **fallback arm** misdescribes the operation. The specific arms are inherently save-only and
already correct:

- Android `ReauthFailed` — re-auth only gates `save()`; `load()` never gates. Correct.
- iOS `.reauthFailed` and `.invalidArgument` — re-auth and range-validation only occur on `save()`;
  `load()` reads leniently (absent/corrupt block ⇒ schema defaults) and clamps, so it produces
  neither. Correct.

So the fix is surgical: **neutralize only the shared fallback**, and extract the whole mapping into
a pure, host-testable function (the project's "pure functions in reusable modules" principle).

### Android

- New pure function `settingsErrorMessage(error: VaultBrowseError): String` in `:vault-access`
  (`org.secretary.browse`, its own small file). `VaultBrowseError` already lives there;
  `:browse-ui` already depends on `:vault-access`.
- Fallback `else` arm: `"Couldn't save settings: …"` → `"Couldn't update settings: …"` (keep the
  `${error::class.simpleName}` detail). Keep the `ReauthFailed` arm verbatim.
- `SettingsErrorBanner` in `:browse-ui` calls the extracted function instead of the inline `when`.
- Host-test in `:vault-access:test`: the `ReauthFailed` arm, the fallback wording, and that a
  representative load-path error (e.g. `CorruptVault`) now reads "update", not "save".

### iOS

- Move `settingsErrorMessage(_ e: VaultAccessError) -> String` out of the app-target
  `SettingsScreen.swift` into `SecretaryVaultAccessUI` (its own small file), visible to the
  `SecretaryVaultAccessUITests` host suite. `SettingsScreen.swift` already imports the module.
- `default` arm: `"Couldn't save settings. Please try again."` →
  `"Couldn't update settings. Please try again."` Keep `.reauthFailed` / `.invalidArgument` verbatim.
- Host-test in `SecretaryVaultAccessUITests`: the three arms, asserting the fallback now reads
  "update".

### Rejected alternative — distinguish load vs save

Threading an operation tag (enum/second field) through `SettingsModel` / `SettingsViewModel` to say
"Couldn't **load** settings" vs "Couldn't **save** settings" was considered and rejected: it adds
state to a carefully-reviewed security model for a purely cosmetic edge case (a genuinely corrupt
vault or a just-wiped session). The issue explicitly blesses neutral copy. YAGNI.

## #417 — render-layer coverage

### Android (instrumented Compose render test)

New instrumented test under `android/browse-ui/src/androidTest/kotlin/org/secretary/browse/ui/`,
mirroring the existing `BrowseScreenSoftDeleteTest` (fake session/gate + `createAndroidComposeRule`;
no real vault). Asserts the render bindings that host tests cannot see:

- **Trash notice:** `testTag("trash-notice")` renders the view-model's `notice` — the success text
  and the `filesFailed > 0` **warning** variant.
- **Settings notice/error:** `testTag("settings-notice")` renders the bound notice; `settings-error`
  renders the bound (extracted-function) error text.

Drives the composable from fake state (not the full browse→trash→purge flow) where the existing
pattern allows it, to keep the instrumented test focused and fast. Runs on an emulator via
`:browse-ui:connectedDebugAndroidTest` with the class filter
(`-Pandroid.testInstrumentationRunnerArguments.class=…`), per the project's instrumented-test
gotchas (no `--tests`).

### iOS (host-logic coverage; defer literal render)

The render-feeding logic is host-covered and stays so:

- `TrashViewModelTests` — 15 tests, `purgeNotice` fully covered (success, warning, single-purge,
  refusal-clears).
- `SettingsViewModelTests` — the settings model logic.
- New in #421: the extracted `settingsErrorMessage` host test.

**Defer** the literal SwiftUI render assertion: there is no ViewInspector dependency and no app
UI-test target; adding either is disproportionate infrastructure for what #417 itself rates a
**low** risk (a thin binding to an already-tested property). Re-scope #417 (comment) so its only
open sliver is the iOS SwiftUI `accessibilityIdentifier` render assertion, to pair with a future
ViewInspector/XCUITest decision and the already-tracked #414 instrumented follow-on.

## Testing & gates

- **Host (fast, primary):**
  - `( cd android && ./gradlew :vault-access:test )` — the new `settingsErrorMessage` tests.
  - `( cd android && ./gradlew :browse-ui:compileDebugKotlin :app:assembleDebug )` — the Composable
    still compiles/wires after the extraction.
  - iOS: the `SecretaryVaultAccess` Swift package host suite (`swift test` in
    `ios/SecretaryVaultAccess/` — the FFI-free ViewModel/logic layer that runs pre-xcframework in
    `run-ios-tests.sh` Step 1) — the moved `settingsErrorMessage` test. Confirm at plan time that
    this package builds standalone with `swift test` on the host (it is FFI-free, unlike
    `SecretaryKit`).
- **Instrumented (Android emulator):** `:browse-ui:connectedDebugAndroidTest` with the class filter.
- **TDD throughout:** a failing test precedes each extracted function, the corrected copy, and the
  render assertions.

## Risks

- **Android instrumented test is the only runtime-cost/flake surface.** Emulator boot; `adb`/
  `emulator` not on the bare PATH (use absolute paths); a cold `:kit` daemon can trigger a
  multi-minute silent Rust→JNI build (warm-build once, run backgrounded with log-poll). `:browse-ui`
  itself does not link the native lib, but a cold full-project configure might touch `:kit`.
- **iOS literal SwiftUI render stays deferred** — documented, #417 re-scoped. No regression risk;
  the binding is unchanged, only its feeding logic gains coverage.

## Delivery

- One PR from `feature/settings-trash-render-consolidation` covering #421 + #417.
- #413 closed separately (comment + close; no code).
- README/ROADMAP: assess at end — likely no change (no user-facing feature; render tests + copy fix).
  If touched, a one-line note only.
- Handoff per the symlink model.
