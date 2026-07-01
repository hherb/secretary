# NEXT_SESSION.md — Android biometric-unlock feedback parity (#341 + #342) ✅ SHIPPED (PR opening)

**Session date:** 2026-07-02. Shipped the **Android** parity for the two UX fixes the iOS session (#284 / PR #346) folded in on the iOS side only: **#341** (non-cancel biometric-unlock failure now surfaces feedback) and **#342** ("Remember this device" checkbox resets on Unlock-screen entry). Both were pre-existing Android UX quirks made routine to hit by #339 (per-cloud-vault biometric open). Worktree `.worktrees/android-biometric-feedback-341-342`, branch `feature/android-biometric-feedback-341-342` (cut from `main` @ `8a1113a`). **Android only — `:app` (classifier + wiring). No `core`/`ffi` Rust, no `:vault-access`/`:kit` change, no on-disk-format / spec / conformance / FFI-surface change** (the `DeviceUnlockError` taxonomy and biometric open path are untouched; this is purely a presentation fix).

Also, at session start: the previous session's #284 work (PR #346) was confirmed merged to `main` (`8a1113a`); its remote branch was already deleted and the local worktree + branch `feature/ios-device-unlock-browse-284` were cleaned up.

## (1) What we shipped this session

**#341 — surface non-cancel biometric-unlock failures.** Both biometric branches in `AppRoot.kt` (demo + cloud) discarded the ephemeral `DeviceUnlockViewModel`'s terminal `Failed(err)` state after `unlockWithBiometrics`, so a `NotEnrolled` / `VaultSlotMismatch` / `WrappedSecretCorrupt` failure was invisible (button silently disappears / screen stays put). Fix:
- New pure **`deviceUnlockFailureDisplay`** classifier (`android/app/.../DeviceUnlockFailureDisplay.kt`) — exhaustive `when` over all 9 `DeviceUnlockError` arms, **no `else`** (a future arm forces a compile decision); only `UserCancelled` → `Silent`, every other arm → a typed `Message`. Sibling of the existing `mapBiometricError`. Mirror of the iOS `deviceUnlockFailureDisplay`. Host-tested over the full taxonomy incl. the `Enclave(detail)` passthrough.
- A shared **`toastBiometricFailure(context, state)`** helper reads the VM's terminal state and Toasts on `Message`. Applied **symmetrically** to both branches. **Ordering matters:** the demo branch calls it **before** `deviceVm.refresh()` (which would overwrite `Failed` → `Enrolled`/`Unenrolled`); the cloud branch binds the VM to a local (`cloudVm`) so its state survives past the inline construction. Complementary to the #332 open-stage failure Toast (that covers the *post-credential* open failure; this covers the *pre-credential* `DeviceUnlockError`).

**#342 — reset "Remember this device" on Unlock route entry.** One line, `rememberDevice = false`, in the existing `LaunchedEffect(route)` block's `Route.Unlock` arm. Keys on `route` only, so it fires on Unlock-screen *entry* (not per-recomposition) — a mid-interaction tick is not clobbered. Mirror of iOS resetting `rememberDevice` on every `.unlock` route entry.

**Verification.** `./gradlew :app:testDebugUnitTest :vault-access:test` — **BUILD SUCCESSFUL**; `:app:compileDebugKotlin` compiled the `AppRoot.kt` wiring; the new `DeviceUnlockFailureDisplayTest` ran **3 tests, 0 failures, 0 skipped**. **Opus code review: clean — no high-confidence issues, all 5 invariants verified at source** (exhaustive classifier no-`else`; demo reads state before `refresh()` clobbers it; cloud reads the correct VM's state; no secret-handling weakening — `Enclave.detail` is already-public error text, not secret material; #342 reset can't clobber a mid-interaction tick).

**Branch commits** (off `main` @ `8a1113a`):
| SHA | What |
|---|---|
| `bfb2ce6` | docs: design |
| `d3df23d` | feat — `deviceUnlockFailureDisplay` classifier + test + `AppRoot` wiring (#341) + `rememberDevice` reset (#342) |
| `7571087` | docs: README + ROADMAP |
| (+ handoff) | this baton + retargeted `NEXT_SESSION.md` symlink |

### Acceptance (verified this session)
```bash
cd /Users/hherb/src/secretary/.worktrees/android-biometric-feedback-341-342/android
./gradlew :app:testDebugUnitTest :vault-access:test --console=plain   # host, green
# (adb/emulator not on bare PATH; host unit tests need no emulator)
```

## (2) What's next
#341 and #342 are complete. Follow-ups (unchanged from the #284 baton, minus the two now done):

1. **Instrumented UI assertions for #341/#342 (emulator, optional).** The pure classifier is host-tested; the Compose wiring (Toast dispatch, the `rememberDevice` reset) is compile-covered only — the same accepted limitation as every biometric app-wiring path in this repo. If desired, add to `UnlockScreenDeviceUiTest`: (a) a non-cancel biometric failure raises a Toast/message node; (b) tick "Remember this device" on target A → navigate to target B's Unlock → assert the checkbox is unticked. *Acceptance:* both assert green on `Medium_Phone_API_36.1`.
2. **iOS on-device Face ID acceptance (#284)** — still pending the physical iPhone 13 Pro Max manual walkthrough (no code). See the #284 baton's checklist. If it passes, flip the "on-device Face ID acceptance pending" note in README/ROADMAP to ✅.
3. **[#347](https://github.com/hherb/secretary/issues/347) — "Unlock with Face ID" is vault-agnostic (iOS).** Enrollment metadata is a single device-global Keychain entry, so with multiple vaults the button appears (and a doomed Face ID prompt fires, then fails gracefully via the post-open UUID check) when unlocking a vault other than the enrolled one. Proper fix stores the vault path in `DeviceEnrollment` — a data-model change rippling into the FFI-free package + Android parity, so a standalone slice. Low severity (graceful failure, UX only). **Note the Android analog:** Android's enrollment is already per-vault keyed via `cloudVaultKey(treeUri)` (#333), so #347 is iOS-specific — but the DeviceEnrollment data-model change would want an Android review too.
4. **Android cloud follow-ups from the #340 baton:** on-device biometric cloud-*open* proof ([#338](https://github.com/hherb/secretary/issues/338)); local/non-GDrive SAF on custom ROMs ([#331](https://github.com/hherb/secretary/issues/331)); settings enroll/disenroll toggle (#333 is opt-in-at-open only); native cloud-provider epic ([#334](https://github.com/hherb/secretary/issues/334), **ADR + threat-model first**).

## (3) Open decisions and risks
- **No automated coverage of the Compose app-wiring** (the two `toastBiometricFailure` call sites, the `rememberDevice` reset) beyond compile + (optional) emulator UI — accepted, same limitation as every biometric path here. The decidable logic (`deviceUnlockFailureDisplay`) is host-tested pure.
- **Classifier placed in `:app`, not `:vault-access`.** iOS put its analog in the pure package's UI product; Android's closest structural match is the app-local sibling `mapBiometricError` (also a `DeviceUnlockError` classifier, also host-tested in `app/src/test`). Chosen for local consistency; the classifier is app-local so there's no cross-module sealed-`when` exhaustiveness break to thread.
- **Two issues in one commit.** #341 and #342 are a single cohesive "biometric-unlock feedback parity" change in one file; committed together (the design doc + PR cover both). Not review-fixup debt, so the one-issue-per-commit discipline (which targets review fixes) doesn't apply.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After this PR merges, remove the worktree + branch:
#   git worktree remove .worktrees/android-biometric-feedback-341-342 && \
#   git branch -D feature/android-biometric-feedback-341-342
git worktree list && git status -s
# Android host unit tests need no emulator; adb/emulator are not on the bare PATH
# (use absolute paths from the toolchain memory if you need the emulator).
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; symlink retargeted in the same commit on the feature branch (new path → no add/add conflict; `main` updates cleanly on merge). Per [[feedback_next_session_in_pr]] / [[feedback_next_session_main_authoritative]] the baton rides inside the PR — do **not** sync to `main` during the pause window.

## Closing inventory
- **State on close:** PR opening on `feature/android-biometric-feedback-341-342` (3 work/docs commits + handoff). Worktree `.worktrees/android-biometric-feedback-341-342`. Feature complete; #341 + #342 resolved.
- **Acceptance:** `:app:testDebugUnitTest` + `:vault-access:test` green (host, 3/3 new tests); `:app` compile green; Opus code review clean (0 issues, 5 invariants source-verified).
- **README.md / ROADMAP.md:** updated (new Android status row; ROADMAP checklist bullet + all three progress-bar enumerations). **CLAUDE.md:** unchanged (the existing Android biometric paragraphs remain accurate; this is a presentation fix, not a new grep-invisible invariant).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-07-02-android-biometric-feedback-341-342-shipped.md`.
