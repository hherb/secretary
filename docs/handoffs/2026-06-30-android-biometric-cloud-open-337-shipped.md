# NEXT_SESSION.md — Android biometric cloud-vault OPEN (#337) ✅ SHIPPED (PR opening)

**Session date:** 2026-06-30. Closed the last gap from #333: an enrolled device now opens a **cloud (SAF) vault by biometric**, at parity with the demo/local biometric-open path. Issue [#337](https://github.com/hherb/secretary/issues/337). Executed subagent-driven (fresh implementer per task → spec+quality review per task → whole-branch opus review) in worktree `.worktrees/android-biometric-cloud-open-337`, branch `feature/android-biometric-cloud-open-337` (cut from `main` @ `b6cb4fa`). **`android/app` Kotlin/Compose only — no `:vault-access`/`:kit`, no `core`/`ffi`, no on-disk-format / spec / `conformance.py` / conflict-KAT / observable-byte / FFI-surface change.**

## (1) What we shipped this session

**The feature.** Post-#333, a cloud vault could be *enrolled* and its *writes* re-authed by biometric, but **cloud open stayed password-only**. The big discovery this session (recorded in the design's "Correction during plan authoring"): the credential pipeline was **already generic** — `openCloudBrowse → openBrowseWithSync → openWithCredential` ([BrowseSession.kt:63](android/app/src/main/kotlin/org/secretary/app/BrowseSession.kt#L63), [UnlockCredential.kt:30-34](android/vault-access/src/main/kotlin/org/secretary/browse/UnlockCredential.kt#L30)) already routes a `DeviceSecret` credential to `openWithDeviceSecret`, and `UnlockScreen` already renders the biometric button for any `isEnrolled`. So **`CloudVaultOpen.kt` and `UnlockScreen.kt` needed ZERO change** — the work shrank to `AppRoot.kt` wiring + one pure helper.

- **Pure helper** — `android/app/src/main/kotlin/org/secretary/app/CloudBiometric.kt`: `unlockBiometricEnrolled(isCloudTarget, demoEnrolled, cloudEnrolled): Boolean` — total, no cross-talk (a cloud target follows `cloudEnrolled`, a demo target follows `demoEnrolled`). Replaces the old inline `cloudTarget == null && state is Enrolled` at the screen. 6 host tests.
- **AppRoot wiring** — a `cloudEnrolled` Compose state computed prompt-free on entering a cloud `Route.Unlock` (`cloudDeviceUnlockCoordinator(...).coordinator.isEnrolled`, keyed by `cloudVaultKey(treeUri)`); the screen's `isEnrolled` now driven by the helper; and a **cloud branch** in `onBiometricUnlock` that releases the secret and routes the `DeviceSecret` credential through the existing `openCloudTarget(..., enrollThisDevice=false)`. The demo branch is byte-identical.
- **Security invariants (opus-verified at source):** the cloud biometric unlock passes the **enrolled** id `cdu.metadataVaultId` to `DeviceUnlockCoordinator.unlock`, which guards `enrollment.vaultId == vaultId` **before** the biometric prompt ([DeviceUnlockCoordinator.kt:56-61](android/vault-access/src/main/kotlin/org/secretary/browse/DeviceUnlockCoordinator.kt#L56)) — a stale/wrong-vault enrollment can neither prompt nor open. The device-secret bytes are double-zeroized via the existing `finally` blocks in `openCloudBrowse`/`openCloudTarget` (no new stash). Same manifest verify-before-decrypt as the password path — not a weaker open. `isUnlocking` resets in a `finally` wrapping both branches; a cancel recomputes `cloudEnrolled` so the button persists.

**Verification.** Host gate green: `:app:testDebugUnitTest :kit:testDebugUnitTest :vault-access:test :app:compileDebugKotlin :app:compileDebugAndroidTestKotlin`. Instrumented on `emulator-5554` (`Medium_Phone_API_36.1`): new `CloudBiometricUnlockUiTest` 2/2 (cloud-titled enrolled → biometric button shown+enabled+routes; unenrolled → absent). Whole-branch review (opus): **Ready to merge: Yes, 0 Critical / 0 Important** — all six load-bearing invariants verified at the source; the single flagged item was a non-issue matching the existing sibling-test pattern.

**Branch commits** (off `main` @ `b6cb4fa`):
| SHA | What |
|---|---|
| `67c4a32` | docs: design |
| `1193d10` | docs: simplify design (dispatch already generic) |
| `f629bf4` | docs: implementation plan |
| `51f8006` | Task 1 — pure `unlockBiometricEnrolled` helper + 6 host tests |
| `e18f2ee` | Task 2 — `AppRoot` wiring (cloudEnrolled state + screen-entry read + cloud `onBiometricUnlock` branch) |
| `ca3d1f3` | Task 3 — instrumented `CloudBiometricUnlockUiTest` (2/2 emulator-5554) |
| `b89f251` | Task 4 — README + ROADMAP (cloud biometric "write-reauth and open") |
| (+ chore) | `.gitignore`: ignore Kotlin 2.x `.kotlin/` build dir |
| (+ handoff) | this baton + retargeted `NEXT_SESSION.md` symlink |

### Acceptance (verified this session)
```bash
cd /Users/hherb/src/secretary/.worktrees/android-biometric-cloud-open-337/android
./gradlew :app:testDebugUnitTest :kit:testDebugUnitTest :vault-access:test \
  :app:compileDebugKotlin :app:compileDebugAndroidTestKotlin              # full host gate green
# Instrumented (emulator-5554 online):
./gradlew :app:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.app.CloudBiometricUnlockUiTest   # 2/2
```

## (2) What's next
#337 is complete. Remaining cloud follow-ups + the native-provider fork (pick at brainstorm):

1. **On-device biometric cloud-*open* proof ([#338](https://github.com/hherb/secretary/issues/338), filed this session).** *Acceptance:* on a RedMagic 11 Pro over a real Google Drive folder, enroll → lock → open the cloud vault by biometric (Face/fingerprint release of the per-cloud-vault device secret); confirm a cancel leaves the screen usable. Manual on-device walkthrough (not an instrumented gate — RedMagic Compose-UI flakiness). No code change expected.
2. **Picker can't grant local/non-GDrive SAF tree on custom ROMs ([#331](https://github.com/hherb/secretary/issues/331)).** *Acceptance:* in-app guidance when no usable provider is granted, and/or an app-managed local vault location not dependent on the system tree picker.
3. **Settings-screen enroll/disenroll toggle for cloud vaults** (#333 is opt-in-at-open only; demo's settings flow is untouched).
4. **Surface `PendingFlushNotPersisted` to the user ([#329](https://github.com/hherb/secretary/issues/329))** — an un-synced offline-create currently only logs to logcat.
5. **Native cloud-provider integration epic ([#334](https://github.com/hherb/secretary/issues/334)).** mSecure-style native Dropbox/Drive OAuth SDK as an *additive* `CloudFolderPort` impl. **Gated on an ADR + threat-model review FIRST** — an embedded OAuth client secret in the secrets process changes the in-process attack surface vs OS-mediated SAF.

## (3) Open decisions and risks
- **Cloud biometric-open failure message stays generic** — the cloud path's existing "couldn't open the cloud vault" Toast is reused (the typed `unlockFailureMessage` re-plumbing stays out of scope, consistent with #332/#333). A biometric-open failure (e.g. stale working copy missing `devices/<uuid>.wrap` → `DeviceSlotNotFound`) surfaces via that Toast — no silent return to Unlock.
- **`cloudDeviceUnlockCoordinator` is built twice on the cloud path** (LaunchedEffect probe + `onBiometricUnlock`) — opus-confirmed benign: deterministic `cloudVaultKey`, prompt-free reads, no shared mutable state.
- **On-device biometric cloud-open is unproven** — emulator-verified only; tracked as #338. The instrumented test pins the UI affordance, not the real Keystore biometric release.
- **`:app` Compose-UI instrumented tests can fail on the RedMagic** ("No compose hierarchies found") — pre-existing, device-specific; the merge gate is the host suite + emulator-5554.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After this PR merges, remove the worktree + branch:
#   git worktree remove .worktrees/android-biometric-cloud-open-337 && \
#   git branch -D feature/android-biometric-cloud-open-337
git worktree list && git status -s
# Pick a next item (see §2). Android toolchain on this machine: emulator-5554 +
# a real RedMagic 11 Pro (serial 912607710061); adb/emulator need absolute paths
# (~/Library/Android/sdk/platform-tools/adb); logcat is blocked on the RedMagic.
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; symlink retargeted in the same commit on the feature branch (new path → no add/add conflict; `main` updates cleanly on merge). Per [[feedback_next_session_in_pr]] / [[feedback_next_session_main_authoritative]] the baton rides inside the PR — do **not** sync to `main` during the pause window.

## Closing inventory
- **State on close:** PR opening on `feature/android-biometric-cloud-open-337` (7 work commits + .gitignore chore + handoff). Worktree `.worktrees/android-biometric-cloud-open-337`. Feature complete; #337 resolved.
- **Acceptance:** full host gate green; instrumented `CloudBiometricUnlockUiTest` 2/2 on emulator-5554; whole-branch opus review Ready-to-merge (Yes, 0 Critical / 0 Important).
- **README.md / ROADMAP.md:** updated (cloud biometric "write-reauth **and open**"; emulator-verified, on-device deferred). **CLAUDE.md:** unchanged.
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-06-30-android-biometric-cloud-open-337-shipped.md`.
