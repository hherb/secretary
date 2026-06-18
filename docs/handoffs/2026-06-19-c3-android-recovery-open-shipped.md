# NEXT_SESSION.md — C.3 Android recovery-phrase open ✅

**Session date:** 2026-06-19. Flow: `/nextsession` → prior baton (sync-on-browse) said "push + open PR" but a **parallel session had already pushed + squash-merged it** (PR #258, `main` @ `e0ca0f9`; `main` then advanced to `c4e2e8e` via #259's deps bump) → housekeeping (removed the merged `c3-android-sync-on-browse` worktree + branch; the two parallel-session worktrees `hardcore-robinson` / `d4-browser-autofill` left untouched) → chose **Android recovery-phrase open** as the next slice → scoped to **recovery-only** (device-secret deferred — it needs biometric Keystore work mirroring iOS B.3) → brainstormed (sealed `UnlockCredential`; recovery sessions reach `BrowseWithSyncScreen` with a status-only badge because Android sync is password-keyed) → spec → 8-task TDD plan → **subagent-driven execution** (fresh implementer + spec/quality review per task; all review items fixed in-task) → final whole-branch review (opus, READY-TO-MERGE) → 4 Minor fixes → this handoff.

**Status:** ✅ **code-complete + all-green**, on branch `feature/c3-android-recovery-open` (worktree `.worktrees/c3-android-recovery-open`). **NOT yet pushed / no PR yet** (push + open PR is the immediate next step — see §4). **Android-only — `core` / `ffi` / `ios` / on-disk-format / UDL all untouched** (both guardrails verified empty, §1). `open_vault_with_recovery` was already in the Rust UDL and is generated into the Android Kotlin bindings at build time, so no FFI work was needed.

## (1) What we shipped this session

**The central idea:** an unlocked Android user can open the golden vault with its 24-word BIP-39 recovery phrase (in addition to the password), reaching the same unified `BrowseWithSyncScreen`. A sealed `UnlockCredential` threads *which secret* through a pure `openWithCredential` dispatch; the `:kit` adapter wraps the already-generated `openVaultWithRecovery`. Because Android sync is **password-keyed** (`sync_vault` takes a password; there is no recovery-credential sync), a recovery-opened session shows a **status-only** sync badge (no auto-sync pass) and syncs manually via the existing badge re-prompt — mirroring iOS's optional-password `onUnlocked`.

| Layer | What landed | Commit (pre-squash) |
|---|---|---|
| **Spec + plan** | design doc + 8-task TDD plan | `0a032ef` `b6c0849` |
| **Task 1 — `RecoveryPhrase.normalize`** | pure `:vault-access` helper (lowercase / split-on-whitespace / drop-empties / single-space join); mirror of iOS. 6 host tests. | `997f67f` |
| **Task 2 — `UnlockCredential` + dispatch** | sealed `UnlockCredential { Password(secret) ; Recovery(secret) }` + pure `openWithCredential(openPort, folder, credential)` (exhaustive `when`, no `else`); `VaultOpenPort.openWithRecovery` seam; `FakeVaultOpenPort` records per-credential opens. (Added a clearly-marked `:kit` `TODO()` stub to keep the build green; replaced in Task 3.) | `1cf16b3` |
| **Task 3 — `:kit` adapter + error mapping** | real `UniffiVaultOpenPort.openWithRecovery` over `openVaultWithRecovery` (IO dispatcher, phrase forwarded per call, `recoveryFn` seam); new `VaultBrowseError.WrongRecoveryOrCorrupt` (conflated §13) + `InvalidRecoveryPhrase(detail)`; two mapping arms added **before** the `else`-fold. Generated binding variant names matched the UDL (no codegen rename). | `7c5af20` |
| **Task 4 — `dispatchPostOpenSync`** | pure `:app` helper (lambdas, no FFI): password → `onPassword(secret)` (background sync); recovery → `onRecovery()` (status refresh only). Host-tested. | `47099e2b` |
| **Task 5 — credential wiring** | `openBrowseWithSync(..., credential)` routes through `openWithCredential`; `unlockAndOpen(credential)` uses `dispatchPostOpenSync` and zeroizes `credential.secret` in `finally` on every exit. 4 callers updated (incl. `BrowseWithSyncScreenUiTest`, found by grep). | `10a84e9` |
| **Task 6 — `UnlockScreen` toggle** | Password/Recovery segmented toggle (material3 `SingleChoiceSegmentedButtonRow`); recovery field is multi-line + unmasked, normalized on submit. Callback now emits `UnlockCredential`; AppRoot arm simplified. Instrumented UI test 2/2. | `7d65f79` |
| **Task 7 — on-device recovery smoke** | `AppVaultProvisioning.goldenRecoveryPhrase` reads `recovery_mnemonic_phrase` from the bundled `golden_vault_001_inputs.json` (no hardcoded literal); `OpenWithRecoverySmokeTest` opens the golden vault via `UnlockCredential.Recovery` over the real `.so` and reaches the block list. PASSED on `emulator-5554`. | `efb67f6` |
| **Task 8 — docs** | README + ROADMAP rows (+ a fix commit deduping the ROADMAP placement and dating the ship 2026-06-19) | `86dc904` `b8a72c63` |
| **Final-review fixes** | 4 Minors: recovery KDocs on `UniffiVaultOpenPort` + `BrowseSession`; `assertNotNull` in the UI test; DRY `loadInputsJson` in `AppVaultProvisioning`. (Amended to drop a stray `sdd/` process artifact.) | `a858538` |

Branch from `main` @ `c4e2e8e`. **Squash-merge collapses to one commit on `main`.**

### Architecture (where the pieces live)

- `:vault-access` (pure) — `RecoveryPhrase.kt` (`normalize`); `UnlockCredential.kt` (sealed type + `openWithCredential` dispatch); `VaultOpenPort.openWithRecovery`; `VaultBrowseError` gains `WrongRecoveryOrCorrupt` / `InvalidRecoveryPhrase`.
- `:kit` (FFI adapter) — `UniffiVaultOpenPort.openWithRecovery` over the generated `openVaultWithRecovery`; `BrowseMapping.mapVaultBrowseError` gains the two recovery arms.
- `:app` (Compose) — `PostOpenSync.kt` (`dispatchPostOpenSync`); `UnlockScreen` toggle; `AppRoot.unlockAndOpen(credential)`; `openBrowseWithSync(..., credential)`; `AppVaultProvisioning.goldenRecoveryPhrase`.

### Acceptance (green this session)

```
cd android && ./gradlew :vault-access:test :kit:test :app:testDebugUnitTest :browse-ui:test     → BUILD SUCCESSFUL (host)
cd android && ANDROID_SERIAL=emulator-5554 ./gradlew :app:connectedDebugAndroidTest               → 13/13 on Medium_Phone_API_36.1 (incl. the recovery smoke + UnlockScreen toggle UI test)
git diff main...HEAD --name-only | grep -E 'core/|ffi/|crypto-design|vault-format'                → empty
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)' → empty (NO ios/)
```

### Deliberate design decisions (so a future reader doesn't "fix" them)

- **Recovery sessions reach `BrowseWithSyncScreen` with a status-only badge, NOT a separate screen** — mirrors iOS. The `sync_vault` FFI is password-keyed; a recovery open has no password, so it runs `refreshStatus()` (cheap disk read) instead of a sync pass. Manual sync still works via the badge's password re-prompt (`SyncScreen`'s `heldPassword`). Wiring recovery sessions to auto-sync would need an FFI change (out of scope).
- **Sealed `UnlockCredential` with exhaustive `when` (no `else`)** at both `openWithCredential` and `dispatchPostOpenSync` — a future credential arm (device-secret) becomes a compile error, not a silent drop.
- **`WrongRecoveryOrCorrupt` is conflated (anti-oracle §13)** — wrong phrase vs corruption indistinguishable, a `data object` with no payload to leak. `InvalidRecoveryPhrase(detail)` is a separate *format* error (bad word/length/UTF-8), safe to surface. Do NOT split the conflated one.
- **Recovery field is unmasked + multi-line** — a dotted 24-word phrase is unreadable, and the unlock moment is trusted under `FLAG_SECURE`.
- **The credential's `ByteArray` is zeroized unconditionally** in `unlockAndOpen`'s `finally`; only the password path hands a COPY to the background sync (`launchSyncAtUnlock` copies synchronously before the original is wiped, and the open is awaited so Argon2id can't race the zeroize). The recovery path hands out no copy.

## (2) What's next

- **Device-secret open path on Android** (the deferred half of this direction) — `add_device_slot` / `open_with_device_secret` plus biometric-gated Keystore/StrongBox storage of the device secret. This is the Android analogue of the iOS B.3 Secure-Enclave stack (#201/#202) and is a multi-slice effort: (a) enrollment, (b) `BiometricPrompt`-gated key release, (c) open. The sealed `UnlockCredential` `when` is ready to gain a `DeviceSecret` arm. **Acceptance:** enrol a device slot on-device, then open the golden vault via the per-device wrap slot behind a biometric prompt, reaching `BrowseWithSyncScreen`.
- **Block create/rename + record move-between-blocks** — the next CRUD tier (slices 9–10 + sync-on-browse manage records *within* a block). **Acceptance:** create a block, rename it, move a record across blocks, all re-read-verified on-device.
- **iOS biometric re-auth before a write** — separate follow-up (ROADMAP C.3 remaining).
- **On-device sync veto round-trip** still needs a seeded concurrent state ([[project_secretary_sync_veto_needs_seeded_state]]).
- Optional `WorkManager` background detection (deferred); `NSMetadataQuery` iCloud-download detection on iOS (deferred).

**Open follow-up issues (carried):** #224 / #234 / #192 / #193 / #190 / #189 / #186 / #161 / #162 / #167 / #202 / #251 / #252 / #255. **Closed this session:** none filed for this slice (no GitHub issue existed for recovery-open — commits carry no issue suffix; file one at PR time if desired).

## (3) Open decisions and risks

- **`ios/` is NOT in this slice's diff** — the standard "no `ios/` change" guardrail re-applies and is verified empty (§1).
- **No host test of the inline `AppRoot.unlockAndOpen` route-assembly** — it depends on the FFI (`makeVaultSync` is Looper-gated), so it's covered by the instrumented smokes. The genuinely pure logic is host-tested: `RecoveryPhrase.normalize`, `openWithCredential` dispatch, `dispatchPostOpenSync` dispatch, error mapping.
- **Final review verdict (opus):** READY-TO-MERGE; 0 Critical / 0 Important; the end-to-end secret-hygiene trace (zeroize unconditional, copy-before-zeroize, open awaited before zeroize), the exhaustive `when`, and the conflated anti-oracle mapping all verified against actual code. 6 Minor findings: 4 fixed (`a858538`); 2 deliberately accepted (`UnlockCredential.secret` exposes the array ref by design + KDoc-documented; the smoke's name-based cleanup matches the sibling smoke).
- **Per-task adjudication (recorded, no-action):** Task 2's interim `:kit` `TODO()` stub was an acknowledged compile-dependency bridge, replaced in Task 3.

## (4) Exact commands to resume

```bash
# 0) THIS BRANCH IS NOT YET PUSHED. Immediate next step: push + open the PR.
cd /Users/hherb/src/secretary/.worktrees/c3-android-recovery-open
git push -u origin feature/c3-android-recovery-open
gh pr create --repo hherb/secretary \
  --title "C.3 Android: recovery-phrase open path (24-word mnemonic → BrowseWithSyncScreen)" \
  --body "<summary>"
#    Then the user reviews + squash-merges (this session does not merge).

# 1) After the PR merges, housekeeping (from the MAIN checkout, not this worktree):
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/c3-android-recovery-open && git branch -D feature/c3-android-recovery-open
git worktree prune && git worktree list   # leaves hardcore-robinson + d4-browser-autofill untouched

# 2) Next direction (device-secret open OR block CRUD — spec first):
git worktree add .worktrees/<slug> -b feature/<slug> main

# Re-run the gauntlet on this branch (emulator must be running for connected tests):
cd /Users/hherb/src/secretary/.worktrees/c3-android-recovery-open/android && \
  ./gradlew :vault-access:test :kit:test :app:testDebugUnitTest :browse-ui:test       # host green
cd /Users/hherb/src/secretary/.worktrees/c3-android-recovery-open/android && \
  ANDROID_SERIAL=emulator-5554 PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :app:connectedDebugAndroidTest
# NOTE: connectedAndroidTest rejects --tests; use -Pandroid.testInstrumentationRunnerArguments.class=<FQN> for one test.
# NOTE: two devices are attached (a physical device + emulator-5554) — set ANDROID_SERIAL to pin the emulator.

# Guardrails (core/ffi/format AND ios/ all empty this slice):
cd /Users/hherb/src/secretary/.worktrees/c3-android-recovery-open
git diff main...HEAD --name-only | grep -E 'core/|ffi/|crypto-design|vault-format'                   # empty
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)'  # empty
```

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Authored once; the symlink is the pointer. `main` did NOT move during this session relative to the branch point (`c4e2e8e`), so the symlink retarget merges cleanly. Both this handoff + the retargeted symlink are committed on the feature branch ([[feedback_next_session_in_pr]]). If you resume this branch for fixups, first `git fetch origin && git merge origin/main` (branch-version-wins on the handoff path) before editing — closes the add/add gap ([[feedback_next_session_main_authoritative]]).

## Closing inventory

- **Branch on close:** `main` @ `c4e2e8e`; `feature/c3-android-recovery-open` carries spec + plan + 8 task commits (incl. doc fix) + 1 final-fix commit + this handoff commit. Squash-merge → one commit on `main`. **Not yet pushed; no PR yet.**
- **Acceptance:** green — `:vault-access` / `:kit` / `:app` host suites + `:browse-ui` + `:app` connected **13/13** on `Medium_Phone_API_36.1`; both guardrails empty (incl. no `ios/`). See §1.
- **Process note:** subagent-driven (fresh implementer + spec/quality review per task; all per-task review items fixed in-task — caught a Task-5/Task-6 ordering coupling at dispatch time and a Task-8 ROADMAP duplication at review). Final whole-branch review (opus) = READY-TO-MERGE; 4 Minor fixes applied, 2 accepted.
- **README.md / ROADMAP.md:** updated — recovery-phrase open ✅ (C.3 recovery-open), 2026-06-19.
- **NEXT_SESSION.md:** symlink retargeted to this file.
