# NEXT_SESSION.md — C.3 Android device-secret open, slice 1 (pure core + FFI adapter) ✅

**Session date:** 2026-06-19. Flow: `/nextsession` → prior baton (recovery-open) said "push + open PR" but a **parallel session had already pushed + squash-merged it** (PR #260, `main` @ `1c46431`) → housekeeping (removed the merged `c3-android-recovery-open` worktree + branch; left the two parallel-session worktrees `hardcore-robinson` / `d4-browser-autofill` untouched) → chose **Android device-secret open** as the next direction → scoped to **slice 1 of 2** (pure coordinator + FFI adapter, FAKE in-memory enclave; real biometric Keystore + UI deferred to slice 2) → brainstormed (split the device FFI by responsibility: `openWithDeviceSecret` joins `VaultOpenPort`, slot mint/remove is a new `VaultDeviceSlotPort`; coordinator returns an `UnlockCredential.DeviceSecret` rather than opening — deliberate iOS divergence) → spec → 9-task TDD plan → **subagent-driven execution** (fresh implementer + spec/quality review per task; all review items fixed in-task) → final whole-branch review (opus, READY-TO-MERGE) → 3 fixes + 1 issue filed → this handoff.

**Status:** ✅ **code-complete + all-green**, on branch `feature/c3-android-device-open-core` (worktree `.worktrees/c3-android-device-open-core`). **NOT yet pushed / no PR yet** (push + open PR is the immediate next step — see §4). **Android-only — `core` / `ffi` / `ios` / on-disk-format / UDL all untouched** (both guardrails verified empty, §1). The device-slot FFI (`add_device_slot` / `open_with_device_secret` / `remove_device_slot`) was already in the UDL and generated into the Kotlin bindings (B.2), so no FFI work was needed.

## (1) What we shipped this session

**The central idea:** an enrolled Android device can open the golden vault with a per-device 32-byte wrap secret instead of the password/recovery phrase. A pure `DeviceUnlockCoordinator` orchestrates three ports — `VaultDeviceSlotPort` (mint/remove the `devices/<uuid>.wrap` slot via the real FFI), `DeviceSecretEnclave` (store/release the secret; biometric in slice 2; a FAKE in-memory enclave in slice 1), `DeviceEnrollmentMetadataStore` (non-secret vaultId + uuid). `unlock` returns an `UnlockCredential.DeviceSecret(uuid, secret)` that flows through the existing `openWithCredential` pipeline (reusing zeroize-in-`finally` + post-open-sync), so the device open is structurally the *same* manifest verify-before-decrypt as password/recovery — never a weaker open.

| Layer | What landed | Commit (pre-squash) |
|---|---|---|
| **Spec + plan** | design doc + 9-task TDD plan | `7b4a96f` `2e27668` |
| **Task 1 — error variants + mapping** | `VaultBrowseError.{WrongDeviceSecretOrCorrupt (conflated §13), DeviceSlotNotFound, DeviceUuidMismatch}`; three `mapVaultBrowseError` arms above the `else`-fold | `85eebcc` |
| **Task 2 — credential arm + seam** | `UnlockCredential.DeviceSecret(deviceUuid, secret)` + exhaustive `when` arm; `VaultOpenPort.openWithDeviceSecret`; `FakeVaultOpenPort` extended (+ a fix adding `deviceSecretError` injection parity) | `2590541` `25c32ba` |
| **Task 3 — ports/types/fakes** | `VaultDeviceSlotPort`+`EnrolledSlot`, `DeviceSecretEnclave`, `DeviceEnrollmentMetadataStore`+`DeviceEnrollment`, `DeviceUnlockError`; in-memory fakes (+ a fix: copy enrollment uuid, pin `lastIssuedSecret` alias, test error injection) | `21ae02b` `c7ab1c8` |
| **Task 4 — `enroll` + `isEnrolled`** | transactional enroll (rollback on each failure, original error rethrown, slot secret zeroized in `finally` after `store` copies) (+ a fix asserting zeroize on the rollback paths) | `fed72f2` `37a98d5` |
| **Task 5 — `unlock`** | guards (`NotEnrolled`/`VaultSlotMismatch`) BEFORE `enclave.release`; returns the credential; coordinator does not zeroize (caller owns) | `7b53b04` |
| **Task 6 — `disenroll`** | idempotent; narrow catch (only `DeviceSlotNotFound` swallowed) (+ a fix pinning non-`DeviceSlotNotFound` propagation) | `47cc5f2` `9a61139` |
| **Task 7 — `:kit` adapters** | `UniffiVaultOpenPort.openWithDeviceSecret` + new `UniffiVaultDeviceSlotPort` over the generated bindings; one-shot `takeSecret()`+`wipe()`-in-`finally`; `mapErrors` promoted to `internal` + reused (+ a doc fix) | `df1d677` `7b7ec39` |
| **Task 8 — on-device round-trip** | `AppVaultProvisioning.goldenPassword`; `OpenWithDeviceSecretSmokeTest` enrol→open→disenroll over the real `.so` with a fake enclave (PASSED on emulator-5554). **Necessary incidental fix:** added the `DeviceSecret` arm to `:app`'s exhaustive `dispatchPostOpenSync` `when` (→ `onRecovery`, status-only) — `:app` had not compiled since Task 2 | `594e8a3` |
| **Task 9 — docs** | README + ROADMAP rows (slice 1 ✅; biometric + UI = slice 2) | `c3f72ea` |
| **Final-review fixes** | I1 secret-residue mitigation (drop extra boxed copy; root-cause UDL change filed as **#261**); M3 enroll-orphan-window comment; M5 randomize the smoke's dummy secret (CodeQL hardcoded-crypto) | `d5ebe10` |

Branch from `main` @ `1c46431`. **Squash-merge collapses to one commit on `main`.**

### Architecture (where the pieces live)

- `:vault-access` (pure, host-tested) — `UnlockCredential.DeviceSecret` arm + `openWithCredential` dispatch; `VaultOpenPort.openWithDeviceSecret` seam; `VaultBrowseError` device arms; `VaultDeviceSlotPort`+`EnrolledSlot`; `DeviceSecretEnclave`; `DeviceEnrollmentMetadataStore`+`DeviceEnrollment`; `DeviceUnlockCoordinator`; `DeviceUnlockError`; in-memory fakes (test source set).
- `:kit` (FFI adapter, real `.so`) — `UniffiVaultOpenPort.openWithDeviceSecret`; `UniffiVaultDeviceSlotPort`; `BrowseMapping` device arms.
- `:app` — `AppVaultProvisioning.goldenPassword`; `dispatchPostOpenSync` `DeviceSecret` arm (status-refresh-only); `OpenWithDeviceSecretSmokeTest` + in-memory test doubles (androidTest).

### Acceptance (green this session)

```
cd android && ./gradlew :vault-access:test :kit:test :app:testDebugUnitTest :browse-ui:test     → BUILD SUCCESSFUL (host)
cd android && ANDROID_SERIAL=emulator-5554 ./gradlew :app:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.app.OpenWithDeviceSecretSmokeTest  → 1/1 PASS on Medium_Phone_API_36.1
git diff main...HEAD --name-only | grep -E 'core/|ffi/|crypto-design|vault-format'                → empty
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)' → empty (NO ios/)
```

### Deliberate design decisions (so a future reader doesn't "fix" them)

- **Device FFI split by responsibility** — `openWithDeviceSecret` lives on `VaultOpenPort` (it's a credential open, parallel to password/recovery); `addDeviceSlot`/`removeDeviceSlot` are a separate `VaultDeviceSlotPort` (slot management). iOS lumped all three because iOS has no credential-open abstraction; Android does.
- **Coordinator `unlock` returns an `UnlockCredential.DeviceSecret`, NOT an opened session** — deliberate iOS divergence (spec §5.2/§10). Open-time errors surface as `VaultBrowseError` from the shared pipeline, consistent with password/recovery; keeps the coordinator's responsibility to the secret lifecycle and reuses the existing zeroize/sync/route machinery.
- **`dispatchPostOpenSync` DeviceSecret arm → `onRecovery()` (status-refresh only)** — Android sync is password-keyed (`sync_vault` runs Argon2id), so a device-secret session (no password) syncs like recovery: status badge only, manual sync re-prompts. The arm was added now (not slice 2) because the exhaustive `when` won't compile without it.
- **`WrongDeviceSecretOrCorrupt` conflated (anti-oracle §13)** — payload-free `data object`; do NOT split. `DeviceUuidMismatch(detail)` is a structural-integrity signal, safe to surface.
- **Guard-before-release in `unlock`** — `NotEnrolled`/`VaultSlotMismatch` fire BEFORE `enclave.release`, so a stale/wrong-vault enrollment never triggers the slice-2 biometric prompt. Pinned by tests injecting a release error that "must not be called".
- **`device_uuid` is NON-SECRET** (loggable filename stem, vault-format §3a) — not zeroized; only `secret` is. A final-review finding to zeroize the uuid was declined on this basis.

## (2) What's next

- **Slice 2 — real biometric device open on Android**: an Android Keystore/StrongBox `DeviceSecretEnclave` whose `release` is gated by `BiometricPrompt` (the Android analogue of iOS's non-exportable Secure-Enclave P-256), plus the `UnlockScreen` toggle + `AppRoot` wiring + an on-device/emulator biometric proof (`adb emu finger`). The pure coordinator + the credential pipeline are already in place; slice 2 is the Android-specific adapter + UI + `DeviceUnlockViewModel`/state machine. **Acceptance:** enrol on-device, then open the golden vault via the per-device slot behind a real biometric prompt, reaching `BrowseWithSyncScreen`.
- **#261 (root-cause secret residue)**: change the UDL `take_secret()` (and sibling one-shot handles) from `sequence<u8>?` to `bytes?` so the Kotlin/Swift binding hands back a zeroizable `ByteArray`/`Data` instead of a boxed list. Cross-platform; needs the Swift+Kotlin conformance harness re-run. Out of this Android-only slice.
- **Block create/rename + record move-between-blocks** — the next CRUD tier.
- **iOS biometric re-auth before a write** — separate follow-up (ROADMAP C.3 remaining).
- **On-device sync veto round-trip** still needs a seeded concurrent state ([[project_secretary_sync_veto_needs_seeded_state]]).

**Open follow-up issues (carried):** #224 / #234 / #192 / #193 / #190 / #189 / #186 / #161 / #162 / #167 / #202 / #251 / #252 / #255. **Filed this session:** **#261** (uniffi `take_secret()` boxed-list residue).

## (3) Open decisions and risks

- **`ios/` NOT in this slice's diff** — guardrail re-applies, verified empty (§1).
- **`:kit` adapters have no host test** — they call the real `.so`; behavioral proof is the instrumented round-trip (Task 8). The pure logic (coordinator, dispatch, mapping, fakes) is fully host-tested.
- **Latent compile coupling caught at Task 8** — adding `UnlockCredential.DeviceSecret` (Task 2) broke `:app`'s exhaustive `dispatchPostOpenSync` `when`; only `:vault-access`/`:kit` were built for Tasks 2–7, so it surfaced at the first `:app` build (Task 8). Resolved (routed to `onRecovery`). **Lesson for slice 2 / future sealed-type changes: build `:app` too, not just the module under edit.**
- **Final review verdict (opus):** READY-TO-MERGE; 0 Critical. The end-to-end secret-hygiene trace, transactional rollback (original-error preservation), guard-before-release ordering, narrow disenroll catch, both exhaustive `when`s, and the conflated anti-oracle mapping were all verified against actual code. 1 Important (I1, secret residue) mitigated + root-cause filed as #261; M3/M5 fixed; M2 (speculative slice-2 length-check) and M4 (conservative `isEnrolled` under-report, matches iOS `try? metadata.load()`) accepted.

## (4) Exact commands to resume

```bash
# 0) THIS BRANCH IS NOT YET PUSHED. Immediate next step: push + open the PR.
cd /Users/hherb/src/secretary/.worktrees/c3-android-device-open-core
git push -u origin feature/c3-android-device-open-core
gh pr create --repo hherb/secretary \
  --title "C.3 Android: device-secret open slice 1 (pure DeviceUnlockCoordinator + :kit FFI adapter)" \
  --body "<summary>"
#    Then the user reviews + squash-merges (this session does not merge).

# 1) After the PR merges, housekeeping (from the MAIN checkout, not this worktree):
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/c3-android-device-open-core && git branch -D feature/c3-android-device-open-core
git worktree prune && git worktree list   # leaves hardcore-robinson + d4-browser-autofill untouched

# 2) Next direction (slice 2 biometric OR block CRUD — spec first):
git worktree add .worktrees/<slug> -b feature/<slug> main

# Re-run the gauntlet on this branch (emulator must be running for connected tests):
cd /Users/hherb/src/secretary/.worktrees/c3-android-device-open-core/android && \
  ./gradlew :vault-access:test :kit:test :app:testDebugUnitTest :browse-ui:test       # host green
cd /Users/hherb/src/secretary/.worktrees/c3-android-device-open-core/android && \
  ANDROID_SERIAL=emulator-5554 PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :app:connectedDebugAndroidTest
# NOTE: connectedAndroidTest rejects --tests; use -Pandroid.testInstrumentationRunnerArguments.class=<FQN> for one test.
# NOTE: two devices are attached (a physical device + emulator-5554) — set ANDROID_SERIAL to pin the emulator.

# Guardrails (core/ffi/format AND ios/ all empty this slice):
cd /Users/hherb/src/secretary/.worktrees/c3-android-device-open-core
git diff main...HEAD --name-only | grep -E 'core/|ffi/|crypto-design|vault-format'                   # empty
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)'  # empty
```

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Authored once; the symlink is the pointer. `main` did NOT move during this session relative to the branch point (`1c46431`), so the symlink retarget merges cleanly. Both this handoff + the retargeted symlink are committed on the feature branch ([[feedback_next_session_in_pr]]). If you resume this branch for fixups, first `git fetch origin && git merge origin/main` (branch-version-wins on the handoff path) before editing — closes the add/add gap ([[feedback_next_session_main_authoritative]]).

## Closing inventory

- **Branch on close:** `main` @ `1c46431`; `feature/c3-android-device-open-core` carries spec + plan + 9 task commits (with per-task fixes) + 1 final-fix commit + this handoff commit. Squash-merge → one commit on `main`. **Not yet pushed; no PR yet.**
- **Acceptance:** green — `:vault-access` / `:kit` / `:app` host suites + `:browse-ui` + the `:app` connected device-secret smoke **1/1** on `Medium_Phone_API_36.1`; both guardrails empty (incl. no `ios/`). See §1.
- **Process note:** subagent-driven (fresh implementer + spec/quality review per task; all per-task review items fixed in-task — 5 of 8 code tasks took one fix round). Final whole-branch review (opus) = READY-TO-MERGE; I1 mitigated + #261 filed, M3/M5 fixed, M2/M4 accepted.
- **README.md / ROADMAP.md:** updated — device-secret open slice 1 ✅ (C.3 device-open slice 1), 2026-06-19.
- **NEXT_SESSION.md:** symlink retargeted to this file.
