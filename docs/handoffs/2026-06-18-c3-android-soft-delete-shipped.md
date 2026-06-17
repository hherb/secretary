# NEXT_SESSION.md — C.3 Android slice 9: soft-delete lifecycle ✅

**Session date:** 2026-06-18. Flow: `/nextsession` → slice-8 baton (PR #250 already merged, `main` @ `4def5ea`) → housekeeping (removed merged `c3-android-reveal-on-tap` worktree/branch; two parallel-session worktrees left untouched) → chose **Android slice 9** (soft-delete lifecycle) → brainstormed (scope decomposed: soft-delete now, edit/add → slice 10; explicit per-row buttons not swipe) → spec → 8-task TDD plan → **subagent-driven execution** (fresh implementer + spec/quality review per task; all review items fixed in-task) → final whole-branch review (opus, "READY TO MERGE") → docs + this handoff.

**Status:** ✅ **code-complete + all-green**, on branch `feature/c3-android-soft-delete` (worktree `.worktrees/c3-android-soft-delete`). **NOT yet pushed / no PR yet** (push + open PR is the immediate next step — see §4). This is the **first Android slice that WRITES to a vault**: a Show-deleted toggle + per-row Delete (tombstone) / Restore (resurrect), plus the device-UUID + write infrastructure all future Android writes reuse. **No `core`/`ffi`/`ios`/format change** — both guardrail greps empty; it projects the existing uniffi `tombstoneRecord`/`resurrectRecord` + `read_block` `includeDeleted` gate onto Android.

## (1) What we shipped this session

**The central idea:** browsing gains a write path that mirrors iOS. A **Show deleted** toggle re-reads the selected block with `includeDeleted` (the Rust gate decides what's returned — the client never filters tombstones). Per-row **Delete** tombstones a live record; per-row **Restore** resurrects a tombstoned one (only reachable with show-deleted on). Every write resolves a **per-vault device UUID** (a non-secret 16-byte CRDT fingerprint) and `now_ms` *inside* the real session, runs the uniffi write under the **same `sessionLock` + `wiped` guard as reads** (a write racing the lock-on-background `wipe()` refuses rather than touching zeroized handles), then re-reads on success. A failed write surfaces a typed error and **leaves the visible list intact**.

| Layer | What landed | Commit(s) |
|---|---|---|
| **Spec + plan** | slice-9 design doc + 8-task plan | `61d89d0` `7b20fc3` |
| **Task 1 — device UUID** | `DeviceUuidProvider` + `FileDeviceUuidStore` (`SecureRandom`, `CREATE_NEW`-converge, corrupt-length typed error) in `:vault-access` | `6f1bc56` (TOCTOU fast-path removed + test magic-number fixed in review) |
| **Task 2 — show-deleted** | `VaultBrowseModel.showDeleted`/`setShowDeleted`; `selectBlock` reads with `includeDeleted = showDeleted.value` | `b4d52b6` |
| **Task 3 — typed write errors** | `VaultBrowseError.RecordNotFound`/`SaveCryptoFailure` + `:kit` mapper arms | `08adb30` |
| **Task 4 — model delete/restore** | `VaultSession.tombstoneRecord`/`resurrectRecord` (interface); model `delete`/`restore`/`commitThenReload`; `hexToBytes` | `1a75c13` |
| **Task 5 — real write impl** | `UniffiVaultSession` writers (under `sessionLock`+`wiped`) + device-uuid resolve/cache + `uniffiVaultOpenPort(deviceUuids)` overload | `e9d5bd4` |
| **Task 6 — Compose UI** | `VaultBrowseViewModel` forwarding + `BrowseScreen` Show-deleted `Switch` + per-row Delete/Restore buttons | `52daf82` |
| **Task 7 — instrumented test** | `BrowseScreenSoftDeleteTest` (toggle + delete + restore) + androidTest fake writers | `a56cf72` |
| **Task 8 — :app + on-device smoke** | `AppRoot` injects `FileDeviceUuidStore(noBackupFilesDir/devices)`; `OpenBrowseSmokeTest` real-`.so` round-trip | `e42b3d1` |
| **Final review + docs** | `Failed` doc reword + README/ROADMAP (incl. slice-8 ROADMAP backfill) + this handoff | `6d87c31` `de4ea60` (+ this commit) |

Branch from `main` @ `4def5ea`. **Squash-merge collapses to one commit on `main`** (per-task SHAs above are pre-squash).

### Architecture (where the pieces live)

- **`:vault-access` (package `org.secretary.browse`) — pure, host-tested JUnit5:**
  - `DeviceUuid.kt` — `DeviceUuidProvider` interface, `FileDeviceUuidStore(directory: File)` (random 16 bytes/`<vaultHex>.dev` via `SecureRandom`, `CREATE_NEW`+catch-`FileAlreadyExistsException`→converge, corrupt-length → `DeviceUuidException`), `const DEVICE_UUID_BYTE_LEN = 16`.
  - `VaultBrowseModel` — `showDeleted: StateFlow<Boolean>` + `setShowDeleted` (re-reads selected block); `selectBlock` reads with `includeDeleted = _showDeleted.value`; `delete`/`restore` via `commitThenReload` (re-read on success only; failed write keeps `selectedRecords`).
  - `VaultSession` interface gains `suspend tombstoneRecord`/`resurrectRecord` (device-uuid/now-ms NOT on the interface).
  - `VaultBrowseError` gains `RecordNotFound(uuidHex)` / `SaveCryptoFailure(detail)`. `HexFormat.kt` gains `hexToBytes`.
- **`:kit` (package `org.secretary.browse`):**
  - `UniffiVaultOpenPort` takes a `DeviceUuidProvider?`; `uniffiVaultOpenPort(deviceUuids)` production factory (no-arg factory kept for read-only callers).
  - `UniffiVaultSession` — writers call the generated `uniffi.secretary.tombstoneRecord`/`resurrectRecord`, resolve+cache device uuid (mapping `DeviceUuidException`→typed `Failed`), stamp `System.currentTimeMillis().toULong()`, all inside `synchronized(sessionLock)` with the `wiped`-first guard. `BrowseMapping.kt` maps the two new arms.
- **`:browse-ui` (package `org.secretary.browse.ui`) — FFI-free Compose:**
  - `VaultBrowseViewModel` re-exposes `showDeleted`, forwards `setShowDeleted`/`delete`/`restore` on `viewModelScope`.
  - `BrowseScreen` — `Show deleted` `Switch` (testTag `toggle-show-deleted`); per-row `delete-<uuidHex>` (live) / `restore-<uuidHex>` (tombstoned) buttons. `recordTitle` already renders the `(deleted)` marker.
- **`:app`** — `AppRoot.unlockAndOpen` builds `FileDeviceUuidStore(File(context.noBackupFilesDir, "devices"))` → `uniffiVaultOpenPort(deviceUuids)`. Password-zeroize `finally` preserved.

### Acceptance (green — full gauntlet this session)

```
cd android && ./gradlew :vault-access:test :kit:testDebugUnitTest :browse-ui:test :app:test   → BUILD SUCCESSFUL (host JUnit5)
cd android && ./gradlew :browse-ui:connectedDebugAndroidTest                                   → BrowseScreenSoftDeleteTest 2/2 + BrowseScreenRevealTest 2/2 (4/4) on Medium_Phone_API_36.1
cd android && ./gradlew :app:connectedDebugAndroidTest                                         → OpenBrowseSmokeTest 4/4 (incl. real-.so soft-delete round-trip) + MakeVaultSyncSmokeTest 2/2 (6/6)
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)'   → empty
git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'               → empty
```

### Deliberate design decisions (so a future reader doesn't "fix" them)

- **Device UUID under `noBackupFilesDir`, per-vault, cached per session** — Android's backup-exclusion equivalent of iOS; a restored backup must not clone the CRDT fingerprint. `FileDeviceUuidStore` lives in `:vault-access` (pure `java.io`+`SecureRandom`, host-tested), exactly as iOS keeps it in its pure module.
- **Writes serialize under the existing `sessionLock` + `wiped` guard** — a write racing `ON_STOP` lock-on-background must not call the FFI on zeroized handles. The `wiped` check is the first statement inside the lock, before any handle touch (verified by the final review).
- **No client-side tombstone filtering** — toggling re-reads with `includeDeleted`; the Rust `read_block` gate is the single source of truth.
- **Failed write leaves the visible list intact** — `commitThenReload` re-reads on success only (mirror iOS).
- **Explicit per-row buttons, not swipe** — testable, matches the reveal/hide idiom.
- **Soft delete is reversible → no confirm dialog** (mirror iOS).
- **Edit/add deferred to slice 10** — this slice manages record *existence*, not field *content*.

## (2) What's next

- **Record editing/adding (Android slice 10).** Field-value edits + new records, mirroring iOS `RecordEditViewModel`/`EditableField` + the edit Form/sheet UI (text + bytes-as-hex). The write infra (device-UUID, `now_ms`, write seam, typed errors) is already in place from this slice; you add `appendRecord`/`editRecord` to the session + a `RecordContentInput`/validation type + an edit screen. Acceptance: add a record (type/tags/fields) → re-read shows it; edit an existing record (reveal-into-form → change → save) → re-read shows the change; both proven on-device against a staged golden-vault copy.
- **Sync-badge re-integration onto `BrowseScreen`** — unify browse + the slice-5 sync flow into one screen (`AppSyncStateDir` retained in `:app`).
- **Recovery-phrase + device-secret open paths** on Android (this + earlier slices are password-only; `open_with_recovery` / `open_with_device_secret` already exist on the uniffi surface).
- **On-device veto round-trip** still needs a seeded concurrent state ([[project_secretary_sync_veto_needs_seeded_state]]).
- Optional `WorkManager` background detection (deferred from slice 3).

**Open follow-up issues (carried):** #224 / #234 / #192 / #193 / #190 / #189 / #186 / #161 / #162 / #167 / #202 / #251. **Filed this session:** **#252** (pre-existing: read-only `blockSummaries`/`vaultUuidHex` on `UniffiVaultSession` lack the `wiped` guard that `readBlock`/`write` have — out of slice scope, likely cross-platform; check iOS too).

## (3) Open decisions and risks

- **#252 (filed, not fixed here):** the read-only path (`blockSummaries`/`vaultUuidHex`) can touch the manifest FFI handle after a concurrent/prior `wipe()` — the write/read-block paths are hardened with the `wiped` guard, this asymmetry is pre-existing. `vaultUuidHex()` also bypasses `mapErrors`, so a `VaultException` from a wiped handle could escape untyped. Deliberately left out of this slice (read-after-wipe semantics deserve a deliberate decision); fix likely belongs cross-platform.
- **First Android write path proven on-device.** The real save-tail (atomic manifest + block rewrite) ran on the emulator for the first time and passed first try (`OpenBrowseSmokeTest.softDelete_roundTrip_*`). Writes go to a **staged copy** of the golden vault in `filesDir` (re-provisioned per test), never the frozen repo fixture ([[feedback_smoke_test_temp_copy_golden_vault]]).
- **`now_ms` is wall-clock** (`System.currentTimeMillis()`) — CRDT correctness already tolerates skew (vector clocks order causally; the death clock handles ties). Same trust model as iOS `Date()`.
- **Carried, not widened:** #251 (cross-platform `openBlocks` decrypted-plaintext accumulation) — a post-write re-read appends another `BlockReadOutput`; same residency tradeoff, unchanged here.
- **Accepted Minors (final review triaged all as non-blocking):** the `setShowDeleted` same-value no-op guard has no dedicated test (one-line, trivially correct); test-only cosmetics in the unit-test fake (redundant `hexOfBytes`, helper placement); VM member ordering; the instrumented test's literal `ByteArray(16){0x4c}` block-UUID fixture (matches sibling `BrowseScreenRevealTest`/`VaultBrowseModelTest`; non-crypto UUID, so CodeQL's hardcoded-crypto-value rule does not fire); `AppRoot` import ordering. The one with user-facing value (the `VaultBrowseError.Failed` doc reword) was fixed (`6d87c31`).

## (4) Exact commands to resume

```bash
# 0) THIS BRANCH IS NOT YET PUSHED. Immediate next step: push + open the PR.
cd /Users/hherb/src/secretary/.worktrees/c3-android-soft-delete
git push -u origin feature/c3-android-soft-delete
gh pr create --repo hherb/secretary --title "C.3 Android slice 9: soft-delete lifecycle — show-deleted + delete/restore + device-UUID/write infra" --body "<summary>"
#    Then the user reviews + squash-merges (this session does not merge).

# 1) After the PR merges, housekeeping (from the MAIN checkout, not this worktree):
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/c3-android-soft-delete && git branch -D feature/c3-android-soft-delete
git worktree prune && git worktree list

# 2) Next direction (record edit/add — slice 10 — spec first):
git worktree add .worktrees/<slug> -b feature/<slug> main

# Re-run the gauntlet on this branch (emulator must be running for connected tests):
cd /Users/hherb/src/secretary/.worktrees/c3-android-soft-delete/android && \
  ./gradlew :vault-access:test :kit:testDebugUnitTest :browse-ui:test :app:test        # host green
cd /Users/hherb/src/secretary/.worktrees/c3-android-soft-delete/android && \
  PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :browse-ui:connectedDebugAndroidTest :app:connectedDebugAndroidTest        # 4/4 + 6/6, emulator running

# Guardrail greps (both must be empty):
cd /Users/hherb/src/secretary/.worktrees/c3-android-soft-delete
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)'
git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'
```

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Authored once; the symlink is the pointer. `main` did NOT move during this session relative to the branch point (`4def5ea`), so the symlink retarget merges cleanly. Both this handoff + the retargeted symlink are committed on the feature branch ([[feedback_next_session_in_pr]]). If you resume this branch for fixups, first `git fetch origin && git merge origin/main` (branch-version-wins on the handoff path) before editing — closes the add/add gap ([[feedback_next_session_main_authoritative]]).

## Closing inventory

- **Branch on close:** `main` @ `4def5ea`; `feature/c3-android-soft-delete` carries spec + plan + 10 task/fix commits + docs + this handoff commit. Squash-merge → one commit on `main`. **Not yet pushed; no PR yet.**
- **Acceptance:** green — `:vault-access`/`:kit`/`:browse-ui`/`:app` host suites + `BrowseScreenSoftDeleteTest` 2/2 + `BrowseScreenRevealTest` 2/2 + `OpenBrowseSmokeTest` 4/4 + `MakeVaultSyncSmokeTest` 2/2 on `Medium_Phone_API_36.1`; both guardrails empty. See §1.
- **Process note:** subagent-driven (fresh implementer + spec/quality review per task; all per-task review items fixed in-task). Final whole-branch review (opus) = "READY TO MERGE", write-path concurrency (`wiped`-before-FFI) + device-uuid caching + typed errors verified airtight; 8 carried Minors triaged non-blocking; #252 filed for a pre-existing read-path gap.
- **README.md / ROADMAP.md:** updated — Android C.3 slice 9 ✅ (soft-delete); ROADMAP slice-8 entry backfilled.
- **NEXT_SESSION.md:** symlink retargeted to this file.
