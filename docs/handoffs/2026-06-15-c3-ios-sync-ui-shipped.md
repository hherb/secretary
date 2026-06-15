# NEXT_SESSION.md — C.3 slice 3 iOS sync UI ✅

**Session date:** 2026-06-15. Flow: `/nextsession` → confirmed slice 2 (#230, folder-change detection) was squash-merged to `main` (`6ff0c26`) + removed its stale worktree/branch → chose **C.3 slice 3 (iOS sync UI)** → brainstormed (two deferred decisions resolved) → spec → 10-task TDD plan → **subagent-driven execution** (fresh implementer + combined spec/quality review per task; final whole-branch review on Opus) → docs + this handoff.

**Status:** ✅ **code-complete + all-green** on branch `feature/c3-ios-sync-ui`. PR: see §4. The iOS app now surfaces sync to the user: a **sync-status badge** on the browse screen, an opportunistic **sync-at-unlock**, an on-demand **re-prompt sync**, and a metadata-only **conflict-resolution sheet** (Keep mine / Accept delete) mirroring desktop D.1.15. **iOS-only; no Rust / FFI / on-disk-format / crypto / CRDT change** — `git diff main...HEAD --name-only` touches only `ios/**` + `docs/**` + `README.md` + `ROADMAP.md` (both guardrail greps below empty).

## (1) What we shipped this session

The two decisions deferred by slices 1–2 were made up front in brainstorming:
- **Password policy = sync-at-unlock + re-prompt.** Sync needs the full password (Argon2id); the app drops it after unlock; the B.3 device-secret path yields an `OpenedVault`, not a password, so it can't feed `runPass` without an FFI change (out of scope). So: run one opportunistic pass at unlock while the password is still in hand (password mode only), and re-prompt for explicit "Sync now" / acting on a detected change.
- **State dir = app-sandbox Application Support** (`<App Support>/secretary/sync/`). YAGNI — single app target, no extension/widget needs to share state, so no App Group entitlement. Matches desktop's `data_dir()/secretary/sync`.

**The central design idea:** two triggers, one interactive resolution path. Sync-at-unlock is silent and only auto-applies non-conflict arms; on `conflictsPending` it flips the badge to "review needed" and **drops the password** (never held across a modal at unlock). All conflict resolution flows through the single re-prompt path (badge tap / "Sync now" → password sheet → `runPass` → conflict sheet → `resolve`, password reused then nulled). Cost: one extra Argon2id when a conflict actually exists at unlock — a deliberate trade favoring secret hygiene.

| Layer | What landed | Commit(s) |
|---|---|---|
| **Spec + plan** | design doc + 10-task TDD plan | `5bb6d6b` `0a6479d` |
| **Task 1 — clock** | `WallClock` port + `FakeWallClock` (keeps the pure layer clock-free) | `2f334d3` |
| **Task 2 — hex** | pure `HexUuid.bytes(fromHex:)` decoder (vault-uuid hex → 16 bytes) | `edd3660` |
| **Task 3 — badge state** | `SyncBadgeState` enum + pure `syncBadgeState(...)` derivation | `29507b8` |
| **Task 4 — monitor seam** | `SyncMonitorHook` protocol + `FakeSyncMonitorHook` + `ChangeDetectionTuning.defaultSelfWriteMuteWindow` (10 s) | `37a2d21` |
| **Task 5 — view model** | `VaultSyncViewModel` (sync-at-unlock, interactive pass, resolve, cancel, badge) | `06d2a66` `4ae7bf5` `d792c03` `16e6946` |
| **Task 6 — conformers** | `SystemWallClock`, `MonitorSyncHook`, `defaultSyncStateDir`, `makeVaultSync` factory (+ a necessary `SecretaryVaultAccessUI` dep in SecretaryKit's `Package.swift`) | `dd11a1f` |
| **Task 7 — views** | `SyncBadgeView` + `SyncPasswordSheet` + `ConflictResolutionSheet` + `dismissPasswordSheet()` | `efb09f7` |
| **Task 8 — wiring** | RootView browse-route + lifecycle start/stop + sync-at-unlock handoff; UnlockScreen password forward; VaultBrowseScreen badge + sheets | `c28d7f2` |
| **Task 8 fix** | **critical:** VM must STRONGLY retain its monitor hook (was `weak` → hook deallocated immediately → mute/acknowledge silent no-ops in production) | `57bd674` |
| **Docs** | README row + ROADMAP C.3 slice-3 entries | `82c21f8` |
| **Handoff** | this file + retargeted `NEXT_SESSION.md` symlink | (this commit) |

Branch from `main` @ `6ff0c26`. **Squash-merge collapses to one commit on `main`** (per-commit SHAs above are pre-squash).

### Architecture (where the pieces live)
- `ios/SecretaryVaultAccess/…/SecretaryVaultAccess/` (pure, FFI-free): `WallClock.swift`, `HexUuid.swift`, `SyncBadgeState.swift`, `SyncMonitorHook.swift`; `MonotonicInstant.swift` gained the mute-window constant. Fakes in `…Testing/{FakeWallClock,FakeSyncMonitorHook}.swift`.
- `ios/SecretaryVaultAccess/…/SecretaryVaultAccessUI/`: `VaultSyncViewModel.swift` (the host-tested heart).
- `ios/SecretaryKit/…/VaultAccess/`: `SystemWallClock.swift`, `MonitorSyncHook.swift`, `SyncStateDirectory.swift`, `VaultSyncFactory.swift`.
- `ios/SecretaryApp/Sources/`: `SyncBadgeView.swift`, `SyncPasswordSheet.swift`, `ConflictResolutionSheet.swift`; wiring in `SecretaryApp.swift` + `UnlockScreen.swift` + `VaultBrowseScreen.swift`.

### Acceptance (green — full gauntlet this session)
```
cd ios/SecretaryVaultAccess && swift test            → 170 host tests, 0 failures, 0 warnings
bash ios/scripts/run-ios-tests.sh                    → ** TEST SUCCEEDED ** + ** BUILD SUCCEEDED **
git diff main...HEAD --name-only | grep -vE '^(ios/|docs/|README.md|ROADMAP.md)'                                  → empty
git diff main...HEAD --name-only | grep -E 'core/|ffi/|crypto-design|vault-format|conflict.rs|core/tests/data'    → empty
```
NOTE: desktop (`pnpm test`) and Python (`pytest`) suites were **not** re-run — pure iOS Swift slice, those layers unaffected. The pre-existing `ld: warning` about `blake3_neon/sse` object files built for a newer iOS-sim SDK appears in the xcframework link; it predates this slice and is not introduced by it.

## (2) What's next — candidate directions

The natural continuation is **C.3 Android** (the last C.3 platform piece) or **C.4 cross-device convergence conformance**:
- **C.3 Android** — folder-change detection + sync UI on Android (Storage Access Framework + `WorkManager`). No Android app scaffold exists yet, so this is greenfield platform setup; mirror the iOS pure-core/real-adapter split over the same uniffi sync surface.
- **C.4 cross-device convergence conformance** — prove two real clients (iOS ↔ desktop, or two iOS) converge through a shared folder, as a conformance test.
- **iOS biometric re-auth before a write** — a self-contained follow-up over the existing B.3 DeviceUnlock infra (carried since iOS record-CRUD).
- **#224** (route iOS RootView VMs as `@StateObject` so a scenePhase toggle doesn't reset wizard state).
- Rust-core backlog: **#193 / #192 / #190 / #189**.

**Acceptance for C.3 Android (sketch):** an Android app (Compose) can open a SAF-granted vault folder, detect remote folder changes via `WorkManager`, run a sync pass (re-prompting for the password), and surface a tombstone-veto conflict in a Keep-mine / Accept-delete UI — mirroring the iOS slice-1/2/3 stack over the same uniffi bindings.

**Open follow-up issues:** carried **#224 / #192 / #193 / #190 / #189 / #186 / #161 / #162 / #167 / #202**.

## (3) Open decisions and risks

- **Biometric/device-secret sync path is deferred (intentional).** Sync-at-unlock is **skipped for Face ID / recovery-phrase unlock** (no password in hand) — those fall back to the badge + re-prompt. Wiring the device-secret path into sync would need an FFI/bridge change (sync's `runPass` takes a password, not a device secret). The biometric unlock path isn't wired into the main app yet anyway, so this is a documented future gap, not a regression.
- **Self-write mute is best-effort.** The VM fires `muteSelfWrite()` (a generous 10 s window) before every pass so sync's own commit doesn't self-trip "changes detected". It does NOT mute around ordinary record-edit writes (benign false positive — defer; badge → user syncs → `nothingToDo`). The earlier **critical bug** here (VM held the hook `weak`, so the only production hook deallocated immediately and mute/acknowledge silently no-op'd) is fixed (`57bd674`) and pinned by `testViewModelRetainsMonitorHookForPasses`. If you touch the VM↔hook wiring, keep `monitor` a STRONG `var` — the only cycle is broken by the factory's `VMBox.vm` weak back-link.
- **Best-effort "synced … ago" label.** Depends on `SyncCoordinator.status(vaultUuid:)` decoding `VaultSession.vaultUuidHex` (32 hex → 16 bytes via `HexUuid`). Failures are swallowed (`try?`); the badge keeps its prior label. Production hex is always 32 chars, so the degenerate `HexUuid("")→[]` path is unreachable.
- **Conflict sheet re-prompts for the password on Apply.** The password sheet clears its `@State` after the pass, so the conflict sheet has its own short-lived `SecureField` rather than threading a retained secret across two sheets — independent, short password lifetime per sheet.
- **Concurrency / hygiene (final review verified):** the pure package stays clock-free (only `SystemWallClock`/`MonotonicInstant.now()` in SecretaryKit touch real time); the VM never stores a password and the `Route` enum never carries one; all `@MainActor`; metadata-only conflict surface carries no secrets.

## (4) Exact commands to resume

```bash
# 1) PR (opened this session — review / merge):
cd /Users/hherb/src/secretary && gh pr list --head feature/c3-ios-sync-ui

# 2) Merge (squash) once reviewed, then housekeeping:
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/c3-ios-sync-ui && git branch -D feature/c3-ios-sync-ui
git worktree prune && git worktree list

# 3) Next direction (C.3 Android, or C.4 convergence): brainstorm → plan → execute
git worktree add .worktrees/<slug> -b feature/<slug> main

# Re-run this slice's gauntlet on the branch:
cd /Users/hherb/src/secretary/.worktrees/c3-ios-sync-ui
( cd ios/SecretaryVaultAccess && swift test )       # 170 host tests
bash ios/scripts/run-ios-tests.sh                   # SecretaryKit sim + app build (slow; cross-compiles xcframework)
git diff main...HEAD --name-only | grep -vE '^(ios/|docs/|README.md|ROADMAP.md)'   # expect empty
```

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Authored once; the symlink is the pointer. `main` did NOT move during this session (branch point == `6ff0c26` == current `main`), so the symlink retarget merges cleanly. Both this handoff + the retargeted symlink are committed on the feature branch ([[feedback_next_session_in_pr]]). If you resume this branch for fixups, first `git fetch origin && git merge origin/main` (branch-version-wins on the handoff path) before editing — closes the add/add gap ([[feedback_next_session_main_authoritative]]).

## Closing inventory

- **Branch on close:** `main` @ `6ff0c26`; `feature/c3-ios-sync-ui` carries spec + plan + the 10-task implementation (clock → hex → badge-state → monitor-seam → VM → conformers/factory → views → wiring) + the critical hook-retain fix + docs + this handoff/symlink. Squash-merge → one commit on `main`.
- **Acceptance:** green — see §1. No `core`-format / crypto / CRDT change.
- **Process note:** subagent-driven (fresh implementer + a combined spec/quality review per task; a final whole-branch review on Opus). Reviews caught + fixed: a Swift name-collision in `FakeWallClock` (stored `nowMs` vs method `nowMs()` → renamed property to `currentMs`, T1); a necessary `SecretaryVaultAccessUI` dep missing from SecretaryKit's `Package.swift` (T6, the factory imports `VaultSyncViewModel`); and the **critical** monitor-hook `weak`-retain bug (T8 → `57bd674`, with a regression test that fails-before/passes-after). The final Opus review returned READY TO MERGE with no Critical/Important issues (three non-blocking doc/edge minors). No functional defect survived review.
- **README.md / ROADMAP.md:** updated — iOS C.3 sync UI ✅.
- **NEXT_SESSION.md:** symlink retargeted to this file.
