# C.3 slice 3 — iOS sync UI (design)

**Date:** 2026-06-15
**Sub-project:** C.3 (iOS sync), slice 3 of 3
**Status:** approved design → implementation plan
**Predecessors:** slice 1 (#228, sync orchestration core), slice 2 (#230, folder-change detection)

## 1. Purpose

Slices 1 and 2 are headless. Slice 1 shipped a host-testable `SyncCoordinator`
(inspect / resolve / status over the uniffi sync bridge); slice 2 shipped a
detect-only `ChangeDetectionMonitor` that raises an advisory `pendingChanges`
flag when an open vault's folder changes. Neither is wired to any UI.

This slice makes both **user-visible** on iOS: a sync-status badge on the
open-vault screen, an opportunistic sync at unlock, an on-demand "Sync now"
flow with a password re-prompt, and a metadata-only conflict-resolution sheet
that mirrors the desktop D.1.15 Keep-mine / Accept-delete UX.

**iOS-only.** No Rust, FFI, on-disk-format, crypto, or CRDT change. The whole
slice is Swift. `git diff main...HEAD --name-only` must touch only `ios/**`,
`docs/**`, `README.md`, `ROADMAP.md`.

## 2. The hard constraint that shapes everything

`VaultSyncPort.sync(password:nowMs:)` and `commitDecisions(...)` take the **full
password** (`[UInt8]`) — they re-derive Argon2id and re-open the identity each
pass. The app **drops the password after unlock** (the browse session holds an
opened `VaultSession`, not the password). The B.3 device-secret / biometric
path opens the vault but yields an `OpenedVault`, **not** a password, so it
cannot feed a sync pass without an FFI/bridge change — which is out of scope.

Therefore sync must re-obtain the password. Two product decisions (deferred by
slices 1+2) were made for this slice:

- **Password policy: sync-at-unlock + re-prompt** (§4).
- **State directory: app-sandbox Application Support** (§5).

## 3. Architecture

Mirror the slice-1/2 split: **pure, host-tested logic** in
`SecretaryVaultAccess` / `SecretaryVaultAccessUI`; **thin SwiftUI views** and
**thin real-IO conformers** in `SecretaryApp` / `SecretaryKit`; everything
testable through injected ports with fakes.

```
┌─ SecretaryVaultAccess (pure core, FFI-free) ────────────────────────────┐
│  WallClock                 port: nowMs() -> UInt64 (keeps core clock-free)│
│  SyncBadgeState            enum + pure derivation function                │
│  SyncCoordinator           (slice 1 — unchanged)                          │
│  ChangeDetectionMonitor    (slice 2 — unchanged)                          │
├─ SecretaryVaultAccessUI ────────────────────────────────────────────────┤
│  VaultSyncViewModel        @MainActor ObservableObject (the testable heart)│
├─ SecretaryVaultAccessTesting ───────────────────────────────────────────┤
│  FakeWallClock                                                            │
├─ SecretaryApp (thin SwiftUI) ───────────────────────────────────────────┤
│  SyncBadgeView, SyncPasswordSheet, ConflictResolutionSheet               │
│  RootView / VaultBrowseScreen wiring (lifecycle + password handoff)       │
├─ SecretaryKit (thin real conformers) ───────────────────────────────────┤
│  SystemWallClock, SyncStateDirectory, sync VM factory                    │
└──────────────────────────────────────────────────────────────────────────┘
```

### 3.1 The unified sync model (one interactive path, two triggers)

There are two triggers but a **single interactive resolution path**, which keeps
the flow DRY and minimizes password lifetime.

**Trigger 1 — sync-at-unlock (silent; password already in hand).**
Right after a *password* unlock, run exactly one `runPass` with the in-hand
password, then zeroize it.

- Auto arms (`nothingToDo`, `appliedAutomatically`, `silentMerge`,
  `mergedClean`, `rollbackRejected`) → update the badge silently. Around any arm
  that **writes the vault** (notably `mergedClean`), the VM fires its injected
  `onWillWriteVault` hook so the app can `monitor.muteUntil(...)` and not
  self-trip "changes detected".
- `conflictsPending` → **do not** hold the password across a modal and **do
  not** auto-open the sheet. Set the badge to `reviewNeeded` and drop the
  password. Resolution defers to trigger 2.

Sync-at-unlock requires a password, so it is **skipped for biometric/device-
secret unlock** (no password in hand). That path falls back to the badge +
re-prompt. The biometric path is not yet wired into the main app, so this is a
documented future gap, not a regression.

**Trigger 2 — re-prompt (the single interactive flow).**
Tapping the badge (whether it shows monitor "changes detected" *or*
sync-at-unlock "review needed") **or** an explicit "Sync now" opens a centered
password sheet → `runInteractivePass(password:)`. If the outcome is
`conflictsPending`, the conflict sheet opens and the **same password is reused**
for `resolve(decisions:password:)`, then nulled. Mirrors desktop D.1.15 1:1.

**Consequence:** all conflict resolution flows through one path; sync-at-unlock
only ever auto-applies non-conflict arms. The cost is one extra Argon2id
re-derive in the rare case a conflict exists at unlock — a deliberate trade
favoring secret hygiene (no password held across a modal at unlock).

### 3.2 Components

**`WallClock` (pure core port).** `protocol WallClock { func nowMs() -> UInt64 }`.
`runPass`/`resolve` need epoch milliseconds for merge timestamps; the pure layer
must stay free of real-clock calls (slice-2 discipline). `FakeWallClock` returns
a settable value; `SystemWallClock` (SecretaryKit) reads `Date`.

**`SyncBadgeState` (pure core).** An enum plus a pure derivation function so the
VM stays thin and the badge logic is trivially host-tested:

```swift
public enum SyncBadgeState: Equatable, Sendable {
    case neverSynced
    case synced(sinceMs: UInt64)   // from SyncStatus.lastStateWriteMs
    case changesDetected           // monitor.pendingChanges == true
    case reviewNeeded              // a prior pass returned conflictsPending
    case syncing
}

public func syncBadgeState(
    inProgress: Bool,
    pendingChanges: Bool,
    hasPendingConflict: Bool,
    status: SyncStatus?
) -> SyncBadgeState
```

Precedence (first match wins): `inProgress` → `syncing`;
`hasPendingConflict` → `reviewNeeded`; `pendingChanges` → `changesDetected`;
`status?.lastStateWriteMs` → `synced(sinceMs:)`; else `neverSynced`.

**`VaultSyncViewModel` (UI; the testable heart).** `@MainActor`
`ObservableObject`. Owns a `SyncCoordinator`, a `WallClock`, the open vault's
`vaultUuid` (best-effort, for status), and an injected `onWillWriteVault: () ->
Void`. Reads `pendingChanges` from the monitor (the app forwards it). Published:
`badge: SyncBadgeState`, `isSyncing: Bool`, `pendingConflict: PendingConflict?`,
`lastError: VaultSyncError?`, `passwordSheetPresented: Bool`,
`conflictSheetPresented: Bool`.

Methods:
- `syncAtUnlock(password:) async` — trigger 1. One `runPass`; auto arms update
  badge + fire `onWillWriteVault` on writing arms; `conflictsPending` sets
  `reviewNeeded`. Never presents a sheet.
- `beginInteractiveSync()` — presents the password sheet (trigger 2 entry).
- `runInteractivePass(password:) async` — one `runPass`; on `conflictsPending`,
  present the conflict sheet (keep the conflict + reuse the password); else
  update badge, dismiss sheet. On writing arms, fire `onWillWriteVault`.
- `resolve(decisions:password:) async` — `coordinator.resolve(...)`; on success
  dismiss conflict sheet, clear `reviewNeeded`, fire `onWillWriteVault`; on
  `evidenceStale` / `decisionsIncomplete` keep the sheet open for retry.
- `acknowledge()` — calls `monitor.acknowledge()` (forwarded by the app) and
  recomputes the badge; used after a completed pass.
- `refreshStatus() async` — best-effort `coordinator.status(vaultUuid:)` →
  refresh the "synced … ago" label.

The VM never retains a password beyond a single in-flight async call (for the
interactive path, the conflict sheet's `password` is held by the sheet's own
state and re-supplied to `resolve`, then nulled — same as desktop).

**SwiftUI views (thin, `SecretaryApp`).**
- `SyncBadgeView` — toolbar item on `VaultBrowseScreen`; renders the five
  `SyncBadgeState` cases (icon + short label, e.g. "Synced 3m ago", "Changes
  detected", "Review needed", spinner); tap → `beginInteractiveSync()` (disabled
  while `syncing`).
- `SyncPasswordSheet` — mirror desktop `SyncPasswordDialog`. Password lives only
  in the sheet's `@State`, handed to the VM, nulled on every terminal outcome
  (success, conflict-handed-off, cancel). Inline error, stays open on failure.
- `ConflictResolutionSheet` — mirror desktop `ConflictResolutionDialog`. One
  card per `SyncVeto`: record type · tags · `fieldNames` · "deleted on device
  <peerDeviceHex prefix>"; **Keep mine** (default `keepLocal = true`) /
  **Accept delete** toggle per record. A read-only `DisclosureGroup` lists
  `SyncCollision` auto-merged fields ("N field(s) auto-merged — no action
  needed"). "Apply" → `resolve`. Inline error, stays open on failure. No secret
  field *values* are shown — metadata only.

**Lifecycle wiring (`RootView` / `VaultBrowseScreen`).** On entering `.browse`:
build the monitor (`makeChangeMonitor`, slice 2) and the `VaultSyncViewModel`
(via the SecretaryKit factory), `start()` the monitor, forward the monitor's
`onChange` into the VM's badge recompute, and — for the password-unlock path —
hand the just-used password to `syncAtUnlock(password:)` before it is zeroized.
On lock/background (`scenePhase` handler that already locks the browse model):
`monitor.stop()` and tear down the VM. The monitor's `muteUntil` is wired to the
VM's `onWillWriteVault` (mute window = a small fixed `ChangeDetectionTuning`
constant; no magic number inline).

**Real conformers (`SecretaryKit`).**
- `SystemWallClock` — `nowMs()` from `Date().timeIntervalSince1970 * 1000`.
- `SyncStateDirectory` — `defaultSyncStateDir(fileManager:) throws -> URL`
  returning `<Application Support>/secretary/sync/`, created if absent. Path
  derivation (appending `secretary/sync`) is pure and unit-tested; directory
  creation is the only IO.
- A factory assembling `VaultSyncViewModel` with `UniffiVaultSyncPort` (slice 1)
  + `SystemWallClock` + the resolved state dir + the open vault folder.

## 4. Password policy (decision)

**Sync-at-unlock + re-prompt** (§3.1). Rationale: the password is free at unlock,
so the common case costs no prompt; explicit/on-demand sync and *all* conflict
resolution re-prompt, holding the password only transiently in the sheet and
nulling it after (JS-style "cannot truly zeroize a Swift Array, so null/replace
ASAP", consistent with the existing unlock flow). Sync-at-unlock never holds the
password across a modal.

## 5. State directory (decision)

**App-sandbox Application Support:** `<Application Support>/secretary/sync/`,
inside the app's own container. YAGNI — there is a single app target and no
extension/widget that needs to share sync state, so no App Group entitlement.
Matches the desktop's `data_dir()/secretary/sync` convention. The directory is
always accessible without a security scope (unlike the vault folder, which is
accessed under the existing browse-session security scope).

## 6. Error handling

Mirror desktop: typed `VaultSyncError` → friendly inline messages; sheets **stay
open on failure for retry** and never auto-dismiss on error.
`wrongPasswordOrCorrupt` stays conflated (no wrong-password oracle).
`evidenceStale` (vault changed mid-modal) and `decisionsIncomplete` keep the
conflict sheet open so the user can re-apply. `inProgress` is surfaced as a
"sync already running" inline notice.

The badge "synced … ago" label is **best-effort**: it depends on
`SyncCoordinator.status(vaultUuid:)`, which needs the 16-byte vault UUID. If the
open `VaultSession` does not expose the UUID, the badge falls back to the last
pass outcome (`neverSynced` until the first successful pass) — confirmed during
planning, not a blocker.

## 7. Testing

TDD throughout; mirror the slice-1/2 gauntlet.

**Host tests (`SecretaryVaultAccess` via `swift test`):**
- `syncBadgeState` — every state and the precedence order.
- `VaultSyncViewModel` with `FakeVaultSyncPort` + `FakeWallClock` + a fake
  monitor seam:
  - each sync-at-unlock arm (auto arms update badge; writing arm fires
    `onWillWriteVault`; `conflictsPending` → `reviewNeeded`, no sheet, password
    dropped);
  - interactive pass: clean outcome dismisses sheet; `conflictsPending` presents
    conflict sheet and retains the conflict;
  - `resolve` happy path clears `reviewNeeded` + fires `onWillWriteVault`;
  - `resolve` `evidenceStale` / `decisionsIncomplete` keep the sheet open;
  - `acknowledge` recomputes the badge.
- `defaultSyncStateDir` path derivation (pure: given a base URL, appends
  `secretary/sync`).

**Sim smoke (`SecretaryKit` via `run-ios-tests.sh`):**
- `defaultSyncStateDir` creates the real directory under a temp Application
  Support base.
- One sync-at-unlock pass against a **temp copy** of a staged vault (never
  mutate a tracked fixture — `cp -R` to a tempdir first).

**Gauntlet (acceptance):**
```
cd ios/SecretaryVaultAccess && swift test          # host: all green, 0 warnings
bash ios/scripts/run-ios-tests.sh                  # ** TEST SUCCEEDED ** + ** BUILD SUCCEEDED **
git diff main...HEAD --name-only | grep -vE '^(ios/|docs/|README.md|ROADMAP.md)'                                  # empty
git diff main...HEAD --name-only | grep -E 'core/|ffi/|crypto-design|vault-format|conflict.rs|core/tests/data'    # empty
```

## 8. Scope

**In:** sync badge; sync-at-unlock (password path); re-prompt on-demand sync;
conflict-resolution sheet; monitor lifecycle wiring; self-write mute around
*sync's own* writes; app-sandbox state dir; `WallClock`/`SystemWallClock`.

**Out (YAGNI / deferred):**
- muting around ordinary record-edit writes (benign false positive — defer);
- biometric/device-secret sync path (needs an FFI change — out of scope);
- App Group container; `NSMetadataQuery` iCloud-download detection;
- backgrounded full-sync cold-start (slice-2 carryover);
- issue #224 (`@StateObject` VM-routing cleanup) — unrelated refactor.

## 9. Risks

- **Vault-UUID availability for `status`** (§6) — confirmed in planning; benign
  fallback if absent.
- **Sync-at-unlock latency** — one Argon2id re-derive after unlock. Runs off the
  main actor (the port offloads, per slice 1), so the UI stays responsive; the
  badge shows `syncing` during the pass.
- **Self-write false positives** — covered for sync's own writes via
  `onWillWriteVault` → `muteUntil`; ordinary record-edit writes remain a benign,
  deferred false positive (badge → user syncs → `nothingToDo`).
- **Password lifetime** — held only transiently in a sheet's state across the
  interactive flow and nulled after; sync-at-unlock never holds it across a
  modal.
