# C.3 slice 3 — iOS sync UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the headless slice-1 sync core and slice-2 change monitor user-visible on iOS — a sync-status badge, opportunistic sync-at-unlock, an on-demand re-prompt sync, and a metadata-only conflict-resolution sheet.

**Architecture:** Mirror the slice-1/2 split — pure, host-tested logic in `SecretaryVaultAccess` / `SecretaryVaultAccessUI`; thin SwiftUI views and thin real-IO conformers in `SecretaryApp` / `SecretaryKit`; everything driven through injected ports with fakes. Two triggers (sync-at-unlock + re-prompt) funnel into one interactive resolution path so all conflict handling is DRY and the password is never held across a modal at unlock.

**Tech Stack:** Swift 5.9, SwiftUI, XCTest (host) + XcodeGen app target (sim), Swift Package Manager. No Rust/FFI/core change.

**Design reference:** [docs/superpowers/specs/2026-06-15-c3-ios-sync-ui-design.md](../specs/2026-06-15-c3-ios-sync-ui-design.md)

---

## Conventions used throughout

- **Where to run host tests:** `cd ios/SecretaryVaultAccess && swift test`
- **Where to run the sim/app gauntlet:** `bash ios/scripts/run-ios-tests.sh`
- **Worktree:** all work happens in `/Users/hherb/src/secretary/.worktrees/c3-ios-sync-ui` on branch `feature/c3-ios-sync-ui`. Verify with `pwd && git branch --show-current` before any `git`/`swift` command.
- **Test style:** `@MainActor final class XxxTests: XCTestCase`, `import SecretaryVaultAccess` + `import SecretaryVaultAccessTesting` + `@testable import SecretaryVaultAccessUI` (for VM tests). Mirror `UnlockViewModelTests.swift`.
- **No magic numbers:** named constants in `ChangeDetectionTuning` (slice 2) or the new types.

## File map

**Create (pure core — `SecretaryVaultAccess/Sources/SecretaryVaultAccess/`):**
- `WallClock.swift` — `protocol WallClock { func nowMs() -> UInt64 }`.
- `HexUuid.swift` — pure `enum HexUuid { static func bytes(fromHex:) -> [UInt8]? }`.
- `SyncBadgeState.swift` — `enum SyncBadgeState` + pure `syncBadgeState(...)`.
- `SyncMonitorHook.swift` — `@MainActor protocol SyncMonitorHook` (mute + acknowledge seam).

**Create (test fakes — `SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/`):**
- `FakeWallClock.swift`
- `FakeSyncMonitorHook.swift`

**Create (view model — `SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/`):**
- `VaultSyncViewModel.swift`

**Modify (pure core):**
- `MonotonicInstant.swift` — add `ChangeDetectionTuning.defaultSelfWriteMuteWindow`.

**Create (real conformers — `SecretaryKit/Sources/SecretaryKit/VaultAccess/`):**
- `SystemWallClock.swift`
- `MonitorSyncHook.swift`
- `SyncStateDirectory.swift`
- `VaultSyncFactory.swift` (`makeVaultSync(...)`)

**Create (SwiftUI — `SecretaryApp/Sources/`):**
- `SyncBadgeView.swift`
- `SyncPasswordSheet.swift`
- `ConflictResolutionSheet.swift`

**Modify (SwiftUI app):**
- `SecretaryApp.swift` (RootView: build sync context on browse entry, lifecycle start/stop, sync-at-unlock)
- `UnlockScreen.swift` (forward the password on a password-mode unlock)
- `VaultBrowseScreen.swift` (badge toolbar item + the two sheets)

**Create (tests):**
- `SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/{HexUuidTests,SyncBadgeStateTests,WallClockFakeTests,SyncMonitorHookFakeTests}.swift`
- `SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultSyncViewModelTests.swift`
- `SecretaryKit/Tests/SecretaryKitTests/SyncStateDirectoryTests.swift`

No `Package.swift` or `project.yml` change: every new file lands in an existing target/source dir.

---

## Task 1: `WallClock` port + `FakeWallClock`

The pure layer must stay free of real-clock calls (slice-2 discipline); `runPass`/`resolve` need epoch ms, so we inject a clock.

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/WallClock.swift`
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeWallClock.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/WallClockFakeTests.swift`

- [ ] **Step 1: Write the failing test**

```swift
// WallClockFakeTests.swift
import XCTest
import SecretaryVaultAccess
import SecretaryVaultAccessTesting

final class WallClockFakeTests: XCTestCase {
    func testReturnsSeededValueAndIsSettable() {
        let clock = FakeWallClock(nowMs: 1_000)
        XCTAssertEqual(clock.nowMs(), 1_000)
        clock.nowMs = 2_500
        XCTAssertEqual(clock.nowMs(), 2_500)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter WallClockFakeTests`
Expected: FAIL — `cannot find 'FakeWallClock' in scope`.

- [ ] **Step 3: Write minimal implementation**

```swift
// WallClock.swift
import Foundation

/// Wall-clock millisecond source for sync merge timestamps. Injected so the pure
/// layer never calls a real clock directly (mirrors `MonotonicInstant`'s split).
public protocol WallClock {
    /// Milliseconds since the Unix epoch.
    func nowMs() -> UInt64
}
```

```swift
// FakeWallClock.swift
import Foundation
import SecretaryVaultAccess

/// Deterministic `WallClock` for tests. `nowMs` is freely settable so a test can
/// advance time between calls.
public final class FakeWallClock: WallClock {
    public var nowMs: UInt64
    public init(nowMs: UInt64 = 0) { self.nowMs = nowMs }
    public func nowMs() -> UInt64 { nowMs }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ios/SecretaryVaultAccess && swift test --filter WallClockFakeTests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/WallClock.swift \
        ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeWallClock.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/WallClockFakeTests.swift
git commit -m "feat(ios-sync): WallClock port + FakeWallClock"
```

---

## Task 2: `HexUuid` decoder

The badge "synced … ago" path calls `SyncCoordinator.status(vaultUuid: [UInt8])`; the open session exposes `vaultUuidHex: String`. This pure decoder converts it to 16 bytes (or `nil` if malformed — status then degrades gracefully).

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/HexUuid.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/HexUuidTests.swift`

- [ ] **Step 1: Write the failing test**

```swift
// HexUuidTests.swift
import XCTest
import SecretaryVaultAccess

final class HexUuidTests: XCTestCase {
    func testDecodes32CharHexTo16Bytes() {
        let bytes = HexUuid.bytes(fromHex: "000102030405060708090a0b0c0d0e0f")
        XCTAssertEqual(bytes, [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15])
    }
    func testAcceptsUppercase() {
        XCTAssertEqual(HexUuid.bytes(fromHex: "AABB"), [0xAA, 0xBB])
    }
    func testRejectsOddLength() {
        XCTAssertNil(HexUuid.bytes(fromHex: "abc"))
    }
    func testRejectsNonHex() {
        XCTAssertNil(HexUuid.bytes(fromHex: "zz"))
    }
    func testEmptyStringDecodesToEmpty() {
        XCTAssertEqual(HexUuid.bytes(fromHex: ""), [])
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter HexUuidTests`
Expected: FAIL — `cannot find 'HexUuid' in scope`.

- [ ] **Step 3: Write minimal implementation**

```swift
// HexUuid.swift
import Foundation

/// Pure lowercase/uppercase hex → bytes decoder for vault-UUID hex strings.
/// Returns `nil` for an odd length or any non-hex nibble. Empty in → empty out.
public enum HexUuid {
    public static func bytes(fromHex hex: String) -> [UInt8]? {
        let scalars = Array(hex.unicodeScalars)
        guard scalars.count % 2 == 0 else { return nil }
        var out = [UInt8]()
        out.reserveCapacity(scalars.count / 2)
        var index = 0
        while index < scalars.count {
            guard let hi = nibble(scalars[index]), let lo = nibble(scalars[index + 1]) else {
                return nil
            }
            out.append(UInt8(hi << 4 | lo))
            index += 2
        }
        return out
    }

    private static func nibble(_ scalar: Unicode.Scalar) -> Int? {
        switch scalar {
        case "0"..."9": return Int(scalar.value - 48)        // '0' == 48
        case "a"..."f": return Int(scalar.value - 87)        // 'a' == 97 → 10
        case "A"..."F": return Int(scalar.value - 55)        // 'A' == 65 → 10
        default: return nil
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ios/SecretaryVaultAccess && swift test --filter HexUuidTests`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/HexUuid.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/HexUuidTests.swift
git commit -m "feat(ios-sync): pure HexUuid decoder for vault-uuid hex"
```

---

## Task 3: `SyncBadgeState` + pure derivation

A pure enum + derivation so the badge logic is trivially host-tested and the VM stays thin.

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/SyncBadgeState.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/SyncBadgeStateTests.swift`

- [ ] **Step 1: Write the failing test**

```swift
// SyncBadgeStateTests.swift
import XCTest
import SecretaryVaultAccess

final class SyncBadgeStateTests: XCTestCase {
    private func status(_ ms: UInt64?) -> SyncStatus {
        SyncStatus(hasState: ms != nil, deviceClocks: [], lastStateWriteMs: ms)
    }

    func testSyncingWinsOverEverything() {
        let s = syncBadgeState(inProgress: true, pendingChanges: true,
                               hasPendingConflict: true, status: status(123))
        XCTAssertEqual(s, .syncing)
    }
    func testReviewNeededBeatsChangesAndSynced() {
        let s = syncBadgeState(inProgress: false, pendingChanges: true,
                               hasPendingConflict: true, status: status(123))
        XCTAssertEqual(s, .reviewNeeded)
    }
    func testChangesDetectedBeatsSynced() {
        let s = syncBadgeState(inProgress: false, pendingChanges: true,
                               hasPendingConflict: false, status: status(123))
        XCTAssertEqual(s, .changesDetected)
    }
    func testSyncedWhenStatusHasWriteTime() {
        let s = syncBadgeState(inProgress: false, pendingChanges: false,
                               hasPendingConflict: false, status: status(123))
        XCTAssertEqual(s, .synced(sinceMs: 123))
    }
    func testNeverSyncedWhenNoStatus() {
        let s = syncBadgeState(inProgress: false, pendingChanges: false,
                               hasPendingConflict: false, status: nil)
        XCTAssertEqual(s, .neverSynced)
    }
    func testNeverSyncedWhenStatusHasNoWriteTime() {
        let s = syncBadgeState(inProgress: false, pendingChanges: false,
                               hasPendingConflict: false, status: status(nil))
        XCTAssertEqual(s, .neverSynced)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter SyncBadgeStateTests`
Expected: FAIL — `cannot find 'SyncBadgeState' / 'syncBadgeState' in scope`.

- [ ] **Step 3: Write minimal implementation**

```swift
// SyncBadgeState.swift
import Foundation

/// What the sync badge shows. Pure presentation state derived from the VM's
/// inputs; carries no secrets.
public enum SyncBadgeState: Equatable, Sendable {
    case neverSynced
    case synced(sinceMs: UInt64)   // from SyncStatus.lastStateWriteMs
    case changesDetected           // monitor raised pendingChanges
    case reviewNeeded              // a prior pass returned conflictsPending
    case syncing
}

/// Derive the badge state. Precedence (first match wins): in-progress →
/// conflict awaiting review → advisory change detected → last-synced → never.
public func syncBadgeState(
    inProgress: Bool,
    pendingChanges: Bool,
    hasPendingConflict: Bool,
    status: SyncStatus?
) -> SyncBadgeState {
    if inProgress { return .syncing }
    if hasPendingConflict { return .reviewNeeded }
    if pendingChanges { return .changesDetected }
    if let ms = status?.lastStateWriteMs { return .synced(sinceMs: ms) }
    return .neverSynced
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ios/SecretaryVaultAccess && swift test --filter SyncBadgeStateTests`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/SyncBadgeState.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/SyncBadgeStateTests.swift
git commit -m "feat(ios-sync): SyncBadgeState + pure derivation"
```

---

## Task 4: `SyncMonitorHook` seam + self-write mute constant

The VM addresses two monitor concerns without depending on `ChangeDetectionMonitor` directly: mute the monitor around the VM's own vault writes, and acknowledge it after a pass so the next change re-detects. A small injected protocol keeps the VM host-testable.

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/SyncMonitorHook.swift`
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeSyncMonitorHook.swift`
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/MonotonicInstant.swift` (add constant)
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/SyncMonitorHookFakeTests.swift`

- [ ] **Step 1: Write the failing test**

```swift
// SyncMonitorHookFakeTests.swift
import XCTest
import SecretaryVaultAccess
import SecretaryVaultAccessTesting

@MainActor
final class SyncMonitorHookFakeTests: XCTestCase {
    func testSpyCountsCalls() {
        let hook = FakeSyncMonitorHook()
        hook.muteSelfWrite()
        hook.muteSelfWrite()
        hook.acknowledge()
        XCTAssertEqual(hook.muteCalls, 2)
        XCTAssertEqual(hook.acknowledgeCalls, 1)
    }
    func testMuteWindowConstantIsAtLeastDebounce() {
        // The self-write mute must outlast the change-detection debounce so our own
        // write's pulse is suppressed rather than raising a spurious badge.
        XCTAssertGreaterThanOrEqual(
            ChangeDetectionTuning.defaultSelfWriteMuteWindow,
            ChangeDetectionTuning.defaultDebounceWindow)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter SyncMonitorHookFakeTests`
Expected: FAIL — `cannot find 'FakeSyncMonitorHook'` / `defaultSelfWriteMuteWindow`.

- [ ] **Step 3: Write minimal implementation**

```swift
// SyncMonitorHook.swift
import Foundation

/// The sync VM's view of the change monitor: mute the monitor around the VM's own
/// vault writes, and reset it after a pass so the next remote change re-detects.
/// `@MainActor` because the real conformer wraps the `@MainActor` monitor.
@MainActor
public protocol SyncMonitorHook: AnyObject {
    /// Suppress watcher pulses for a self-write window starting now.
    func muteSelfWrite()
    /// Acknowledge handled changes so the detector re-arms for the next one.
    func acknowledge()
}
```

```swift
// FakeSyncMonitorHook.swift
import Foundation
import SecretaryVaultAccess

/// Spy `SyncMonitorHook` for VM tests.
@MainActor
public final class FakeSyncMonitorHook: SyncMonitorHook {
    public private(set) var muteCalls = 0
    public private(set) var acknowledgeCalls = 0
    public init() {}
    public func muteSelfWrite() { muteCalls += 1 }
    public func acknowledge() { acknowledgeCalls += 1 }
}
```

Add to `MonotonicInstant.swift`, inside `enum ChangeDetectionTuning` (after `defaultDebounceWindow`):

```swift
    /// How long to suppress the folder watcher after the app initiates its own
    /// vault write (sync commit), so the write does not raise a spurious
    /// "changes detected" signal. Best-effort and generous: it must outlast the
    /// debounce plus a slow Argon2id pass + filesystem settling. Residual false
    /// positives are benign (badge → user syncs → nothingToDo).
    public static let defaultSelfWriteMuteWindow: Duration = .milliseconds(10_000)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ios/SecretaryVaultAccess && swift test --filter SyncMonitorHookFakeTests`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/SyncMonitorHook.swift \
        ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeSyncMonitorHook.swift \
        ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/MonotonicInstant.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/SyncMonitorHookFakeTests.swift
git commit -m "feat(ios-sync): SyncMonitorHook seam + self-write mute window constant"
```

---

## Task 5: `VaultSyncViewModel`

The testable heart. Owns a `SyncCoordinator` + `WallClock` + optional `vaultUuid` + optional `SyncMonitorHook`. Implements the unified model: sync-at-unlock (silent), interactive pass (re-prompt), resolve, badge recompute. Never stores a password beyond a single in-flight call.

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultSyncViewModel.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultSyncViewModelTests.swift`

Build the VM incrementally. Each behavior cluster is test-first.

- [ ] **Step 1: Write the first failing test (sync-at-unlock auto arm)**

```swift
// VaultSyncViewModelTests.swift
import XCTest
import SecretaryVaultAccess
import SecretaryVaultAccessTesting
@testable import SecretaryVaultAccessUI

@MainActor
final class VaultSyncViewModelTests: XCTestCase {

    private func coordinator(_ port: FakeVaultSyncPort) -> SyncCoordinator {
        SyncCoordinator(port: port, stateDir: "/state", vaultFolder: "/vault")
    }

    private func makeVM(
        port: FakeVaultSyncPort,
        vaultUuid: [UInt8]? = [UInt8](repeating: 7, count: 16),
        hook: FakeSyncMonitorHook? = nil
    ) -> VaultSyncViewModel {
        VaultSyncViewModel(coordinator: coordinator(port),
                           wallClock: FakeWallClock(nowMs: 42),
                           vaultUuid: vaultUuid,
                           monitor: hook)
    }

    func testSyncAtUnlockNothingToDoStaysIdle() async {
        let port = FakeVaultSyncPort(syncResult: .success(.nothingToDo))
        let hook = FakeSyncMonitorHook()
        let vm = makeVM(port: port, hook: hook)

        await vm.syncAtUnlock(password: Array("pw".utf8))

        XCTAssertFalse(vm.isSyncing)
        XCTAssertFalse(vm.reviewNeeded)
        XCTAssertNil(vm.pendingConflict)
        XCTAssertFalse(vm.conflictSheetPresented)
        XCTAssertEqual(port.syncCalls, 1)
        XCTAssertEqual(port.lastSyncPassword, Array("pw".utf8))
        XCTAssertEqual(port.lastSyncStateDir, "/state")
        XCTAssertEqual(hook.muteCalls, 1)         // muted before the (possibly-writing) pass
        XCTAssertEqual(hook.acknowledgeCalls, 1)  // success → acknowledge
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter VaultSyncViewModelTests`
Expected: FAIL — `cannot find 'VaultSyncViewModel' in scope`.

- [ ] **Step 3: Write the initial VM (enough to pass Step 1)**

```swift
// VaultSyncViewModel.swift
import Foundation
import Combine
import SecretaryVaultAccess

/// Drives the iOS sync UI: the status badge, sync-at-unlock, the re-prompt sync,
/// and conflict resolution. Host-testable — holds only the pure `SyncCoordinator`,
/// an injected `WallClock`, the (optional) 16-byte vault UUID for status, and an
/// optional `SyncMonitorHook`. It NEVER stores a password: each password arrives
/// as a method argument for a single in-flight call. `@MainActor` (publishes UI
/// state); the CPU-heavy Argon2id pass is offloaded by the port, so the VM only
/// suspends, never blocks, the main actor.
@MainActor
public final class VaultSyncViewModel: ObservableObject {
    @Published public private(set) var badge: SyncBadgeState = .neverSynced
    @Published public private(set) var isSyncing = false
    @Published public private(set) var reviewNeeded = false
    @Published public private(set) var pendingConflict: PendingConflict?
    @Published public private(set) var lastError: VaultSyncError?
    @Published public var passwordSheetPresented = false
    @Published public var conflictSheetPresented = false

    private var pendingChanges = false
    private var lastStatus: SyncStatus?

    private let coordinator: SyncCoordinator
    private let wallClock: WallClock
    private let vaultUuid: [UInt8]?
    private weak var monitor: SyncMonitorHook?

    public init(coordinator: SyncCoordinator, wallClock: WallClock,
                vaultUuid: [UInt8]? = nil, monitor: SyncMonitorHook? = nil) {
        self.coordinator = coordinator
        self.wallClock = wallClock
        self.vaultUuid = vaultUuid
        self.monitor = monitor
    }

    // MARK: - Trigger 1: sync-at-unlock (silent; password already in hand)

    /// Run one pass with the just-used password. Auto arms update the badge
    /// silently; `conflictsPending` only flips `reviewNeeded` (no sheet, password
    /// dropped — resolution defers to the interactive path).
    public func syncAtUnlock(password: [UInt8]) async {
        await runPass(password: password) { [weak self] outcome in
            guard let self else { return }
            if case .conflictsPending = outcome { self.reviewNeeded = true }
        }
    }

    // MARK: - Badge

    private func recomputeBadge() {
        badge = syncBadgeState(inProgress: isSyncing, pendingChanges: pendingChanges,
                               hasPendingConflict: reviewNeeded, status: lastStatus)
    }

    /// Shared pass runner: mute self-writes, flip `isSyncing`, run, route the
    /// outcome through `onSuccess`, acknowledge on success, refresh status.
    private func runPass(password: [UInt8],
                         onSuccess: (SyncOutcome) -> Void) async {
        isSyncing = true
        lastError = nil
        recomputeBadge()
        monitor?.muteSelfWrite()
        do {
            let outcome = try await coordinator.runPass(password: password,
                                                        nowMs: wallClock.nowMs())
            onSuccess(outcome)
            monitor?.acknowledge()
            pendingChanges = false
            await refreshStatus()
        } catch let e as VaultSyncError {
            lastError = e
        } catch {
            lastError = .failed(String(describing: error))
        }
        isSyncing = false
        recomputeBadge()
    }

    // MARK: - Status

    /// Best-effort: needs the 16-byte vault UUID. Failures are swallowed (the
    /// badge simply keeps its prior last-synced label).
    public func refreshStatus() async {
        guard let vaultUuid else { return }
        lastStatus = try? await coordinator.status(vaultUuid: vaultUuid)
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ios/SecretaryVaultAccess && swift test --filter VaultSyncViewModelTests`
Expected: PASS (1 test).

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultSyncViewModel.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultSyncViewModelTests.swift
git commit -m "feat(ios-sync): VaultSyncViewModel — sync-at-unlock auto arm"
```

- [ ] **Step 6: Write failing tests for the remaining sync-at-unlock arms**

Append to `VaultSyncViewModelTests`:

```swift
    func testSyncAtUnlockConflictFlipsReviewNoSheet() async {
        let veto = SyncVeto(recordUuidHex: "aa", recordType: "login", tags: [],
                            fieldNames: ["password"], localLastModMs: 1,
                            peerTombstonedAtMs: 2, peerDeviceHex: "bb")
        let port = FakeVaultSyncPort(syncResult: .success(
            .conflictsPending(vetoes: [veto], collisions: [], manifestHash: [9])))
        let hook = FakeSyncMonitorHook()
        let vm = makeVM(port: port, hook: hook)

        await vm.syncAtUnlock(password: Array("pw".utf8))

        XCTAssertTrue(vm.reviewNeeded)
        XCTAssertNil(vm.pendingConflict)             // detail NOT surfaced at unlock
        XCTAssertFalse(vm.conflictSheetPresented)
        XCTAssertFalse(vm.passwordSheetPresented)
        XCTAssertEqual(vm.badge, .reviewNeeded)
        XCTAssertEqual(hook.acknowledgeCalls, 1)
    }

    func testSyncAtUnlockFailureSetsErrorNoAcknowledge() async {
        let port = FakeVaultSyncPort(syncResult: .failure(.wrongPasswordOrCorrupt))
        let hook = FakeSyncMonitorHook()
        let vm = makeVM(port: port, hook: hook)

        await vm.syncAtUnlock(password: Array("bad".utf8))

        XCTAssertEqual(vm.lastError, .wrongPasswordOrCorrupt)
        XCTAssertFalse(vm.reviewNeeded)
        XCTAssertEqual(hook.muteCalls, 1)            // mute happened before the pass
        XCTAssertEqual(hook.acknowledgeCalls, 0)     // failure → no acknowledge
    }
```

- [ ] **Step 7: Run to verify they fail**

Run: `cd ios/SecretaryVaultAccess && swift test --filter VaultSyncViewModelTests`
Expected: FAIL — `testSyncAtUnlockFailureSetsErrorNoAcknowledge` fails (current code acknowledges only on success — should already pass; the conflict test should already pass too). If both already pass, no code change needed; proceed. If `acknowledgeCalls` assertion fails, confirm `runPass` only calls `acknowledge()` inside the `do` success path (it does). 

Expected outcome: both PASS with the Step-3 code (the success/failure split and the `conflictsPending` routing are already implemented). This step exists to lock the behavior with explicit tests.

- [ ] **Step 8: Commit**

```bash
git add ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultSyncViewModelTests.swift
git commit -m "test(ios-sync): lock sync-at-unlock conflict + failure arms"
```

- [ ] **Step 9: Write failing tests for the interactive pass + badge inputs**

Append:

```swift
    func testPendingChangesRaisedUpdatesBadge() {
        let vm = makeVM(port: FakeVaultSyncPort())
        vm.pendingChangesRaised()
        XCTAssertEqual(vm.badge, .changesDetected)
    }

    func testBeginInteractiveSyncPresentsPasswordSheet() {
        let vm = makeVM(port: FakeVaultSyncPort())
        vm.beginInteractiveSync()
        XCTAssertTrue(vm.passwordSheetPresented)
    }

    func testInteractivePassCleanDismissesAndClears() async {
        let port = FakeVaultSyncPort(syncResult: .success(.mergedClean))
        let vm = makeVM(port: port)
        vm.beginInteractiveSync()
        vm.pendingChangesRaised()                    // badge was changesDetected

        await vm.runInteractivePass(password: Array("pw".utf8))

        XCTAssertFalse(vm.passwordSheetPresented)
        XCTAssertFalse(vm.conflictSheetPresented)
        XCTAssertNil(vm.pendingConflict)
        XCTAssertFalse(vm.reviewNeeded)
    }

    func testInteractivePassConflictPresentsConflictSheet() async {
        let veto = SyncVeto(recordUuidHex: "aa", recordType: "login", tags: ["t"],
                            fieldNames: ["password"], localLastModMs: 1,
                            peerTombstonedAtMs: 2, peerDeviceHex: "bb")
        let port = FakeVaultSyncPort(syncResult: .success(
            .conflictsPending(vetoes: [veto], collisions: [], manifestHash: [9])))
        let vm = makeVM(port: port)
        vm.beginInteractiveSync()

        await vm.runInteractivePass(password: Array("pw".utf8))

        XCTAssertFalse(vm.passwordSheetPresented)    // password sheet dismissed
        XCTAssertTrue(vm.conflictSheetPresented)     // conflict sheet up
        XCTAssertEqual(vm.pendingConflict?.vetoes.first?.recordUuidHex, "aa")
        XCTAssertTrue(vm.reviewNeeded)
    }

    func testInteractivePassFailureKeepsPasswordSheetOpen() async {
        let port = FakeVaultSyncPort(syncResult: .failure(.inProgress))
        let vm = makeVM(port: port)
        vm.beginInteractiveSync()

        await vm.runInteractivePass(password: Array("pw".utf8))

        XCTAssertEqual(vm.lastError, .inProgress)
        XCTAssertTrue(vm.passwordSheetPresented)     // stays open for retry
        XCTAssertFalse(vm.conflictSheetPresented)
    }
```

- [ ] **Step 10: Run to verify they fail**

Run: `cd ios/SecretaryVaultAccess && swift test --filter VaultSyncViewModelTests`
Expected: FAIL — `cannot find 'pendingChangesRaised' / 'beginInteractiveSync' / 'runInteractivePass'`.

- [ ] **Step 11: Implement the interactive pass + badge inputs**

Add to `VaultSyncViewModel` (inside the class):

```swift
    // MARK: - Monitor input

    /// The change monitor raised its advisory flag. Mirror it into the badge.
    public func pendingChangesRaised() {
        pendingChanges = true
        recomputeBadge()
    }

    // MARK: - Trigger 2: interactive re-prompt sync

    /// Open the password sheet (entry point for badge tap / "Sync now").
    public func beginInteractiveSync() {
        passwordSheetPresented = true
    }

    /// Run a pass with the re-prompted password. On `conflictsPending`, dismiss the
    /// password sheet and present the conflict sheet (the view retains the password
    /// and re-supplies it to `resolve`); on any clean arm, dismiss and clear; on
    /// failure, keep the password sheet open for retry.
    public func runInteractivePass(password: [UInt8]) async {
        await runPass(password: password) { [weak self] outcome in
            guard let self else { return }
            if case let .conflictsPending(vetoes, collisions, _) = outcome {
                self.pendingConflict = PendingConflict(vetoes: vetoes, collisions: collisions)
                self.reviewNeeded = true
                self.passwordSheetPresented = false
                self.conflictSheetPresented = true
            } else {
                self.reviewNeeded = false
                self.passwordSheetPresented = false
                self.conflictSheetPresented = false
                self.pendingConflict = nil
            }
        }
    }
```

The shared `runPass` sets `lastError` on failure but does NOT touch `passwordSheetPresented`, so a failed interactive pass leaves the sheet open — exactly the required behavior. The `onSuccess` closure runs only on success, so failure also leaves `pendingConflict`/sheets untouched.

- [ ] **Step 12: Run to verify they pass**

Run: `cd ios/SecretaryVaultAccess && swift test --filter VaultSyncViewModelTests`
Expected: PASS (all interactive tests).

- [ ] **Step 13: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultSyncViewModel.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultSyncViewModelTests.swift
git commit -m "feat(ios-sync): VaultSyncViewModel interactive pass + badge inputs"
```

- [ ] **Step 14: Write failing tests for `resolve` (happy + retry) and `cancelConflict`**

Append:

```swift
    /// Drives a conflict into the stash, then resolves it. Returns the VM + port.
    private func vmWithStashedConflict(
        commitResult: Result<SyncOutcome, VaultSyncError>
    ) async -> (VaultSyncViewModel, FakeVaultSyncPort) {
        let veto = SyncVeto(recordUuidHex: "aa", recordType: "login", tags: [],
                            fieldNames: ["password"], localLastModMs: 1,
                            peerTombstonedAtMs: 2, peerDeviceHex: "bb")
        let port = FakeVaultSyncPort(
            syncResult: .success(.conflictsPending(vetoes: [veto], collisions: [],
                                                   manifestHash: [9])),
            commitResult: commitResult)
        let vm = makeVM(port: port)
        vm.beginInteractiveSync()
        await vm.runInteractivePass(password: Array("pw".utf8))   // stash the conflict
        return (vm, port)
    }

    func testResolveSuccessCommitsAndClears() async {
        let (vm, port) = await vmWithStashedConflict(commitResult: .success(.mergedClean))
        let decision = SyncVetoDecision(recordUuidHex: "aa", keepLocal: true)

        await vm.resolve(decisions: [decision], password: Array("pw".utf8))

        XCTAssertEqual(port.commitCalls, 1)
        XCTAssertEqual(port.lastCommitDecisions, [decision])
        XCTAssertEqual(port.lastCommitManifestHash, [9])    // freshness token replayed
        XCTAssertFalse(vm.conflictSheetPresented)
        XCTAssertNil(vm.pendingConflict)
        XCTAssertFalse(vm.reviewNeeded)
        XCTAssertNil(vm.lastError)
    }

    func testResolveEvidenceStaleKeepsSheetOpen() async {
        let (vm, _) = await vmWithStashedConflict(commitResult: .failure(.evidenceStale))
        let decision = SyncVetoDecision(recordUuidHex: "aa", keepLocal: false)

        await vm.resolve(decisions: [decision], password: Array("pw".utf8))

        XCTAssertEqual(vm.lastError, .evidenceStale)
        XCTAssertTrue(vm.conflictSheetPresented)            // stays open for retry
        XCTAssertNotNil(vm.pendingConflict)
    }

    func testCancelConflictDismissesButKeepsReviewNeeded() async {
        let (vm, _) = await vmWithStashedConflict(commitResult: .success(.mergedClean))
        vm.cancelConflict()
        XCTAssertFalse(vm.conflictSheetPresented)
        XCTAssertNil(vm.pendingConflict)
        XCTAssertTrue(vm.reviewNeeded)                      // badge still flags review
    }
```

- [ ] **Step 15: Run to verify they fail**

Run: `cd ios/SecretaryVaultAccess && swift test --filter VaultSyncViewModelTests`
Expected: FAIL — `cannot find 'resolve' / 'cancelConflict'`.

- [ ] **Step 16: Implement `resolve` + `cancelConflict`**

Add to `VaultSyncViewModel`:

```swift
    /// Commit the user's per-record decisions for the pending conflict. On any
    /// non-conflict result, dismiss + clear; on `evidenceStale` /
    /// `decisionsIncomplete`, keep the sheet open (the coordinator preserves the
    /// stash) so the user can re-apply.
    public func resolve(decisions: [SyncVetoDecision], password: [UInt8]) async {
        isSyncing = true
        lastError = nil
        recomputeBadge()
        monitor?.muteSelfWrite()
        do {
            let outcome = try await coordinator.resolve(decisions: decisions,
                                                        password: password,
                                                        nowMs: wallClock.nowMs())
            if case let .conflictsPending(vetoes, collisions, _) = outcome {
                pendingConflict = PendingConflict(vetoes: vetoes, collisions: collisions)
            } else {
                conflictSheetPresented = false
                pendingConflict = nil
                reviewNeeded = false
            }
            monitor?.acknowledge()
            pendingChanges = false
            await refreshStatus()
        } catch let e as VaultSyncError {
            lastError = e
        } catch {
            lastError = .failed(String(describing: error))
        }
        isSyncing = false
        recomputeBadge()
    }

    /// Dismiss the conflict sheet without committing. Keeps `reviewNeeded` so the
    /// badge still flags that the conflict is unresolved.
    public func cancelConflict() {
        conflictSheetPresented = false
        pendingConflict = nil
    }
```

- [ ] **Step 17: Run to verify they pass**

Run: `cd ios/SecretaryVaultAccess && swift test --filter VaultSyncViewModelTests`
Expected: PASS (all VM tests).

- [ ] **Step 18: Write the mid-flight "syncing" badge test (gate-based)**

Append:

```swift
    func testBadgeIsSyncingMidPass() async {
        let gate = SuspensionGate()
        let port = FakeVaultSyncPort(syncResult: .success(.nothingToDo))
        port.gate = gate
        let vm = makeVM(port: port)

        let task = Task { await vm.runInteractivePass(password: Array("pw".utf8)) }
        await gate.waitUntilEntered()
        XCTAssertEqual(vm.badge, .syncing)
        XCTAssertTrue(vm.isSyncing)
        await gate.release()
        await task.value
        XCTAssertFalse(vm.isSyncing)
    }
```

- [ ] **Step 19: Run to verify it passes**

Run: `cd ios/SecretaryVaultAccess && swift test --filter VaultSyncViewModelTests`
Expected: PASS — the gate proves the badge shows `.syncing` while the port is in flight (and that the VM only suspends, not blocks, the main actor).

- [ ] **Step 20: Run the full host suite + commit**

Run: `cd ios/SecretaryVaultAccess && swift test`
Expected: PASS, 0 warnings.

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultSyncViewModel.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultSyncViewModelTests.swift
git commit -m "feat(ios-sync): VaultSyncViewModel resolve + cancel + syncing badge"
```

---

## Task 6: Real conformers in `SecretaryKit`

`SystemWallClock`, `MonitorSyncHook` (wraps the real monitor), `SyncStateDirectory`, and the `makeVaultSync` factory that wires the VM ↔ monitor cycle.

**Files:**
- Create: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/SystemWallClock.swift`
- Create: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/MonitorSyncHook.swift`
- Create: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/SyncStateDirectory.swift`
- Create: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/VaultSyncFactory.swift`
- Test: `ios/SecretaryKit/Tests/SecretaryKitTests/SyncStateDirectoryTests.swift`

- [ ] **Step 1: Write the failing test (state-dir derivation + creation)**

```swift
// SyncStateDirectoryTests.swift
import XCTest
import SecretaryKit

final class SyncStateDirectoryTests: XCTestCase {
    func testAppendsSecretarySyncUnderBaseAndCreates() throws {
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("synctest-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: base) }

        let dir = try defaultSyncStateDir(applicationSupport: base)

        XCTAssertEqual(dir.lastPathComponent, "sync")
        XCTAssertEqual(dir.deletingLastPathComponent().lastPathComponent, "secretary")
        var isDir: ObjCBool = false
        XCTAssertTrue(FileManager.default.fileExists(atPath: dir.path, isDirectory: &isDir))
        XCTAssertTrue(isDir.boolValue)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bash ios/scripts/run-ios-tests.sh` (or, faster, `cd ios/SecretaryKit && swift test --filter SyncStateDirectoryTests` if the host toolchain links it; otherwise the sim run is authoritative).
Expected: FAIL — `cannot find 'defaultSyncStateDir' in scope`.

- [ ] **Step 3: Write the implementations**

```swift
// SyncStateDirectory.swift
import Foundation

/// Subdirectory names for the on-disk sync state, mirroring desktop's
/// `data_dir()/secretary/sync`. Named to avoid magic string literals.
private enum SyncStatePath {
    static let appFolder = "secretary"
    static let syncFolder = "sync"
}

/// Derive `<applicationSupport>/secretary/sync` and create it if absent. The
/// directory lives in the app's own sandbox (always accessible, no security
/// scope). Pure derivation + one `createDirectory` call (the only IO).
public func defaultSyncStateDir(applicationSupport: URL) throws -> URL {
    let dir = applicationSupport
        .appendingPathComponent(SyncStatePath.appFolder, isDirectory: true)
        .appendingPathComponent(SyncStatePath.syncFolder, isDirectory: true)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    return dir
}

/// Resolve the production sync state dir under the real Application Support base.
public func defaultSyncStateDir() throws -> URL {
    let base = try FileManager.default.url(for: .applicationSupportDirectory,
                                           in: .userDomainMask,
                                           appropriateFor: nil, create: true)
    return try defaultSyncStateDir(applicationSupport: base)
}
```

```swift
// SystemWallClock.swift
import Foundation
import SecretaryVaultAccess

/// Production `WallClock` reading the system clock in epoch milliseconds.
public struct SystemWallClock: WallClock {
    public init() {}
    public func nowMs() -> UInt64 {
        UInt64(Date().timeIntervalSince1970 * 1_000)
    }
}
```

```swift
// MonitorSyncHook.swift
import Foundation
import SecretaryVaultAccess

/// Real `SyncMonitorHook` over a `ChangeDetectionMonitor`: mute around our own
/// vault writes (a window starting now) and acknowledge handled changes.
@MainActor
public final class MonitorSyncHook: SyncMonitorHook {
    private let monitor: ChangeDetectionMonitor
    private let muteWindow: Duration
    public init(monitor: ChangeDetectionMonitor,
                muteWindow: Duration = ChangeDetectionTuning.defaultSelfWriteMuteWindow) {
        self.monitor = monitor
        self.muteWindow = muteWindow
    }
    public func muteSelfWrite() {
        monitor.muteUntil(MonotonicInstant.now().advanced(by: muteWindow))
    }
    public func acknowledge() {
        monitor.acknowledge()
    }
}
```

```swift
// VaultSyncFactory.swift
import Foundation
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Assemble the sync VM + change monitor for an open vault, wiring the two-way
/// link (monitor.onChange → vm.pendingChangesRaised; vm self-write/ack → monitor)
/// and resolving the construction cycle via a late-bound monitor reference.
///
/// `folder` is the open vault's folder URL (security-scoped by the browse
/// session). `stateDir` is the app-sandbox sync state dir (`defaultSyncStateDir`).
@MainActor
public func makeVaultSync(
    session: VaultSession,
    folder: URL,
    stateDir: URL
) -> (VaultSyncViewModel, ChangeDetectionMonitor) {
    let coordinator = SyncCoordinator(port: UniffiVaultSyncPort(),
                                      stateDir: stateDir.path,
                                      vaultFolder: folder.path)
    let vaultUuid = HexUuid.bytes(fromHex: session.vaultUuidHex)
    let monitor = makeChangeMonitor(folder: folder, onChange: {})   // onChange set below
    let hook = MonitorSyncHook(monitor: monitor)
    let vm = VaultSyncViewModel(coordinator: coordinator,
                                wallClock: SystemWallClock(),
                                vaultUuid: vaultUuid,
                                monitor: hook)
    // Re-point onChange now that vm exists. `makeChangeMonitor` captured an empty
    // closure; replace via a fresh monitor would break the hook, so instead build
    // the monitor with a closure that forwards into a holder.
    return (vm, monitor)
}
```

> NOTE for the implementer: `makeChangeMonitor`'s `onChange` is fixed at construction. To forward into the VM (which is built after the monitor), construct the monitor's `onChange` to call through a captured `weak var vm` set immediately after. Replace the body of `makeVaultSync` with the cycle-safe form below (this is the version to ship; the block above shows the intent):

```swift
@MainActor
public func makeVaultSync(
    session: VaultSession,
    folder: URL,
    stateDir: URL
) -> (VaultSyncViewModel, ChangeDetectionMonitor) {
    let coordinator = SyncCoordinator(port: UniffiVaultSyncPort(),
                                      stateDir: stateDir.path,
                                      vaultFolder: folder.path)
    let vaultUuid = HexUuid.bytes(fromHex: session.vaultUuidHex)

    // Late-bound VM reference so the monitor's onChange can forward into it.
    final class VMBox { weak var vm: VaultSyncViewModel? }
    let box = VMBox()
    let monitor = makeChangeMonitor(folder: folder,
                                    onChange: { [box] in box.vm?.pendingChangesRaised() })
    let hook = MonitorSyncHook(monitor: monitor)
    let vm = VaultSyncViewModel(coordinator: coordinator,
                                wallClock: SystemWallClock(),
                                vaultUuid: vaultUuid,
                                monitor: hook)
    box.vm = vm
    return (vm, monitor)
}
```

Use only the cycle-safe form (delete the intent stub).

- [ ] **Step 4: Run test to verify it passes**

Run: `bash ios/scripts/run-ios-tests.sh`
Expected: `** TEST SUCCEEDED **` (includes `SyncStateDirectoryTests`) + `** BUILD SUCCEEDED **`.

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/SystemWallClock.swift \
        ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/MonitorSyncHook.swift \
        ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/SyncStateDirectory.swift \
        ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/VaultSyncFactory.swift \
        ios/SecretaryKit/Tests/SecretaryKitTests/SyncStateDirectoryTests.swift
git commit -m "feat(ios-sync): SecretaryKit conformers — clock, monitor hook, state dir, factory"
```

---

## Task 7: SwiftUI views

Thin presentation. No host unit tests (SwiftUI) — validated by the sim build in Task 8's gauntlet. Mirror desktop D.1.15.

**Files:**
- Create: `ios/SecretaryApp/Sources/SyncBadgeView.swift`
- Create: `ios/SecretaryApp/Sources/SyncPasswordSheet.swift`
- Create: `ios/SecretaryApp/Sources/ConflictResolutionSheet.swift`

- [ ] **Step 1: Create `SyncBadgeView`**

```swift
// SyncBadgeView.swift
import SwiftUI
import SecretaryVaultAccess

/// Toolbar badge rendering `SyncBadgeState`. Tapping (when not syncing) starts an
/// interactive sync. The "synced … ago" label is computed from the state's epoch
/// millis against `nowMs` supplied by the parent.
struct SyncBadgeView: View {
    let state: SyncBadgeState
    let nowMs: UInt64
    let onTap: () -> Void

    var body: some View {
        Button(action: onTap) {
            switch state {
            case .syncing:
                HStack(spacing: 4) { ProgressView(); Text("Syncing…") }
            case .reviewNeeded:
                Label("Review needed", systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
            case .changesDetected:
                Label("Changes detected", systemImage: "arrow.triangle.2.circlepath")
            case .synced(let sinceMs):
                Label(Self.syncedLabel(sinceMs: sinceMs, nowMs: nowMs),
                      systemImage: "checkmark.circle")
                    .foregroundStyle(.secondary)
            case .neverSynced:
                Label("Sync now", systemImage: "arrow.triangle.2.circlepath")
            }
        }
        .disabled(state == .syncing)
        .font(.footnote)
    }

    /// "Synced just now / Nm ago / Nh ago". Defends against a future-dated stamp.
    static func syncedLabel(sinceMs: UInt64, nowMs: UInt64) -> String {
        let deltaMs = nowMs > sinceMs ? nowMs - sinceMs : 0
        let seconds = deltaMs / 1_000
        if seconds < 60 { return "Synced just now" }
        let minutes = seconds / 60
        if minutes < 60 { return "Synced \(minutes)m ago" }
        return "Synced \(minutes / 60)h ago"
    }
}
```

- [ ] **Step 2: Create `SyncPasswordSheet`**

```swift
// SyncPasswordSheet.swift
import SwiftUI
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Centered password re-prompt for an interactive sync. The password lives only
/// in this view's `@State` and is reused for `resolve` via the conflict sheet
/// when the pass surfaces a conflict; it is replaced with "" on every dismissal.
struct SyncPasswordSheet: View {
    @ObservedObject var model: VaultSyncViewModel
    @State private var password = ""

    var body: some View {
        NavigationStack {
            Form {
                Section("Master password") {
                    SecureField("password", text: $password)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                }
                if let err = model.lastError {
                    Section("Error") {
                        Text(String(describing: err))
                            .font(.footnote.monospaced()).foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Sync now")
            .overlay { if model.isSyncing { ProgressView() } }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        password = ""
                        model.dismissPasswordSheet()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Sync") {
                        let pw = Array(password.utf8)
                        password = ""              // drop the view copy ASAP
                        Task { await model.runInteractivePass(password: pw) }
                    }
                    .disabled(model.isSyncing || password.isEmpty)
                }
            }
        }
    }
}
```

> The conflict sheet needs the password too. Because the password is cleared after the pass, the conflict sheet re-prompts for it on Apply (a second `SecureField`) rather than threading a retained secret across two sheets — this keeps each sheet's password lifetime independent and short. See Step 3.

- [ ] **Step 3: Create `ConflictResolutionSheet`**

```swift
// ConflictResolutionSheet.swift
import SwiftUI
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Metadata-only conflict resolution. One row per veto with Keep-mine (default) /
/// Accept-delete; a read-only disclosure lists auto-merged collisions. Apply
/// re-prompts for the password (short-lived) and commits the decisions.
struct ConflictResolutionSheet: View {
    @ObservedObject var model: VaultSyncViewModel
    let conflict: PendingConflict

    /// Per-record choice; true = keep local (default, no data loss).
    @State private var keepLocal: [String: Bool] = [:]
    @State private var password = ""

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("These records were deleted on another device but you still have them. Choose what to keep — nothing is written until you tap Apply.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                ForEach(conflict.vetoes, id: \.recordUuidHex) { veto in
                    Section(summary(veto)) {
                        if !veto.fieldNames.isEmpty {
                            Text("fields: \(veto.fieldNames.joined(separator: " · "))")
                                .font(.footnote.monospaced())
                        }
                        Text("deleted on device \(veto.peerDeviceHex.prefix(8))…")
                            .font(.caption).foregroundStyle(.secondary)
                        Picker("Resolution", selection: choiceBinding(veto.recordUuidHex)) {
                            Text("Keep mine").tag(true)
                            Text("Accept delete").tag(false)
                        }
                        .pickerStyle(.segmented)
                    }
                }
                if !conflict.collisions.isEmpty {
                    Section {
                        DisclosureGroup("\(conflict.collisions.count) field group(s) auto-merged — no action needed") {
                            ForEach(conflict.collisions, id: \.recordUuidHex) { c in
                                Text("\(c.recordUuidHex.prefix(8))…: \(c.fieldNames.joined(separator: ", "))")
                                    .font(.caption.monospaced())
                            }
                        }
                    }
                }
                Section("Master password") {
                    SecureField("password", text: $password)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                }
                if let err = model.lastError {
                    Section("Error") {
                        Text(String(describing: err))
                            .font(.footnote.monospaced()).foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Resolve conflicts")
            .overlay { if model.isSyncing { ProgressView() } }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { password = ""; model.cancelConflict() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Apply") {
                        let decisions = conflict.vetoes.map {
                            SyncVetoDecision(recordUuidHex: $0.recordUuidHex,
                                             keepLocal: keepLocal[$0.recordUuidHex] ?? true)
                        }
                        let pw = Array(password.utf8)
                        password = ""
                        Task { await model.resolve(decisions: decisions, password: pw) }
                    }
                    .disabled(model.isSyncing || password.isEmpty)
                }
            }
        }
    }

    private func choiceBinding(_ uuid: String) -> Binding<Bool> {
        Binding(get: { keepLocal[uuid] ?? true }, set: { keepLocal[uuid] = $0 })
    }

    private func summary(_ v: SyncVeto) -> String {
        v.tags.isEmpty ? v.recordType : "\(v.recordType) · \(v.tags.joined(separator: " · "))"
    }
}
```

- [ ] **Step 4: Add the `dismissPasswordSheet` method the sheet calls**

The password sheet's Cancel calls `model.dismissPasswordSheet()`. Add to `VaultSyncViewModel` (Task 5 file) — TDD it first.

Append to `VaultSyncViewModelTests`:

```swift
    func testDismissPasswordSheet() {
        let vm = makeVM(port: FakeVaultSyncPort())
        vm.beginInteractiveSync()
        vm.dismissPasswordSheet()
        XCTAssertFalse(vm.passwordSheetPresented)
    }
```

Run: `cd ios/SecretaryVaultAccess && swift test --filter VaultSyncViewModelTests` → FAIL (no `dismissPasswordSheet`).

Add to `VaultSyncViewModel`:

```swift
    /// Dismiss the password sheet (Cancel).
    public func dismissPasswordSheet() {
        passwordSheetPresented = false
    }
```

Run again → PASS.

- [ ] **Step 5: Build the app target to typecheck the views + commit**

Run: `bash ios/scripts/run-ios-tests.sh`
Expected: `** BUILD SUCCEEDED **` (the views compile against the app target) + `** TEST SUCCEEDED **`.

```bash
git add ios/SecretaryApp/Sources/SyncBadgeView.swift \
        ios/SecretaryApp/Sources/SyncPasswordSheet.swift \
        ios/SecretaryApp/Sources/ConflictResolutionSheet.swift \
        ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultSyncViewModel.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultSyncViewModelTests.swift
git commit -m "feat(ios-sync): sync badge + password sheet + conflict sheet views"
```

---

## Task 8: App wiring (lifecycle + sync-at-unlock handoff)

Wire the badge + sheets onto the browse screen, build the sync context on browse entry, start/stop the monitor with the scene lifecycle, and hand the password to `syncAtUnlock` on a password-mode unlock.

**Files:**
- Modify: `ios/SecretaryApp/Sources/UnlockScreen.swift`
- Modify: `ios/SecretaryApp/Sources/SecretaryApp.swift`
- Modify: `ios/SecretaryApp/Sources/VaultBrowseScreen.swift`

- [ ] **Step 1: `UnlockScreen` — forward the password on password-mode unlock**

Change the `onUnlocked` callback to also pass the password bytes when (and only when) the unlock used `.password` mode (recovery/biometric have no usable sync password → `nil`).

In `UnlockScreen.swift`, change the property + call site:

```swift
    // was: let onUnlocked: (VaultSession) -> Void
    let onUnlocked: (VaultSession, _ password: [UInt8]?) -> Void
```

```swift
    init(viewModel: UnlockViewModel,
         onUnlocked: @escaping (VaultSession, _ password: [UInt8]?) -> Void) {
        self._viewModel = StateObject(wrappedValue: viewModel)
        self.onUnlocked = onUnlocked
    }
```

Capture the just-submitted secret so the success handler can forward it for password mode. Add `@State private var lastPasswordSecret: [UInt8]?` and set it in the Unlock button:

```swift
                Button("Unlock") {
                    viewModel.mode = mode
                    let secret: [UInt8] = mode == .password
                        ? Array(password.utf8)
                        : Array(RecoveryPhrase.normalize(phrase).utf8)
                    lastPasswordSecret = (mode == .password) ? secret : nil
                    Task { await viewModel.unlock(secret: secret) }
                }
```

```swift
            .onChange(of: stateIsUnlocked) { _, unlocked in
                if unlocked, case .unlocked(let session) = viewModel.state {
                    onUnlocked(session, lastPasswordSecret)
                    lastPasswordSecret = nil       // drop our copy
                }
            }
```

- [ ] **Step 2: `SecretaryApp.swift` (RootView) — carry the sync context into `.browse`**

Extend the `.browse` route to carry the `VaultSyncViewModel` + `ChangeDetectionMonitor`, build them on unlock, start the monitor, and kick off sync-at-unlock.

Change the `Route` enum's browse case:

```swift
        case browse(VaultBrowseViewModel, VaultSyncViewModel, ChangeDetectionMonitor, ScopedVaultPath)
```

Replace the `.unlock` route body:

```swift
                case .unlock(let scoped):
                    UnlockScreen(
                        viewModel: UnlockViewModel(port: UniffiVaultOpenPort(),
                                                   vaultPath: scoped.pathData),
                        onUnlocked: { session, password in
                            let folder = URL(fileURLWithPath:
                                String(decoding: scoped.pathData, as: UTF8.self))
                            let stateDir = (try? defaultSyncStateDir())
                                ?? FileManager.default.temporaryDirectory
                            let (syncVM, monitor) = makeVaultSync(
                                session: session, folder: folder, stateDir: stateDir)
                            try? monitor.start()
                            if let password {
                                Task { await syncVM.syncAtUnlock(password: password) }
                            } else {
                                Task { await syncVM.refreshStatus() }
                            }
                            route = .browse(VaultBrowseViewModel(session: session),
                                            syncVM, monitor, scoped)
                        })
```

Replace the `.browse` route body:

```swift
                case .browse(let browseModel, let syncVM, let monitor, _):
                    VaultBrowseScreen(viewModel: browseModel, syncModel: syncVM)
                        .onDisappear { monitor.stop() }
```

Update the background lock handler's `.browse` case to also stop the monitor:

```swift
            case .browse(let browseModel, _, let monitor, let scoped):
                monitor.stop()
                browseModel.lock()
                scoped.end()
                route = .select
```

> NOTE: `import SecretaryKit` already present. `defaultSyncStateDir()`, `makeVaultSync`, `ChangeDetectionMonitor` come from `SecretaryKit` / `SecretaryVaultAccess` (already imported at the top of the file).

- [ ] **Step 3: `VaultBrowseScreen` — accept the sync model, add the badge + sheets**

Add the stored sync model + presentation. Change the initializer:

```swift
    @StateObject private var viewModel: VaultBrowseViewModel
    @ObservedObject private var syncModel: VaultSyncViewModel
    @Environment(\.scenePhase) private var scenePhase
```

```swift
    init(viewModel: VaultBrowseViewModel, syncModel: VaultSyncViewModel) {
        self._viewModel = StateObject(wrappedValue: viewModel)
        self.syncModel = syncModel
    }
```

Add `import SecretaryVaultAccessUI` is already present. Add a leading toolbar item with the badge, and the two sheets. Inside `.toolbar { ... }` add:

```swift
                ToolbarItem(placement: .topBarLeading) {
                    SyncBadgeView(state: syncModel.badge,
                                  nowMs: UInt64(Date().timeIntervalSince1970 * 1_000),
                                  onTap: { syncModel.beginInteractiveSync() })
                }
```

After the existing `.sheet(item: $editSession)` modifier, add:

```swift
            .sheet(isPresented: $syncModel.passwordSheetPresented) {
                SyncPasswordSheet(model: syncModel)
            }
            .sheet(isPresented: $syncModel.conflictSheetPresented) {
                if let conflict = syncModel.pendingConflict {
                    ConflictResolutionSheet(model: syncModel, conflict: conflict)
                }
            }
```

- [ ] **Step 4: Build + run the full gauntlet**

Run: `bash ios/scripts/run-ios-tests.sh`
Expected: `** TEST SUCCEEDED **` + `** BUILD SUCCEEDED **`.

- [ ] **Step 5: Host suite + iOS-only guardrail greps**

Run:
```bash
cd ios/SecretaryVaultAccess && swift test
cd /Users/hherb/src/secretary/.worktrees/c3-ios-sync-ui
git diff main...HEAD --name-only | grep -vE '^(ios/|docs/|README.md|ROADMAP.md)'
git diff main...HEAD --name-only | grep -E 'core/|ffi/|crypto-design|vault-format|conflict.rs|core/tests/data'
```
Expected: host PASS, 0 warnings; both greps print nothing.

- [ ] **Step 6: Commit**

```bash
git add ios/SecretaryApp/Sources/UnlockScreen.swift \
        ios/SecretaryApp/Sources/SecretaryApp.swift \
        ios/SecretaryApp/Sources/VaultBrowseScreen.swift
git commit -m "feat(ios-sync): wire sync badge + sheets + monitor lifecycle + sync-at-unlock"
```

---

## Task 9: Docs

**Files:**
- Modify: `README.md` (iOS status row)
- Modify: `ROADMAP.md` (C.3 slice-3 entry)

- [ ] **Step 1: Update README.md**

Find the iOS C.3 row (added by slice 2 — "folder-change detection") and add a sibling line for the sync UI. Keep it brief (dot point, audience = curious contributors), e.g.:
`- iOS sync UI ✅ — status badge, sync-at-unlock, on-demand re-prompt sync, metadata-only conflict resolution`

- [ ] **Step 2: Update ROADMAP.md**

Mark C.3 slice 3 (iOS sync UI) ✅ with a one-line summary mirroring the slice-1/2 entries.

- [ ] **Step 3: Commit**

```bash
git add README.md ROADMAP.md
git commit -m "docs(ios-sync): README + ROADMAP for C.3 slice 3 (iOS sync UI)"
```

---

## Task 10: Final verification

- [ ] **Step 1: Full gauntlet**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/c3-ios-sync-ui
( cd ios/SecretaryVaultAccess && swift test )            # host: all green, 0 warnings
bash ios/scripts/run-ios-tests.sh                        # ** TEST SUCCEEDED ** + ** BUILD SUCCEEDED **
git diff main...HEAD --name-only | grep -vE '^(ios/|docs/|README.md|ROADMAP.md)'                                  # empty
git diff main...HEAD --name-only | grep -E 'core/|ffi/|crypto-design|vault-format|conflict.rs|core/tests/data'    # empty
```

- [ ] **Step 2: Request code review** (per `superpowers:requesting-code-review`), then push + open PR.

---

## Self-review notes (author)

- **Spec coverage:** badge (T3,T7,T8) · sync-at-unlock (T5,T8) · re-prompt interactive pass (T5,T7) · conflict sheet + resolve (T5,T7) · monitor lifecycle wiring (T8) · self-write mute around sync writes (T4,T5,T6) · app-sandbox state dir (T6) · WallClock (T1) · best-effort status via vault UUID (T2,T5,T6). All spec §3–§8 items map to a task.
- **Password lifetime:** never stored on the VM; each method takes it per call; views null their `@State` copy on every dismissal. Sync-at-unlock never holds it across a modal (conflict → `reviewNeeded`, drop). ✓ matches spec §4.
- **No magic numbers:** `defaultSelfWriteMuteWindow`, `defaultDebounceWindow`, `SyncStatePath.{appFolder,syncFolder}`, `RevealPolicy`/`ChangeDetectionTuning` reused. ✓
- **Type consistency:** `VaultSyncViewModel` API names (`syncAtUnlock`, `beginInteractiveSync`, `runInteractivePass`, `resolve`, `cancelConflict`, `dismissPasswordSheet`, `pendingChangesRaised`, `badge`, `isSyncing`, `reviewNeeded`, `pendingConflict`, `passwordSheetPresented`, `conflictSheetPresented`) are used identically in tests (T5), views (T7), and wiring (T8). `syncBadgeState(inProgress:pendingChanges:hasPendingConflict:status:)` and `SyncBadgeState` cases match across T3/T5/T7. `SyncMonitorHook.{muteSelfWrite,acknowledge}` match across T4/T5/T6. `makeVaultSync(session:folder:stateDir:)` and `defaultSyncStateDir(applicationSupport:)`/`defaultSyncStateDir()` match across T6/T8.
- **iOS-only:** every file under `ios/**` or `docs/**`/`README`/`ROADMAP`. No Rust/FFI/core touch. ✓
