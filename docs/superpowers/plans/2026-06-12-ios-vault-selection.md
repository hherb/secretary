# iOS Vault Selection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the iOS app open a user-selected vault folder (system picker) and remember it across launches via a persisted security-scoped bookmark, replacing the hardcoded bundled demo vault + prefilled password.

**Architecture:** Approach A — a pure, FFI-free `VaultLocationStore` port + host-tested `VaultSelectionViewModel` in `SecretaryVaultAccess`; a Foundation `BookmarkVaultLocationStore` adapter in `SecretaryKit`; SwiftUI `.fileImporter` + `select → unlock → browse` routing in `SecretaryApp`. The security scope is held for the whole session (lazy block reads) via a single-owner `ScopedVaultPath` handle whose begin/end balance is unit-tested against a fake.

**Tech Stack:** Swift 5.9, SwiftUI, SPM, XCTest (host + simulator), uniffi FFI (unchanged), XcodeGen. No Rust / on-disk-format / FFI-surface change.

**Spec:** `docs/superpowers/specs/2026-06-12-ios-vault-selection-design.md`

**Working directory:** `/Users/hherb/src/secretary/.worktrees/ios-vault-selection` (branch `feature/ios-vault-selection`). Verify with `pwd && git branch --show-current` before any command.

---

## File Structure

**Pure package `ios/SecretaryVaultAccess/`:**
- Create `Sources/SecretaryVaultAccess/VaultLocation.swift` — value model (display name + opaque bookmark).
- Create `Sources/SecretaryVaultAccess/VaultSelectionError.swift` — typed selection-layer errors.
- Create `Sources/SecretaryVaultAccess/ScopedVaultPath.swift` — single-owner scoped-access handle, idempotent `end()`.
- Create `Sources/SecretaryVaultAccess/VaultLocationStore.swift` — the port protocol.
- Create `Sources/SecretaryVaultAccessTesting/FakeVaultLocationStore.swift` — in-memory store + start/stop counter.
- Create `Sources/SecretaryVaultAccessUI/VaultSelectionState.swift` — observable state enum.
- Create `Sources/SecretaryVaultAccessUI/VaultSelectionViewModel.swift` — `@MainActor` state machine.
- Create tests: `Tests/SecretaryVaultAccessTests/VaultLocationTests.swift`, `ScopedVaultPathTests.swift`, `FakeVaultLocationStoreTests.swift`; `Tests/SecretaryVaultAccessUITests/VaultSelectionViewModelTests.swift`.

**Real adapter `ios/SecretaryKit/`:**
- Create `Sources/SecretaryKit/VaultAccess/BookmarkVaultLocationStore.swift`.
- Create `Tests/SecretaryKitTests/BookmarkVaultLocationStoreTests.swift` (simulator round-trip + golden-vault open through the resolved path).

**App `ios/SecretaryApp/`:**
- Create `Sources/VaultSelectionScreen.swift`.
- Modify `Sources/SecretaryApp.swift` (RootView routing `select → unlock → browse`).
- Modify `Sources/UnlockScreen.swift` (delete the prefilled demo password).

**Docs:** `README.md`, `ROADMAP.md`, `ios/README.md`, and the handoff/symlink (final task).

No test-harness change: `ios/scripts/run-ios-tests.sh` already host-runs `SecretaryVaultAccess` (Tasks 1–4), simulator-runs `SecretaryKit` (Task 5), and builds the app (Task 6).

---

## Task 1: `VaultLocation` value model

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultLocation.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/VaultLocationTests.swift`

- [ ] **Step 1: Write the failing test**

```swift
// ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/VaultLocationTests.swift
import XCTest
import SecretaryVaultAccess

final class VaultLocationTests: XCTestCase {
    func testStoresDisplayNameAndBookmark() {
        let loc = VaultLocation(displayName: "MyVault", bookmark: Data([0x01, 0x02]))
        XCTAssertEqual(loc.displayName, "MyVault")
        XCTAssertEqual(loc.bookmark, Data([0x01, 0x02]))
    }

    func testEquatableByValue() {
        let a = VaultLocation(displayName: "V", bookmark: Data([0xAA]))
        let b = VaultLocation(displayName: "V", bookmark: Data([0xAA]))
        let c = VaultLocation(displayName: "V", bookmark: Data([0xBB]))
        XCTAssertEqual(a, b)
        XCTAssertNotEqual(a, c)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter VaultLocationTests`
Expected: FAIL — `cannot find 'VaultLocation' in scope`.

- [ ] **Step 3: Write minimal implementation**

```swift
// ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultLocation.swift
import Foundation

/// A remembered vault location: a human-readable `displayName` plus an opaque
/// security-scoped `bookmark` produced by the platform file picker. The bookmark
/// is NOT secret — it is a path-style token with no key material — so persisting
/// it (e.g. in `UserDefaults`) carries no secret-residue risk. No vault key or
/// credential ever flows through this type.
public struct VaultLocation: Equatable {
    public let displayName: String
    public let bookmark: Data

    public init(displayName: String, bookmark: Data) {
        self.displayName = displayName
        self.bookmark = bookmark
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ios/SecretaryVaultAccess && swift test --filter VaultLocationTests`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultLocation.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/VaultLocationTests.swift
git commit -m "$(cat <<'EOF'
feat(ios): VaultLocation value model for vault selection

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: `VaultSelectionError` + `ScopedVaultPath`

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultSelectionError.swift`
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/ScopedVaultPath.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/ScopedVaultPathTests.swift`

- [ ] **Step 1: Write the failing test**

```swift
// ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/ScopedVaultPathTests.swift
import XCTest
import SecretaryVaultAccess

final class ScopedVaultPathTests: XCTestCase {
    func testExposesPathData() {
        let scoped = ScopedVaultPath(pathData: Data("/vaults/v1".utf8), onEnd: {})
        XCTAssertEqual(scoped.pathData, Data("/vaults/v1".utf8))
    }

    func testEndReleasesExactlyOnce() {
        var releases = 0
        let scoped = ScopedVaultPath(pathData: Data(), onEnd: { releases += 1 })
        scoped.end()
        scoped.end() // idempotent — must not double-release
        XCTAssertEqual(releases, 1)
    }

    func testErrorIsEquatable() {
        XCTAssertEqual(VaultSelectionError.noVaultSelected, .noVaultSelected)
        XCTAssertEqual(VaultSelectionError.locationUnavailable("x"),
                       .locationUnavailable("x"))
        XCTAssertNotEqual(VaultSelectionError.locationUnavailable("x"),
                          .locationUnavailable("y"))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter ScopedVaultPathTests`
Expected: FAIL — `cannot find 'ScopedVaultPath' in scope`.

- [ ] **Step 3: Write minimal implementation**

```swift
// ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultSelectionError.swift
import Foundation

/// Typed failures from the vault-selection layer. Kept distinct from
/// `VaultAccessError` (which models opening/browsing a vault): selection failures
/// are about *locating* a vault, not credential checks, so there is no anti-oracle
/// conflation concern here.
///
/// There is deliberately NO `.accessDenied` case. On iOS,
/// `startAccessingSecurityScopedResource()` returning `false` is not a reliable
/// "denied" signal — it is also benign-false for in-sandbox paths (the demo vault,
/// test temp dirs) where access works anyway. So a genuine lack of access is not
/// swallowed here; it surfaces loudly downstream as the FFI's typed open error
/// (`VaultAccessError.folderInvalid` / `.wrongPasswordOrCorrupt`) when the open is
/// attempted. This preserves the project's no-silent-failure posture without
/// hard-failing the benign case.
public enum VaultSelectionError: Error, Equatable {
    /// `beginAccess` was called with no vault remembered.
    case noVaultSelected
    /// The persisted bookmark could not be resolved to a folder (vault moved/deleted).
    case locationUnavailable(String)
}
```

```swift
// ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/ScopedVaultPath.swift
import Foundation

/// A live, scoped handle to a vault folder. While this object is alive, the
/// underlying platform security scope is held open — which is required because
/// vault block reads are LAZY (they happen during browse, not just at open), so
/// the scope must span the whole session, not just the open call.
///
/// `ScopedVaultPath` is the single owner of one scope acquisition. `end()` releases
/// it exactly once (idempotent); the `onEnd` closure is dropped after the first call
/// so a double-`end()` (e.g. lock racing background) cannot double-release. The real
/// adapter injects `onEnd = { url.stopAccessingSecurityScopedResource() }`; the fake
/// injects a counter bump — so the begin/end balance is unit-testable.
public final class ScopedVaultPath {
    /// UTF-8 folder path for the FFI (`open_vault_with_password` / `…recovery`).
    public let pathData: Data
    private var onEnd: (() -> Void)?

    public init(pathData: Data, onEnd: @escaping () -> Void) {
        self.pathData = pathData
        self.onEnd = onEnd
    }

    /// Release the held scope. Idempotent: subsequent calls are no-ops.
    public func end() {
        onEnd?()
        onEnd = nil
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ios/SecretaryVaultAccess && swift test --filter ScopedVaultPathTests`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultSelectionError.swift \
        ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/ScopedVaultPath.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/ScopedVaultPathTests.swift
git commit -m "$(cat <<'EOF'
feat(ios): VaultSelectionError + idempotent ScopedVaultPath handle

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: `VaultLocationStore` port + `FakeVaultLocationStore`

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultLocationStore.swift`
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeVaultLocationStore.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/FakeVaultLocationStoreTests.swift`

- [ ] **Step 1: Write the failing test**

```swift
// ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/FakeVaultLocationStoreTests.swift
import XCTest
import SecretaryVaultAccess
import SecretaryVaultAccessTesting

final class FakeVaultLocationStoreTests: XCTestCase {
    func testPersistLoadClearRoundTrip() {
        let store = FakeVaultLocationStore()
        XCTAssertNil(store.load())
        let loc = VaultLocation(displayName: "V", bookmark: Data([0x01]))
        store.persist(loc)
        XCTAssertEqual(store.load(), loc)
        store.clear()
        XCTAssertNil(store.load())
    }

    func testBeginAccessCountsStartAndScopedEndCountsStop() throws {
        let store = FakeVaultLocationStore(
            stored: VaultLocation(displayName: "V", bookmark: Data([0x01])),
            pathDataToReturn: Data("/fake/v".utf8))
        let scoped = try store.beginAccess(store.load()!)
        XCTAssertEqual(scoped.pathData, Data("/fake/v".utf8))
        XCTAssertEqual(store.started, 1)
        XCTAssertEqual(store.stopped, 0)
        XCTAssertEqual(store.liveScopes, 1)
        scoped.end()
        scoped.end() // idempotent
        XCTAssertEqual(store.stopped, 1)
        XCTAssertEqual(store.liveScopes, 0)
    }

    func testBeginAccessThrowsSeededError() {
        let store = FakeVaultLocationStore(
            stored: VaultLocation(displayName: "V", bookmark: Data()))
        store.beginAccessError = .locationUnavailable("gone")
        XCTAssertThrowsError(try store.beginAccess(store.load()!)) { err in
            XCTAssertEqual(err as? VaultSelectionError, .locationUnavailable("gone"))
        }
        XCTAssertEqual(store.started, 0, "a thrown beginAccess must not count a start")
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter FakeVaultLocationStoreTests`
Expected: FAIL — `cannot find 'FakeVaultLocationStore'` / `VaultLocationStore`.

- [ ] **Step 3: Write minimal implementation**

```swift
// ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultLocationStore.swift
import Foundation

/// Persists ONE remembered vault location and brokers scoped access to it. The
/// port keeps the platform bookmark / security-scope machinery (and its known
/// pitfalls: stale bookmarks, the begin/end balance) behind a boundary so the
/// `VaultSelectionViewModel` state machine is host-testable against a fake.
///
/// Single-vault by design (this slice): `persist` replaces any prior location.
public protocol VaultLocationStore {
    /// The remembered location, or `nil` if none has been selected.
    func load() -> VaultLocation?
    /// Remember `location`, replacing any prior one.
    func persist(_ location: VaultLocation)
    /// Forget the remembered location.
    func clear()
    /// Resolve `location` and acquire a scope held until the returned handle's
    /// `end()`. Throws `VaultSelectionError.locationUnavailable` if the underlying
    /// bookmark cannot be resolved.
    func beginAccess(_ location: VaultLocation) throws -> ScopedVaultPath
}
```

```swift
// ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeVaultLocationStore.swift
import Foundation
import SecretaryVaultAccess

/// In-memory `VaultLocationStore` for host tests. Counts scope starts/stops so
/// tests can assert the begin/end balance (no leaked scopes) that the real
/// adapter must also honour.
public final class FakeVaultLocationStore: VaultLocationStore {
    public private(set) var stored: VaultLocation?
    public private(set) var started = 0
    public private(set) var stopped = 0
    /// When set, `beginAccess` throws this instead of returning a handle.
    public var beginAccessError: VaultSelectionError?
    /// `pathData` returned by a successful `beginAccess`.
    public var pathDataToReturn: Data

    public init(stored: VaultLocation? = nil,
                pathDataToReturn: Data = Data("/fake/vault".utf8)) {
        self.stored = stored
        self.pathDataToReturn = pathDataToReturn
    }

    public func load() -> VaultLocation? { stored }
    public func persist(_ location: VaultLocation) { stored = location }
    public func clear() { stored = nil }

    public func beginAccess(_ location: VaultLocation) throws -> ScopedVaultPath {
        if let beginAccessError { throw beginAccessError }
        started += 1
        return ScopedVaultPath(pathData: pathDataToReturn,
                               onEnd: { [weak self] in self?.stopped += 1 })
    }

    /// Scopes acquired but not yet released. Must be 0 after balanced use.
    public var liveScopes: Int { started - stopped }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ios/SecretaryVaultAccess && swift test --filter FakeVaultLocationStoreTests`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultLocationStore.swift \
        ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeVaultLocationStore.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/FakeVaultLocationStoreTests.swift
git commit -m "$(cat <<'EOF'
feat(ios): VaultLocationStore port + counting FakeVaultLocationStore

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: `VaultSelectionState` + `VaultSelectionViewModel`

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultSelectionState.swift`
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultSelectionViewModel.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultSelectionViewModelTests.swift`

- [ ] **Step 1: Write the failing test**

```swift
// ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultSelectionViewModelTests.swift
import XCTest
import SecretaryVaultAccess
import SecretaryVaultAccessTesting
@testable import SecretaryVaultAccessUI

@MainActor
final class VaultSelectionViewModelTests: XCTestCase {
    func testLoadPersistedEmptyWhenNoneStored() {
        let vm = VaultSelectionViewModel(store: FakeVaultLocationStore())
        vm.loadPersisted()
        XCTAssertEqual(vm.state, .empty)
    }

    func testLoadPersistedLocatedWhenStored() {
        let store = FakeVaultLocationStore(
            stored: VaultLocation(displayName: "MyVault", bookmark: Data([0x01])))
        let vm = VaultSelectionViewModel(store: store)
        vm.loadPersisted()
        XCTAssertEqual(vm.state, .located(displayName: "MyVault"))
    }

    func testRecordSelectionPersistsAndLocates() {
        let store = FakeVaultLocationStore()
        let vm = VaultSelectionViewModel(store: store)
        vm.recordSelection(bookmark: Data([0xAB]), displayName: "Picked")
        XCTAssertEqual(vm.state, .located(displayName: "Picked"))
        XCTAssertEqual(store.load(),
                       VaultLocation(displayName: "Picked", bookmark: Data([0xAB])))
    }

    func testChooseDifferentClearsToEmpty() {
        let store = FakeVaultLocationStore(
            stored: VaultLocation(displayName: "V", bookmark: Data([0x01])))
        let vm = VaultSelectionViewModel(store: store)
        vm.loadPersisted()
        vm.chooseDifferent()
        XCTAssertEqual(vm.state, .empty)
        XCTAssertNil(store.load())
    }

    func testBeginAccessThrowsWhenEmpty() {
        let vm = VaultSelectionViewModel(store: FakeVaultLocationStore())
        vm.loadPersisted()
        XCTAssertThrowsError(try vm.beginAccess()) { err in
            XCTAssertEqual(err as? VaultSelectionError, .noVaultSelected)
        }
    }

    func testBeginAccessReturnsScopedPathWhenLocated() throws {
        let store = FakeVaultLocationStore(
            stored: VaultLocation(displayName: "V", bookmark: Data([0x01])),
            pathDataToReturn: Data("/vaults/v".utf8))
        let vm = VaultSelectionViewModel(store: store)
        vm.loadPersisted()
        let scoped = try vm.beginAccess()
        XCTAssertEqual(scoped.pathData, Data("/vaults/v".utf8))
        scoped.end()
        XCTAssertEqual(store.liveScopes, 0)
    }

    func testBeginAccessUnavailableTransitionsStateAndRetainsLocation() {
        let store = FakeVaultLocationStore(
            stored: VaultLocation(displayName: "V", bookmark: Data([0x01])))
        store.beginAccessError = .locationUnavailable("vault moved")
        let vm = VaultSelectionViewModel(store: store)
        vm.loadPersisted()
        XCTAssertThrowsError(try vm.beginAccess())
        XCTAssertEqual(vm.state, .unavailable(reason: "vault moved"))
        XCTAssertNotNil(store.load(), "an unavailable vault is NOT silently cleared")
    }

    func testBalanceAcrossManyOpenLockCycles() throws {
        let store = FakeVaultLocationStore(
            stored: VaultLocation(displayName: "V", bookmark: Data([0x01])))
        let vm = VaultSelectionViewModel(store: store)
        vm.loadPersisted()
        for _ in 0..<5 {
            let scoped = try vm.beginAccess()
            scoped.end()
        }
        XCTAssertEqual(store.started, 5)
        XCTAssertEqual(store.stopped, 5)
        XCTAssertEqual(store.liveScopes, 0, "no leaked scopes across cycles")
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter VaultSelectionViewModelTests`
Expected: FAIL — `cannot find 'VaultSelectionViewModel'` / `VaultSelectionState`.

- [ ] **Step 3: Write minimal implementation**

```swift
// ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultSelectionState.swift
/// Observable state of the vault-selection screen. Unlike `UnlockState`, this is
/// `Equatable`: it carries no live reference (the scoped handle is returned out of
/// band from `beginAccess`, not stored here), so tests compare it directly.
public enum VaultSelectionState: Equatable {
    /// No vault remembered — show "Select a vault…" / "Try the demo vault".
    case empty
    /// A vault is remembered — show "Open <name>" / "Choose a different vault".
    case located(displayName: String)
    /// The remembered vault could not be opened (bookmark unresolvable) — offer re-pick.
    case unavailable(reason: String)
}
```

```swift
// ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultSelectionViewModel.swift
import Foundation
import Combine
import SecretaryVaultAccess

/// Drives the vault-selection screen over a `VaultLocationStore` port. Holds only
/// the injected store, so it is fully host-testable. `@MainActor` because it
/// publishes UI state.
@MainActor
public final class VaultSelectionViewModel: ObservableObject {
    @Published public private(set) var state: VaultSelectionState = .empty

    private let store: VaultLocationStore

    public init(store: VaultLocationStore) {
        self.store = store
    }

    /// Refresh state from the persisted store (call on appear / on returning to
    /// the selection screen after a lock).
    public func loadPersisted() {
        if let loc = store.load() {
            state = .located(displayName: loc.displayName)
        } else {
            state = .empty
        }
    }

    /// Record a freshly picked vault (bookmark + name), persist it, and locate it.
    public func recordSelection(bookmark: Data, displayName: String) {
        store.persist(VaultLocation(displayName: displayName, bookmark: bookmark))
        state = .located(displayName: displayName)
    }

    /// Forget the remembered vault and return to the empty state.
    public func chooseDifferent() {
        store.clear()
        state = .empty
    }

    /// Acquire a scope for the remembered vault. The returned `ScopedVaultPath`
    /// must be held for the whole session and `end()`-ed on lock/background.
    /// Throws `.noVaultSelected` if nothing is remembered; on an unresolvable
    /// bookmark, transitions to `.unavailable` (the location is RETAINED, not
    /// cleared — losing the user's selection silently would be wrong) and rethrows.
    public func beginAccess() throws -> ScopedVaultPath {
        guard let loc = store.load() else { throw VaultSelectionError.noVaultSelected }
        do {
            return try store.beginAccess(loc)
        } catch let VaultSelectionError.locationUnavailable(reason) {
            state = .unavailable(reason: reason)
            throw VaultSelectionError.locationUnavailable(reason)
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ios/SecretaryVaultAccess && swift test --filter VaultSelectionViewModelTests`
Expected: PASS (8 tests).

- [ ] **Step 5: Run the whole pure package to confirm no regressions**

Run: `cd ios/SecretaryVaultAccess && swift test`
Expected: PASS (all prior tests + the new selection tests).

- [ ] **Step 6: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultSelectionState.swift \
        ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultSelectionViewModel.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultSelectionViewModelTests.swift
git commit -m "$(cat <<'EOF'
feat(ios): host-tested VaultSelectionViewModel state machine

empty/located/unavailable transitions; begin/end scope balance asserted across
many open/lock cycles; an unavailable vault is retained, not silently cleared.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: `BookmarkVaultLocationStore` (real Foundation adapter)

**Files:**
- Create: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/BookmarkVaultLocationStore.swift`
- Test: `ios/SecretaryKit/Tests/SecretaryKitTests/BookmarkVaultLocationStoreTests.swift`

> **Note:** these are simulator/device tests (they need iOS Foundation bookmark APIs + the `SecretaryFFI` xcframework), so they run under `xcodebuild test`, not `swift test`. Build the framework first if absent (`bash ios/scripts/build-xcframework.sh`).

- [ ] **Step 1: Write the failing test**

```swift
// ios/SecretaryKit/Tests/SecretaryKitTests/BookmarkVaultLocationStoreTests.swift
import XCTest
@testable import SecretaryKit
import SecretaryVaultAccess

/// Exercises the REAL Foundation bookmark + security-scope round-trip on a
/// simulator, then proves a *bookmarked* path opens the golden vault identically
/// to a staged path. Uses an ephemeral UserDefaults suite so it never touches the
/// app's real defaults.
final class BookmarkVaultLocationStoreTests: XCTestCase {
    private let goldenPassword = "correct horse battery staple"
    private var suiteName: String!
    private var defaults: UserDefaults!
    private var tmpRoot: URL!
    private var vaultURL: URL!

    private func pinnedVaultUuidHex() throws -> String {
        let url = try XCTUnwrap(
            Bundle.module.url(forResource: "golden_vault_001_inputs", withExtension: "json"))
        let json = try JSONSerialization.jsonObject(with: Data(contentsOf: url))
        let dict = try XCTUnwrap(json as? [String: Any])
        let dashed = try XCTUnwrap(dict["vault_uuid"] as? String)
        return dashed.replacingOccurrences(of: "-", with: "").lowercased()
    }

    override func setUpWithError() throws {
        suiteName = "test.bookmarkstore.\(UUID().uuidString)"
        defaults = try XCTUnwrap(UserDefaults(suiteName: suiteName))
        let bundled = try XCTUnwrap(
            Bundle.module.url(forResource: "golden_vault_001", withExtension: nil),
            "golden_vault_001 not bundled — run ios/scripts/build-xcframework.sh")
        tmpRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("bm-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tmpRoot, withIntermediateDirectories: true)
        vaultURL = tmpRoot.appendingPathComponent("golden_vault_001", isDirectory: true)
        try FileManager.default.copyItem(at: bundled, to: vaultURL)
    }

    override func tearDownWithError() throws {
        defaults.removePersistentDomain(forName: suiteName)
        if let tmpRoot { try? FileManager.default.removeItem(at: tmpRoot) }
    }

    private func makeStore() -> BookmarkVaultLocationStore {
        BookmarkVaultLocationStore(defaults: defaults)
    }

    func testLoadNilWhenNothingPersisted() {
        XCTAssertNil(makeStore().load())
    }

    func testPersistLoadClearRoundTrip() throws {
        let store = makeStore()
        let bookmark = try vaultURL.bookmarkData()
        let loc = VaultLocation(displayName: "golden_vault_001", bookmark: bookmark)
        store.persist(loc)
        XCTAssertEqual(store.load(), loc)
        store.clear()
        XCTAssertNil(store.load())
    }

    func testBeginAccessResolvesToFolderAndOpensGoldenVault() throws {
        let store = makeStore()
        let bookmark = try vaultURL.bookmarkData()
        store.persist(VaultLocation(displayName: "golden_vault_001", bookmark: bookmark))

        let scoped = try store.beginAccess(XCTUnwrap(store.load()))
        defer { scoped.end() }

        // The resolved path must point at our vault folder.
        let resolvedPath = String(decoding: scoped.pathData, as: UTF8.self)
        XCTAssertTrue(resolvedPath.hasSuffix("golden_vault_001"),
                      "resolved \(resolvedPath)")

        // And a bookmarked path opens the vault exactly like a staged path.
        let port = UniffiVaultOpenPort()
        let session = try port.openWithPassword(
            vaultPath: scoped.pathData, password: [UInt8](goldenPassword.utf8))
        defer { session.wipe() }
        XCTAssertEqual(session.vaultUuidHex, try pinnedVaultUuidHex())
    }

    func testBeginAccessUnresolvableBookmarkThrowsLocationUnavailable() {
        let store = makeStore()
        let garbage = VaultLocation(displayName: "x", bookmark: Data([0x00, 0x01, 0x02, 0x03]))
        XCTAssertThrowsError(try store.beginAccess(garbage)) { err in
            guard case VaultSelectionError.locationUnavailable = err else {
                return XCTFail("expected .locationUnavailable, got \(err)")
            }
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bash ios/scripts/build-xcframework.sh && cd ios/SecretaryKit && xcodebuild test -scheme SecretaryKit -destination 'platform=iOS Simulator,name=iPhone 16' -only-testing:SecretaryKitTests/BookmarkVaultLocationStoreTests`
Expected: FAIL to compile — `cannot find 'BookmarkVaultLocationStore' in scope`.

- [ ] **Step 3: Write minimal implementation**

```swift
// ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/BookmarkVaultLocationStore.swift
import Foundation
import SecretaryVaultAccess

/// Real `VaultLocationStore`: persists the remembered vault as a security-scoped
/// bookmark in `UserDefaults` and brokers scoped access via Foundation.
///
/// iOS bookmark note: unlike macOS, iOS does NOT use the `.withSecurityScope`
/// create/resolve options — a bookmark created from a document-picker URL is
/// implicitly security-scoped on iOS. We therefore use `[]` options throughout.
public final class BookmarkVaultLocationStore: VaultLocationStore {
    private let defaults: UserDefaults
    private let bookmarkKey: String
    private let nameKey: String

    public init(defaults: UserDefaults = .standard,
                bookmarkKey: String = "secretary.vault.bookmark",
                nameKey: String = "secretary.vault.displayName") {
        self.defaults = defaults
        self.bookmarkKey = bookmarkKey
        self.nameKey = nameKey
    }

    public func load() -> VaultLocation? {
        guard let bookmark = defaults.data(forKey: bookmarkKey),
              let name = defaults.string(forKey: nameKey) else { return nil }
        return VaultLocation(displayName: name, bookmark: bookmark)
    }

    public func persist(_ location: VaultLocation) {
        defaults.set(location.bookmark, forKey: bookmarkKey)
        defaults.set(location.displayName, forKey: nameKey)
    }

    public func clear() {
        defaults.removeObject(forKey: bookmarkKey)
        defaults.removeObject(forKey: nameKey)
    }

    public func beginAccess(_ location: VaultLocation) throws -> ScopedVaultPath {
        var isStale = false
        let url: URL
        do {
            url = try URL(resolvingBookmarkData: location.bookmark,
                          options: [], relativeTo: nil, bookmarkDataIsStale: &isStale)
        } catch {
            throw VaultSelectionError.locationUnavailable(String(describing: error))
        }

        // `false` here is NOT treated as fatal: it is benign for in-sandbox paths,
        // and a genuine lack of access surfaces downstream as the FFI's typed open
        // error. We only `stop` if we actually `start`ed (`granted == true`).
        let granted = url.startAccessingSecurityScopedResource()

        // Refresh a stale bookmark WHILE access is held (re-persist; logged, not
        // silent). Best-effort: a failed refresh does not abort the open.
        if isStale, let fresh = try? url.bookmarkData() {
            persist(VaultLocation(displayName: location.displayName, bookmark: fresh))
        }

        return ScopedVaultPath(pathData: Data(url.path.utf8),
                               onEnd: { if granted { url.stopAccessingSecurityScopedResource() } })
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ios/SecretaryKit && xcodebuild test -scheme SecretaryKit -destination 'platform=iOS Simulator,name=iPhone 16' -only-testing:SecretaryKitTests/BookmarkVaultLocationStoreTests`
Expected: PASS (4 tests). (If `iPhone 16` is unavailable, use a simulator from `xcrun simctl list devices available`.)

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/BookmarkVaultLocationStore.swift \
        ios/SecretaryKit/Tests/SecretaryKitTests/BookmarkVaultLocationStoreTests.swift
git commit -m "$(cat <<'EOF'
feat(ios): BookmarkVaultLocationStore — bookmark persistence + scoped access

Foundation security-scoped bookmark round-trip (iOS [] options), stale refresh
while access held, scope released only if granted. Simulator test opens the
golden vault through the resolved bookmark path.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: App wiring — selection screen, routing, remove prefilled password

**Files:**
- Create: `ios/SecretaryApp/Sources/VaultSelectionScreen.swift`
- Modify: `ios/SecretaryApp/Sources/SecretaryApp.swift`
- Modify: `ios/SecretaryApp/Sources/UnlockScreen.swift`

This task has no host unit test (the app layer is iOS-only SwiftUI glue, compile-proofed by `build-app.sh`, consistent with the #216 RootView). The selection *logic* is already host-tested in Task 4; the real store in Task 5.

- [ ] **Step 1: Remove the prefilled demo password from `UnlockScreen`**

In `ios/SecretaryApp/Sources/UnlockScreen.swift`, replace:

```swift
    // Demo convenience ONLY: the app stages the golden demo vault, so prefilling
    // its fixture password saves typing. MUST be removed when real vault
    // selection/import lands — never ship a prefilled credential into a build
    // that opens a user's real vault.
    @State private var password: String = "correct horse battery staple"
```

with:

```swift
    @State private var password: String = ""
```

- [ ] **Step 2: Create the selection screen**

```swift
// ios/SecretaryApp/Sources/VaultSelectionScreen.swift
import SwiftUI
import UniformTypeIdentifiers
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// First screen: pick a vault folder (system file importer) or open the remembered
/// one. Also offers an explicit, opt-in "Try the demo vault" (no prefilled
/// password). Calls `onOpen` with a held `ScopedVaultPath` once a vault is ready to
/// unlock; `onOpenDemo` stages + opens the bundled golden vault.
struct VaultSelectionScreen: View {
    @ObservedObject var viewModel: VaultSelectionViewModel
    let onOpen: (ScopedVaultPath) -> Void
    let onOpenDemo: () -> Void

    @State private var importing = false
    @State private var errorText: String?

    var body: some View {
        NavigationStack {
            Form {
                switch viewModel.state {
                case .empty:
                    selectSection
                case .located(let name):
                    Section("Remembered vault") {
                        Text(name).font(.body.monospaced())
                        Button("Open") { open() }
                        Button("Choose a different vault") { viewModel.chooseDifferent() }
                    }
                case .unavailable(let reason):
                    Section("Vault unavailable") {
                        Text(reason).font(.footnote).foregroundStyle(.secondary)
                        Button("Choose a different vault") { viewModel.chooseDifferent() }
                    }
                }

                Section {
                    Button("Try the demo vault") { onOpenDemo() }
                }

                if let errorText {
                    Section("Error") {
                        Text(errorText).font(.footnote.monospaced()).foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Choose vault")
            .onAppear { viewModel.loadPersisted() }
            .fileImporter(isPresented: $importing,
                          allowedContentTypes: [.folder]) { result in
                handleImport(result)
            }
        }
    }

    private var selectSection: some View {
        Section("Open a vault") {
            Button("Select a vault…") { importing = true }
        }
    }

    private func open() {
        errorText = nil
        do {
            let scoped = try viewModel.beginAccess()
            onOpen(scoped)
        } catch {
            // .unavailable state is already set by the VM; surface a line too.
            errorText = String(describing: error)
        }
    }

    private func handleImport(_ result: Result<URL, Error>) {
        errorText = nil
        switch result {
        case .failure(let error):
            errorText = String(describing: error)
        case .success(let url):
            // Create the bookmark while access is briefly held (iOS requirement).
            let didAccess = url.startAccessingSecurityScopedResource()
            defer { if didAccess { url.stopAccessingSecurityScopedResource() } }
            do {
                let bookmark = try url.bookmarkData()
                viewModel.recordSelection(bookmark: bookmark,
                                          displayName: url.lastPathComponent)
            } catch {
                errorText = String(describing: error)
            }
        }
    }
}
```

- [ ] **Step 3: Rewrite `RootView` routing in `SecretaryApp.swift`**

Replace the entire `private struct RootView: View { … }` (keep the `@main struct SecretaryApp` above it unchanged) with:

```swift
/// Routes `select → unlock → browse`. A user-selected vault's security scope is
/// held by the `ScopedVaultPath` for the whole session (lazy block reads) and
/// released on lock/background, which returns to the selection screen showing the
/// still-remembered vault (one tap re-opens — no re-pick). The demo vault reuses
/// the same unlock/browse flow with a no-op scope over its staged path.
private struct RootView: View {
    private enum Route {
        case select
        case unlock(ScopedVaultPath)
        case browse(VaultBrowseViewModel, ScopedVaultPath)
    }

    @StateObject private var selectionVM =
        VaultSelectionViewModel(store: BookmarkVaultLocationStore())
    @State private var route: Route = .select
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        Group {
            switch route {
            case .select:
                VaultSelectionScreen(
                    viewModel: selectionVM,
                    onOpen: { scoped in route = .unlock(scoped) },
                    onOpenDemo: { openDemo() })
            case .unlock(let scoped):
                UnlockScreen(
                    viewModel: UnlockViewModel(port: UniffiVaultOpenPort(),
                                               vaultPath: scoped.pathData),
                    onUnlocked: { session in
                        route = .browse(VaultBrowseViewModel(session: session), scoped)
                    })
            case .browse(let browseModel, _):
                VaultBrowseScreen(viewModel: browseModel)
            }
        }
        // Lock on background: wipe + drop reveals, release the held scope, and
        // return to the selection screen (which still shows the remembered vault).
        .onChange(of: scenePhase) { _, phase in
            guard phase == .background else { return }
            switch route {
            case .browse(let browseModel, let scoped):
                browseModel.lock()
                scoped.end()
                route = .select
            case .unlock(let scoped):
                scoped.end()
                route = .select
            case .select:
                break
            }
        }
    }

    /// Stage + open the bundled golden vault behind an explicit opt-in. The demo
    /// path is in-sandbox, so its `ScopedVaultPath` holds no real scope (no-op end).
    private func openDemo() {
        do {
            let url = try AppVaultProvisioning.stageGoldenVault()
            let scoped = ScopedVaultPath(pathData: Data(url.path.utf8), onEnd: {})
            route = .unlock(scoped)
        } catch {
            // Staging failure is surfaced by returning to select; the demo button
            // simply has no effect. (A dedicated error surface is a later polish.)
            route = .select
        }
    }
}
```

- [ ] **Step 4: Update the imports at the top of `SecretaryApp.swift`**

Ensure the import block reads (add `SecretaryVaultAccessUI` if missing — it already is, but `BookmarkVaultLocationStore` comes from `SecretaryKit`):

```swift
import SwiftUI
import SecretaryKit
import SecretaryVaultAccess
import SecretaryVaultAccessUI
```

- [ ] **Step 5: Build the app (compile proof + simulator)**

Run: `bash ios/scripts/build-app.sh`
Expected: `** BUILD SUCCEEDED **`.

- [ ] **Step 6: Commit**

```bash
git add ios/SecretaryApp/Sources/VaultSelectionScreen.swift \
        ios/SecretaryApp/Sources/SecretaryApp.swift \
        ios/SecretaryApp/Sources/UnlockScreen.swift
git commit -m "$(cat <<'EOF'
feat(ios): vault-selection screen + select->unlock->browse routing

.fileImporter folder pick over BookmarkVaultLocationStore; remembered vault
reopens with one tap; demo vault kept as an explicit opt-in; prefilled demo
password removed. Scope released on background; routes back to selection.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Full gauntlet + docs + handoff

**Files:**
- Modify: `README.md`, `ROADMAP.md`, `ios/README.md`
- Create: `docs/handoffs/2026-06-12-ios-vault-selection-shipped.md`
- Retarget: `NEXT_SESSION.md` symlink

- [ ] **Step 1: Run the full iOS gauntlet**

Run: `bash ios/scripts/run-ios-tests.sh`
Expected: host `SecretaryDeviceUnlock` + `SecretaryVaultAccess` green (incl. all new selection tests), simulator `SecretaryKitTests` green (incl. `BookmarkVaultLocationStoreTests`), app `BUILD SUCCEEDED`.

- [ ] **Step 2: Confirm no Rust / FFI-surface change**

Run: `git diff main..HEAD --name-only | grep -E '\.rs$' || echo "no rust touched"`
Expected: `no rust touched`.

- [ ] **Step 3: Update `README.md` and `ios/README.md`**

In the iOS status section of each, add a brief dot point: the iOS app can now select a vault folder via the system picker and remember it across launches (security-scoped bookmark); the bundled demo is an explicit opt-in. Keep it brief (dot points, no test-count walls — README style).

- [ ] **Step 4: Update `ROADMAP.md`**

Mark the iOS vault-selection slice done; note record-editing / vault-create-import as the remaining iOS read/write slices.

- [ ] **Step 5: Author the handoff + retarget the symlink**

Create `docs/handoffs/2026-06-12-ios-vault-selection-shipped.md` capturing: (1) what shipped + commit SHAs, (2) what's next with acceptance criteria (record editing; vault create/import), (3) open risks (on-device manual smoke with a side-loaded vault is the carried item; `@MainActor` KDF block carried from #216; Swift-side secret residue carried), (4) exact resume commands (worktree, branch, `run-ios-tests.sh`). Then:

```bash
ln -snf docs/handoffs/2026-06-12-ios-vault-selection-shipped.md NEXT_SESSION.md
ls -la NEXT_SESSION.md   # shows -> target
head -3 NEXT_SESSION.md  # reads the handoff transparently
```

- [ ] **Step 6: Commit docs + handoff + symlink together**

```bash
git add README.md ROADMAP.md ios/README.md \
        docs/handoffs/2026-06-12-ios-vault-selection-shipped.md NEXT_SESSION.md
git commit -m "$(cat <<'EOF'
docs(ios): vault-selection shipped — README/ROADMAP + handoff/symlink

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 7: Push + open PR**

```bash
git push -u origin feature/ios-vault-selection
gh pr create --base main --title "iOS app — vault selection (folder picker + persisted bookmark)" \
  --body "$(cat <<'EOF'
Lets the iOS app open a user-selected vault folder (system picker) and remember it
across launches via a persisted security-scoped bookmark. Removes the prefilled
demo password; bundled golden vault retained as an explicit opt-in. 100% Swift —
no Rust / on-disk-format / FFI-surface change.

Approach A: pure VaultLocationStore port + host-tested VaultSelectionViewModel;
Foundation BookmarkVaultLocationStore adapter; .fileImporter + select→unlock→browse
routing. Scope held for the whole session (lazy block reads), begin/end balance
unit-tested; stale/unresolvable bookmarks surface as typed errors (no silent fallback).

Spec: docs/superpowers/specs/2026-06-12-ios-vault-selection-design.md
Plan: docs/superpowers/plans/2026-06-12-ios-vault-selection.md

Outstanding: on-device manual smoke with a side-loaded vault (needs a physical device).

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Self-Review

**Spec coverage:**
- Folder picker (`.fileImporter([.folder])`) → Task 6. ✅
- Persist security-scoped bookmark (single vault) → Task 5 (`BookmarkVaultLocationStore`) + Task 3 (port). ✅
- Reopen remembered vault on relaunch → Task 4 (`loadPersisted`) + Task 6 (`onAppear`). ✅
- "Choose a different vault" replaces it → Task 4 (`chooseDifferent`) + Task 6. ✅
- Opt-in demo, no prefilled password → Task 6 (`onOpenDemo`, password `= ""`). ✅
- Remove prefilled password → Task 6 Step 1. ✅
- Session-spanning scope + begin/end balance → Task 2 (`ScopedVaultPath`) + Task 4 (balance test) + Task 5 (real). ✅
- No silent fallback (stale/unavailable) → Task 4 (`.unavailable`, retained) + Task 5 (`.locationUnavailable` on resolve failure, stale refresh+re-persist). ✅
- No `.accessDenied` (benign false) → Task 2 (doc) + Task 5 (`granted` non-fatal). ✅
- No Rust/FFI change → Task 7 Step 2 assertion. ✅
- On-device smoke carried → Task 7 handoff. ✅

**Placeholder scan:** No TBD/TODO; every code step shows complete code; commands have expected output. ✅

**Type consistency:** `VaultLocation(displayName:bookmark:)`, `ScopedVaultPath(pathData:onEnd:)` + `.pathData`/`.end()`, `VaultLocationStore` {`load`/`persist`/`clear`/`beginAccess`}, `VaultSelectionError` {`.noVaultSelected`/`.locationUnavailable`}, `VaultSelectionState` {`.empty`/`.located(displayName:)`/`.unavailable(reason:)`}, `VaultSelectionViewModel` {`loadPersisted`/`recordSelection(bookmark:displayName:)`/`chooseDifferent`/`beginAccess`}, `FakeVaultLocationStore` {`started`/`stopped`/`liveScopes`/`beginAccessError`/`pathDataToReturn`} — names match across all tasks. ✅
