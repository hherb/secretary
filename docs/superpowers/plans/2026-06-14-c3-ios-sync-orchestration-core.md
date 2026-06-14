# C.3 (iOS) Sync Orchestration Core — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the iOS app a pure, host-tested orchestration core to run one sync pass and carry a tombstone-veto conflict to resolution, over the existing uniffi sync surface.

**Architecture:** Pure ports + Equatable value types in `SecretaryVaultAccess`; a host-tested `SyncCoordinator` actor threads the two-call inspect→commit round-trip (freshness token held internally, password passed per call); a real `UniffiVaultSyncPort` adapter in `SecretaryKit` maps generated DTOs ↔ pure types and offloads the Argon2id-bearing calls off the main actor. No Rust/FFI/format change.

**Tech Stack:** Swift 5.9, Swift Concurrency (`actor`, `async`/`await`), XCTest host tests via `swift test`, uniffi-generated bindings (consumed, not modified).

**Spec:** [docs/superpowers/specs/2026-06-14-c3-ios-sync-orchestration-core-design.md](../specs/2026-06-14-c3-ios-sync-orchestration-core-design.md)

**Working directory:** `/Users/hherb/src/secretary/.worktrees/ios-sync-core` (branch `feature/ios-sync-core`). Verify with `pwd && git branch --show-current` before every command.

---

## File Structure

**Create (pure — `SecretaryVaultAccess` target):**
- `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultSyncError.swift` — typed sync failures (own enum, like `VaultSelectionError`).
- `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/SyncModels.swift` — `SyncStatus`, `DeviceClock`, `SyncVeto`, `SyncCollision`, `SyncVetoDecision`, `SyncOutcome`, `PendingConflict`.
- `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultSyncPort.swift` — the port protocol.
- `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/SyncCoordinator.swift` — the round-trip orchestrator.

**Create (fakes — `SecretaryVaultAccessTesting` target):**
- `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeVaultSyncPort.swift`

**Create (host tests — `SecretaryVaultAccessTests` target):**
- `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/SyncModelsTests.swift`
- `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/SyncCoordinatorTests.swift`

**Create (real adapter — `SecretaryKit` target):**
- `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/VaultSyncErrorMapping.swift`
- `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSyncPort.swift`

**Create (adapter test — `SecretaryKitTests` target):**
- `ios/SecretaryKit/Tests/SecretaryKitTests/UniffiVaultSyncPortOffMainActorTests.swift`

**Modify (docs):**
- `README.md`, `ROADMAP.md`, `NEXT_SESSION.md` (symlink + handoff).

No file exceeds the 500-line guideline; `SyncModels.swift` groups the small value types (one concept-cluster) per the existing `ModelsTests.swift`/models convention.

---

## Task 1: Pure value types, port protocol, error enum, and fake

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultSyncError.swift`
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/SyncModels.swift`
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultSyncPort.swift`
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeVaultSyncPort.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/SyncModelsTests.swift`

- [ ] **Step 1: Write the value types**

Create `SyncModels.swift`:

```swift
import Foundation

/// One device's vector-clock entry — public metadata, never secret.
/// Mirrors the bridge `DeviceClockDto`.
public struct DeviceClock: Equatable {
    public let deviceUuidHex: String
    public let counter: UInt64
    public init(deviceUuidHex: String, counter: UInt64) {
        self.deviceUuidHex = deviceUuidHex
        self.counter = counter
    }
}

/// Read-only sync status for a vault. Mirrors the bridge `SyncStatusDto`.
public struct SyncStatus: Equatable {
    public let hasState: Bool
    public let deviceClocks: [DeviceClock]
    public let lastStateWriteMs: UInt64?
    public init(hasState: Bool, deviceClocks: [DeviceClock], lastStateWriteMs: UInt64?) {
        self.hasState = hasState
        self.deviceClocks = deviceClocks
        self.lastStateWriteMs = lastStateWriteMs
    }
}

/// A tombstone dispute awaiting a human decision. Metadata-only by construction
/// (the bridge projects field *names*, never values) — no plaintext secret here.
public struct SyncVeto: Equatable {
    public let recordUuidHex: String
    public let recordType: String
    public let tags: [String]
    public let fieldNames: [String]
    public let localLastModMs: UInt64
    public let peerTombstonedAtMs: UInt64
    public let peerDeviceHex: String
    public init(recordUuidHex: String, recordType: String, tags: [String],
                fieldNames: [String], localLastModMs: UInt64,
                peerTombstonedAtMs: UInt64, peerDeviceHex: String) {
        self.recordUuidHex = recordUuidHex
        self.recordType = recordType
        self.tags = tags
        self.fieldNames = fieldNames
        self.localLastModMs = localLastModMs
        self.peerTombstonedAtMs = peerTombstonedAtMs
        self.peerDeviceHex = peerDeviceHex
    }
}

/// Metadata-only field-level collision summary for the "auto-merged" notice.
public struct SyncCollision: Equatable {
    public let recordUuidHex: String
    public let fieldNames: [String]
    public init(recordUuidHex: String, fieldNames: [String]) {
        self.recordUuidHex = recordUuidHex
        self.fieldNames = fieldNames
    }
}

/// Caller's per-record decision. `keepLocal == true` rejects the peer tombstone;
/// `false` accepts the delete.
public struct SyncVetoDecision: Equatable {
    public let recordUuidHex: String
    public let keepLocal: Bool
    public init(recordUuidHex: String, keepLocal: Bool) {
        self.recordUuidHex = recordUuidHex
        self.keepLocal = keepLocal
    }
}

/// Result of one sync pass. Mirrors the bridge `SyncOutcomeDto`.
public enum SyncOutcome: Equatable {
    /// Disk clock == local highest-seen. No change.
    case nothingToDo
    /// Disk strictly dominates local. State advanced; no vault write.
    case appliedAutomatically
    /// Concurrent but no surviving block divergence. State advanced; no write.
    case silentMerge
    /// Concurrent, diverging, zero vetoes → merged result committed.
    case mergedClean
    /// Disk strictly dominated by local (rollback). Nothing changed.
    case rollbackRejected
    /// Concurrent, diverging, tombstone vetoes need a human. NOT committed.
    /// `manifestHash` is the opaque freshness token to pass back to commit.
    case conflictsPending(vetoes: [SyncVeto], collisions: [SyncCollision], manifestHash: [UInt8])
}

/// The pending conflict detail surfaced after a `runPass` that paused.
/// The freshness token is held privately by the coordinator and intentionally
/// NOT exposed here — callers never thread it themselves.
public struct PendingConflict: Equatable {
    public let vetoes: [SyncVeto]
    public let collisions: [SyncCollision]
    public init(vetoes: [SyncVeto], collisions: [SyncCollision]) {
        self.vetoes = vetoes
        self.collisions = collisions
    }
}
```

- [ ] **Step 2: Write the error enum**

Create `VaultSyncError.swift`:

```swift
import Foundation

/// Typed failures from a sync pass. A dedicated enum (like `VaultSelectionError`),
/// NOT a reuse of `VaultAccessError`: the sync FFI surfaces a structurally
/// different `VaultError` variant set, and folding it through the vault-access
/// cases would misattribute errors.
///
/// `wrongPasswordOrCorrupt` is the core's deliberately-conflated anti-oracle
/// variant (wrong password is indistinguishable from a tampered vault). Do NOT
/// split it into a "wrong credential" case — that reintroduces the oracle.
public enum VaultSyncError: Error, Equatable {
    /// Password re-open during the pass failed: wrong password OR corruption.
    case wrongPasswordOrCorrupt
    /// Another sync pass already holds the per-vault lock.
    case inProgress
    /// The persisted sync state belongs to a different vault.
    case stateVaultMismatch
    /// The persisted sync state could not be decoded.
    case stateCorrupt(String)
    /// The freshness token no longer matches on-disk state (TOCTOU gate tripped).
    case evidenceStale
    /// The supplied decisions did not exactly cover the recomputed veto set.
    case decisionsIncomplete
    /// FFI input-shape error (e.g. wrong-length vault UUID / manifest hash).
    case invalidArgument(String)
    /// Any other sync failure carried as a string (never a raw panic).
    case failed(String)
    /// `resolve` was called without a prior `conflictsPending` pass. Raised
    /// entirely Swift-side; no FFI call is made.
    case noPendingConflict
}
```

- [ ] **Step 3: Write the port protocol**

Create `VaultSyncPort.swift`:

```swift
import Foundation

/// Runs sync operations over the (FFI) sync surface. Implementations throw
/// `VaultSyncError`.
///
/// All methods are `async` because the real `sync`/`commitDecisions` re-open the
/// identity from the password and pay the full Argon2id cost; the real adapter
/// offloads them off the calling actor (see `SecretaryKit.runOffMainActor`) so a
/// `@MainActor` caller stays responsive. `status` is a cheap disk read but is
/// `async` for protocol uniformity.
///
/// `password` is passed per call and never retained by callers.
public protocol VaultSyncPort {
    func status(stateDir: String, vaultUuid: [UInt8]) async throws -> SyncStatus
    func sync(stateDir: String, vaultFolder: String,
              password: [UInt8], nowMs: UInt64) async throws -> SyncOutcome
    func commitDecisions(stateDir: String, vaultFolder: String,
                         password: [UInt8], decisions: [SyncVetoDecision],
                         manifestHash: [UInt8], nowMs: UInt64) async throws -> SyncOutcome
}
```

- [ ] **Step 4: Write the fake**

Create `FakeVaultSyncPort.swift`:

```swift
import Foundation
import SecretaryVaultAccess

/// In-memory `VaultSyncPort` returning pre-seeded results and spying on inputs.
/// Mirrors `FakeVaultOpenPort`'s convention.
public final class FakeVaultSyncPort: VaultSyncPort {
    private let statusResult: Result<SyncStatus, VaultSyncError>
    private let syncResult: Result<SyncOutcome, VaultSyncError>
    private let commitResult: Result<SyncOutcome, VaultSyncError>

    /// Spies for assertions.
    public private(set) var statusCalls = 0
    public private(set) var syncCalls = 0
    public private(set) var commitCalls = 0
    public private(set) var lastSyncPassword: [UInt8]?
    public private(set) var lastCommitPassword: [UInt8]?
    public private(set) var lastCommitDecisions: [SyncVetoDecision]?
    public private(set) var lastCommitManifestHash: [UInt8]?

    /// Optional rendezvous so an off-main-actor test can hold a call mid-flight.
    public var gate: SuspensionGate?

    public init(statusResult: Result<SyncStatus, VaultSyncError> = .success(
                    SyncStatus(hasState: false, deviceClocks: [], lastStateWriteMs: nil)),
                syncResult: Result<SyncOutcome, VaultSyncError> = .success(.nothingToDo),
                commitResult: Result<SyncOutcome, VaultSyncError> = .success(.mergedClean)) {
        self.statusResult = statusResult
        self.syncResult = syncResult
        self.commitResult = commitResult
    }

    public func status(stateDir: String, vaultUuid: [UInt8]) async throws -> SyncStatus {
        statusCalls += 1
        return try statusResult.get()
    }

    public func sync(stateDir: String, vaultFolder: String,
                     password: [UInt8], nowMs: UInt64) async throws -> SyncOutcome {
        syncCalls += 1
        lastSyncPassword = password
        await gate?.enterAndWait()
        return try syncResult.get()
    }

    public func commitDecisions(stateDir: String, vaultFolder: String,
                                password: [UInt8], decisions: [SyncVetoDecision],
                                manifestHash: [UInt8], nowMs: UInt64) async throws -> SyncOutcome {
        commitCalls += 1
        lastCommitPassword = password
        lastCommitDecisions = decisions
        lastCommitManifestHash = manifestHash
        await gate?.enterAndWait()
        return try commitResult.get()
    }
}
```

- [ ] **Step 5: Write the value-type test**

Create `SyncModelsTests.swift`:

```swift
import XCTest
@testable import SecretaryVaultAccess

final class SyncModelsTests: XCTestCase {
    func testSyncOutcomeEqualityDiscriminatesVariants() {
        XCTAssertEqual(SyncOutcome.nothingToDo, SyncOutcome.nothingToDo)
        XCTAssertNotEqual(SyncOutcome.nothingToDo, SyncOutcome.appliedAutomatically)
        XCTAssertNotEqual(SyncOutcome.silentMerge, SyncOutcome.mergedClean)
        XCTAssertNotEqual(SyncOutcome.mergedClean, SyncOutcome.rollbackRejected)
    }

    func testConflictsPendingEqualityIncludesPayload() {
        let veto = SyncVeto(recordUuidHex: "aa", recordType: "login", tags: ["x"],
                            fieldNames: ["password"], localLastModMs: 10,
                            peerTombstonedAtMs: 20, peerDeviceHex: "bb")
        let a = SyncOutcome.conflictsPending(vetoes: [veto], collisions: [], manifestHash: [1, 2, 3])
        let b = SyncOutcome.conflictsPending(vetoes: [veto], collisions: [], manifestHash: [1, 2, 3])
        let c = SyncOutcome.conflictsPending(vetoes: [veto], collisions: [], manifestHash: [9, 9, 9])
        XCTAssertEqual(a, b)
        XCTAssertNotEqual(a, c)
    }

    func testVaultSyncErrorEquatable() {
        XCTAssertEqual(VaultSyncError.evidenceStale, VaultSyncError.evidenceStale)
        XCTAssertEqual(VaultSyncError.stateCorrupt("x"), VaultSyncError.stateCorrupt("x"))
        XCTAssertNotEqual(VaultSyncError.stateCorrupt("x"), VaultSyncError.stateCorrupt("y"))
        XCTAssertNotEqual(VaultSyncError.inProgress, VaultSyncError.noPendingConflict)
    }
}
```

- [ ] **Step 6: Run the test (verify it passes — value types compile)**

Run: `cd /Users/hherb/src/secretary/.worktrees/ios-sync-core/ios/SecretaryVaultAccess && swift test --filter SyncModelsTests`
Expected: PASS (3 tests). If the package fails to build, the value types / fake have a syntax error — fix before moving on.

- [ ] **Step 7: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/ios-sync-core
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultSyncError.swift \
        ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/SyncModels.swift \
        ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultSyncPort.swift \
        ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeVaultSyncPort.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/SyncModelsTests.swift
git commit -m "feat(ios-sync): pure value types, VaultSyncPort, VaultSyncError, fake"
```

---

## Task 2: `SyncCoordinator` (TDD)

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/SyncCoordinator.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/SyncCoordinatorTests.swift`

- [ ] **Step 1: Write the failing tests**

Create `SyncCoordinatorTests.swift`:

```swift
import XCTest
@testable import SecretaryVaultAccess
import SecretaryVaultAccessTesting

final class SyncCoordinatorTests: XCTestCase {
    private let pw: [UInt8] = Array("correct horse battery staple".utf8)
    private func makeVeto() -> SyncVeto {
        SyncVeto(recordUuidHex: "aa", recordType: "login", tags: [],
                 fieldNames: ["password"], localLastModMs: 1,
                 peerTombstonedAtMs: 2, peerDeviceHex: "bb")
    }

    func testRunPassPassesSafeArmThroughAndLeavesNoPendingConflict() async throws {
        let port = FakeVaultSyncPort(syncResult: .success(.appliedAutomatically))
        let coord = SyncCoordinator(port: port, stateDir: "/tmp/s", vaultFolder: "/tmp/v")
        let outcome = try await coord.runPass(password: pw, nowMs: 0)
        XCTAssertEqual(outcome, .appliedAutomatically)
        let pending = await coord.pendingConflict
        XCTAssertNil(pending)
        XCTAssertEqual(port.syncCalls, 1)
        XCTAssertEqual(port.lastSyncPassword, pw)
    }

    func testRunPassOnConflictStashesDetail() async throws {
        let veto = makeVeto()
        let port = FakeVaultSyncPort(syncResult: .success(
            .conflictsPending(vetoes: [veto], collisions: [], manifestHash: [7, 7, 7])))
        let coord = SyncCoordinator(port: port, stateDir: "/tmp/s", vaultFolder: "/tmp/v")
        let outcome = try await coord.runPass(password: pw, nowMs: 0)
        XCTAssertEqual(outcome, .conflictsPending(vetoes: [veto], collisions: [], manifestHash: [7, 7, 7]))
        let pending = await coord.pendingConflict
        XCTAssertEqual(pending, PendingConflict(vetoes: [veto], collisions: []))
    }

    func testResolveUsesStashedTokenAndDecisions() async throws {
        let veto = makeVeto()
        let port = FakeVaultSyncPort(
            syncResult: .success(.conflictsPending(vetoes: [veto], collisions: [], manifestHash: [7, 7, 7])),
            commitResult: .success(.mergedClean))
        let coord = SyncCoordinator(port: port, stateDir: "/tmp/s", vaultFolder: "/tmp/v")
        _ = try await coord.runPass(password: pw, nowMs: 0)
        let decisions = [SyncVetoDecision(recordUuidHex: "aa", keepLocal: true)]
        let outcome = try await coord.resolve(decisions: decisions, password: pw, nowMs: 0)
        XCTAssertEqual(outcome, .mergedClean)
        XCTAssertEqual(port.commitCalls, 1)
        XCTAssertEqual(port.lastCommitManifestHash, [7, 7, 7])
        XCTAssertEqual(port.lastCommitDecisions, decisions)
        XCTAssertEqual(port.lastCommitPassword, pw)
        let pending = await coord.pendingConflict
        XCTAssertNil(pending) // cleared after a non-conflict commit
    }

    func testResolveWithoutPendingConflictThrowsAndMakesNoFfiCall() async {
        let port = FakeVaultSyncPort()
        let coord = SyncCoordinator(port: port, stateDir: "/tmp/s", vaultFolder: "/tmp/v")
        do {
            _ = try await coord.resolve(decisions: [], password: pw, nowMs: 0)
            XCTFail("expected noPendingConflict")
        } catch let e as VaultSyncError {
            XCTAssertEqual(e, .noPendingConflict)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
        XCTAssertEqual(port.commitCalls, 0)
    }

    func testResolveStaleTokenPropagatesError() async throws {
        let veto = makeVeto()
        let port = FakeVaultSyncPort(
            syncResult: .success(.conflictsPending(vetoes: [veto], collisions: [], manifestHash: [7])),
            commitResult: .failure(.evidenceStale))
        let coord = SyncCoordinator(port: port, stateDir: "/tmp/s", vaultFolder: "/tmp/v")
        _ = try await coord.runPass(password: pw, nowMs: 0)
        do {
            _ = try await coord.resolve(decisions: [], password: pw, nowMs: 0)
            XCTFail("expected evidenceStale")
        } catch let e as VaultSyncError {
            XCTAssertEqual(e, .evidenceStale)
        }
        // Stash survives a stale-token failure so the caller can re-inspect/retry.
        let pending = await coord.pendingConflict
        XCTAssertEqual(pending, PendingConflict(vetoes: [veto], collisions: []))
    }

    func testRunPassClearsAStalePendingConflictOnASafeArm() async throws {
        let veto = makeVeto()
        let port = FakeVaultSyncPort(
            syncResult: .success(.conflictsPending(vetoes: [veto], collisions: [], manifestHash: [7])))
        let coord = SyncCoordinator(port: port, stateDir: "/tmp/s", vaultFolder: "/tmp/v")
        _ = try await coord.runPass(password: pw, nowMs: 0)
        XCTAssertNotNil(await coord.pendingConflict)
        // Now a second pass that resolves cleanly elsewhere returns a safe arm.
        let port2 = FakeVaultSyncPort(syncResult: .success(.nothingToDo))
        let coord2 = SyncCoordinator(port: port2, stateDir: "/tmp/s", vaultFolder: "/tmp/v")
        _ = try await coord2.runPass(password: pw, nowMs: 0)
        XCTAssertNil(await coord2.pendingConflict)
    }

    func testStatusForwardsToPort() async throws {
        let status = SyncStatus(hasState: true,
                                deviceClocks: [DeviceClock(deviceUuidHex: "aa", counter: 3)],
                                lastStateWriteMs: 99)
        let port = FakeVaultSyncPort(statusResult: .success(status))
        let coord = SyncCoordinator(port: port, stateDir: "/tmp/s", vaultFolder: "/tmp/v")
        let got = try await coord.status(vaultUuid: Array(repeating: 9, count: 16))
        XCTAssertEqual(got, status)
        XCTAssertEqual(port.statusCalls, 1)
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /Users/hherb/src/secretary/.worktrees/ios-sync-core/ios/SecretaryVaultAccess && swift test --filter SyncCoordinatorTests`
Expected: FAIL to compile — `SyncCoordinator` is undefined.

- [ ] **Step 3: Implement `SyncCoordinator`**

Create `SyncCoordinator.swift`:

```swift
import Foundation

/// Orchestrates the two-call inspect→commit sync round-trip over a
/// `VaultSyncPort`. An `actor` so concurrent `runPass`/`resolve` calls against
/// the same vault serialize cleanly (the FFI also holds a per-vault lockfile and
/// would return `.inProgress`, but the actor avoids a redundant FFI hop).
///
/// Secret hygiene: the password is passed per call and never stored. Only the
/// non-secret freshness token + veto metadata persist between calls.
public actor SyncCoordinator {
    private let port: VaultSyncPort
    private let stateDir: String
    private let vaultFolder: String

    /// Stashed across the round-trip after a paused `runPass`. The token is held
    /// here (private) and replayed by `resolve`; the public `pendingConflict`
    /// exposes only the display detail.
    private var stashedToken: [UInt8]?
    private var stashedConflict: PendingConflict?

    public init(port: VaultSyncPort, stateDir: String, vaultFolder: String) {
        self.port = port
        self.stateDir = stateDir
        self.vaultFolder = vaultFolder
    }

    /// The pending conflict detail from the last paused `runPass`, if any.
    public var pendingConflict: PendingConflict? { stashedConflict }

    /// Read-only sync status.
    public func status(vaultUuid: [UInt8]) async throws -> SyncStatus {
        try await port.status(stateDir: stateDir, vaultUuid: vaultUuid)
    }

    /// Run one inspect pass. On `.conflictsPending` the detail + token are
    /// stashed for a subsequent `resolve`; every other arm clears any prior stash.
    public func runPass(password: [UInt8], nowMs: UInt64) async throws -> SyncOutcome {
        let outcome = try await port.sync(stateDir: stateDir, vaultFolder: vaultFolder,
                                          password: password, nowMs: nowMs)
        switch outcome {
        case let .conflictsPending(vetoes, collisions, manifestHash):
            stashedToken = manifestHash
            stashedConflict = PendingConflict(vetoes: vetoes, collisions: collisions)
        default:
            stashedToken = nil
            stashedConflict = nil
        }
        return outcome
    }

    /// Commit `decisions` against the stashed freshness token. Throws
    /// `.noPendingConflict` if `runPass` did not pause on a conflict.
    ///
    /// On a non-`conflictsPending` result the stash is cleared. On a thrown
    /// error (e.g. `.evidenceStale`) the stash is preserved so the caller can
    /// re-inspect and retry. If the recompute re-raises a conflict, the new
    /// detail replaces the old.
    public func resolve(decisions: [SyncVetoDecision],
                        password: [UInt8], nowMs: UInt64) async throws -> SyncOutcome {
        guard let token = stashedToken else { throw VaultSyncError.noPendingConflict }
        let outcome = try await port.commitDecisions(
            stateDir: stateDir, vaultFolder: vaultFolder, password: password,
            decisions: decisions, manifestHash: token, nowMs: nowMs)
        switch outcome {
        case let .conflictsPending(vetoes, collisions, manifestHash):
            stashedToken = manifestHash
            stashedConflict = PendingConflict(vetoes: vetoes, collisions: collisions)
        default:
            stashedToken = nil
            stashedConflict = nil
        }
        return outcome
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /Users/hherb/src/secretary/.worktrees/ios-sync-core/ios/SecretaryVaultAccess && swift test --filter SyncCoordinatorTests`
Expected: PASS (7 tests).

- [ ] **Step 5: Run the whole host suite (no regressions)**

Run: `cd /Users/hherb/src/secretary/.worktrees/ios-sync-core/ios/SecretaryVaultAccess && swift test`
Expected: PASS, all tests (the pre-existing ~103 + the new Sync* tests), 0 failures.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/ios-sync-core
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/SyncCoordinator.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/SyncCoordinatorTests.swift
git commit -m "feat(ios-sync): SyncCoordinator inspect→commit round-trip (TDD)"
```

---

## Task 3: `UniffiVaultSyncPort` real adapter + off-main-actor test

**Files:**
- Create: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/VaultSyncErrorMapping.swift`
- Create: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSyncPort.swift`
- Test: `ios/SecretaryKit/Tests/SecretaryKitTests/UniffiVaultSyncPortOffMainActorTests.swift`

> **Generated-symbol note.** The uniffi bindings (`syncStatus`, `syncVault`,
> `syncCommitDecisions`, the DTO types `SyncStatusDto` / `SyncOutcomeDto` /
> `DeviceClockDto` / `VetoDto` / `CollisionDto` / `VetoDecisionDto`, and the
> `VaultError` enum with its `Sync*` cases) are generated into the SecretaryFFI
> binary target and are reachable from inside `SecretaryKit`, exactly like the
> open adapter's `SecretaryKit.openVaultWithPassword`. The names below follow
> uniffi 0.31's deterministic UDL→Swift mapping (snake→camelCase; `bytes`→`Data`;
> `[Enum] interface`→Swift enum with associated values). If the build reports a
> different generated spelling, match the generated symbol — do not change the
> UDL. Build the framework first if not already present:
> `bash ios/scripts/run-ios-tests.sh` regenerates it.

- [ ] **Step 1: Write the error mapping**

Create `VaultSyncErrorMapping.swift`:

```swift
import SecretaryVaultAccess

/// Map the uniffi `VaultError` onto the pure `VaultSyncError`. `internal`, and
/// deliberately SEPARATE from `mapVaultAccessError` — the sync surface returns a
/// different `VaultError` variant set (the `Sync*` cases), and routing it through
/// the vault-access mapping would misattribute errors (see that function's doc).
///
/// `WrongPasswordOrCorrupt` is the core's anti-oracle conflation and maps 1:1;
/// do NOT split it.
internal func mapVaultSyncError(_ e: VaultError) -> VaultSyncError {
    switch e {
    case .WrongPasswordOrCorrupt:           return .wrongPasswordOrCorrupt
    case .SyncInProgress:                   return .inProgress
    case .SyncStateVaultMismatch:           return .stateVaultMismatch
    case .SyncStateCorrupt(let detail):     return .stateCorrupt(detail)
    case .SyncEvidenceStale:                return .evidenceStale
    case .SyncDecisionsIncomplete:          return .decisionsIncomplete
    case .InvalidArgument(let detail):      return .invalidArgument(detail)
    case .SyncFailed(let detail):           return .failed(detail)
    default:                                return .failed(String(describing: e))
    }
}
```

- [ ] **Step 2: Write the adapter**

Create `UniffiVaultSyncPort.swift`:

```swift
import Foundation
import SecretaryVaultAccess

/// Real `VaultSyncPort` over the uniffi sync functions (#187). `sync` and
/// `commitDecisions` re-open the identity from the password (full Argon2id), so
/// they run off the calling actor via `runOffMainActor` — exactly like
/// `UniffiVaultOpenPort` — keeping a `@MainActor` caller responsive. `status`
/// is a cheap disk read and runs inline.
public struct UniffiVaultSyncPort: VaultSyncPort {
    public init() {}

    public func status(stateDir: String, vaultUuid: [UInt8]) async throws -> SyncStatus {
        do {
            let dto = try SecretaryKit.syncStatus(stateDir: stateDir, vaultUuid: Data(vaultUuid))
            return Self.mapStatus(dto)
        } catch let e as VaultError {
            throw mapVaultSyncError(e)
        }
    }

    public func sync(stateDir: String, vaultFolder: String,
                     password: [UInt8], nowMs: UInt64) async throws -> SyncOutcome {
        try await runOffMainActor {
            do {
                let dto = try SecretaryKit.syncVault(
                    stateDir: stateDir, vaultFolder: vaultFolder,
                    password: Data(password), nowMs: nowMs)
                return Self.mapOutcome(dto)
            } catch let e as VaultError {
                throw mapVaultSyncError(e)
            }
        }
    }

    public func commitDecisions(stateDir: String, vaultFolder: String,
                                password: [UInt8], decisions: [SyncVetoDecision],
                                manifestHash: [UInt8], nowMs: UInt64) async throws -> SyncOutcome {
        try await runOffMainActor {
            do {
                let dtoDecisions = decisions.map {
                    VetoDecisionDto(recordUuidHex: $0.recordUuidHex, keepLocal: $0.keepLocal)
                }
                let dto = try SecretaryKit.syncCommitDecisions(
                    stateDir: stateDir, vaultFolder: vaultFolder, password: Data(password),
                    decisions: dtoDecisions, manifestHash: Data(manifestHash), nowMs: nowMs)
                return Self.mapOutcome(dto)
            } catch let e as VaultError {
                throw mapVaultSyncError(e)
            }
        }
    }

    // MARK: - DTO → pure value type mapping

    private static func mapStatus(_ s: SyncStatusDto) -> SyncStatus {
        SyncStatus(
            hasState: s.hasState,
            deviceClocks: s.deviceClocks.map {
                DeviceClock(deviceUuidHex: $0.deviceUuidHex, counter: $0.counter)
            },
            lastStateWriteMs: s.lastStateWriteMs)
    }

    private static func mapVeto(_ v: VetoDto) -> SyncVeto {
        SyncVeto(recordUuidHex: v.recordUuidHex, recordType: v.recordType, tags: v.tags,
                 fieldNames: v.fieldNames, localLastModMs: v.localLastModMs,
                 peerTombstonedAtMs: v.peerTombstonedAtMs, peerDeviceHex: v.peerDeviceHex)
    }

    private static func mapCollision(_ c: CollisionDto) -> SyncCollision {
        SyncCollision(recordUuidHex: c.recordUuidHex, fieldNames: c.fieldNames)
    }

    private static func mapOutcome(_ o: SyncOutcomeDto) -> SyncOutcome {
        switch o {
        case .nothingToDo:          return .nothingToDo
        case .appliedAutomatically: return .appliedAutomatically
        case .silentMerge:          return .silentMerge
        case .mergedClean:          return .mergedClean
        case .rollbackRejected:     return .rollbackRejected
        case let .conflictsPending(vetoes, collisions, manifestHash):
            return .conflictsPending(
                vetoes: vetoes.map(mapVeto),
                collisions: collisions.map(mapCollision),
                manifestHash: [UInt8](manifestHash))
        }
    }
}
```

- [ ] **Step 3: Write the off-main-actor adapter test**

This proves the coordinator-over-adapter stays off the main actor during a
(faked-slow) sync, mirroring `RunOffMainActorTests` / `testMainActorIsFreeWhileOpening`.
It uses the `FakeVaultSyncPort` + `SuspensionGate` (the real FFI offload is identical
plumbing to the open path already shipped in #227; this guards the sync wiring).

Create `UniffiVaultSyncPortOffMainActorTests.swift`:

```swift
import XCTest
@testable import SecretaryKit
import SecretaryVaultAccess
import SecretaryVaultAccessTesting

final class UniffiVaultSyncPortOffMainActorTests: XCTestCase {
    /// While a sync pass is suspended mid-call, the main actor must remain free
    /// to run work. Against a synchronous-on-main-actor regression this would
    /// deadlock → XCTest timeout (a hung test is still a red CI).
    @MainActor
    func testMainActorIsFreeWhileSyncing() async throws {
        let gate = SuspensionGate()
        let port = FakeVaultSyncPort(syncResult: .success(.nothingToDo))
        port.gate = gate
        let coord = SyncCoordinator(port: port, stateDir: "/tmp/s", vaultFolder: "/tmp/v")

        let task = Task { try await coord.runPass(password: [1, 2, 3], nowMs: 0) }
        await gate.waitUntilEntered()       // sync is in flight, suspended
        // We reached here on the main actor while the pass is mid-call ⇒ not blocked.
        var ran = false
        ran = true
        XCTAssertTrue(ran)
        gate.release()
        let outcome = try await task.value
        XCTAssertEqual(outcome, .nothingToDo)
    }
}
```

- [ ] **Step 4: Build the framework + run the SecretaryKit suite**

Run: `cd /Users/hherb/src/secretary/.worktrees/ios-sync-core && bash ios/scripts/run-ios-tests.sh`
Expected: `** TEST SUCCEEDED **` + `** BUILD SUCCEEDED **`. The new
`UniffiVaultSyncPortOffMainActorTests` passes; `UniffiVaultSyncPort` compiles against
the generated bindings. If a generated symbol name differs, fix the adapter to match
(see the generated-symbol note) and re-run.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/ios-sync-core
git add ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/VaultSyncErrorMapping.swift \
        ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSyncPort.swift \
        ios/SecretaryKit/Tests/SecretaryKitTests/UniffiVaultSyncPortOffMainActorTests.swift
git commit -m "feat(ios-sync): UniffiVaultSyncPort adapter + off-main-actor test"
```

---

## Task 4: Docs + handoff

**Files:**
- Modify: `README.md`
- Modify: `ROADMAP.md`
- Create: `docs/handoffs/2026-06-15-c3-ios-sync-orchestration-core-shipped.md`
- Retarget: `NEXT_SESSION.md` symlink

- [ ] **Step 1: Update README**

Add a row/line to the iOS status section noting the iOS sync orchestration core
(pure ports + `SyncCoordinator` + uniffi adapter; manual trigger; no file detection/UI
yet). Keep it brief per the README style (dot points, no test-count walls).

- [ ] **Step 2: Update ROADMAP**

Under C.3, mark the iOS orchestration-core slice done and note the remaining iOS work
(file-change detection via `NSFilePresenter`/`NSMetadataQuery`; UI) + Android still
pending. Bump any progress indicator consistently with existing entries.

- [ ] **Step 3: Write the handoff + retarget the symlink**

Author `docs/handoffs/2026-06-15-c3-ios-sync-orchestration-core-shipped.md` covering
(1) what shipped with commit SHAs, (2) next slice with acceptance, (3) open
decisions/risks, (4) resume commands. Then:

```bash
cd /Users/hherb/src/secretary/.worktrees/ios-sync-core
ln -snf docs/handoffs/2026-06-15-c3-ios-sync-orchestration-core-shipped.md NEXT_SESSION.md
ls -la NEXT_SESSION.md   # shows the -> target
head -3 NEXT_SESSION.md  # reads handoff content transparently
```

- [ ] **Step 4: Final gauntlet**

```bash
cd /Users/hherb/src/secretary/.worktrees/ios-sync-core
( cd ios/SecretaryVaultAccess && swift test )                 # all host tests green
bash ios/scripts/run-ios-tests.sh                             # SecretaryKit sim + app build
git diff main...HEAD --name-only | grep -vE '^(ios/|docs/|README.md|ROADMAP.md)'   # expect empty
git diff main...HEAD --name-only | grep -E 'core/|ffi/|crypto-design|vault-format|conflict.rs|core/tests/data'  # expect empty
```
Expected: host suite green; `** TEST SUCCEEDED **` + `** BUILD SUCCEEDED **`; both
greps print nothing.

- [ ] **Step 5: Commit + open PR**

```bash
cd /Users/hherb/src/secretary/.worktrees/ios-sync-core
git add README.md ROADMAP.md docs/handoffs/ NEXT_SESSION.md
git commit -m "docs(ios-sync): README + ROADMAP + handoff for iOS sync orchestration core"
git push -u origin feature/ios-sync-core
gh pr create --title "iOS C.3 slice 1: sync orchestration core" --body "<summary>"
```

---

## Self-Review Notes

- **Spec coverage:** §4a value types → Task 1; §4a port → Task 1; §4b fake → Task 1;
  §4d `SyncCoordinator` → Task 2; §4c adapter + error mapping → Task 3; §5 off-main-actor
  → Task 3 (helper reuse) + adapter test; §6 tests → Tasks 1–3; §8 acceptance → Task 4
  gauntlet; docs → Task 4.
- **Refinement vs spec:** spec §4c said "extend `VaultAccessError`"; this plan uses a
  dedicated `VaultSyncError` + `mapVaultSyncError` instead — required because the existing
  `mapVaultAccessError`'s doc forbids sync reuse, and matches the `VaultSelectionError`
  precedent. Cleaner, same behaviour.
- **Type consistency:** `SyncOutcome` arms identical across Tasks 1/2/3; `VaultSyncError`
  cases identical across Tasks 1/3; `PendingConflict`/`SyncVetoDecision`/`SyncVeto` field
  names consistent throughout.
- **No placeholders:** every code step is complete; the only `<...>` is the PR body /
  README wording, authored at Task 4 from the shipped detail.
