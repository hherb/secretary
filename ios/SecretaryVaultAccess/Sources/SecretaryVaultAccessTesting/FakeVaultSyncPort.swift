import Foundation
import SecretaryVaultAccess

/// In-memory `VaultSyncPort` returning pre-seeded results and spying on inputs.
/// Mirrors `FakeVaultOpenPort`'s convention.
///
/// `@unchecked Sendable`: mutable spy state satisfying the (now `Sendable`) port
/// protocol. Safe because XCTest drives it serially through `await`; the
/// assumption is stated, not hidden (#231).
public final class FakeVaultSyncPort: VaultSyncPort, @unchecked Sendable {
    /// Settable so one test can fail a later status read.
    public var statusResult: Result<SyncStatus, VaultSyncError>
    /// Settable so one test can run two passes with different outcomes.
    public var syncResult: Result<SyncOutcome, VaultSyncError>
    private let commitResult: Result<SyncOutcome, VaultSyncError>

    /// Spies for assertions.
    public private(set) var statusCalls = 0
    public private(set) var syncCalls = 0
    public private(set) var commitCalls = 0
    public private(set) var lastCommitDecisions: [SyncVetoDecision]?
    public private(set) var lastCommitManifestHash: [UInt8]?
    public private(set) var lastStatusVaultUuid: [UInt8]?
    public private(set) var lastSyncStateDir: String?
    public private(set) var lastCommitStateDir: String?

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
        lastStatusVaultUuid = vaultUuid
        return try statusResult.get()
    }

    public func sync(stateDir: String, nowMs: UInt64) async throws -> SyncOutcome {
        syncCalls += 1
        lastSyncStateDir = stateDir
        await gate?.enterAndWait()
        return try syncResult.get()
    }

    public func commitDecisions(stateDir: String, decisions: [SyncVetoDecision],
                                manifestHash: [UInt8], nowMs: UInt64) async throws -> SyncOutcome {
        commitCalls += 1
        lastCommitDecisions = decisions
        lastCommitManifestHash = manifestHash
        lastCommitStateDir = stateDir
        await gate?.enterAndWait()
        return try commitResult.get()
    }
}
