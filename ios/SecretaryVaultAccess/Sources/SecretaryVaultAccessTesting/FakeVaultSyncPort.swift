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
