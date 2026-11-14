import Foundation

/// Runs sync operations over the (FFI) sync surface, through the OPEN session
/// (#101): no password and no folder cross this boundary, so a Face ID session
/// syncs exactly like a password one. Implementations throw `VaultSyncError`.
///
/// After a pass the real conformer has already refreshed the session's manifest
/// handle from disk, so the next write sees the merged state. It never refreshes
/// on `.rollbackRejected` or `.conflictsPending`. If the pass succeeded but the
/// refresh failed (typically iCloud still delivering block files), the call
/// THROWS and the handle is unchanged. Retrying is safe, but it does not always
/// recover: after a `.silentMerge` the persisted clock dominates the disk, so the
/// repeat pass is `.rollbackRejected` and does not refresh (#730).
///
/// `sync`/`commitDecisions` do disk I/O and crypto, so the real conformer offloads
/// them off the calling actor (`SecretaryKit.runOffMainActor`). `status` is a
/// cheap disk read run inline on the conformer's own executor.
///
/// `Sendable` because the `SyncCoordinator` actor holds a conformer and reaches
/// it across its actor boundary on every `async` call (#231).
public protocol VaultSyncPort: Sendable {
    func status(stateDir: String, vaultUuid: [UInt8]) async throws -> SyncStatus
    func sync(stateDir: String, nowMs: UInt64) async throws -> SyncOutcome
    func commitDecisions(stateDir: String, decisions: [SyncVetoDecision],
                         manifestHash: [UInt8], nowMs: UInt64) async throws -> SyncOutcome
}
