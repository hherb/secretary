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
