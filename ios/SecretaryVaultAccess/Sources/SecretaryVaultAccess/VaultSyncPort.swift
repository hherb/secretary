import Foundation

/// Runs sync operations over the (FFI) sync surface. Implementations throw
/// `VaultSyncError`.
///
/// All methods are `async` because the real `sync`/`commitDecisions` re-open the
/// identity from the password and pay the full Argon2id cost; the real adapter
/// offloads them off the calling actor (see `SecretaryKit.runOffMainActor`) so a
/// `@MainActor` caller stays responsive. `status` is a cheap disk read and the
/// real adapter runs its FFI call inline (no `runOffMainActor`); "inline" means
/// on the adapter's own async executor, not the caller's — driven through
/// `SyncCoordinator` (a plain `actor`, not `@MainActor`) it executes on the
/// cooperative pool, so even the synchronous read never lands on the main thread.
/// `async` is also kept for protocol uniformity.
///
/// `password` is passed per call and never retained by callers.
///
/// `Sendable` because the `SyncCoordinator` actor holds a conformer and reaches
/// it across its actor boundary on every `async` call (#231).
public protocol VaultSyncPort: Sendable {
    func status(stateDir: String, vaultUuid: [UInt8]) async throws -> SyncStatus
    func sync(stateDir: String, vaultFolder: String,
              password: [UInt8], nowMs: UInt64) async throws -> SyncOutcome
    func commitDecisions(stateDir: String, vaultFolder: String,
                         password: [UInt8], decisions: [SyncVetoDecision],
                         manifestHash: [UInt8], nowMs: UInt64) async throws -> SyncOutcome
}
