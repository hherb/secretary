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
        stash(from: outcome)
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
        stash(from: outcome)
        return outcome
    }

    /// Update the stash from a pass outcome: keep the token + detail on a
    /// conflict, clear both on any resolved arm.
    private func stash(from outcome: SyncOutcome) {
        switch outcome {
        case let .conflictsPending(vetoes, collisions, manifestHash):
            stashedToken = manifestHash
            stashedConflict = PendingConflict(vetoes: vetoes, collisions: collisions)
        default:
            stashedToken = nil
            stashedConflict = nil
        }
    }
}
