import Foundation
import SecretaryVaultAccess

/// `VaultSyncPort` conformance for `UniffiVaultSession` (#101): sync runs
/// through this session's own identity + manifest handles, so a Face ID session
/// syncs exactly like a password one and no password is ever re-entered.
///
/// Every handle access goes through `withLiveHandles` (lock + wiped-guard), the
/// `+Trash.swift` discipline. `sync`/`commitDecisions` do disk I/O and crypto, so
/// they run in `runOffMainActor`; they hold the session lock for the pass, which
/// also stops a concurrent write from racing the handle refresh.
///
/// The bridge refreshes the manifest handle itself on every outcome except
/// `.rollbackRejected` / `.conflictsPending`. If the pass succeeded but the
/// refresh failed it throws (mapped to `VaultSyncError`), the handle is
/// unchanged, and a retry is safe (see `VaultSyncPort`).
extension UniffiVaultSession: VaultSyncPort {
    private static let wipedError = VaultSyncError.failed("sync on a wiped session")

    public func status(stateDir: String, vaultUuid: [UInt8]) async throws -> SyncStatus {
        do {
            let dto = try SecretaryKit.syncStatus(stateDir: stateDir, vaultUuid: Data(vaultUuid))
            return Self.mapStatus(dto)
        } catch let e as VaultError {
            throw mapVaultSyncError(e)
        }
    }

    public func sync(stateDir: String, nowMs: UInt64) async throws -> SyncOutcome {
        try await runOffMainActor {
            try self.syncLocked { identity, manifest, dev in
                try SecretaryKit.syncVaultWithSession(
                    stateDir: stateDir, identity: identity, manifest: manifest,
                    deviceUuid: dev, nowMs: nowMs)
            }
        }
    }

    public func commitDecisions(stateDir: String, decisions: [SyncVetoDecision],
                                manifestHash: [UInt8], nowMs: UInt64) async throws -> SyncOutcome {
        let dtoDecisions = decisions.map {
            VetoDecisionDto(recordUuidHex: $0.recordUuidHex, keepLocal: $0.keepLocal)
        }
        return try await runOffMainActor {
            try self.syncLocked { identity, manifest, dev in
                try SecretaryKit.syncCommitDecisionsWithSession(
                    stateDir: stateDir, identity: identity, manifest: manifest,
                    decisions: dtoDecisions, manifestHash: Data(manifestHash),
                    deviceUuid: dev, nowMs: nowMs)
            }
        }
    }

    /// `VaultSession.refreshFromDisk`: re-read the manifest into this session's
    /// handle, rollback-guarded by the sync state in `stateDir`. Maps onto
    /// `VaultAccessError` like every other `VaultSession` call.
    public func refreshFromDisk(stateDir: String) throws {
        try readMapped {
            try SecretaryKit.refreshManifest(stateDir: stateDir, identity: identity, manifest: manifest)
        }
    }

    /// Run a session sync call on the live handles under the lock, mapping its
    /// `VaultError` onto `VaultSyncError` and its DTO onto `SyncOutcome`. The
    /// body gets this vault's device UUID, the one writes tick: a merge ticks it
    /// on the vector clocks (#744). A device-UUID store failure is `.failed`.
    private func syncLocked(
        _ body: (UnlockedIdentity, OpenVaultManifest, Data) throws -> SyncOutcomeDto
    ) throws -> SyncOutcome {
        do {
            return Self.mapOutcome(try withLiveHandles(onWiped: Self.wipedError) {
                let dev: [UInt8]
                do {
                    dev = try deviceUuid()
                } catch {
                    throw VaultSyncError.failed(
                        "device-uuid resolve failed: \(diagnosticDetail(error))")
                }
                return try body(identity, manifest, Data(dev))
            })
        } catch let e as VaultError {
            throw mapVaultSyncError(e)
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
