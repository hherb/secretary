import Foundation
import SecretaryVaultAccess

/// Real `VaultSyncPort` over the uniffi sync functions (#187). `sync` and
/// `commitDecisions` re-open the identity from the password (full Argon2id), so
/// they run off the calling actor via `runOffMainActor` — exactly like
/// `UniffiVaultOpenPort` — keeping a `@MainActor` caller responsive. `status`
/// is a cheap disk read and runs inline (no `runOffMainActor`): under
/// `SyncCoordinator` (a plain `actor`) that still executes on the cooperative
/// pool, never the main thread.
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
                let dto = try withZeroizingData(password) { pw in
                    try SecretaryKit.syncVault(
                        stateDir: stateDir, vaultFolder: vaultFolder,
                        password: pw, nowMs: nowMs)
                }
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
                let dto = try withZeroizingData(password) { pw in
                    try SecretaryKit.syncCommitDecisions(
                        stateDir: stateDir, vaultFolder: vaultFolder, password: pw,
                        decisions: dtoDecisions, manifestHash: Data(manifestHash), nowMs: nowMs)
                }
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
