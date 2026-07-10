import Foundation
import SecretaryVaultAccess

/// `TrashPort` conformance for `UniffiVaultSession`. Reuses the internal
/// `write`/`readTrash`/`readTrashInfallible`/`writeTrashReturning`/`deviceUuid`/
/// `mapVaultAccessError` helpers so trash writes get the same device-uuid/now
/// resolution, wiped-guard, and error mapping as every other write. Only block
/// names + counts cross this boundary — no record plaintext (guaranteed by the
/// bridge; this adapter never calls a decrypt/read-record FFI function).
extension UniffiVaultSession: TrashPort {
    public func listTrashedBlocks() throws -> [TrashedBlockInfo] {
        try readTrash {
            try SecretaryKit.listTrashedBlocks(identity: identity, manifest: manifest)
                .map { b in
                    TrashedBlockInfo(blockUuid: [UInt8](b.blockUuid),
                                      blockName: b.blockName,
                                      tombstonedAtMs: b.tombstonedAtMs,
                                      tombstonedBy: [UInt8](b.tombstonedBy))
                }
        }
    }

    public func expiredTrashEntries(windowMs: UInt64) -> [ExpiredEntryInfo] {
        readTrashInfallible {
            SecretaryKit.expiredTrashEntries(
                manifest: manifest, windowMs: windowMs, nowMs: Self.nowMsPublic())
                .map { e in
                    ExpiredEntryInfo(blockUuid: [UInt8](e.blockUuid),
                                      tombstonedAtMs: e.tombstonedAtMs, ageMs: e.ageMs)
                }
        }
    }

    public func defaultRetentionWindowMs() -> UInt64 {
        SecretaryKit.defaultRetentionWindowMs()
    }

    public func restoreBlock(uuid: [UInt8]) throws {
        try writeTrash { dev, now in
            try SecretaryKit.restoreBlock(
                identity: identity, manifest: manifest, blockUuid: Data(uuid),
                deviceUuid: Data(dev), nowMs: now)
        }
    }

    public func purgeBlock(uuid: [UInt8]) throws -> PurgeResultInfo {
        try writeTrashReturning { dev, now in
            let r = try SecretaryKit.purgeBlock(
                identity: identity, manifest: manifest, blockUuid: Data(uuid),
                deviceUuid: Data(dev), nowMs: now)
            return PurgeResultInfo(blockUuid: [UInt8](r.blockUuid), wasShared: r.wasShared,
                                    recipientCount: r.recipientCount, filesRemoved: r.filesRemoved)
        }
    }

    public func emptyTrash() throws -> EmptyTrashReportInfo {
        try writeTrashReturning { dev, now in
            let r = try SecretaryKit.emptyTrash(
                identity: identity, manifest: manifest, deviceUuid: Data(dev), nowMs: now)
            return EmptyTrashReportInfo(
                purgedCount: r.purgedCount, sharedCount: r.sharedCount,
                ownerOnlyCount: r.ownerOnlyCount, unknownCount: r.unknownCount,
                filesRemoved: r.filesRemoved, filesFailed: r.filesFailed)
        }
    }

    public func autoPurgeExpired(windowMs: UInt64) throws -> RetentionReportInfo {
        try writeTrashReturning { dev, now in
            let r = try SecretaryKit.autoPurgeExpired(
                identity: identity, manifest: manifest, windowMs: windowMs,
                nowMs: now, deviceUuid: Data(dev))
            return RetentionReportInfo(
                purgedCount: r.purgedCount, sharedCount: r.sharedCount,
                ownerOnlyCount: r.ownerOnlyCount, unknownCount: r.unknownCount,
                filesRemoved: r.filesRemoved, filesFailed: r.filesFailed, windowMs: r.windowMs)
        }
    }
}
