import SecretaryVaultAccess

/// In-memory `TrashPort` double with spies + write-failure injection,
/// modeled on `FakeVaultSession`.
public final class FakeTrashPort: TrashPort, @unchecked Sendable {
    public var trashedBlocks: [TrashedBlockInfo]
    public var expiredEntries: [ExpiredEntryInfo]
    public var defaultWindowMs: UInt64
    public var emptyTrashFilesFailed: UInt32 = 0
    public var failNextWrite: VaultAccessError?

    public private(set) var listCount = 0
    public private(set) var previewCount = 0
    public private(set) var restoredUuids: [[UInt8]] = []
    public private(set) var purgedUuids: [[UInt8]] = []
    public private(set) var emptyTrashCount = 0
    public private(set) var autoPurgeWindows: [UInt64] = []

    public init(trashedBlocks: [TrashedBlockInfo] = [],
                expiredEntries: [ExpiredEntryInfo] = [],
                defaultWindowMs: UInt64 = 90 * 86_400_000) {
        self.trashedBlocks = trashedBlocks
        self.expiredEntries = expiredEntries
        self.defaultWindowMs = defaultWindowMs
    }

    private func throwIfInjected() throws {
        if let e = failNextWrite { failNextWrite = nil; throw e }
    }

    public func listTrashedBlocks() throws -> [TrashedBlockInfo] {
        listCount += 1
        return trashedBlocks
    }

    public func expiredTrashEntries(windowMs: UInt64) -> [ExpiredEntryInfo] {
        previewCount += 1
        return expiredEntries
    }

    public func defaultRetentionWindowMs() -> UInt64 { defaultWindowMs }

    public func restoreBlock(uuid: [UInt8]) throws {
        try throwIfInjected()
        restoredUuids.append(uuid)
        trashedBlocks.removeAll { $0.blockUuid == uuid }
    }

    public func purgeBlock(uuid: [UInt8]) throws -> PurgeResultInfo {
        try throwIfInjected()
        purgedUuids.append(uuid)
        trashedBlocks.removeAll { $0.blockUuid == uuid }
        return PurgeResultInfo(blockUuid: uuid, wasShared: false,
                               recipientCount: 0, filesRemoved: 1)
    }

    public func emptyTrash() throws -> EmptyTrashReportInfo {
        try throwIfInjected()
        emptyTrashCount += 1
        let n = UInt32(trashedBlocks.count)
        trashedBlocks.removeAll()
        return EmptyTrashReportInfo(purgedCount: n, sharedCount: 0, ownerOnlyCount: n,
                                    unknownCount: 0, filesRemoved: n, filesFailed: emptyTrashFilesFailed)
    }

    public func autoPurgeExpired(windowMs: UInt64) throws -> RetentionReportInfo {
        try throwIfInjected()
        autoPurgeWindows.append(windowMs)
        let n = UInt32(expiredEntries.count)
        return RetentionReportInfo(purgedCount: n, sharedCount: 0, ownerOnlyCount: n,
                                   unknownCount: 0, filesRemoved: n, filesFailed: 0,
                                   windowMs: windowMs)
    }
}
