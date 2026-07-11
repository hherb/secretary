import Foundation

/// Read-only metadata for one trashed block. No secret material — the block
/// name is plaintext in the manifest; record content never leaves the core.
public struct TrashedBlockInfo: Equatable {
    public let blockUuid: [UInt8]
    public let blockName: String
    public let tombstonedAtMs: UInt64
    public let tombstonedBy: [UInt8]

    public init(blockUuid: [UInt8], blockName: String,
                tombstonedAtMs: UInt64, tombstonedBy: [UInt8]) {
        self.blockUuid = blockUuid
        self.blockName = blockName
        self.tombstonedAtMs = tombstonedAtMs
        self.tombstonedBy = tombstonedBy
    }

    /// Lowercase hex, no dashes — stable SwiftUI list identity.
    public var uuidHex: String { blockUuid.map { String(format: "%02x", $0) }.joined() }
}

/// One trash entry eligible for retention auto-purge (preview only).
public struct ExpiredEntryInfo: Equatable {
    public let blockUuid: [UInt8]
    public let tombstonedAtMs: UInt64
    public let ageMs: UInt64

    public init(blockUuid: [UInt8], tombstonedAtMs: UInt64, ageMs: UInt64) {
        self.blockUuid = blockUuid
        self.tombstonedAtMs = tombstonedAtMs
        self.ageMs = ageMs
    }
}

/// Aggregate outcome of a retention auto-purge commit. Counts only.
public struct RetentionReportInfo: Equatable {
    public let purgedCount: UInt32
    public let sharedCount: UInt32
    public let ownerOnlyCount: UInt32
    public let unknownCount: UInt32
    public let filesRemoved: UInt32
    public let filesFailed: UInt32
    public let windowMs: UInt64

    public init(purgedCount: UInt32, sharedCount: UInt32, ownerOnlyCount: UInt32,
                unknownCount: UInt32, filesRemoved: UInt32, filesFailed: UInt32,
                windowMs: UInt64) {
        self.purgedCount = purgedCount
        self.sharedCount = sharedCount
        self.ownerOnlyCount = ownerOnlyCount
        self.unknownCount = unknownCount
        self.filesRemoved = filesRemoved
        self.filesFailed = filesFailed
        self.windowMs = windowMs
    }
}

/// Outcome of a single-block purge.
public struct PurgeResultInfo: Equatable {
    public let blockUuid: [UInt8]
    public let wasShared: Bool?
    public let recipientCount: UInt16?
    public let filesRemoved: UInt32

    public init(blockUuid: [UInt8], wasShared: Bool?,
                recipientCount: UInt16?, filesRemoved: UInt32) {
        self.blockUuid = blockUuid
        self.wasShared = wasShared
        self.recipientCount = recipientCount
        self.filesRemoved = filesRemoved
    }
}

/// Aggregate outcome of an empty-trash batch. Counts only.
public struct EmptyTrashReportInfo: Equatable {
    public let purgedCount: UInt32
    public let sharedCount: UInt32
    public let ownerOnlyCount: UInt32
    public let unknownCount: UInt32
    public let filesRemoved: UInt32
    public let filesFailed: UInt32

    public init(purgedCount: UInt32, sharedCount: UInt32, ownerOnlyCount: UInt32,
                unknownCount: UInt32, filesRemoved: UInt32, filesFailed: UInt32) {
        self.purgedCount = purgedCount
        self.sharedCount = sharedCount
        self.ownerOnlyCount = ownerOnlyCount
        self.unknownCount = unknownCount
        self.filesRemoved = filesRemoved
        self.filesFailed = filesFailed
    }
}

/// The vault-trash operations a Trash browser needs. Conformed by the
/// `SecretaryKit` adapter (`UniffiVaultSession`) and by `FakeTrashPort` in
/// tests. `AnyObject, Sendable` mirrors `VaultSession` (reference identity
/// for handle ownership; crosses the gate's async boundary).
public protocol TrashPort: AnyObject, Sendable {
    /// All not-yet-purged trashed blocks, projected by name.
    func listTrashedBlocks() throws -> [TrashedBlockInfo]
    /// Retention preview for `windowMs` (adapter supplies `now`). Non-throwing.
    func expiredTrashEntries(windowMs: UInt64) -> [ExpiredEntryInfo]
    /// The frozen default retention window (90 days).
    func defaultRetentionWindowMs() -> UInt64
    /// Restore the newest trashed copy of a block.
    func restoreBlock(uuid: [UInt8]) throws
    /// Permanently purge one trashed block.
    func purgeBlock(uuid: [UInt8]) throws -> PurgeResultInfo
    /// Permanently purge every currently-trashed block.
    func emptyTrash() throws -> EmptyTrashReportInfo
    /// Permanently purge every trashed block older than `windowMs`.
    func autoPurgeExpired(windowMs: UInt64) throws -> RetentionReportInfo
}
