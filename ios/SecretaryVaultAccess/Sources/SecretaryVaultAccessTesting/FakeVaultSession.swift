import Foundation
import SecretaryVaultAccess

/// In-memory `VaultSession` for host tests. `recordsByBlock` is keyed by raw
/// block uuid bytes. Records reveal-call deferral via whatever closures the
/// test installs on its `FieldView`s; this fake only counts reads + wipes.
public final class FakeVaultSession: VaultSession {
    public let vaultUuidHex: String
    private let blocks: [BlockSummary]
    private let recordsByBlock: [[UInt8]: [RecordView]]
    public private(set) var readCount = 0
    public private(set) var wipeCount = 0

    public init(vaultUuidHex: String,
                blocks: [BlockSummary],
                recordsByBlock: [[UInt8]: [RecordView]]) {
        self.vaultUuidHex = vaultUuidHex
        self.blocks = blocks
        self.recordsByBlock = recordsByBlock
    }

    public func blockSummaries() -> [BlockSummary] { blocks }

    public func readBlock(blockUuid: [UInt8]) throws -> [RecordView] {
        readCount += 1
        guard let records = recordsByBlock[blockUuid] else {
            let hex = blockUuid.map { String(format: "%02x", $0) }.joined()
            throw VaultAccessError.blockNotFound(hex)
        }
        return records
    }

    public func wipe() { wipeCount += 1 }
}
