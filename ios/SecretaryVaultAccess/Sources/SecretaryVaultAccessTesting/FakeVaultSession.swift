import Foundation
import SecretaryVaultAccess

/// In-memory `VaultSession` for host tests. `recordsByBlock` is mutable so the
/// write methods model real add/edit/delete/restore state transitions. Field
/// `reveal` closures capture the stored plaintext.
public final class FakeVaultSession: VaultSession {
    public let vaultUuidHex: String
    private let blocks: [BlockSummary]
    private var recordsByBlock: [[UInt8]: [RecordView]]
    private var nextUuidByte: UInt8 = 0xA0
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
            throw VaultAccessError.blockNotFound(hex(blockUuid))
        }
        return records
    }

    @discardableResult
    public func appendRecord(blockUuid: [UInt8], content: RecordContentInput) throws -> [UInt8] {
        try requireBlock(blockUuid)
        let uuid = mintUuid()
        recordsByBlock[blockUuid]?.append(recordView(uuid: uuid, content: content, tombstone: false))
        return uuid
    }

    public func editRecord(blockUuid: [UInt8], recordUuid: [UInt8], content: RecordContentInput) throws {
        let idx = try liveIndex(blockUuid, recordUuid)
        recordsByBlock[blockUuid]?[idx] = recordView(uuid: recordUuid, content: content, tombstone: false)
    }

    public func tombstoneRecord(blockUuid: [UInt8], recordUuid: [UInt8]) throws {
        let idx = try liveIndex(blockUuid, recordUuid)
        setTombstone(blockUuid, idx, true)
    }

    public func resurrectRecord(blockUuid: [UInt8], recordUuid: [UInt8]) throws {
        try requireBlock(blockUuid)
        guard let idx = recordsByBlock[blockUuid]?.firstIndex(
            where: { $0.uuid == recordUuid && $0.tombstone }) else {
            throw VaultAccessError.recordNotFound(hex(recordUuid))
        }
        setTombstone(blockUuid, idx, false)
    }

    public func wipe() { wipeCount += 1 }

    // MARK: - helpers

    private func requireBlock(_ blockUuid: [UInt8]) throws {
        guard recordsByBlock[blockUuid] != nil else {
            throw VaultAccessError.blockNotFound(hex(blockUuid))
        }
    }

    private func liveIndex(_ blockUuid: [UInt8], _ recordUuid: [UInt8]) throws -> Int {
        try requireBlock(blockUuid)
        guard let idx = recordsByBlock[blockUuid]?.firstIndex(
            where: { $0.uuid == recordUuid && !$0.tombstone }) else {
            throw VaultAccessError.recordNotFound(hex(recordUuid))
        }
        return idx
    }

    private func setTombstone(_ blockUuid: [UInt8], _ idx: Int, _ value: Bool) {
        guard let old = recordsByBlock[blockUuid]?[idx] else { return }
        recordsByBlock[blockUuid]?[idx] = RecordView(
            uuid: old.uuid, type: old.type, tags: old.tags, fields: old.fields, tombstone: value)
    }

    private func recordView(uuid: [UInt8], content: RecordContentInput, tombstone: Bool) -> RecordView {
        let fields = content.fields.map { f -> FieldView in
            switch f.value {
            case .text(let s):
                return FieldView(name: f.name, kind: .text) { .text(s) }
            case .bytes(let b):
                return FieldView(name: f.name, kind: .bytes) { .bytes(b) }
            }
        }
        return RecordView(uuid: uuid, type: content.recordType, tags: content.tags,
                          fields: fields, tombstone: tombstone)
    }

    private func mintUuid() -> [UInt8] {
        let b = nextUuidByte
        nextUuidByte = nextUuidByte &+ 1
        return [UInt8](repeating: b, count: 16)
    }

    private func hex(_ bytes: [UInt8]) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
}
