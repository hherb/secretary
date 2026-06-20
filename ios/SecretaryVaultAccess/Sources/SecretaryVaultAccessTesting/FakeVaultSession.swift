import Foundation
import SecretaryVaultAccess

/// In-memory `VaultSession` for host tests. `recordsByBlock` is mutable so the
/// write methods model real add/edit/delete/restore state transitions. Field
/// `reveal` closures capture the stored plaintext.
public final class FakeVaultSession: VaultSession {
    public let vaultUuidHex: String
    private var blocks: [BlockSummary]
    private var recordsByBlock: [[UInt8]: [RecordView]]
    private var nextUuidByte: UInt8 = 0xA0
    public private(set) var readCount = 0
    public private(set) var wipeCount = 0
    /// Spy: the includeDeleted value passed to the most recent readBlock.
    public private(set) var lastIncludeDeleted = false
    /// Test seam: when set, the NEXT create/rename/move throws this once, then clears.
    public var failNextWrite: VaultAccessError?

    public init(vaultUuidHex: String,
                blocks: [BlockSummary],
                recordsByBlock: [[UInt8]: [RecordView]]) {
        self.vaultUuidHex = vaultUuidHex
        self.blocks = blocks
        self.recordsByBlock = recordsByBlock
    }

    public func blockSummaries() -> [BlockSummary] { blocks }

    public func readBlock(blockUuid: [UInt8], includeDeleted: Bool) throws -> [RecordView] {
        readCount += 1
        lastIncludeDeleted = includeDeleted
        guard let records = recordsByBlock[blockUuid] else {
            throw VaultAccessError.blockNotFound(hex(blockUuid))
        }
        // Model the Rust gate: withhold tombstoned records unless asked.
        return includeDeleted ? records : records.filter { !$0.tombstone }
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

    @discardableResult
    public func createBlock(blockName: String) throws -> [UInt8] {
        try throwIfInjected()
        let uuid = mintUuid()
        blocks.append(BlockSummary(uuid: uuid, name: blockName, createdAtMs: 0, lastModMs: 0))
        recordsByBlock[uuid] = []
        return uuid
    }

    public func renameBlock(blockUuid: [UInt8], newName: String) throws {
        try throwIfInjected()
        guard let idx = blocks.firstIndex(where: { $0.uuid == blockUuid }) else {
            throw VaultAccessError.blockNotFound(hex(blockUuid))
        }
        let old = blocks[idx]
        blocks[idx] = BlockSummary(uuid: old.uuid, name: newName,
                                   createdAtMs: old.createdAtMs, lastModMs: old.lastModMs)
    }

    @discardableResult
    public func moveRecord(sourceBlockUuid: [UInt8], targetBlockUuid: [UInt8],
                           sourceRecordUuid: [UInt8]) throws -> [UInt8] {
        try throwIfInjected()
        let idx = try liveIndex(sourceBlockUuid, sourceRecordUuid)
        try requireBlock(targetBlockUuid)
        guard let src = recordsByBlock[sourceBlockUuid]?[idx] else {
            throw VaultAccessError.recordNotFound(hex(sourceRecordUuid))
        }
        let newUuid = mintUuid()
        // copy-before-delete: land the copy in the target, THEN tombstone the source.
        recordsByBlock[targetBlockUuid]?.append(RecordView(
            uuid: newUuid, type: src.type, tags: src.tags, fields: src.fields, tombstone: false))
        setTombstone(sourceBlockUuid, idx, true)
        return newUuid
    }

    public func wipe() { wipeCount += 1 }

    // MARK: - helpers

    private func throwIfInjected() throws {
        if let e = failNextWrite { failNextWrite = nil; throw e }
    }

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
