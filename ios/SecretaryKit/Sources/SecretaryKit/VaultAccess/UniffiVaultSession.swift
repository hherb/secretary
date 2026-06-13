import Foundation
import Security
import SecretaryVaultAccess

/// Real `VaultSession` over the uniffi `OpenVaultOutput` (identity + manifest)
/// plus `readBlock`. Retains every `BlockReadOutput` it decodes so the
/// per-field `reveal` closures (which capture an FFI `FieldHandle`) stay valid
/// until `wipe()`. `wipe()` releases blocks, then manifest, then identity.
public final class UniffiVaultSession: VaultSession {
    private let identity: UnlockedIdentity
    private let manifest: OpenVaultManifest
    private let deviceUuids: DeviceUuidProviding
    /// Retained decrypted-block handles, so reveal closures remain valid.
    private var openBlocks: [BlockReadOutput] = []
    /// Cached per this session so every write stamps the same device UUID.
    private var cachedDeviceUuid: [UInt8]?

    public convenience init(output: OpenVaultOutput) throws {
        self.init(output: output, deviceUuids: try DeviceUuidStore.applicationSupportDefault())
    }

    public init(output: OpenVaultOutput, deviceUuids: DeviceUuidProviding) {
        self.identity = output.identity
        self.manifest = output.manifest
        self.deviceUuids = deviceUuids
    }

    public var vaultUuidHex: String {
        [UInt8](manifest.vaultUuid()).map { String(format: "%02x", $0) }.joined()
    }

    public func blockSummaries() -> [SecretaryVaultAccess.BlockSummary] {
        manifest.blockSummaries().map { s in
            SecretaryVaultAccess.BlockSummary(
                uuid: [UInt8](s.blockUuid),
                name: s.blockName,
                createdAtMs: s.createdAtMs,
                lastModMs: s.lastModifiedMs)
        }
    }

    public func readBlock(blockUuid: [UInt8]) throws -> [RecordView] {
        let out: BlockReadOutput
        do {
            out = try SecretaryKit.readBlock(
                identity: identity, manifest: manifest, blockUuid: Data(blockUuid))
        } catch let e as VaultError {
            throw mapVaultAccessError(e)
        }
        openBlocks.append(out)  // keep alive for reveal closures + wipe
        let count = out.recordCount()
        var records: [RecordView] = []
        records.reserveCapacity(Int(count))
        var i: UInt64 = 0
        while i < count {
            // An in-range `nil` on a freshly-decrypted, non-wiped block is not a
            // routine skip — it signals corruption or an FFI bug. Surface it as a
            // typed error rather than silently returning fewer records than the
            // block declares (a silent drop could hide a tampered record).
            guard let rec = out.recordAt(idx: i) else {
                throw VaultAccessError.corruptVault("recordAt(\(i)) returned nil on an open block")
            }
            records.append(try makeRecordView(rec))
            i += 1
        }
        return records
    }

    private func makeRecordView(_ rec: Record) throws -> RecordView {
        let fieldCount = rec.fieldCount()
        var fields: [FieldView] = []
        fields.reserveCapacity(Int(fieldCount))
        var j: UInt64 = 0
        while j < fieldCount {
            // Same rationale as `recordAt`: an in-range `nil` field is corruption.
            guard let handle = rec.fieldAt(idx: j) else {
                throw VaultAccessError.corruptVault("fieldAt(\(j)) returned nil on an open record")
            }
            fields.append(makeFieldView(handle))
            j += 1
        }
        return RecordView(
            uuid: [UInt8](rec.recordUuid()),
            type: rec.recordType(),
            tags: rec.tags(),
            fields: fields,
            tombstone: rec.tombstone())
    }

    private func makeFieldView(_ handle: FieldHandle) -> FieldView {
        let kind: FieldView.Kind = handle.isText() ? .text : .bytes
        // `handle` is captured: calling reveal() invokes expose_* ON DEMAND.
        // The owning BlockReadOutput is retained in `openBlocks` until wipe().
        return FieldView(name: handle.name(), kind: kind) {
            switch kind {
            case .text:
                guard let s = handle.exposeText() else {
                    throw VaultAccessError.corruptVault("text field could not be exposed")
                }
                return .text(s)
            case .bytes:
                guard let b = handle.exposeBytes() else {
                    throw VaultAccessError.corruptVault("bytes field could not be exposed")
                }
                return .bytes([UInt8](b))
            }
        }
    }

    public func wipe() {
        for b in openBlocks { b.wipe() }
        openBlocks.removeAll()
        manifest.wipe()
        identity.wipe()
    }

    @discardableResult
    public func appendRecord(blockUuid: [UInt8], content: RecordContentInput) throws -> [UInt8] {
        let recordUuid = Self.freshRecordUuid()
        try write { dev, now in
            try SecretaryKit.appendRecord(
                identity: identity, manifest: manifest,
                blockUuid: Data(blockUuid), recordUuid: Data(recordUuid),
                content: Self.toFfi(content), deviceUuid: Data(dev), nowMs: now)
        }
        return recordUuid
    }

    public func editRecord(blockUuid: [UInt8], recordUuid: [UInt8], content: RecordContentInput) throws {
        try write { dev, now in
            try SecretaryKit.editRecord(
                identity: identity, manifest: manifest,
                blockUuid: Data(blockUuid), recordUuid: Data(recordUuid),
                content: Self.toFfi(content), deviceUuid: Data(dev), nowMs: now)
        }
    }

    public func tombstoneRecord(blockUuid: [UInt8], recordUuid: [UInt8]) throws {
        try write { dev, now in
            try SecretaryKit.tombstoneRecord(
                identity: identity, manifest: manifest,
                blockUuid: Data(blockUuid), recordUuid: Data(recordUuid),
                deviceUuid: Data(dev), nowMs: now)
        }
    }

    public func resurrectRecord(blockUuid: [UInt8], recordUuid: [UInt8]) throws {
        try write { dev, now in
            try SecretaryKit.resurrectRecord(
                identity: identity, manifest: manifest,
                blockUuid: Data(blockUuid), recordUuid: Data(recordUuid),
                deviceUuid: Data(dev), nowMs: now)
        }
    }

    /// Resolve (device uuid, now-ms), run the FFI write, map errors. Centralizes
    /// the device-uuid resolve + `VaultError` mapping for all four writers.
    private func write(_ body: (_ deviceUuid: [UInt8], _ nowMs: UInt64) throws -> Void) throws {
        let dev = try deviceUuid()
        do {
            try body(dev, Self.nowMs())
        } catch let e as VaultError {
            throw mapVaultAccessError(e)
        }
    }

    private func deviceUuid() throws -> [UInt8] {
        if let c = cachedDeviceUuid { return c }
        let d = try deviceUuids.deviceUuid(forVaultHex: vaultUuidHex)
        cachedDeviceUuid = d
        return d
    }

    private static func nowMs() -> UInt64 {
        UInt64(Date().timeIntervalSince1970 * 1000)
    }

    private static func freshRecordUuid() -> [UInt8] {
        var u = [UInt8](repeating: 0, count: DeviceUuidStore.uuidByteLen)
        _ = SecRandomCopyBytes(kSecRandomDefault, u.count, &u)
        return u
    }

    /// Map the FFI-free `RecordContentInput` to the uniffi `RecordContent`,
    /// zeroizing the plaintext byte payloads we copy in once the value type is
    /// built (text values are Strings — same residue limitation as the unlock
    /// password field).
    private static func toFfi(_ c: RecordContentInput) -> RecordContent {
        let fields = c.fields.map { f -> FieldInput in
            switch f.value {
            case .text(let s):
                return FieldInput(name: f.name, value: .text(text: s))
            case .bytes(var b):
                let input = FieldInput(name: f.name, value: .bytes(data: Data(b)))
                for i in b.indices { b[i] = 0 }  // overwrite our copy of the payload
                return input
            }
        }
        return RecordContent(recordType: c.recordType, tags: c.tags, fields: fields)
    }
}
