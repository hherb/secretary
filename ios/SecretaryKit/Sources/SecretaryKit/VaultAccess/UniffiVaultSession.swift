import Foundation
import Security
import SecretaryVaultAccess

/// Real `VaultSession` over the uniffi `OpenVaultOutput` (identity + manifest)
/// plus `readBlock`. Retains only the most-recently-decoded `BlockReadOutput`
/// (`currentBlock`) so the per-field `reveal` closures (which capture an FFI
/// `FieldHandle`) stay valid while the block is on screen. Prior blocks are
/// wiped on each `readBlock` call (#251). `wipe()` releases the current block,
/// then manifest, then identity.
///
/// Thread-safety (#300, mirror of the Android `UniffiVaultSession`, #250): every
/// touch of the shared FFI state — the `identity`/`manifest` handles and
/// `currentBlock` — is serialized under `lock`, and a `wiped` flag makes a read
/// that loses the race to a concurrent `wipe()` zeroize its just-decrypted block
/// (and a write short-circuit) instead of operating on handles a caller believed
/// cleared. Today every production caller is `@MainActor` (`VaultBrowseViewModel`,
/// including the scene-phase `.background` lock) and `readBlock` is synchronous, so
/// the lock is uncontended; it makes the type thread-safe *by construction* rather
/// than by an actor-isolation argument a future off-actor caller could silently
/// break. (Marking the type `@MainActor` is not viable: the session is constructed
/// off the main actor inside `UniffiVaultOpenPort`'s `runOffMainActor` so Argon2id
/// open does not block the UI.) The lock is non-recursive — no method re-enters
/// another; `currentBlock?.wipe()` is the FFI handle's own wipe, not `self.wipe()`.
///
/// `@unchecked Sendable`: `VaultSession` is `Sendable` (a session returns across
/// the open port's `async` boundary, #231), and this conformer earns it through
/// the `lock` above rather than immutability — the compiler cannot see that the
/// mutable `wiped`/`currentBlock`/`cachedDeviceUuid` state and the `deviceUuids`
/// provider are all lock-serialized, so the guarantee is asserted here.
public final class UniffiVaultSession: VaultSession, @unchecked Sendable {
    // `internal`, not `private`: the trash-port conformance in
    // `UniffiVaultSession+Trash.swift` is a same-module, different-file
    // extension and reads these two handles directly inside its FFI-call
    // closures (Swift's `private` is file-scoped, so a same-type extension
    // in another file cannot see a `private` stored property). Still not
    // `public` — no cross-module surface is added.
    //
    // INVARIANT: widening these to `internal` trades away the file-scoped
    // guarantee that once enforced lock-serialized access. Any new same-module
    // read/write of `identity`/`manifest` MUST go through a lock-guarded helper
    // (`readTrash`/`readTrashInfallible`/`write`/`writeTrash*`) — never touch
    // the raw handles outside `lock.withLock`, or the `wipe()` race the lock
    // exists to close reopens.
    internal let identity: UnlockedIdentity
    internal let manifest: OpenVaultManifest
    private let deviceUuids: DeviceUuidProviding?
    /// Serializes all access to the FFI handles + `currentBlock`. The held section
    /// spans the block decrypt, so a concurrent `wipe()` waits for an in-flight read
    /// (bounded — one block decrypt is milliseconds).
    private let lock = NSLock()
    /// Set true by `wipe()`; a read that observes it must not retain its block and a
    /// write must not touch the now-zeroized handles.
    private var wiped = false
    /// The single retained decrypted block — the on-screen one. Bounding to one
    /// block (not a growing list) makes "≤1 block resident" a type-level invariant
    /// and dedups re-selection. The VM clears the reveal map on `selectBlock`, so no
    /// live reveal closure references a prior block when we evict it here (#251).
    private var currentBlock: BlockReadOutput?
    /// Cached per this session so every write stamps the same device UUID.
    private var cachedDeviceUuid: [UInt8]?
    /// The vault UUID is immutable for the session's life, so it is snapshotted to
    /// hex at construction (while the manifest handle is valid). `vaultUuidHex`
    /// returns this stored value and never touches the FFI handle, so it stays
    /// correct after `wipe()` zeroizes the manifest — a post-wipe read pre-fix
    /// returned the bridge's all-zero default (#252).
    private let vaultUuidHexValue: String

    public init(output: OpenVaultOutput) {
        self.identity = output.identity
        self.manifest = output.manifest
        self.deviceUuids = nil
        self.vaultUuidHexValue = Self.hexEncode(output.manifest.vaultUuid())
    }

    /// Test/seam initializer: inject a device-uuid provider. Production uses
    /// `init(output:)`, which resolves `DeviceUuidStore.applicationSupportDefault()`
    /// lazily on the first write (read-only sessions never touch write infra).
    public init(output: OpenVaultOutput, deviceUuids: DeviceUuidProviding) {
        self.identity = output.identity
        self.manifest = output.manifest
        self.deviceUuids = deviceUuids
        self.vaultUuidHexValue = Self.hexEncode(output.manifest.vaultUuid())
    }

    public var vaultUuidHex: String { vaultUuidHexValue }

    /// Lowercase, dash-free hex of a uniffi byte blob.
    private static func hexEncode(_ bytes: Data) -> String {
        [UInt8](bytes).map { String(format: "%02x", $0) }.joined()
    }

    public func blockSummaries() -> [SecretaryVaultAccess.BlockSummary] {
        lock.withLock {
            // After wipe() the session is closed: expose no blocks without touching
            // the zeroized manifest handle (mirrors readBlock's lost-race empty return
            // + the write-path guard). The bridge also returns empty for a wiped handle,
            // but the session enforces its own contract rather than relying on that
            // cross-crate default.
            if wiped { return [] }
            return manifest.blockSummaries().map { s in
                SecretaryVaultAccess.BlockSummary(
                    uuid: [UInt8](s.blockUuid),
                    name: s.blockName,
                    createdAtMs: s.createdAtMs,
                    lastModMs: s.lastModifiedMs)
            }
        }
    }

    public func readBlock(blockUuid: [UInt8], includeDeleted: Bool) throws -> [RecordView] {
        try lock.withLock {
            let out: BlockReadOutput
            do {
                out = try SecretaryKit.readBlock(
                    identity: identity, manifest: manifest, blockUuid: Data(blockUuid),
                    includeDeleted: includeDeleted)
            } catch let e as VaultError {
                throw mapVaultAccessError(e)
            }
            // Lost the race to a concurrent wipe(): the session is closed. Zeroize the
            // block we just decrypted rather than retain plaintext past the lock the
            // caller believed cleared everything.
            if wiped {
                out.wipe()
                return []
            }
            // Decrypt-first ordering: `out` is already decoded above, so a thrown read
            // left the prior block retained. Now evict it before retaining the new one.
            currentBlock?.wipe()
            currentBlock = out  // keep alive for reveal closures + wipe
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
        // The owning BlockReadOutput is retained in `currentBlock` until wipe()
        // or the next readBlock().
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
        // Under `lock` so an in-flight readBlock/write either completes before we
        // zeroize the handles or observes `wiped` and bails. Idempotent — wipe may be
        // called repeatedly (e.g. scene-phase `.background` then an explicit lock).
        lock.withLock {
            wiped = true
            currentBlock?.wipe()
            currentBlock = nil
            manifest.wipe()
            identity.wipe()
        }
    }

    @discardableResult
    public func appendRecord(blockUuid: [UInt8], content: RecordContentInput) throws -> [UInt8] {
        let recordUuid = try Self.freshUuid()
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

    @discardableResult
    public func createBlock(blockName: String) throws -> [UInt8] {
        let blockUuid = try Self.freshUuid()
        try write { dev, now in
            try SecretaryKit.createBlock(
                identity: identity, manifest: manifest,
                blockUuid: Data(blockUuid), blockName: blockName,
                deviceUuid: Data(dev), nowMs: now)
        }
        return blockUuid
    }

    public func renameBlock(blockUuid: [UInt8], newName: String) throws {
        try write { dev, now in
            try SecretaryKit.renameBlock(
                identity: identity, manifest: manifest,
                blockUuid: Data(blockUuid), newBlockName: newName,
                deviceUuid: Data(dev), nowMs: now)
        }
    }

    @discardableResult
    public func moveRecord(sourceBlockUuid: [UInt8], targetBlockUuid: [UInt8],
                           sourceRecordUuid: [UInt8]) throws -> [UInt8] {
        let newRecordUuid = try Self.freshUuid()
        try write { dev, now in
            try SecretaryKit.moveRecord(
                identity: identity, manifest: manifest,
                sourceBlockUuid: Data(sourceBlockUuid), targetBlockUuid: Data(targetBlockUuid),
                sourceRecordUuid: Data(sourceRecordUuid), newRecordUuid: Data(newRecordUuid),
                deviceUuid: Data(dev), nowMs: now)
        }
        return newRecordUuid
    }

    /// Resolve (device uuid, now-ms), run the FFI write, map errors. Centralizes
    /// the device-uuid resolve + `VaultError` mapping for every writer
    /// (append/edit/tombstone/resurrect + createBlock/renameBlock/moveRecord).
    /// Serialized under `lock` with the `wiped` guard checked **before** touching the
    /// handles, so a write on a wiped session short-circuits cleanly rather than
    /// calling the FFI on zeroized `identity`/`manifest`.
    ///
    /// - Throws: `VaultAccessError.other` if the session has been wiped;
    ///   `VaultAccessError` for any FFI `VaultError`; additionally, the **first
    ///   write** of a session may throw a `DeviceUuidStoreError` (an I/O error from
    ///   resolving the per-vault device UUID) which is deliberately NOT mapped to a
    ///   `VaultAccessError` — callers must handle both error types.
    private func write(_ body: (_ deviceUuid: [UInt8], _ nowMs: UInt64) throws -> Void) throws {
        try lock.withLock {
            if wiped { throw VaultAccessError.other("write on a wiped session") }
            let dev = try deviceUuid()
            do {
                try body(dev, Self.nowMs())
            } catch let e as VaultError {
                throw mapVaultAccessError(e)
            }
        }
    }

    /// Read under the lock with the wiped-guard, returning a value or throwing.
    /// Mirrors `write`'s wiped-check-then-map-error shape for the read side
    /// (`listTrashedBlocks` is the only throwing trash read).
    internal func readTrash<T>(_ body: () throws -> T) throws -> T {
        try lock.withLock {
            if wiped { throw VaultAccessError.other("read on a wiped session") }
            do {
                return try body()
            } catch let e as VaultError {
                throw mapVaultAccessError(e)
            }
        }
    }

    /// Infallible read under the lock; returns an empty projection when wiped
    /// rather than throwing, matching `blockSummaries()`'s post-wipe contract.
    internal func readTrashInfallible<T>(_ body: () -> [T]) -> [T] {
        lock.withLock { wiped ? [] : body() }
    }

    /// Like `write`, but the body returns a value (purge/empty-trash/auto-purge
    /// all report a summary struct on success).
    internal func writeTrashReturning<T>(
        _ body: (_ deviceUuid: [UInt8], _ nowMs: UInt64) throws -> T
    ) throws -> T {
        try lock.withLock {
            if wiped { throw VaultAccessError.other("write on a wiped session") }
            let dev = try deviceUuid()
            do {
                return try body(dev, Self.nowMs())
            } catch let e as VaultError {
                throw mapVaultAccessError(e)
            }
        }
    }

    /// Alias for the existing private `write`, exposed so the trash extension
    /// (a different file) can drive a Void-returning write
    /// (`restoreBlock`) without widening `write` itself.
    internal func writeTrash(
        _ body: (_ deviceUuid: [UInt8], _ nowMs: UInt64) throws -> Void
    ) throws {
        try write(body)
    }

    /// `nowMs()` exposed for the infallible-read preview path
    /// (`expiredTrashEntries`), which has no write to derive `now` from.
    internal static func nowMsPublic() -> UInt64 { nowMs() }

    private func deviceUuid() throws -> [UInt8] {
        if let c = cachedDeviceUuid { return c }
        let provider = try (deviceUuids ?? DeviceUuidStore.applicationSupportDefault())
        let d = try provider.deviceUuid(forVaultHex: vaultUuidHex)
        cachedDeviceUuid = d
        return d
    }

    private static func nowMs() -> UInt64 {
        UInt64(Date().timeIntervalSince1970 * 1000)
    }

    /// 16 bytes — a UUID (block or record). Both kinds share the byte length but
    /// are unrelated values; named generically since this mints both.
    private static let uuidByteLen = 16

    private static func freshUuid() throws -> [UInt8] {
        var u = [UInt8](repeating: 0, count: uuidByteLen)
        let status = SecRandomCopyBytes(kSecRandomDefault, u.count, &u)
        guard status == errSecSuccess else {
            throw VaultAccessError.other("OS entropy unavailable for UUID (status \(status))")
        }
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
