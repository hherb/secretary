import Foundation

/// An opened vault. Abstracts the uniffi `OpenVaultOutput` (identity+manifest)
/// + `readBlock`, so the pure package never names an FFI handle type. The real
/// adapter retains the decrypted block handles for `reveal`, and `wipe` releases
/// all of them plus the manifest + identity.
/// `AnyObject` is load-bearing, not stylistic: the session owns FFI-backed
/// decrypted block handles, so it needs reference identity (callers compare
/// sessions with `===`) and a single authoritative `wipe` — value-copy
/// semantics would duplicate the handles and make `wipe` non-authoritative.
public protocol VaultSession: AnyObject {
    /// Opened vault UUID, lowercase hex, no dashes.
    var vaultUuidHex: String { get }
    /// Block metadata from the manifest (no plaintext).
    func blockSummaries() -> [BlockSummary]
    /// Decrypt one block and return its VISIBLE records (tombstoned records are
    /// withheld by the Rust gate unless `includeDeleted`). Returns records with
    /// on-demand-reveal fields.
    func readBlock(blockUuid: [UInt8], includeDeleted: Bool) throws -> [RecordView]
    /// Append a NEW record to a block. The session mints a fresh 16-byte record
    /// UUID, stamps this device's UUID + now, and returns the new UUID.
    @discardableResult
    func appendRecord(blockUuid: [UInt8], content: RecordContentInput) throws -> [UInt8]
    /// Edit an existing LIVE record's full content (CRDT-correct: untouched
    /// fields keep their per-field clocks). Throws `.recordNotFound` if absent.
    func editRecord(blockUuid: [UInt8], recordUuid: [UInt8], content: RecordContentInput) throws
    /// Soft-delete a LIVE record (flips its tombstone). Throws `.recordNotFound`.
    func tombstoneRecord(blockUuid: [UInt8], recordUuid: [UInt8]) throws
    /// Restore a TOMBSTONED record. Throws `.recordNotFound`.
    func resurrectRecord(blockUuid: [UInt8], recordUuid: [UInt8]) throws
    /// Release ALL secret material held by this session. Idempotent.
    func wipe()
}
