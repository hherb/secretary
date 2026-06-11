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
    /// Decrypt one block; returns records with on-demand-reveal fields.
    func readBlock(blockUuid: [UInt8]) throws -> [RecordView]
    /// Release ALL secret material held by this session. Idempotent.
    func wipe()
}
