import Foundation

/// Read-only metadata for one block in an opened vault's manifest. Carries no
/// secret material — block names + timestamps are plaintext in the manifest.
public struct BlockSummary: Equatable {
    /// 16-byte block UUID (raw, for passing back to `readBlock`).
    public let uuid: [UInt8]
    /// User-visible block name.
    public let name: String
    public let createdAtMs: UInt64
    public let lastModMs: UInt64

    public init(uuid: [UInt8], name: String, createdAtMs: UInt64, lastModMs: UInt64) {
        self.uuid = uuid
        self.name = name
        self.createdAtMs = createdAtMs
        self.lastModMs = lastModMs
    }

    /// Lowercase hex, no dashes — stable key for UI identity + reveal maps.
    public var uuidHex: String { uuid.map { String(format: "%02x", $0) }.joined() }
}
