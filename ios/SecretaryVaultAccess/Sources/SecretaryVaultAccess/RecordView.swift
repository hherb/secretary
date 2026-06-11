import Foundation

/// A revealed (decrypted) field value. Equatable for test assertions; holds
/// plaintext, so callers must drop it promptly (see `VaultBrowseViewModel`).
public enum RevealedValue: Equatable {
    case text(String)
    case bytes([UInt8])
}

/// One field of a record. Metadata (name, kind) is non-secret. `reveal`
/// materializes the plaintext ON DEMAND only — the real adapter wires it to the
/// FFI `expose_text`/`expose_bytes`, so plaintext is never eagerly decrypted.
/// Not `Equatable` (it holds a closure); assert on `name`/`kind`/`reveal()`.
public struct FieldView {
    public enum Kind: Equatable { case text, bytes }
    public let name: String
    public let kind: Kind
    public let reveal: () throws -> RevealedValue

    public init(name: String, kind: Kind, reveal: @escaping () throws -> RevealedValue) {
        self.name = name
        self.kind = kind
        self.reveal = reveal
    }
}

/// One decrypted record. Field metadata is exposed; plaintext stays behind
/// `FieldView.reveal`.
public struct RecordView {
    public let uuid: [UInt8]
    public let type: String
    public let tags: [String]
    public let fields: [FieldView]

    public init(uuid: [UInt8], type: String, tags: [String], fields: [FieldView]) {
        self.uuid = uuid
        self.type = type
        self.tags = tags
        self.fields = fields
    }

    public var uuidHex: String { uuid.map { String(format: "%02x", $0) }.joined() }
}
