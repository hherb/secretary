// ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/RecordContentInput.swift
import Foundation

/// A field's plaintext value to write. Text is keyboard plaintext; Bytes is raw
/// bytes (the edit UI enters/edits these as hex). Mirrors the FFI
/// `FieldInputValue` without naming it, keeping this package FFI-free.
public enum FieldContentValue: Equatable {
    case text(String)
    case bytes([UInt8])

    public enum Kind: Equatable { case text, bytes }
    public var kind: Kind { switch self { case .text: return .text; case .bytes: return .bytes } }
}

/// One field to write: a non-secret name + a value. Mirrors FFI `FieldInput`.
public struct FieldContentInput: Equatable {
    public let name: String
    public let value: FieldContentValue
    public init(name: String, value: FieldContentValue) {
        self.name = name
        self.value = value
    }
}

/// Full desired content of a record to add or edit. Mirrors FFI `RecordContent`.
/// `record_uuid`, `created_at_ms`, per-field clocks and forward-compat `unknown`
/// maps are intentionally NOT here — the bridge edit primitives own those
/// (mint-on-add / preserve-on-edit).
public struct RecordContentInput: Equatable {
    public let recordType: String
    public let tags: [String]
    public let fields: [FieldContentInput]
    public init(recordType: String, tags: [String], fields: [FieldContentInput]) {
        self.recordType = recordType
        self.tags = tags
        self.fields = fields
    }

    /// Pure pre-commit validation. `nil` == valid. Field names must be
    /// non-blank and unique (the bridge diffs fields by name on edit, so two
    /// same-named fields would alias). Record type and tags are unconstrained.
    public func validate() -> RecordContentInputError? {
        var seen = Set<String>()
        for f in fields {
            if f.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                return .emptyFieldName
            }
            if !seen.insert(f.name).inserted {
                return .duplicateFieldName(f.name)
            }
        }
        return nil
    }
}

/// Why a `RecordContentInput` is not writable. Surfaced inline in the edit UI.
public enum RecordContentInputError: Error, Equatable {
    case emptyFieldName
    case duplicateFieldName(String)
}
