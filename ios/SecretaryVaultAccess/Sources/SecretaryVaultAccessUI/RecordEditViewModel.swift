// ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/RecordEditViewModel.swift
import Foundation
import Combine
import SecretaryVaultAccess

/// One editable field row. `rawText` holds plaintext for `.text` fields and a
/// hex string for `.bytes` fields (the only byte-entry affordance this slice).
public struct EditableField: Identifiable, Equatable {
    public let id: UUID
    public var name: String
    public var kind: FieldContentValue.Kind
    public var rawText: String

    public init(id: UUID = UUID(), name: String = "", kind: FieldContentValue.Kind = .text,
                rawText: String = "") {
        self.id = id; self.name = name; self.kind = kind; self.rawText = rawText
    }
}

/// Drives the add/edit record form. Host-testable with `FakeVaultSession`. On a
/// successful `commit()` it sets `committed` (the screen dismisses + the browse
/// VM re-reads); on failure it sets a typed `error` and writes nothing.
@MainActor
public final class RecordEditViewModel: ObservableObject {
    public enum Mode: Equatable {
        case add
        case edit(recordUuid: [UInt8])
    }

    @Published public var recordType: String = ""
    @Published public var tags: [String] = []
    @Published public var fields: [EditableField] = []
    @Published public private(set) var error: VaultAccessError?
    @Published public private(set) var committed = false
    @Published public private(set) var isWriting = false
    // Set by load(record:) on a reveal failure; reset only by a successful load. A fresh VM (always built per-edit) starts clean.
    @Published public private(set) var loadFailed = false

    private let session: VaultSession
    private let blockUuid: [UInt8]
    private let gate: WriteReauthGate
    public let mode: Mode

    public init(session: VaultSession, blockUuid: [UInt8], mode: Mode, gate: WriteReauthGate) {
        self.session = session
        self.blockUuid = blockUuid
        self.mode = mode
        self.gate = gate
    }

    /// Append a blank field row. Removal + kind changes are driven directly
    /// through the `fields` binding by the SwiftUI Form (`.onDelete`, the kind
    /// Picker), so no guarded mutators are needed beyond this one.
    public func addField() { fields.append(EditableField()) }

    /// Reveal each field of an existing record into the editable rows. Text →
    /// plaintext; bytes → lowercase hex. Throws if a field cannot be revealed.
    public func loadForEdit(record: RecordView) throws {
        recordType = record.type
        tags = record.tags
        fields = try record.fields.map { fv in
            switch try fv.reveal() {
            case .text(let s):
                return EditableField(name: fv.name, kind: .text, rawText: s)
            case .bytes(let b):
                return EditableField(name: fv.name, kind: .bytes, rawText: Self.hex(b))
            }
        }
    }

    /// Prefill from an existing record for editing, capturing any reveal failure
    /// into `error` (instead of throwing) and setting `loadFailed`. While
    /// `loadFailed` is true, `commit()` refuses to write — a partially-revealed
    /// record must never be saved back, which would clobber the fields that
    /// could not be read.
    public func load(record: RecordView) {
        do {
            try loadForEdit(record: record)
            loadFailed = false
        } catch let e as VaultAccessError {
            error = e
            loadFailed = true
        } catch {
            self.error = .other(String(describing: error))
            loadFailed = true
        }
    }

    /// Build → validate → re-auth gate → write. Sets `committed` on success; sets
    /// `error` and writes nothing on any validation, gate, or FFI failure.
    ///
    /// Guards on `committed` (render-gap re-tap), `isWriting` (in-flight re-entry),
    /// and `loadFailed` (refuse to overwrite a record we couldn't fully read).
    /// The gate is awaited AFTER content validation so that a biometric prompt is
    /// never shown for input the VM would reject anyway.
    public func commit() async {
        guard !committed, !isWriting, !loadFailed else { return }
        isWriting = true
        defer { isWriting = false }
        let content: RecordContentInput
        do {
            content = try buildContent()
        } catch let e as VaultAccessError {
            error = e
            return
        } catch {
            self.error = .other(String(describing: error))
            return
        }
        if let v = content.validate() {
            error = Self.mapValidation(v)
            return
        }
        // Re-auth gate: a refused biometric stops the write and surfaces the error,
        // leaving the form intact (committed stays false → screen does not dismiss).
        do {
            try await gate.authorizeWrite(reason: "Confirm saving this entry")
        } catch let e as VaultAccessError {
            error = e
            return
        } catch {
            self.error = .reauthFailed(String(describing: error))
            return
        }
        do {
            switch mode {
            case .add:
                try session.appendRecord(blockUuid: blockUuid, content: content)
            case .edit(let recordUuid):
                try session.editRecord(blockUuid: blockUuid, recordUuid: recordUuid, content: content)
            }
            error = nil
            committed = true
        } catch let e as VaultAccessError {
            error = e
        } catch {
            self.error = .other(String(describing: error))
        }
    }

    // MARK: - helpers

    private func buildContent() throws -> RecordContentInput {
        let built = try fields.map { f -> FieldContentInput in
            switch f.kind {
            case .text:
                return FieldContentInput(name: f.name, value: .text(f.rawText))
            case .bytes:
                guard let bytes = Self.parseHex(f.rawText) else {
                    throw VaultAccessError.invalidArgument("field '\(f.name)' is not valid hex")
                }
                return FieldContentInput(name: f.name, value: .bytes(bytes))
            }
        }
        let cleanTags = tags
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        return RecordContentInput(recordType: recordType, tags: cleanTags, fields: built)
    }

    private static func mapValidation(_ v: RecordContentInputError) -> VaultAccessError {
        switch v {
        case .emptyFieldName:            return .invalidArgument("a field name is empty")
        case .duplicateFieldName(let n): return .invalidArgument("duplicate field name: \(n)")
        }
    }

    private static func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    /// Parse an even-length hex string to bytes; `nil` if malformed. Whitespace
    /// is stripped so users can paste spaced hex.
    private static func parseHex(_ s: String) -> [UInt8]? {
        let cleaned = s.filter { !$0.isWhitespace }
        guard cleaned.count % 2 == 0 else { return nil }
        var out = [UInt8](); out.reserveCapacity(cleaned.count / 2)
        var i = cleaned.startIndex
        while i < cleaned.endIndex {
            let j = cleaned.index(i, offsetBy: 2)
            guard let b = UInt8(cleaned[i..<j], radix: 16) else { return nil }
            out.append(b)
            i = j
        }
        return out
    }
}
