import Foundation
import Combine
import SecretaryVaultAccess

/// Drives the read-only browse screen. Owns the `VaultSession` and is the single
/// place that decides WHEN secret material is materialized (reveal) and WHEN it
/// is released (hide/lock). Host-testable with `FakeVaultSession`.
@MainActor
public final class VaultBrowseViewModel: ObservableObject {
    @Published public private(set) var blocks: [BlockSummary] = []
    @Published public private(set) var records: [RecordView]?
    @Published public private(set) var error: VaultAccessError?
    /// Currently-revealed plaintext, keyed "<recordUuidHex>/<fieldName>". Kept as
    /// small + short-lived as possible; cleared on hide / lock / background.
    @Published public private(set) var revealed: [String: RevealedValue] = [:]

    /// When false (default) the browse list shows only live records. The Rust
    /// gate withholds tombstoned records; toggling RE-READS the selected block
    /// with the new flag (the client never holds withheld data).
    @Published public var showDeleted = false {
        didSet {
            guard showDeleted != oldValue, let blockUuid = selectedBlockUuid else { return }
            reload(blockUuid: blockUuid)
        }
    }

    /// True for the brief window while a delete or restore is being committed to
    /// disk. Synchronous on @MainActor so it cannot truly re-enter; this flag is
    /// UX parity (disables swipe/dialog buttons during the write) rather than a
    /// correctness guard.
    @Published public private(set) var isWriting = false

    /// Drives the block-name prompt. nil = closed. `.create` = new block;
    /// `.rename` carries the block being renamed.
    public enum BlockNameDialog: Equatable { case create; case rename(block: BlockSummary) }
    @Published public private(set) var blockNameDialog: BlockNameDialog?

    /// The record currently being moved (drives the target-block picker sheet). nil = none.
    @Published public private(set) var movingRecord: RecordView?

    /// The currently-selected block uuid, so delete/restore can re-read it.
    private var selectedBlockUuid: [UInt8]?

    private let session: VaultSession
    private let gate: WriteReauthGate
    public init(session: VaultSession, gate: WriteReauthGate) {
        self.session = session
        self.gate = gate
    }

    public var vaultUuidHex: String { session.vaultUuidHex }

    public func loadBlocks() { blocks = session.blockSummaries() }

    public func selectBlock(_ block: BlockSummary) {
        selectedBlockUuid = block.uuid
        reload(blockUuid: block.uuid)
    }

    /// Read `blockUuid` into `records`, mapping any failure to `error` and
    /// clearing `records`. Always drops revealed plaintext first — a reload must
    /// never carry a stale reveal across the new read (block switch, refresh, or
    /// post-mutation re-read).
    private func reload(blockUuid: [UInt8]) {
        error = nil
        revealed.removeAll()
        do {
            records = try session.readBlock(blockUuid: blockUuid, includeDeleted: showDeleted)
        } catch let e as VaultAccessError {
            records = nil
            error = e
        } catch {
            records = nil
            self.error = .other(String(describing: error))
        }
    }

    /// Records to display. The Rust gate already withheld tombstoned records
    /// (unless `showDeleted`), so no client-side filtering happens here.
    public var visibleRecords: [RecordView] { records ?? [] }

    /// Soft-delete a record, then re-read so `visibleRecords` reflects it.
    public func delete(record: RecordView) async {
        guard let blockUuid = selectedBlockUuid else { return }
        _ = await reauthedWrite(reason: "Confirm deleting this entry",
                                onSuccess: { self.reload(blockUuid: blockUuid) }) {
            try self.session.tombstoneRecord(blockUuid: blockUuid, recordUuid: record.uuid)
        }
    }

    /// Restore a soft-deleted record, then re-read.
    public func restore(record: RecordView) async {
        guard let blockUuid = selectedBlockUuid else { return }
        _ = await reauthedWrite(reason: "Confirm restoring this entry",
                                onSuccess: { self.reload(blockUuid: blockUuid) }) {
            try self.session.resurrectRecord(blockUuid: blockUuid, recordUuid: record.uuid)
        }
    }

    /// Re-read the currently-selected block (e.g. after the edit sheet writes),
    /// using the VM's own selection rather than a caller-held BlockSummary.
    /// No-op if no block is selected.
    public func refresh() {
        guard let blockUuid = selectedBlockUuid else { return }
        reload(blockUuid: blockUuid)
    }

    /// Run `op`, then on SUCCESS run `onSuccess`. A failed write surfaces `error`
    /// and runs neither `onSuccess` nor any caller-deferred dialog clear — so the
    /// visible list / open dialog is preserved. Returns true iff the write
    /// succeeded. Re-entrancy guarded by `isWriting`.
    @discardableResult
    private func guardedWrite(onSuccess: () -> Void, op: () throws -> Void) -> Bool {
        guard !isWriting else { return false }
        isWriting = true
        defer { isWriting = false }
        do {
            try op()
        } catch let e as VaultAccessError {
            error = e
            return false
        } catch {
            self.error = .other(String(describing: error))
            return false
        }
        onSuccess()
        return true
    }

    /// Re-auth, then run a guarded write. Returns false (write not performed) if the
    /// re-auth is refused — surfacing `.reauthFailed` and leaving any open dialog/sheet
    /// untouched, exactly like a failed write. Otherwise delegates to `guardedWrite`.
    private func reauthedWrite(reason: String,
                               onSuccess: () -> Void,
                               op: () throws -> Void) async -> Bool {
        do {
            try await gate.authorizeWrite(reason: reason)
        } catch let e as VaultAccessError {
            error = e
            return false
        } catch {
            self.error = .reauthFailed(String(describing: error))
            return false
        }
        return guardedWrite(onSuccess: onSuccess, op: op)
    }

    /// Composite reveal-map key. Collision-safe: `recordUuidHex` is always
    /// exactly 32 lowercase hex chars (hex of a 16-byte UUID, charset [0-9a-f]),
    /// so it can never contain the "/" separator nor be confused with a field
    /// name — no `(record, field)` pair can alias another's key even though
    /// field names are arbitrary vault-supplied strings.
    private func key(_ recordUuidHex: String, _ fieldName: String) -> String {
        "\(recordUuidHex)/\(fieldName)"
    }

    /// Materialize one field's plaintext on explicit user action. Takes the full
    /// `FieldView` (not just string ids) because it must call `field.reveal()` —
    /// the on-demand closure that pulls plaintext across the FFI boundary.
    public func reveal(record: RecordView, field: FieldView) {
        do {
            revealed[key(record.uuidHex, field.name)] = try field.reveal()
        } catch let e as VaultAccessError {
            error = e
        } catch {
            self.error = .other(String(describing: error))
        }
    }

    public func revealedValue(recordUuidHex: String, fieldName: String) -> RevealedValue? {
        revealed[key(recordUuidHex, fieldName)]
    }

    public func hide(recordUuidHex: String, fieldName: String) {
        revealed[key(recordUuidHex, fieldName)] = nil
    }

    /// Drop all revealed plaintext (e.g. on backgrounding) without locking.
    public func hideAll() { revealed.removeAll() }

    /// Lock the vault: drop all plaintext AND release the session's handles.
    /// After `lock`, this VM should be discarded (route back to unlock).
    public func lock() {
        revealed.removeAll()
        blockNameDialog = nil
        movingRecord = nil
        session.wipe()
    }

    /// Open the name prompt for a NEW block.
    public func startCreateBlock() { blockNameDialog = .create }
    /// Open the name prompt to RENAME `block` (pre-binds the current name in the UI).
    public func startRenameBlock(_ block: BlockSummary) { blockNameDialog = .rename(block: block) }
    /// Dismiss the block-name prompt without writing.
    public func cancelBlockNameDialog() { blockNameDialog = nil }

    /// Begin moving `record` — opens the target-block picker.
    public func startMoveRecord(_ record: RecordView) { movingRecord = record }
    /// Dismiss the move picker without writing.
    public func cancelMove() { movingRecord = nil }

    /// Confirm a move into `target`. Rejects a same-block move as a UI guard
    /// (`.invalidArgument`, no write, picker stays open). On success the SOURCE
    /// block is re-read (so the tombstone shows with show-deleted on) and the
    /// picker cleared; on a failed write the picker stays open with `error` set.
    public func confirmMove(target: BlockSummary) async {
        guard let record = movingRecord else { return }
        guard let source = selectedBlockUuid else { return }
        guard target.uuid != source else {
            error = .invalidArgument("source and target block must differ")
            return
        }
        let ok = await reauthedWrite(reason: "Confirm moving this entry",
                                     onSuccess: { self.refresh() }) {
            try self.session.moveRecord(sourceBlockUuid: source,
                                        targetBlockUuid: target.uuid,
                                        sourceRecordUuid: record.uuid)
        }
        if ok { movingRecord = nil }
    }

    /// Confirm the block-name prompt. Blank names are rejected as a UI policy
    /// (the spec/FFI permit empty block names; the UI requires a non-blank one) —
    /// this surfaces `.invalidArgument` WITHOUT writing and keeps the dialog open.
    /// On a successful write the block LIST is reloaded and the dialog cleared;
    /// on a failed write the dialog stays open with `error` set.
    public func confirmBlockName(_ name: String) async {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            error = .invalidArgument("block name must not be blank")
            return
        }
        guard let dialog = blockNameDialog else { return }
        let ok = await reauthedWrite(reason: "Confirm saving this block",
                                     onSuccess: { self.loadBlocks() }) {
            switch dialog {
            case .create:
                try self.session.createBlock(blockName: trimmed)
            case .rename(let block):
                try self.session.renameBlock(blockUuid: block.uuid, newName: trimmed)
            }
        }
        if ok { blockNameDialog = nil }
    }

    /// Build a record-edit VM bound to this session + the selected block.
    /// Returns nil if no block is selected. The edit screen calls `commit()`;
    /// on success the browse screen re-selects the block to refresh the list.
    public func makeEditViewModel(mode: RecordEditViewModel.Mode) -> RecordEditViewModel? {
        guard let blockUuid = selectedBlockUuid else { return nil }
        return RecordEditViewModel(session: session, blockUuid: blockUuid, mode: mode, gate: gate)
    }
}
