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

    /// The currently-selected block uuid, so delete/restore can re-read it.
    private var selectedBlockUuid: [UInt8]?

    private let session: VaultSession
    public init(session: VaultSession) { self.session = session }

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
    public func delete(record: RecordView) {
        commitThenReload { try session.tombstoneRecord(blockUuid: $0, recordUuid: record.uuid) }
    }

    /// Restore a soft-deleted record, then re-read.
    public func restore(record: RecordView) {
        commitThenReload { try session.resurrectRecord(blockUuid: $0, recordUuid: record.uuid) }
    }

    /// Re-read the currently-selected block (e.g. after the edit sheet writes),
    /// using the VM's own selection rather than a caller-held BlockSummary.
    /// No-op if no block is selected.
    public func refresh() {
        guard let blockUuid = selectedBlockUuid else { return }
        reload(blockUuid: blockUuid)
    }

    /// Run a mutation against the selected block, then re-read on success. A
    /// failed mutation surfaces `error` but deliberately leaves `records` (and
    /// any reveal) intact — a rejected delete must not blank the visible list.
    private func commitThenReload(_ op: ([UInt8]) throws -> Void) {
        guard let blockUuid = selectedBlockUuid else { return }
        guard !isWriting else { return }
        isWriting = true
        defer { isWriting = false }
        do {
            try op(blockUuid)
        } catch let e as VaultAccessError {
            error = e
            return
        } catch {
            self.error = .other(String(describing: error))
            return
        }
        reload(blockUuid: blockUuid)
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
        session.wipe()
    }

    /// Build a record-edit VM bound to this session + the selected block.
    /// Returns nil if no block is selected. The edit screen calls `commit()`;
    /// on success the browse screen re-selects the block to refresh the list.
    public func makeEditViewModel(mode: RecordEditViewModel.Mode) -> RecordEditViewModel? {
        guard let blockUuid = selectedBlockUuid else { return nil }
        return RecordEditViewModel(session: session, blockUuid: blockUuid, mode: mode)
    }
}
