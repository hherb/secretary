import Combine
import SecretaryVaultAccess

/// Host-testable Trash browser view model. Mirrors
/// `VaultBrowseViewModel.reauthedWrite`: the `isWriting` guard is set BEFORE
/// the gate await; a refused re-auth aborts silently (error surfaced, list
/// untouched). Destructive-op reports are discarded — the reloaded (empty)
/// list is the success signal, parity with desktop.
@MainActor
public final class TrashViewModel: ObservableObject {
    @Published public private(set) var entries: [TrashedBlockInfo] = []
    @Published public private(set) var error: VaultAccessError?
    @Published public private(set) var isWriting = false
    /// Populated by `previewRetention()`; drives the retention sheet summary.
    @Published public private(set) var preview: [ExpiredEntryInfo]?

    private let port: TrashPort
    private let gate: WriteReauthGate

    public init(port: TrashPort, gate: WriteReauthGate) {
        self.port = port
        self.gate = gate
    }

    /// The frozen 90-day default retention window (no per-vault setting yet).
    public var retentionWindowMs: UInt64 { port.defaultRetentionWindowMs() }

    public func load() {
        error = nil
        do {
            entries = sortTrashed(try port.listTrashedBlocks())
        } catch let e as VaultAccessError {
            error = e
        } catch {
            self.error = .other(String(describing: error))
        }
    }

    public func previewRetention() {
        preview = port.expiredTrashEntries(windowMs: port.defaultRetentionWindowMs())
    }

    public func restore(uuid: [UInt8]) async {
        _ = await reauthedWrite(reason: "Confirm restoring this block") {
            try self.port.restoreBlock(uuid: uuid)
        }
    }

    public func purge(uuid: [UInt8]) async {
        _ = await reauthedWrite(reason: "Confirm permanently deleting this block") {
            _ = try self.port.purgeBlock(uuid: uuid)
        }
    }

    public func emptyTrash() async {
        _ = await reauthedWrite(reason: "Confirm permanently deleting all trashed blocks") {
            _ = try self.port.emptyTrash()
        }
    }

    public func runRetention() async {
        let window = port.defaultRetentionWindowMs()
        _ = await reauthedWrite(reason: "Confirm permanently deleting expired trash") {
            _ = try self.port.autoPurgeExpired(windowMs: window)
        }
    }

    /// Re-auth, run a guarded write, then reload. `isWriting` set before the
    /// gate await so a second action during the biometric prompt is rejected.
    private func reauthedWrite(reason: String, op: () throws -> Void) async -> Bool {
        guard !isWriting else { return false }
        isWriting = true
        defer { isWriting = false }
        do {
            try await gate.authorizeWrite(reason: reason)
        } catch let e as VaultAccessError {
            error = e
            return false
        } catch {
            self.error = .reauthFailed(String(describing: error))
            return false
        }
        do {
            try op()
        } catch let e as VaultAccessError {
            error = e
            return false
        } catch {
            self.error = .other(String(describing: error))
            return false
        }
        load()
        return true
    }
}
