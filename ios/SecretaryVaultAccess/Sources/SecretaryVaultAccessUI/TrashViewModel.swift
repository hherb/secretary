import Combine
import SecretaryVaultAccess

/// Host-testable Trash browser view model. Mirrors
/// `VaultBrowseViewModel.reauthedWrite`: the `isWriting` guard is set BEFORE
/// the gate await; a refused re-auth aborts silently (error surfaced, list
/// untouched). Destructive-op reports are surfaced as `purgeNotice` (#411)
/// after the reload.
@MainActor
public final class TrashViewModel: ObservableObject {
    @Published public private(set) var entries: [TrashedBlockInfo] = []
    @Published public private(set) var error: VaultAccessError?
    @Published public private(set) var isWriting = false
    /// Populated by `previewRetention()`; drives the retention sheet summary.
    @Published public private(set) var preview: [ExpiredEntryInfo]?
    /// The last destructive op's outcome, rendered as an inline banner (#411).
    /// Cleared at the start of any new write; set on a successful op.
    @Published public private(set) var purgeNotice: PurgeNotice?

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

    /// Drop the cached preview so a reopened retention sheet shows its loading
    /// state instead of flashing the previous run's (now stale) result before
    /// `previewRetention()` recomputes.
    public func clearPreview() {
        preview = nil
    }

    public func restore(uuid: [UInt8]) async {
        _ = await reauthedWrite(reason: "Confirm restoring this block") {
            try self.port.restoreBlock(uuid: uuid)
        }
    }

    public func purge(uuid: [UInt8]) async {
        let result = await reauthedWrite(reason: "Confirm permanently deleting this block") {
            try self.port.purgeBlock(uuid: uuid)
        }
        if result != nil { purgeNotice = formatPurgeNotice(.singlePurge) }
    }

    public func emptyTrash() async {
        let report = await reauthedWrite(reason: "Confirm permanently deleting all trashed blocks") {
            try self.port.emptyTrash()
        }
        if let report {
            purgeNotice = formatPurgeNotice(.emptyTrash(purgedCount: report.purgedCount, filesFailed: report.filesFailed))
        }
    }

    public func runRetention() async {
        let window = port.defaultRetentionWindowMs()
        let report = await reauthedWrite(reason: "Confirm permanently deleting expired trash") {
            try self.port.autoPurgeExpired(windowMs: window)
        }
        if let report {
            purgeNotice = formatPurgeNotice(.retention(purgedCount: report.purgedCount, filesFailed: report.filesFailed))
        }
    }

    /// Re-auth, run a guarded write, then reload; returns the op's result (or
    /// nil if the guard/op failed). `isWriting` set before the gate await so a
    /// second action during the biometric prompt is rejected; `purgeNotice`
    /// cleared here so any initiated write supersedes the prior banner.
    private func reauthedWrite<T>(reason: String, op: () throws -> T) async -> T? {
        guard !isWriting else { return nil }
        isWriting = true
        purgeNotice = nil
        defer { isWriting = false }
        do {
            try await gate.authorizeWrite(reason: reason)
        } catch let e as VaultAccessError {
            error = e
            return nil
        } catch {
            self.error = .reauthFailed(String(describing: error))
            return nil
        }
        let result: T
        do {
            result = try op()
        } catch let e as VaultAccessError {
            error = e
            return nil
        } catch {
            self.error = .other(String(describing: error))
            return nil
        }
        load()
        return result
    }
}
