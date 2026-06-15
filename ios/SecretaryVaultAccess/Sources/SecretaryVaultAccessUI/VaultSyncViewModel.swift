// VaultSyncViewModel.swift
import Foundation
import Combine
import SecretaryVaultAccess

/// Drives the iOS sync UI: the status badge, sync-at-unlock, the re-prompt sync,
/// and conflict resolution. Host-testable — holds only the pure `SyncCoordinator`,
/// an injected `WallClock`, the (optional) 16-byte vault UUID for status, and an
/// optional `SyncMonitorHook`. It NEVER stores a password: each password arrives
/// as a method argument for a single in-flight call. `@MainActor` (publishes UI
/// state); the CPU-heavy Argon2id pass is offloaded by the port, so the VM only
/// suspends, never blocks, the main actor.
@MainActor
public final class VaultSyncViewModel: ObservableObject {
    @Published public private(set) var badge: SyncBadgeState = .neverSynced
    @Published public private(set) var isSyncing = false
    @Published public private(set) var reviewNeeded = false
    @Published public private(set) var pendingConflict: PendingConflict?
    @Published public private(set) var lastError: VaultSyncError?
    @Published public var passwordSheetPresented = false
    @Published public var conflictSheetPresented = false

    private var pendingChanges = false
    private var lastStatus: SyncStatus?

    private let coordinator: SyncCoordinator
    private let wallClock: WallClock
    private let vaultUuid: [UInt8]?
    private weak var monitor: SyncMonitorHook?

    public init(coordinator: SyncCoordinator, wallClock: WallClock,
                vaultUuid: [UInt8]? = nil, monitor: SyncMonitorHook? = nil) {
        self.coordinator = coordinator
        self.wallClock = wallClock
        self.vaultUuid = vaultUuid
        self.monitor = monitor
    }

    // MARK: - Trigger 1: sync-at-unlock (silent; password already in hand)

    /// Run one pass with the just-used password. Auto arms update the badge
    /// silently; `conflictsPending` only flips `reviewNeeded` (no sheet, password
    /// dropped — resolution defers to the interactive path).
    public func syncAtUnlock(password: [UInt8]) async {
        await runPass(password: password) { [weak self] outcome in
            guard let self else { return }
            if case .conflictsPending = outcome { self.reviewNeeded = true }
        }
    }

    // MARK: - Badge

    private func recomputeBadge() {
        badge = syncBadgeState(inProgress: isSyncing, pendingChanges: pendingChanges,
                               hasPendingConflict: reviewNeeded, status: lastStatus)
    }

    /// Shared pass runner: mute self-writes, flip `isSyncing`, run, route the
    /// outcome through `onSuccess`, acknowledge on success, refresh status.
    private func runPass(password: [UInt8],
                         onSuccess: (SyncOutcome) -> Void) async {
        isSyncing = true
        lastError = nil
        recomputeBadge()
        monitor?.muteSelfWrite()
        do {
            let outcome = try await coordinator.runPass(password: password,
                                                        nowMs: wallClock.nowMs())
            onSuccess(outcome)
            monitor?.acknowledge()
            pendingChanges = false
            await refreshStatus()
        } catch let e as VaultSyncError {
            lastError = e
        } catch {
            lastError = .failed(String(describing: error))
        }
        isSyncing = false
        recomputeBadge()
    }

    // MARK: - Status

    /// Best-effort: needs the 16-byte vault UUID. Failures are swallowed (the
    /// badge simply keeps its prior last-synced label).
    public func refreshStatus() async {
        guard let vaultUuid else { return }
        lastStatus = try? await coordinator.status(vaultUuid: vaultUuid)
    }
}
