// VaultSyncViewModel.swift
import Foundation
import Combine
import SecretaryVaultAccess

/// Drives the iOS sync UI: the status badge, sync-at-unlock, "Sync now", and
/// conflict resolution. Host-testable — holds only the pure `SyncCoordinator`,
/// an injected `WallClock`, the write re-auth gate, the (optional) 16-byte vault
/// UUID for status, and an optional `SyncMonitorHook`. It holds no secret: the
/// port syncs through the open session (#101), for every session kind.
///
/// Gating: `syncNow` and `resolve` ask `gate.authorizeWrite` first, because a pass
/// can write the vault. `syncAtUnlock` is deliberately NOT gated — the user
/// authenticated at that instant, and the password path does not seed the grace
/// window, so gating it would raise a Face ID prompt right after a typed password.
///
/// `@MainActor` (publishes UI state); the port offloads the pass, so the VM only
/// suspends, never blocks, the main actor.
@MainActor
public final class VaultSyncViewModel: ObservableObject {
    @Published public private(set) var badge: SyncBadgeState = .neverSynced
    @Published public private(set) var isSyncing = false
    @Published public private(set) var reviewNeeded = false
    @Published public private(set) var pendingConflict: PendingConflict?
    @Published public private(set) var lastError: VaultSyncError?
    @Published public var conflictSheetPresented = false

    private var pendingChanges = false
    private var lastStatus: SyncStatus?

    /// One reason for both gated entry points: each runs a pass that may write.
    static let gateReason = "Confirm syncing this vault"

    private let coordinator: SyncCoordinator
    private let wallClock: WallClock
    private let gate: WriteReauthGate
    private let vaultUuid: [UInt8]?
    // Strongly owned: no retain cycle — the factory's VMBox.vm back-reference is
    // already `weak`, so the vm → hook direction must be strong to keep the hook alive.
    private var monitor: SyncMonitorHook?
    // Strongly owned for the same reason: in production this closure is its only
    // reference, so a weak hold would make the browse reload silently no-op.
    private let onVaultChanged: (@MainActor () -> Void)?

    public init(coordinator: SyncCoordinator, wallClock: WallClock,
                gate: WriteReauthGate,
                vaultUuid: [UInt8]? = nil, monitor: SyncMonitorHook? = nil,
                onVaultChanged: (@MainActor () -> Void)? = nil) {
        self.coordinator = coordinator
        self.wallClock = wallClock
        self.gate = gate
        self.vaultUuid = vaultUuid
        self.monitor = monitor
        self.onVaultChanged = onVaultChanged
    }

    // MARK: - Trigger 1: sync-at-unlock (silent, never gated)

    /// Run one pass right after unlock. Auto arms update the badge silently;
    /// `conflictsPending` only flips `reviewNeeded` (no sheet — resolution defers
    /// to "Sync now").
    public func syncAtUnlock() async {
        await runPass { [weak self] outcome in
            guard let self else { return }
            if case .conflictsPending = outcome { self.reviewNeeded = true }
        }
    }

    // MARK: - Trigger 2: "Sync now" (gated)

    /// Entry point for the badge tap / "Sync now". Asks the re-auth gate, then
    /// runs a pass. A refusal sets `.reauthFailed` and runs no pass. On
    /// `conflictsPending` the conflict sheet opens; on any other arm it is cleared.
    public func syncNow() async {
        guard await authorized() else { return }
        await runPass { [weak self] outcome in
            guard let self else { return }
            if case let .conflictsPending(vetoes, collisions, _) = outcome {
                self.pendingConflict = PendingConflict(vetoes: vetoes, collisions: collisions)
                self.reviewNeeded = true
                self.conflictSheetPresented = true
            } else {
                self.reviewNeeded = false
                self.conflictSheetPresented = false
                self.pendingConflict = nil
            }
        }
    }

    // MARK: - Badge

    private func recomputeBadge() {
        badge = syncBadgeState(inProgress: isSyncing, pendingChanges: pendingChanges,
                               hasPendingConflict: reviewNeeded, status: lastStatus)
    }

    /// Ask the gate. `isSyncing` is held across the await so a second tap while
    /// the prompt is up is dropped rather than prompting twice; it is released
    /// before returning, with no suspension point before the caller's pass sets it
    /// again. Returns false (and sets `.reauthFailed`) on refusal.
    private func authorized() async -> Bool {
        guard !isSyncing else { return false }
        isSyncing = true
        defer { isSyncing = false }
        do {
            try await gate.authorizeWrite(reason: Self.gateReason)
            return true
        } catch {
            lastError = .reauthFailed(foldDiagnostic(error))
            return false
        }
    }

    /// Fire `onVaultChanged` unless the outcome left the session untouched.
    /// The session sync refreshes the handle on every other arm, `.silentMerge`
    /// included, so the browse list must reload to show it.
    private func notifyIfChanged(_ outcome: SyncOutcome) {
        switch outcome {
        case .rollbackRejected, .conflictsPending: return
        default: onVaultChanged?()
        }
    }

    /// Shared pass runner: mute self-writes, flip `isSyncing`, run, route the
    /// outcome through `onSuccess`, acknowledge on success, refresh status.
    private func runPass(onSuccess: (SyncOutcome) -> Void) async {
        isSyncing = true
        lastError = nil
        recomputeBadge()
        monitor?.muteSelfWrite()
        do {
            let outcome = try await coordinator.runPass(nowMs: wallClock.nowMs())
            onSuccess(outcome)
            notifyIfChanged(outcome)
            monitor?.acknowledge()
            pendingChanges = false
            await refreshStatus()
        } catch let e as VaultSyncError {
            lastError = e
        } catch {
            lastError = .failed(foldDiagnostic(error))
        }
        isSyncing = false
        recomputeBadge()
    }

    // MARK: - Monitor input

    /// The change monitor raised its advisory flag. Mirror it into the badge.
    public func pendingChangesRaised() {
        pendingChanges = true
        recomputeBadge()
    }

    // MARK: - Trigger 3: resolve conflict (gated)

    /// Commit the user's per-record decisions for the pending conflict, after the
    /// re-auth gate. A refusal sets `.reauthFailed`, commits nothing, and leaves
    /// the sheet open. On any non-conflict result, dismiss + clear; on
    /// `evidenceStale` / `decisionsIncomplete`, keep the sheet open (the
    /// coordinator preserves the stash) so the user can re-apply.
    public func resolve(decisions: [SyncVetoDecision]) async {
        guard await authorized() else { return }
        isSyncing = true
        lastError = nil
        recomputeBadge()
        monitor?.muteSelfWrite()
        do {
            let outcome = try await coordinator.resolve(decisions: decisions,
                                                        nowMs: wallClock.nowMs())
            if case let .conflictsPending(vetoes, collisions, _) = outcome {
                pendingConflict = PendingConflict(vetoes: vetoes, collisions: collisions)
            } else {
                conflictSheetPresented = false
                pendingConflict = nil
                reviewNeeded = false
            }
            notifyIfChanged(outcome)
            monitor?.acknowledge()
            pendingChanges = false
            await refreshStatus()
        } catch let e as VaultSyncError {
            lastError = e
        } catch {
            lastError = .failed(foldDiagnostic(error))
        }
        isSyncing = false
        recomputeBadge()
    }

    /// Dismiss the conflict sheet without committing. Keeps `reviewNeeded` so the
    /// badge still flags that the conflict is unresolved.
    public func cancelConflict() {
        conflictSheetPresented = false
        pendingConflict = nil
    }

    // MARK: - Status

    /// Best-effort: needs the 16-byte vault UUID. Failures are swallowed (the
    /// badge simply keeps its prior last-synced label).
    public func refreshStatus() async {
        guard let vaultUuid else { return }
        lastStatus = try? await coordinator.status(vaultUuid: vaultUuid)
    }
}
