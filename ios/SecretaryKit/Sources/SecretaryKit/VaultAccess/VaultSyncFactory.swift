import Foundation
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Assemble the sync VM + change monitor for an open vault, wiring the two-way
/// link (monitor.onChange → vm.pendingChangesRaised; vm self-write/ack → monitor)
/// and resolving the construction cycle via a late-bound monitor reference.
///
/// The session itself is the sync port (#101: `UniffiVaultSession+Sync.swift`),
/// so sync needs no password on any unlock path. `gate` must be the SAME gate the
/// browse VM writes through, so "Sync now" / Apply share its grace window.
/// `onVaultChanged` runs after a pass that changed the session (the caller
/// reloads the browse list). `folder` is the open vault's folder URL
/// (security-scoped by the browse session), watched by the change monitor.
/// `stateDir` is the app-sandbox sync state dir (`defaultSyncStateDir`).
@MainActor
public func makeVaultSync(
    session: VaultSession,
    folder: URL,
    stateDir: URL,
    gate: WriteReauthGate,
    onVaultChanged: @escaping @MainActor () -> Void
) -> (VaultSyncViewModel, ChangeDetectionMonitor) {
    guard let port = session as? VaultSyncPort else {
        preconditionFailure("production sessions conform to VaultSyncPort")
    }
    let coordinator = SyncCoordinator(port: port, stateDir: stateDir.path)
    let vaultUuid = HexUuid.bytes(fromHex: session.vaultUuidHex)

    // Late-bound VM reference so the monitor's onChange can forward into it.
    final class VMBox { weak var vm: VaultSyncViewModel? }
    let box = VMBox()
    let monitor = makeChangeMonitor(folder: folder,
                                    onChange: { [box] in box.vm?.pendingChangesRaised() })
    let hook = MonitorSyncHook(monitor: monitor)
    let vm = VaultSyncViewModel(coordinator: coordinator,
                                wallClock: SystemWallClock(),
                                gate: gate,
                                vaultUuid: vaultUuid,
                                monitor: hook,
                                onVaultChanged: onVaultChanged)
    box.vm = vm
    return (vm, monitor)
}
