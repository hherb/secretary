import Foundation
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Assemble the sync VM + change monitor for an open vault, wiring the two-way
/// link (monitor.onChange → vm.pendingChangesRaised; vm self-write/ack → monitor)
/// and resolving the construction cycle via a late-bound monitor reference.
///
/// `folder` is the open vault's folder URL (security-scoped by the browse
/// session). `stateDir` is the app-sandbox sync state dir (`defaultSyncStateDir`).
@MainActor
public func makeVaultSync(
    session: VaultSession,
    folder: URL,
    stateDir: URL
) -> (VaultSyncViewModel, ChangeDetectionMonitor) {
    let coordinator = SyncCoordinator(port: UniffiVaultSyncPort(),
                                      stateDir: stateDir.path,
                                      vaultFolder: folder.path)
    let vaultUuid = HexUuid.bytes(fromHex: session.vaultUuidHex)

    // Late-bound VM reference so the monitor's onChange can forward into it.
    final class VMBox { weak var vm: VaultSyncViewModel? }
    let box = VMBox()
    let monitor = makeChangeMonitor(folder: folder,
                                    onChange: { [box] in box.vm?.pendingChangesRaised() })
    let hook = MonitorSyncHook(monitor: monitor)
    let vm = VaultSyncViewModel(coordinator: coordinator,
                                wallClock: SystemWallClock(),
                                vaultUuid: vaultUuid,
                                monitor: hook)
    box.vm = vm
    return (vm, monitor)
}
