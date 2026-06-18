package org.secretary.app

import org.secretary.browse.VaultBrowseModel
import org.secretary.browse.VaultOpenPort
import org.secretary.browse.ui.VaultBrowseViewModel
import org.secretary.sync.ChangeDetectionMonitor
import org.secretary.sync.makeVaultSync
import org.secretary.sync.ui.VaultSyncViewModel
import java.io.File

/**
 * The three handles for an unlocked, browsable, sync-aware session. Mirrors the iOS
 * `.browse(VaultBrowseViewModel, VaultSyncViewModel, ChangeDetectionMonitor)` route payload.
 * The caller owns the monitor lifecycle (`start()` on screen entry, `stop()` on dispose).
 */
data class BrowseSession(
    val browse: VaultBrowseViewModel,
    val sync: VaultSyncViewModel,
    val monitor: ChangeDetectionMonitor,
)

/**
 * Opens the vault for browsing and assembles the sync model+monitor for the same folder.
 *
 * MUST be called on the main thread: [makeVaultSync] is Looper-gated. [openPort.openWithPassword]
 * suspends and hops to IO internally, returning to the caller's (main) dispatcher afterward, so the
 * subsequent [makeVaultSync] call is still on main.
 *
 * Does NOT launch sync-at-unlock and does NOT zeroize [password] — the caller owns the original
 * buffer (it zeroizes the original after handing a copy to [launchSyncAtUnlock]; see AppRoot).
 *
 * @throws the same typed open errors as [VaultOpenPort.openWithPassword] (e.g. wrong password) —
 *   the caller catches and returns the user to Unlock.
 */
suspend fun openBrowseWithSync(
    openPort: VaultOpenPort,
    folder: File,
    stateDir: File,
    vaultUuid: ByteArray,
    password: ByteArray,
): BrowseSession {
    val session = openPort.openWithPassword(folder.path, password)
    val browseModel = VaultBrowseModel(session)
    browseModel.loadBlocks()
    val (syncModel, monitor) = makeVaultSync(folder, stateDir, vaultUuid)
    return BrowseSession(
        browse = VaultBrowseViewModel(browseModel),
        sync = VaultSyncViewModel(syncModel),
        monitor = monitor,
    )
}
