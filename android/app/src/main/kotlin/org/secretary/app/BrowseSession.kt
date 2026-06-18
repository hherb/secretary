package org.secretary.app

import org.secretary.browse.UnlockCredential
import org.secretary.browse.VaultBrowseModel
import org.secretary.browse.VaultOpenPort
import org.secretary.browse.openWithCredential
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
 * Opens the vault for browsing with the supplied [credential] and assembles the sync model+monitor
 * for the same folder.
 *
 * MUST be called on the main thread: [makeVaultSync] is Looper-gated. The open suspends and hops to
 * IO internally, returning to the caller's (main) dispatcher afterward, so [makeVaultSync] is still
 * on main.
 *
 * Does NOT zeroize the credential bytes and does NOT launch sync-at-unlock — the caller owns both
 * (see AppRoot: it zeroizes after handing a copy to launchSyncAtUnlock, and only for the password
 * credential; a recovery open has no password to sync with).
 *
 * @throws the typed open errors from [VaultOpenPort] (e.g. WrongPasswordOrCorrupt /
 *   WrongRecoveryOrCorrupt / InvalidRecoveryPhrase) — the caller catches and returns to Unlock.
 */
suspend fun openBrowseWithSync(
    openPort: VaultOpenPort,
    folder: File,
    stateDir: File,
    vaultUuid: ByteArray,
    credential: UnlockCredential,
): BrowseSession {
    val session = openWithCredential(openPort, folder.path, credential)
    val browseModel = VaultBrowseModel(session)
    browseModel.loadBlocks()
    val (syncModel, monitor) = makeVaultSync(folder, stateDir, vaultUuid)
    return BrowseSession(
        browse = VaultBrowseViewModel(browseModel),
        sync = VaultSyncViewModel(syncModel),
        monitor = monitor,
    )
}
