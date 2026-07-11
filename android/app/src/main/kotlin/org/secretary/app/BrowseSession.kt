package org.secretary.app

import android.os.SystemClock
import org.secretary.browse.NoopReauthGate
import org.secretary.browse.TrashBrowseModel
import org.secretary.browse.TrashPort
import org.secretary.browse.UnlockCredential
import org.secretary.browse.hexToBytesPublic
import org.secretary.browse.VaultBrowseModel
import org.secretary.browse.VaultOpenPort
import org.secretary.browse.WriteReauthGate
import org.secretary.browse.openWithCredential
import org.secretary.browse.ui.TrashBrowseViewModel
import org.secretary.browse.ui.VaultBrowseViewModel
import org.secretary.sync.ChangeDetectionMonitor
import org.secretary.sync.makeVaultSync
import org.secretary.sync.ui.VaultSyncViewModel
import java.io.File

/**
 * The three handles for an unlocked, browsable, sync-aware session. Mirrors the iOS
 * `.browse(VaultBrowseViewModel, VaultSyncViewModel, ChangeDetectionMonitor)` route payload.
 * The caller owns the monitor lifecycle (`start()` on screen entry, `stop()` on dispose).
 *
 * [trash] is OPTIONAL: it is only non-null when the opened session conforms to [TrashPort] (the
 * real [org.secretary.browse.UniffiVaultSession] always does; a non-conforming fake session, e.g.
 * in host tests, leaves it null so existing callers are unaffected).
 */
data class BrowseSession(
    val browse: VaultBrowseViewModel,
    val sync: VaultSyncViewModel,
    val monitor: ChangeDetectionMonitor,
    val trash: TrashBrowseViewModel? = null,
)

/**
 * Opens the vault for browsing with the supplied [credential] and assembles the sync model+monitor
 * for the same folder.
 *
 * MUST be called on the main thread: [makeVaultSync] is Looper-gated. The open suspends and hops to
 * IO internally, returning to the caller's (main) dispatcher afterward, so [makeVaultSync] is still
 * on main.
 *
 * Does NOT zeroize the credential bytes and does NOT launch sync-at-unlock — the caller owns both.
 * AppRoot zeroizes the credential bytes unconditionally (both credentials, in its `finally` block);
 * the copy handed to launchSyncAtUnlock is password-only (a recovery open has no password to sync with).
 *
 * [onCommit] is invoked by the browse model after every successful committed write (Task 7's seam):
 * the cloud path wires it to `coordinator.afterCommit()` so a commit is flushed working→cloud. The
 * default no-op keeps the demo (golden-vault) path unchanged.
 *
 * [vaultUuid] may be an EMPTY array for a SAF-picked existing vault whose UUID is not yet known: the
 * real UUID is learned from the opened session and threaded into sync, and [onVaultUuidLearned] is
 * invoked with its lowercase hex so the caller can persist it back into the remembered location.
 * (An empty UUID would otherwise suppress sync status reads — see makeVaultSync's `vaultUuid: null`.)
 * When [vaultUuid] is non-empty it is used as-is and [onVaultUuidLearned] still fires with its hex.
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
    gate: WriteReauthGate = NoopReauthGate,
    onCommit: suspend () -> Unit = {},
    onVaultUuidLearned: (String) -> Unit = {},
): BrowseSession {
    val session = openWithCredential(openPort, folder.path, credential)
    // Learn the real UUID from the opened session when the caller passed an empty one (a SAF-picked
    // existing vault). The session snapshots its UUID at construction, so this never touches a wiped
    // handle. Pass the resolved bytes to makeVaultSync so status reads are not suppressed.
    val resolvedUuidHex = session.vaultUuidHex()
    onVaultUuidLearned(resolvedUuidHex)
    val effectiveUuid = if (vaultUuid.isNotEmpty()) vaultUuid else hexToBytesPublic(resolvedUuidHex)
    val browseModel = VaultBrowseModel(session, gate, onCommit)
    // Monotonic clock (elapsedRealtime, not wall-clock): the grace window measures *elapsed* time
    // since the last proof, so it must not move under NTP corrections or a user-set system clock.
    // MUST share the same time base as the gate's clock in AppRoot.unlockAndOpen.
    gate.seed(SystemClock.elapsedRealtime()) // just unlocked → open the grace window
    browseModel.loadBlocks()
    val (syncModel, monitor) = makeVaultSync(folder, stateDir, effectiveUuid)
    // Built from the SAME already-open session + gate the browse write path uses — no second FFI
    // open. `session` is the real UniffiVaultSession in production (and in every androidTest
    // caller), which now conforms to TrashPort; the safe cast is null only for a non-conforming
    // fake session (e.g. a host-test double), which leaves `trash` null.
    val trashVm = (session as? TrashPort)?.let { TrashBrowseViewModel(TrashBrowseModel(it, gate)) }
    return BrowseSession(
        browse = VaultBrowseViewModel(browseModel),
        sync = VaultSyncViewModel(syncModel),
        monitor = monitor,
        trash = trashVm,
    )
}
