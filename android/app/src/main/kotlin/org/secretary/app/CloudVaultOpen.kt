package org.secretary.app

import android.content.Context
import android.util.Log
import org.secretary.browse.FileDeviceUuidStore
import org.secretary.browse.UnlockCredential
import org.secretary.browse.VaultLocation
import org.secretary.browse.VaultLocationStore
import org.secretary.browse.VaultSelectionViewModel
import org.secretary.browse.hexToBytesPublic
import org.secretary.browse.uniffiVaultOpenPort
import org.secretary.mirror.FilePendingFlushMarker
import org.secretary.mirror.VaultMirror
import org.secretary.mirror.VaultMirrorWorkingCopy
import org.secretary.mirror.VaultWorkingCopyCoordinator
import org.secretary.mirror.safCloudFolderPort
import java.io.File

private const val TAG = "CloudVaultOpen"

/**
 * The cloud vault the Unlock screen is gating, carried into [Route.Unlock] so the credential the
 * user enters there is applied to THIS cloud vault (not the demo golden vault). Both cloud paths —
 * opening a remembered vault and the just-created vault — route through the SAME Unlock screen so
 * they reuse the existing password/biometric UI and its zeroize discipline; the freshly-created
 * vault is NOT auto-opened with the wizard password (matches desktop "no auto-open").
 *
 * @param location the remembered (or just-created+persisted) cloud location, incl. its tree URI.
 * @param workingDir the app-private working copy the coordinator materializes into / flushes from.
 * @param isCreate true for the create-then-open flow (flush working→cloud first, push the new vault
 *   up, then open); false for opening a remembered vault (flush any pending edits, materialize, open).
 */
data class CloudVaultTarget(
    val location: VaultLocation,
    val workingDir: File,
    val isCreate: Boolean,
)

/**
 * Assemble the working-copy coordinator for a cloud [location]. The pending-flush marker lives in
 * the app-private sync-state dir (NOT the working copy — [VaultMirror] mirrors every working file,
 * so a marker placed there would be pushed to the cloud and deleted on materialize). [openAndSync]
 * runs the existing open+sync pass against the materialized working dir.
 *
 * The marker filename is keyed by [cloudVaultKey] (a stable hash of the cloud treeUri), the SAME key
 * as [workingDir], so a pending-flush set in one session is always re-checked on the next open of the
 * same cloud vault — un-pushed edits can never orphan, even before the vault UUID is known.
 */
internal fun cloudCoordinator(
    context: Context,
    location: VaultLocation,
    workingDir: File,
    openAndSync: suspend () -> BrowseSession,
): VaultWorkingCopyCoordinator<BrowseSession> {
    val cloud = safCloudFolderPort(context, location.treeUri)
    val mirror = VaultMirrorWorkingCopy(VaultMirror(cloud), workingDir)
    val markerName = "${cloudVaultKey(location.treeUri)}.pending-flush"
    val markerFile = File(syncStateDir(context.filesDir), markerName)
    return VaultWorkingCopyCoordinator(mirror, FilePendingFlushMarker(markerFile), openAndSync)
}

/**
 * Opens a materialized cloud working copy into Browse — the cloud sibling of `unlockAndOpen`. Runs
 * AFTER the coordinator has materialized [workingDir] (open path) or is about to flush it (create
 * path). Wires [onCommit] = `coordinator.afterCommit` so each committed write is flushed working→
 * cloud; and threads the learned vault UUID back via [onVaultUuidLearned] (a SAF-picked existing
 * vault may not know its UUID until first open).
 *
 * Secret hygiene mirrors `unlockAndOpen`: the credential bytes are zeroized in a `finally` wrapping
 * the whole body (success or open failure). The password background sync-at-unlock copy is
 * independent of the zeroize here.
 *
 * Sync-at-unlock is deliberately NOT fired here: Android sync is the cloud working-copy flush, which
 * the coordinator owns (materialize on open, afterCommit on each write). A status refresh keeps the
 * sync badge honest without re-entering the coordinator from the browse scope.
 *
 * @throws the typed open errors from VaultOpenPort — the caller (Unlock handler) catches and routes
 *   back to Unlock carrying the same cloud target.
 */
internal suspend fun openCloudBrowse(
    context: Context,
    workingDir: File,
    credential: UnlockCredential,
    coordinator: VaultWorkingCopyCoordinator<BrowseSession>,
    location: VaultLocation,
    onVaultUuidLearned: (String) -> Unit,
): BrowseSession {
    try {
        val deviceUuids = FileDeviceUuidStore(File(context.noBackupFilesDir, "devices"))
        val stateDir = syncStateDir(context.filesDir).apply { mkdirs() }
        val vaultId = location.vaultUuidHex
        // No write-reauth gate on the cloud path yet: no device secret is enrolled against a cloud
        // working copy (biometric write-reauth over a cloud vault is a later slice), so the default
        // NoopReauthGate authorizes writes — exactly what an un-enrolled GraceWindowReauthGate would do.
        val session = openBrowseWithSync(
            uniffiVaultOpenPort(deviceUuids),
            workingDir,
            stateDir,
            vaultUuid = if (vaultId.isEmpty()) ByteArray(0) else hexToBytesPublic(vaultId),
            credential = credential,
            onCommit = { coordinator.afterCommit() },
            onVaultUuidLearned = onVaultUuidLearned,
        )
        session.sync.refreshStatus()
        return session
    } finally {
        credential.secret.fill(0) // zeroize on every exit, mirroring unlockAndOpen's discipline
    }
}

/**
 * The cloud sibling of `unlockAndOpen`: applies the credential entered on the Unlock screen to the
 * [target] cloud vault via its working-copy coordinator, returning the Browse route on success or an
 * Unlock route carrying the SAME [target] on failure (so a retry stays pointed at this vault).
 *
 * - Open (`isCreate == false`): `coordinator.openExisting()` = flush any pending edits → materialize
 *   cloud→working → open+sync. If the location's UUID was empty (a SAF-picked existing vault), the
 *   real UUID is learned on open and persisted back into the remembered location.
 * - Create (`isCreate == true`): `coordinator.createThenOpen(uuid)` = flush working→cloud (pushes the
 *   freshly-created vault up) → persist → open+sync. The location is already persisted (in create());
 *   the persist callback refreshes the selection state.
 *
 * The credential bytes are zeroized inside [openCloudBrowse]'s `finally` on every exit (including the
 * coordinator/open failure caught here), preserving the `unlockAndOpen` zeroize discipline.
 */
internal suspend fun openCloudTarget(
    context: Context,
    target: CloudVaultTarget,
    credential: UnlockCredential,
    locationStore: VaultLocationStore,
    selectionVm: VaultSelectionViewModel,
): Route {
    // The learned UUID is captured here so the open path can persist it back; for the create path the
    // location already carries the UUID so this is a harmless re-affirm. openCloudBrowse needs the
    // coordinator (to wire afterCommit) and the coordinator needs openCloudBrowse (as openAndSync), so
    // the coordinator is `lateinit` and captured by the openAndSync closure.
    var location = target.location
    lateinit var coordinator: VaultWorkingCopyCoordinator<BrowseSession>
    coordinator = cloudCoordinator(context, location, target.workingDir) {
        openCloudBrowse(
            context = context,
            workingDir = target.workingDir,
            credential = credential,
            coordinator = coordinator,
            location = location,
            onVaultUuidLearned = { learnedHex ->
                if (location.vaultUuidHex.isEmpty() && learnedHex.isNotEmpty()) {
                    location = location.copy(vaultUuidHex = learnedHex)
                    locationStore.persist(location)
                    selectionVm.recordSelection(location)
                }
            },
        )
    }
    return try {
        val session = if (target.isCreate) {
            coordinator.createThenOpen(location.vaultUuidHex) {
                selectionVm.recordSelection(location) // location already carries the uuid
            }
        } else {
            coordinator.openExisting()
        }
        // Clear isCreate on the live Browse route: the vault has now been pushed up + opened, so it is
        // no longer "to be created". Backgrounding (ON_STOP) re-targets Unlock with THIS cloudTarget,
        // and a stuck isCreate=true would make every reopen run createThenOpen — which flushes
        // working→cloud and opens WITHOUT materialize(), so this device would never pull another
        // device's remote edits. isCreate=false routes reopens through openExisting (materialize → open).
        Route.Browse(session, target.workingDir, cloudTarget = target.copy(location = location, isCreate = false))
    } catch (e: Exception) {
        Log.w(TAG, "cloud open/create failed; returning to unlock with same target", e)
        Route.Unlock(cloudTarget = target)
    } finally {
        // Backstop zeroize: openCloudBrowse zeroizes too, but the coordinator's flush/materialize
        // runs BEFORE openAndSync — if it throws, openCloudBrowse (and its finally) never runs, so the
        // credential would otherwise linger. fill(0) is idempotent; no background copy exists on the
        // cloud path (no sync-at-unlock is fired here), so a double-fill cannot corrupt anything.
        credential.secret.fill(0)
    }
}
