package org.secretary.app

import android.content.Context
import android.os.SystemClock
import android.util.Log
import androidx.fragment.app.FragmentActivity
import org.secretary.browse.CoordinatorBiometricAuthorizer
import org.secretary.browse.FileDeviceUuidStore
import org.secretary.browse.GraceWindowReauthGate
import org.secretary.browse.NoopReauthGate
import org.secretary.browse.UnlockCredential
import org.secretary.browse.VaultLocation
import org.secretary.browse.VaultLocationStore
import org.secretary.browse.VaultSelectionViewModel
import org.secretary.browse.WriteReauthGate
import org.secretary.browse.hexToBytesPublic
import org.secretary.browse.uniffiVaultOpenPort
import org.secretary.mirror.FilePendingFlushMarker
import org.secretary.mirror.PendingFlushNotPersisted
import org.secretary.mirror.VaultMirror
import org.secretary.mirror.VaultMirrorWorkingCopy
import org.secretary.mirror.VaultWorkingCopyCoordinator
import org.secretary.mirror.WorkingCopyMirror
import org.secretary.mirror.RetryingCloudFolderPort
import org.secretary.mirror.safCloudFolderPort
import java.io.File

private const val TAG = "CloudVaultOpen"

/**
 * The decision for a failed cloud open/create, factored out of [openCloudTarget] so it is
 * host-testable without a Context. [createdButNotSynced] is true only for [PendingFlushNotPersisted]
 * (an offline-created vault that could neither sync nor be marked for retry). The [target] is always
 * returned with `isCreate` unchanged so a reopen retries the push (never a materialize that could
 * clobber the un-pushed vault — the materialize guard backs this up).
 *
 * Today [createdButNotSynced] only selects a louder log line in [openCloudTarget]; both failure
 * branches return the same [Route.Unlock]. The data is preserved regardless (materialize guard +
 * push-before-pull retry), so the user is not warned in the UI yet — wiring [createdButNotSynced]
 * into a user-facing banner is deferred to #329.
 */
internal data class CloudOpenFailure(val target: CloudVaultTarget, val createdButNotSynced: Boolean)

internal fun cloudOpenFailureRoute(error: Throwable, target: CloudVaultTarget): CloudOpenFailure =
    CloudOpenFailure(target, createdButNotSynced = error is PendingFlushNotPersisted)

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
 *
 * The [mirror] is built by the caller so it can also be handed to [openCloudBrowse] as the throwing
 * flush for the atomic device enroll.
 */
internal fun cloudCoordinator(
    context: Context,
    location: VaultLocation,
    mirror: WorkingCopyMirror,
    openAndSync: suspend () -> BrowseSession,
): VaultWorkingCopyCoordinator<BrowseSession> {
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
 * Write-reauth gate: [cloudDeviceUnlockCoordinator] reads enrollment state for this cloud vault;
 * [cloudReauthRoute] selects [GateChoice.GRACE_WINDOW] when a device secret is enrolled for this
 * exact vault UUID, or [GateChoice.NOOP] otherwise (un-enrolled or stale enrollment). The grace
 * window is seeded inside [openBrowseWithSync] (it seeds the gate it is handed), so the window starts
 * at the real unlock instant — this path does not seed again.
 *
 * Device enroll: when [enrollThisDevice] is true and the credential is a password, calls
 * [cloudEnrollThisDevice] to mint `devices/<uuid>.wrap` and flush it atomically to the cloud. This
 * runs BEFORE the `finally` zeroize (the password is still live). On failure the enroll is non-fatal
 * (logged + swallowed); the open already succeeded and Browse is still returned.
 *
 * Secret hygiene mirrors `unlockAndOpen`: the credential bytes are zeroized in a `finally` wrapping
 * the whole body (success or open failure). The password background sync-at-unlock copy is
 * independent of the zeroize here.
 *
 * @throws the typed open errors from VaultOpenPort — the caller (Unlock handler) catches and routes
 *   back to Unlock carrying the same cloud target.
 */
internal suspend fun openCloudBrowse(
    context: Context,
    activity: FragmentActivity,
    workingDir: File,
    credential: UnlockCredential,
    coordinator: VaultWorkingCopyCoordinator<BrowseSession>,
    location: VaultLocation,
    enrollThisDevice: Boolean,
    flushWorkingToCloud: suspend () -> Unit,
    onVaultUuidLearned: (String) -> Unit,
): BrowseSession {
    try {
        val deviceUuids = FileDeviceUuidStore(File(context.noBackupFilesDir, "devices"))
        val stateDir = syncStateDir(context.filesDir).apply { mkdirs() }
        val vaultId = location.vaultUuidHex
        val deviceUnlock = cloudDeviceUnlockCoordinator(activity, context.noBackupFilesDir, cloudVaultKey(location.treeUri))
        val gate: WriteReauthGate = when (cloudReauthRoute(deviceUnlock.enclaveEnrolled, vaultId, deviceUnlock.metadataVaultId)) {
            GateChoice.GRACE_WINDOW -> GraceWindowReauthGate(
                authorizer = CoordinatorBiometricAuthorizer(deviceUnlock.coordinator, vaultId),
                clock = { SystemClock.elapsedRealtime() },
            )
            GateChoice.NOOP -> NoopReauthGate
        }
        var learnedVaultId = vaultId // will be overwritten by onVaultUuidLearned with the real resolved uuid
        val session = openBrowseWithSync(
            uniffiVaultOpenPort(deviceUuids),
            workingDir,
            stateDir,
            vaultUuid = if (vaultId.isEmpty()) ByteArray(0) else hexToBytesPublic(vaultId),
            credential = credential,
            gate = gate,
            onCommit = { coordinator.afterCommit() },
            onVaultUuidLearned = { resolvedHex ->
                learnedVaultId = resolvedHex
                onVaultUuidLearned(resolvedHex)
            },
        )
        // openBrowseWithSync already seeds the gate it was handed (BrowseSession.openBrowseWithSync),
        // matching the demo path — do not seed again here.
        session.sync.refreshStatus()
        // learnedVaultId is populated by onVaultUuidLearned (fired inside openBrowseWithSync before it
        // returns); the isNotEmpty() guard makes "never enrol against an empty vaultId" a LOCAL
        // invariant rather than relying on that call ordering.
        if (enrollThisDevice && credential is UnlockCredential.Password && learnedVaultId.isNotEmpty()) {
            try {
                cloudEnrollThisDevice(
                    coordinator = deviceUnlock.coordinator,
                    // Skip-guard compares against learnedVaultId (the resolved UUID), NOT the pre-open
                    // vaultId — a SAF-picked vault may not know its UUID until open. Do not "dedup" to vaultId.
                    alreadyEnrolledForThisVault = deviceUnlock.enclaveEnrolled && deviceUnlock.metadataVaultId == learnedVaultId,
                    workingDirPath = workingDir.path,
                    vaultId = learnedVaultId,
                    password = credential.secret,
                    flushWorkingToCloud = flushWorkingToCloud,
                )
            } catch (e: Exception) {
                Log.w(TAG, "cloud device enroll failed; password open still succeeded", e)
                // Non-fatal: route to Browse regardless (mirrors demo unlockAndOpen).
            }
        }
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
 *
 * The [mirror] is constructed once here and passed into [cloudCoordinator] and as the throwing flush
 * into [openCloudBrowse] so the device enroll can flush the new wrap file atomically.
 */
internal suspend fun openCloudTarget(
    context: Context,
    activity: FragmentActivity,
    target: CloudVaultTarget,
    credential: UnlockCredential,
    enrollThisDevice: Boolean,
    locationStore: VaultLocationStore,
    selectionVm: VaultSelectionViewModel,
): Route {
    // The learned UUID is captured here so the open path can persist it back; for the create path the
    // location already carries the UUID so this is a harmless re-affirm. openCloudBrowse needs the
    // coordinator (to wire afterCommit) and the coordinator needs openCloudBrowse (as openAndSync), so
    // the coordinator is `lateinit` and captured by the openAndSync closure.
    var location = target.location
    val mirror = VaultMirrorWorkingCopy(
        VaultMirror(
            RetryingCloudFolderPort(
                safCloudFolderPort(context, location.treeUri),
                onRetry = { Log.i(TAG, it) },
            ),
        ),
        target.workingDir,
    )
    lateinit var coordinator: VaultWorkingCopyCoordinator<BrowseSession>
    coordinator = cloudCoordinator(context, location, mirror) {
        openCloudBrowse(
            context = context,
            activity = activity,
            workingDir = target.workingDir,
            credential = credential,
            coordinator = coordinator,
            location = location,
            enrollThisDevice = enrollThisDevice,
            flushWorkingToCloud = { mirror.flush() }, // throwing flush for atomic enroll
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
        val failure = cloudOpenFailureRoute(e, target)
        if (failure.createdButNotSynced) {
            Log.w(TAG, "cloud vault CREATED but not synced and not marked for retry — user must not lose it", e)
        } else {
            Log.w(TAG, "cloud open/create failed; returning to unlock with same target", e)
        }
        Route.Unlock(cloudTarget = failure.target)
    } finally {
        // Backstop zeroize: openCloudBrowse zeroizes too, but the coordinator's flush/materialize
        // runs BEFORE openAndSync — if it throws, openCloudBrowse (and its finally) never runs, so the
        // credential would otherwise linger. fill(0) is idempotent; no background copy exists on the
        // cloud path (no sync-at-unlock is fired here), so a double-fill cannot corrupt anything.
        credential.secret.fill(0)
    }
}
