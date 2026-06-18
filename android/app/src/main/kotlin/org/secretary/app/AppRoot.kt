package org.secretary.app

import android.content.Context
import android.util.Log
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import org.secretary.browse.FileDeviceUuidStore
import org.secretary.browse.UnlockCredential
import org.secretary.browse.uniffiVaultOpenPort
import java.io.File

private const val TAG = "AppRoot"

/** The app's two screens; Browse carries the live session for the unlocked vault. */
private sealed interface Route {
    data object Unlock : Route
    data class Browse(val session: BrowseSession) : Route
}

/**
 * Top-level routing for the walking skeleton: Unlock → Browse. On unlock it opens the REAL vault
 * (open_vault_with_password, Argon2id offloaded to IO inside the port), builds a BrowseSession
 * (browse VM + sync VM + monitor), fires a background sync-at-unlock, and routes to the unified
 * BrowseWithSyncScreen. On background (ON_STOP) the app routes back to Unlock; leaving Browse
 * disposes its composition, whose DisposableEffect stops the monitor and calls browse.lock() —
 * the session is wiped, so returning requires the password again (lock-on-background, mirroring
 * iOS). FLAG_SECURE (set on the Activity) blocks screenshot/recents capture.
 */
@Composable
fun AppRoot() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var route by remember { mutableStateOf<Route>(Route.Unlock) }

    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP) route = Route.Unlock
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    when (val r = route) {
        is Route.Unlock -> UnlockScreen(
            // TODO(Task 6): wire device-unlock
            isEnrolled = false,
            onEnrollChoice = {},
            onBiometricUnlock = {},
            onUnlock = { credential ->
                scope.launch { route = unlockAndOpen(context, scope, credential) }
            },
        )
        is Route.Browse -> {
            // The monitor runs only while Browse is composed: started on enter, stopped on dispose
            // (background → Unlock, or teardown). The browse session is also wiped on dispose so the
            // decrypted manifest/identity never outlives the on-screen session (re-entry re-opens
            // from the password). A failed monitor start leaves detection advisory-blind (the badge
            // falls back to manual "Sync now"); not fatal.
            DisposableEffect(r.session) {
                try {
                    r.session.monitor.start()
                } catch (e: Exception) {
                    Log.w(TAG, "folder-change monitor failed to start", e)
                }
                onDispose {
                    r.session.monitor.stop()
                    r.session.browse.lock()
                }
            }
            BrowseWithSyncScreen(browse = r.session.browse, sync = r.session.sync)
        }
    }
}

/**
 * Opens the vault for browsing with [credential], assembles the sync model+monitor, fires the
 * post-open sync action ([dispatchPostOpenSync]: password → background sync-at-unlock; recovery →
 * status refresh, since Android sync is password-keyed), and returns the Browse route. Runs on the
 * main `scope` (Argon2id hops to IO inside the open port; makeVaultSync inside [openBrowseWithSync]
 * requires main — satisfied here).
 *
 * Secret hygiene: the credential bytes are zeroized in a `finally` wrapping the whole body — on
 * every exit (success, open failure, early provisioning throw). For the password credential the
 * background sync-at-unlock receives a COPY ([launchSyncAtUnlock]); zeroizing the original here
 * cannot corrupt that copy, and because [openBrowseWithSync] awaits the open the zeroize cannot race
 * the Argon2id that consumes the original. The recovery credential hands no copy to a background
 * job, so its bytes are fully owned here.
 */
private suspend fun unlockAndOpen(
    context: Context,
    scope: CoroutineScope,
    credential: UnlockCredential,
): Route {
    try {
        val folder = AppVaultProvisioning.stageGoldenVault(context)
        val deviceUuids = FileDeviceUuidStore(File(context.noBackupFilesDir, "devices"))
        val stateDir = syncStateDir(context.filesDir).apply { mkdirs() }
        val uuid = AppVaultProvisioning.goldenVaultUuid(context)
        val session = openBrowseWithSync(
            uniffiVaultOpenPort(deviceUuids), folder, stateDir, uuid, credential)
        // Password → background sync-at-unlock from a COPY (deliberately outlives Browse disposal:
        // it opens its own vault handle and never touches the browse session; binding it to the
        // Browse scope would cancel the in-flight Argon2id on background). Recovery → status refresh
        // only: Android sync is password-keyed, so a recovery session has no password to sync with;
        // the user syncs manually via the badge re-prompt.
        dispatchPostOpenSync(
            credential,
            onPassword = { pw -> launchSyncAtUnlock(scope, pw, session.sync::syncAtUnlock) },
            onRecovery = { session.sync.refreshStatus() },
        )
        return Route.Browse(session)
    } catch (e: Exception) {
        Log.w(TAG, "unlock/open failed; returning to unlock screen", e)
        return Route.Unlock
    } finally {
        credential.secret.fill(0) // zeroize on every exit; the password background copy is independent
    }
}
