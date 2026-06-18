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
        is Route.Unlock -> UnlockScreen(onUnlock = { password ->
            scope.launch { route = unlockAndOpen(context, scope, password) }
        })
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
 * Opens the vault for browsing, assembles the sync model+monitor, fires a background
 * sync-at-unlock, and returns the Browse route. Runs on the main `scope` (Argon2id hops to IO
 * inside the open port; makeVaultSync inside [openBrowseWithSync] requires main — satisfied here).
 *
 * Secret hygiene: the original password buffer is zeroized in a `finally` wrapping the whole body —
 * overwritten on every exit (success, open failure, early provisioning throw). The background
 * sync-at-unlock receives a COPY ([launchSyncAtUnlock]); zeroizing the original here cannot corrupt
 * that copy. Because [openBrowseWithSync] awaits the open, the zeroize cannot race the Argon2id that
 * consumes the original.
 *
 * Known accepted minor race (mirrors slices 6/7): if backgrounded while this suspends, the coroutine
 * may still set route = Browse afterward; the next ON_STOP disposes Browse (stops the monitor, wipes
 * the session) and the password is already zeroized — self-heals.
 */
private suspend fun unlockAndOpen(
    context: Context,
    scope: CoroutineScope,
    password: ByteArray,
): Route {
    try {
        val folder = AppVaultProvisioning.stageGoldenVault(context)
        val deviceUuids = FileDeviceUuidStore(File(context.noBackupFilesDir, "devices"))
        val stateDir = syncStateDir(context.filesDir).apply { mkdirs() }
        val uuid = AppVaultProvisioning.goldenVaultUuid(context)
        val session = openBrowseWithSync(
            uniffiVaultOpenPort(deviceUuids), folder, stateDir, uuid, password)
        // Background silent sync-at-unlock with a password copy (browse renders immediately;
        // the second Argon2id never blocks the UI). A conflict on this path only raises the
        // review badge — the interactive path (badge tap) re-prompts for the password.
        launchSyncAtUnlock(scope, password, session.sync::syncAtUnlock)
        return Route.Browse(session)
    } catch (e: Exception) {
        Log.w(TAG, "unlock/open failed; returning to unlock screen", e)
        return Route.Unlock
    } finally {
        password.fill(0) // zeroize the original on every exit; the background copy is independent
    }
}
