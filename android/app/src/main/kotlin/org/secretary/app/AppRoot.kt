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
import kotlinx.coroutines.launch
import org.secretary.sync.ChangeDetectionMonitor
import org.secretary.sync.makeVaultSync
import org.secretary.sync.ui.SyncScreen
import org.secretary.sync.ui.VaultSyncViewModel

private const val TAG = "AppRoot"

/** The app's two screens; Sync carries the live model + monitor for the unlocked session. */
private sealed interface Route {
    data object Unlock : Route
    data class Sync(
        val viewModel: VaultSyncViewModel,
        val monitor: ChangeDetectionMonitor,
    ) : Route
}

/**
 * Top-level routing for the walking skeleton: Unlock → Sync. On unlock it builds the REAL
 * makeVaultSync pair on the main thread (Compose runs on main), awaits a silent syncAtUnlock,
 * zeroizes the password, then routes to the slice-5 SyncScreen. The folder monitor's lifecycle is
 * bound to the Sync screen's composition (see the DisposableEffect in the Route.Sync arm): it runs
 * only while Sync is on screen. On background (ON_STOP) the app routes back to Unlock, which
 * disposes the Sync composition and stops the monitor (mirrors iOS scenePhase == .background;
 * Android has no session to resume since the password is transient per pass).
 */
@Composable
fun AppRoot() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var route by remember { mutableStateOf<Route>(Route.Unlock) }

    // Background → return to Unlock. Leaving Route.Sync disposes its composition, whose
    // DisposableEffect stops the monitor — so the watcher is never left running once we leave Sync.
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
            scope.launch {
                route = unlockAndSync(context, password)
            }
        })
        is Route.Sync -> {
            // The monitor runs only while the Sync screen is composed: started on enter, stopped
            // on dispose (route change back to Unlock on background, or activity teardown). This
            // binds detection to the on-screen session and never leaves a watcher running after we
            // leave Sync. A failed start leaves detection advisory-blind (the badge falls back to
            // manual "Sync now"); not fatal.
            DisposableEffect(r.monitor) {
                try {
                    r.monitor.start()
                } catch (e: Exception) {
                    Log.w(TAG, "folder-change monitor failed to start", e)
                }
                onDispose { r.monitor.stop() }
            }
            SyncScreen(viewModel = r.viewModel)
        }
    }
}

/**
 * Builds makeVaultSync (main thread), awaits the silent unlock pass, zeroizes the password, kicks
 * a best-effort status refresh (for the "synced N ago" label), and returns the Sync route. The
 * monitor is NOT started here — it is started by the Route.Sync DisposableEffect when the Sync
 * screen enters composition, so a watcher is never started for a session the user never sees.
 * Called from a main-dispatched coroutine (the heavy Argon2id work hops to IO inside the sync
 * port). The password buffer is zeroized only after the awaited pass consumes it.
 */
private suspend fun unlockAndSync(context: Context, password: ByteArray): Route {
    val folder = AppVaultProvisioning.stageGoldenVault(context)
    val stateDir = syncStateDir(context.filesDir).apply { mkdirs() }
    val uuid = AppVaultProvisioning.goldenVaultUuid(context)

    val (model, monitor) = makeVaultSync(folder, stateDir, uuid)

    val viewModel = VaultSyncViewModel(model)
    try {
        viewModel.syncAtUnlock(password)
    } finally {
        password.fill(0) // zeroize after the pass has consumed it
    }
    viewModel.refreshStatus() // best-effort "synced N ago" label; reactive via the badge flow

    return Route.Sync(viewModel, monitor)
}
