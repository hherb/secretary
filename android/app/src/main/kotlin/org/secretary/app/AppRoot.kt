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
 * makeVaultSync pair on the main thread (Compose runs on main), starts the folder monitor
 * (advisory — a failed start is logged, not fatal), awaits a silent syncAtUnlock, zeroizes the
 * password, then routes to the slice-5 SyncScreen. On background (ON_STOP) it stops the monitor
 * and returns to Unlock, dropping the session (mirrors iOS scenePhase == .background; Android has
 * no session to resume since the password is transient per pass).
 */
@Composable
fun AppRoot() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var route by remember { mutableStateOf<Route>(Route.Unlock) }

    // Background → stop monitor + return to Unlock, dropping the model.
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner, route) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP) {
                (route as? Route.Sync)?.let { it.monitor.stop() }
                route = Route.Unlock
            }
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
        is Route.Sync -> SyncScreen(viewModel = r.viewModel)
    }
}

/**
 * Builds makeVaultSync (main thread), starts the monitor, awaits the silent unlock pass, zeroizes
 * the password, kicks a best-effort status refresh (for the "synced N ago" label), and returns the
 * Sync route. Called from a main-dispatched coroutine (the heavy Argon2id work hops to IO inside
 * the sync port). The password buffer is zeroized only after the awaited pass consumes it.
 */
private suspend fun unlockAndSync(context: Context, password: ByteArray): Route {
    val folder = AppVaultProvisioning.stageGoldenVault(context)
    val stateDir = syncStateDir(context.filesDir).apply { mkdirs() }
    val uuid = AppVaultProvisioning.goldenVaultUuid(context)

    val (model, monitor) = makeVaultSync(folder, stateDir, uuid)
    try {
        monitor.start()
    } catch (e: Exception) {
        // Advisory-blind detection (badge falls back to manual "Sync now"); not fatal.
        Log.w(TAG, "folder-change monitor failed to start", e)
    }

    val viewModel = VaultSyncViewModel(model)
    try {
        viewModel.syncAtUnlock(password)
    } finally {
        password.fill(0) // zeroize after the pass has consumed it
    }
    viewModel.refreshStatus() // best-effort "synced N ago" label; reactive via the badge flow

    return Route.Sync(viewModel, monitor)
}
