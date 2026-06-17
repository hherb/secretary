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
import org.secretary.browse.VaultBrowseModel
import org.secretary.browse.uniffiVaultOpenPort
import org.secretary.browse.ui.BrowseScreen
import org.secretary.browse.ui.VaultBrowseViewModel

private const val TAG = "AppRoot"

/** The app's two screens; Browse carries the live view-model for the unlocked session. */
private sealed interface Route {
    data object Unlock : Route
    data class Browse(val viewModel: VaultBrowseViewModel) : Route
}

/**
 * Top-level routing for the walking skeleton: Unlock → Browse. On unlock it opens the REAL vault
 * (open_vault_with_password, Argon2id offloaded to IO inside the port), builds a VaultBrowseModel,
 * lists blocks, and routes to the metadata-only BrowseScreen. On background (ON_STOP) the app routes
 * back to Unlock; leaving Browse disposes its composition, whose DisposableEffect calls
 * viewModel.lock() — the session is wiped, so returning requires the password again (lock-on-background,
 * mirroring iOS). FLAG_SECURE (set on the Activity) blocks screenshot/recents capture.
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
            scope.launch { route = unlockAndOpen(context, password) }
        })
        is Route.Browse -> {
            // Wipe the session when we leave Browse (background → Unlock, or teardown): the decrypted
            // manifest/identity never outlives the on-screen session. Re-entry re-opens from password.
            DisposableEffect(r.viewModel) {
                onDispose { r.viewModel.lock() }
            }
            BrowseScreen(viewModel = r.viewModel)
        }
    }
}

/**
 * Opens the vault (main-dispatched coroutine; Argon2id hops to IO inside the port), lists blocks,
 * and returns the Browse route. Unlike the sync slice, this open is session-producing and CAN refuse:
 * a wrong password / corrupt or provisioning failure is logged and returns the user to Unlock.
 *
 * Secret hygiene: the password buffer is zeroized in a `finally` wrapping the whole body — overwritten
 * on every exit (success, open failure, early provisioning throw). Because openWithPassword is awaited,
 * the zeroize cannot race the async Argon2id that consumes the buffer.
 *
 * Known accepted minor race (mirrors slice 6): if backgrounded (ON_STOP → route = Unlock) while this
 * suspends, the coroutine may still set route = Browse afterwards; the next ON_STOP disposes Browse and
 * wipes the session, and the password is already zeroized — self-heals.
 */
private suspend fun unlockAndOpen(context: Context, password: ByteArray): Route {
    try {
        val folder = AppVaultProvisioning.stageGoldenVault(context)
        val session = uniffiVaultOpenPort().openWithPassword(folder.path, password)
        val model = VaultBrowseModel(session)
        model.loadBlocks()
        return Route.Browse(VaultBrowseViewModel(model))
    } catch (e: Exception) {
        Log.w(TAG, "unlock/open failed; returning to unlock screen", e)
        return Route.Unlock
    } finally {
        password.fill(0) // zeroize on every exit — success, open failure, or early throw
    }
}
