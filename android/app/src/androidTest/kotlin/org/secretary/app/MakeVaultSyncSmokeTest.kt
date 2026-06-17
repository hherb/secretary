package org.secretary.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.secretary.sync.ChangeDetectionMonitor
import org.secretary.sync.SyncBadgeState
import org.secretary.sync.VaultSyncModel
import org.secretary.sync.makeVaultSync
import java.io.File

/**
 * The first on-device exercise of the FULL app wiring: production provisioning → makeVaultSync
 * (Looper-gated factory) → VaultSyncModel.syncAtUnlock over the REAL SyncCoordinator + native
 * libsecretary_ffi_uniffi.so. Host tests (fakes) cannot touch makeVaultSync or the .so. This
 * complements :kit's SyncRoundTripInstrumentedTest, which proves only the raw port + bare
 * coordinator runPass — bypassing both the factory and the model state machine asserted here.
 *
 * Single-device golden vault: the first pass against a fresh state dir is an AppliedAutomatically
 * fast-forward (characterized in :kit), a clean arm — never ConflictsPending.
 */
@RunWith(AndroidJUnit4::class)
class MakeVaultSyncSmokeTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext

    // The published golden-vault KAT password — not a real secret, so not zeroized here.
    private val goldenPassword = "correct horse battery staple"

    private val toClean = mutableListOf<File>()

    @After fun cleanup() {
        toClean.forEach { it.deleteRecursively() }
        // Reset provisioning so each test stages fresh (stageGoldenVault is idempotent on filesDir).
        File(context.filesDir, "golden_vault_001").deleteRecursively()
    }

    /** Build the real model+monitor on the main thread (makeVaultSync fast-fails off-main). */
    private fun buildOnMain(): Pair<VaultSyncModel, ChangeDetectionMonitor> {
        val folder = AppVaultProvisioning.stageGoldenVault(context)
        // Resolve via the production `syncStateDir` helper (under a unique throwaway base so tests
        // don't collide), exercising the same base→subdir mapping `unlockAndSync` uses in the app.
        val stateBase = File(context.cacheDir, "run-${System.nanoTime()}")
        val stateDir = syncStateDir(stateBase).apply { mkdirs() }
        toClean += stateBase
        val uuid = AppVaultProvisioning.goldenVaultUuid(context)
        lateinit var pair: Pair<VaultSyncModel, ChangeDetectionMonitor>
        instrumentation.runOnMainSync {
            pair = makeVaultSync(folder, stateDir, uuid)
        }
        return pair
    }

    @Test
    fun syncAtUnlock_correctPassword_reachesSyncedBadge() = runBlocking {
        val (model, monitor) = buildOnMain()
        instrumentation.runOnMainSync { monitor.start() }

        model.syncAtUnlock(goldenPassword.toByteArray())

        // Clean silent pass: no error, review cleared.
        assertNull("clean pass surfaces no error", model.lastError.value)
        assertFalse("clean pass clears review", model.reviewNeeded.value)

        // The Synced label needs a status read (the model does not refresh inside a pass).
        model.refreshStatus()
        assertTrue(
            "after a clean pass + status refresh the badge is Synced, was ${model.badge.value}",
            model.badge.value is SyncBadgeState.Synced,
        )

        instrumentation.runOnMainSync { monitor.stop() }
    }

    @Test
    fun syncAtUnlock_wrongPassword_surfacesError() = runBlocking {
        val (model, monitor) = buildOnMain()
        instrumentation.runOnMainSync { monitor.start() }

        model.syncAtUnlock("definitely-the-wrong-password".toByteArray())

        assertNotNull("wrong password surfaces a VaultSyncError", model.lastError.value)
        assertFalse(
            "a failed pass does not reach Synced, was ${model.badge.value}",
            model.badge.value is SyncBadgeState.Synced,
        )

        instrumentation.runOnMainSync { monitor.stop() }
    }
}
