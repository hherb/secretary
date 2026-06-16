package org.secretary.sync

import android.os.Looper
import java.io.File

/**
 * Composes the real adapters into a ready-to-use [VaultSyncModel] + its backing
 * [ChangeDetectionMonitor] for an open vault. Mirror of the iOS makeVaultSync factory.
 *
 * Must be called on the main thread: the returned monitor is main-thread-confined and the model's
 * mutating methods are expected to run on the UI dispatcher. A fast-fail check enforces this so a
 * background-thread misuse crashes in development rather than producing a silently misconfigured
 * pair (the same discipline as [makeChangeMonitor]).
 *
 * The model↔monitor reference cycle (monitor.onChange → model.pendingChangesRaised, model → hook →
 * monitor) is harmless on the JVM: the garbage collector reclaims cycles, so — unlike iOS ARC — no
 * weak back-reference is needed. The caller owns the monitor's lifecycle: `start()` on unlock,
 * `stop()` on lock/background.
 *
 * @param vaultUuid the open vault's UUID, or null to suppress status reads until it is known.
 * @return the model and the monitor; the caller starts/stops the monitor and calls
 *   [VaultSyncModel.syncAtUnlock] once the unlock password is in hand.
 */
fun makeVaultSync(
    folder: File,
    stateDir: File,
    vaultUuid: ByteArray?,
    wallClock: WallClock = SystemWallClock(),
): Pair<VaultSyncModel, ChangeDetectionMonitor> {
    check(Looper.myLooper() == Looper.getMainLooper()) {
        "makeVaultSync must be called on the main thread"
    }
    val coordinator = SyncCoordinator(
        port = UniffiVaultSyncPort(),
        stateDir = stateDir.path,
        vaultFolder = folder.path,
    )
    lateinit var model: VaultSyncModel
    val monitor = makeChangeMonitor(folder) { model.pendingChangesRaised() }
    model = VaultSyncModel(
        coordinator = coordinator,
        wallClock = wallClock,
        monitorHook = MonitorSyncHook(monitor),
        vaultUuid = vaultUuid,
    )
    return model to monitor
}
