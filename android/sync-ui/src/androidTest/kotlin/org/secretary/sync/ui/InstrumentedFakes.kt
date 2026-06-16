package org.secretary.sync.ui

import org.secretary.sync.SyncMonitorHook
import org.secretary.sync.SyncOutcome
import org.secretary.sync.SyncStatus
import org.secretary.sync.SyncVetoDecision
import org.secretary.sync.VaultSyncPort
import org.secretary.sync.WallClock

// Local minimal doubles for the androidTest source set (the :vault-access test fakes and the
// host src/test fakes are not visible here — different source sets / modules).

/**
 * Returns a scripted [syncOutcome] from [sync] and [commitOutcome] from [commitDecisions].
 * Holds no mutable state — just routes calls to the pre-baked outcomes.
 */
class ScriptedSyncPort(
    private val syncOutcome: SyncOutcome,
    private val commitOutcome: SyncOutcome,
) : VaultSyncPort {
    override suspend fun status(stateDir: String, vaultUuid: ByteArray): SyncStatus =
        SyncStatus(hasState = false, deviceClocks = emptyList(), lastStateWriteMs = null)

    override suspend fun sync(stateDir: String, vaultFolder: String, password: ByteArray, nowMs: ULong): SyncOutcome =
        syncOutcome

    override suspend fun commitDecisions(
        stateDir: String,
        vaultFolder: String,
        password: ByteArray,
        decisions: List<SyncVetoDecision>,
        manifestHash: ByteArray,
        nowMs: ULong,
    ): SyncOutcome = commitOutcome
}

/** Always returns epoch zero — removes wall-clock non-determinism from instrumented tests. */
class ZeroWallClock : WallClock {
    override fun nowMs(): ULong = 0uL
}

/** No-op monitor hook — the androidTest environment has no real FileObserver to mute. */
object NoopMonitorHook : SyncMonitorHook {
    override fun muteSelfWrite() {}
    override fun acknowledge() {}
}
