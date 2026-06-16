package org.secretary.sync.ui

import org.secretary.sync.SyncMonitorHook
import org.secretary.sync.SyncOutcome
import org.secretary.sync.SyncStatus
import org.secretary.sync.SyncVetoDecision
import org.secretary.sync.VaultSyncPort
import org.secretary.sync.WallClock

// Local minimal test doubles — :vault-access's test fakes are not visible across modules (no
// test-fixtures configuration); replace with shared fixtures if one is introduced later.

/** Returns a fixed outcome for sync/commit and an empty status. Records the password seen. */
class ScriptedSyncPort(
    private val syncOutcome: SyncOutcome,
    private val commitOutcome: SyncOutcome = syncOutcome,
) : VaultSyncPort {
    val passwords: MutableList<ByteArray> = mutableListOf()

    override suspend fun status(stateDir: String, vaultUuid: ByteArray): SyncStatus =
        SyncStatus(hasState = false, deviceClocks = emptyList(), lastStateWriteMs = null)

    override suspend fun sync(stateDir: String, vaultFolder: String, password: ByteArray, nowMs: ULong): SyncOutcome {
        passwords += password
        return syncOutcome
    }

    override suspend fun commitDecisions(
        stateDir: String,
        vaultFolder: String,
        password: ByteArray,
        decisions: List<SyncVetoDecision>,
        manifestHash: ByteArray,
        nowMs: ULong,
    ): SyncOutcome {
        passwords += password
        return commitOutcome
    }
}

class ZeroWallClock : WallClock {
    override fun nowMs(): ULong = 0uL
}

object NoopMonitorHook : SyncMonitorHook {
    override fun muteSelfWrite() {}
    override fun acknowledge() {}
}
