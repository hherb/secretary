package org.secretary.sync

/**
 * Scriptable in-memory [VaultSyncPort] for host tests. Seed per-method results and inspect
 * the recorded calls (spy). A seeded `Result.failure` is thrown, mirroring how the real
 * adapter surfaces [VaultSyncError].
 *
 * Seeding model: [sync] and [commitDecisions] are FIFO queues (so a multi-pass coordinator
 * test can script a sequence of outcomes); [status] is a single stable value returned on
 * every read.
 */
class FakeVaultSyncPort : VaultSyncPort {
    val syncResults: ArrayDeque<Result<SyncOutcome>> = ArrayDeque()
    val commitResults: ArrayDeque<Result<SyncOutcome>> = ArrayDeque()
    var statusResult: Result<SyncStatus> = Result.success(
        SyncStatus(hasState = false, deviceClocks = emptyList(), lastStateWriteMs = null),
    )

    val syncCalls: MutableList<SyncCall> = mutableListOf()
    val commitCalls: MutableList<CommitCall> = mutableListOf()
    val statusCalls: MutableList<ByteArray> = mutableListOf()

    // Field-access only; never ==-compared, so the ByteArray fields' referential equals/hashCode are unused.
    data class SyncCall(
        val stateDir: String,
        val nowMs: ULong,
    )

    // Field-access only; never ==-compared, so the ByteArray fields' referential equals/hashCode are unused.
    data class CommitCall(
        val stateDir: String,
        val decisions: List<SyncVetoDecision>,
        val manifestHash: ByteArray,
        val nowMs: ULong,
    )

    override suspend fun status(stateDir: String, vaultUuid: ByteArray): SyncStatus {
        statusCalls += vaultUuid
        return statusResult.getOrThrow()
    }

    override suspend fun sync(stateDir: String, nowMs: ULong): SyncOutcome {
        syncCalls += SyncCall(stateDir, nowMs)
        return syncResults.removeFirst().getOrThrow()
    }

    override suspend fun commitDecisions(
        stateDir: String,
        decisions: List<SyncVetoDecision>,
        manifestHash: ByteArray,
        nowMs: ULong,
    ): SyncOutcome {
        commitCalls += CommitCall(stateDir, decisions, manifestHash, nowMs)
        return commitResults.removeFirst().getOrThrow()
    }
}
