package org.secretary.sync

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SyncCoordinatorTest {
    private val pw = byteArrayOf(1, 2, 3)

    private fun coordinator(port: FakeVaultSyncPort) =
        SyncCoordinator(port, stateDir = "/state", vaultFolder = "/vault")

    @Test
    fun safeOutcomePassesThroughAndLeavesNoStash() = runTest {
        val port = FakeVaultSyncPort()
        port.syncResults += Result.success(SyncOutcome.MergedClean)
        val c = coordinator(port)

        assertEquals(SyncOutcome.MergedClean, c.runPass(pw, 100uL))
        assertNull(c.pendingConflict())
        val call = port.syncCalls.single()
        assertEquals("/state", call.stateDir)
        assertEquals("/vault", call.vaultFolder)
    }

    @Test
    fun conflictStashesTokenAndConflictDetail() = runTest {
        val port = FakeVaultSyncPort()
        val veto = SyncVeto("r1", "login", emptyList(), listOf("password"), 100uL, 200uL, "dev")
        port.syncResults += Result.success(
            SyncOutcome.ConflictsPending(listOf(veto), emptyList(), byteArrayOf(7, 7)),
        )
        val c = coordinator(port)

        val out = c.runPass(pw, 100uL)

        assertTrue(out is SyncOutcome.ConflictsPending)
        assertEquals(PendingConflict(listOf(veto), emptyList()), c.pendingConflict())
    }

    @Test
    fun resolveSendsStashedTokenAndClearsOnResolvedArm() = runTest {
        val port = FakeVaultSyncPort()
        val token = byteArrayOf(5, 5, 5)
        port.syncResults += Result.success(
            SyncOutcome.ConflictsPending(emptyList(), emptyList(), token),
        )
        port.commitResults += Result.success(SyncOutcome.MergedClean)
        val c = coordinator(port)
        c.runPass(pw, 100uL)

        val decisions = listOf(SyncVetoDecision("r1", true))
        assertEquals(SyncOutcome.MergedClean, c.resolve(decisions, pw, 200uL))

        val commit = port.commitCalls.single()
        assertTrue(commit.manifestHash.contentEquals(token))
        assertEquals(decisions, commit.decisions)
        assertNull(c.pendingConflict())
    }

    @Test
    fun resolveWithoutStashThrowsAndDoesNotCallPort() = runTest {
        val port = FakeVaultSyncPort()
        val c = coordinator(port)

        val err = runCatching { c.resolve(emptyList(), pw, 1uL) }.exceptionOrNull()

        assertTrue(err is VaultSyncError.NoPendingConflict)
        assertTrue(port.commitCalls.isEmpty())
    }

    @Test
    fun staleErrorPreservesStashSoRetryReusesToken() = runTest {
        val port = FakeVaultSyncPort()
        val token = byteArrayOf(8)
        port.syncResults += Result.success(
            SyncOutcome.ConflictsPending(emptyList(), emptyList(), token),
        )
        port.commitResults += Result.failure(VaultSyncError.EvidenceStale)
        port.commitResults += Result.success(SyncOutcome.MergedClean)
        val c = coordinator(port)
        c.runPass(pw, 1uL)

        val err = runCatching { c.resolve(emptyList(), pw, 2uL) }.exceptionOrNull()
        assertTrue(err is VaultSyncError.EvidenceStale)
        assertNotNull(c.pendingConflict())

        assertEquals(SyncOutcome.MergedClean, c.resolve(emptyList(), pw, 3uL))
        assertTrue(port.commitCalls.last().manifestHash.contentEquals(token))
        assertNull(c.pendingConflict())
    }

    @Test
    fun resolveReturningConflictReStashesNewToken() = runTest {
        val port = FakeVaultSyncPort()
        port.syncResults += Result.success(
            SyncOutcome.ConflictsPending(emptyList(), emptyList(), byteArrayOf(1)),
        )
        port.commitResults += Result.success(
            SyncOutcome.ConflictsPending(emptyList(), emptyList(), byteArrayOf(2)),
        )
        port.commitResults += Result.success(SyncOutcome.MergedClean)
        val c = coordinator(port)
        c.runPass(pw, 1uL)

        val out = c.resolve(emptyList(), pw, 2uL)
        assertTrue(out is SyncOutcome.ConflictsPending)

        c.resolve(emptyList(), pw, 3uL)
        assertTrue(port.commitCalls.last().manifestHash.contentEquals(byteArrayOf(2)))
    }

    @Test
    fun statusDelegatesToPort() = runTest {
        val port = FakeVaultSyncPort()
        port.statusResult = Result.success(SyncStatus(true, listOf(DeviceClock("aa", 3uL)), 999uL))
        val c = coordinator(port)

        val status = c.status(byteArrayOf(0))

        assertTrue(status.hasState)
        assertEquals(1, port.statusCalls.size)
    }

    @Test
    fun passwordIsForwardedToPortNotAltered() = runTest {
        val port = FakeVaultSyncPort()
        port.syncResults += Result.success(SyncOutcome.NothingToDo)
        val c = coordinator(port)

        c.runPass(pw, 1uL)

        assertTrue(port.syncCalls.single().password.contentEquals(pw))
    }

    @Test
    fun secondRunPassWithSafeArmClearsPriorStash() = runTest {
        val port = FakeVaultSyncPort()
        port.syncResults += Result.success(
            SyncOutcome.ConflictsPending(emptyList(), emptyList(), byteArrayOf(9)),
        )
        port.syncResults += Result.success(SyncOutcome.MergedClean)
        val c = coordinator(port)

        c.runPass(pw, 1uL)
        assertNotNull(c.pendingConflict())

        assertEquals(SyncOutcome.MergedClean, c.runPass(pw, 2uL))
        assertNull(c.pendingConflict())
    }

    @Test
    fun mutexSerializesConcurrentRunPasses() = runTest {
        val gate = CompletableDeferred<Unit>()
        var insideSync = 0
        var maxConcurrentInside = 0
        var entries = 0
        val gatedPort = object : VaultSyncPort {
            override suspend fun status(stateDir: String, vaultUuid: ByteArray): SyncStatus =
                throw UnsupportedOperationException()

            override suspend fun sync(
                stateDir: String,
                vaultFolder: String,
                password: ByteArray,
                nowMs: ULong,
            ): SyncOutcome {
                insideSync++
                entries++
                maxConcurrentInside = maxOf(maxConcurrentInside, insideSync)
                gate.await()
                insideSync--
                return SyncOutcome.NothingToDo
            }

            override suspend fun commitDecisions(
                stateDir: String,
                vaultFolder: String,
                password: ByteArray,
                decisions: List<SyncVetoDecision>,
                manifestHash: ByteArray,
                nowMs: ULong,
            ): SyncOutcome = throw UnsupportedOperationException()
        }
        val c = SyncCoordinator(gatedPort, "/state", "/vault")

        val a = launch { c.runPass(pw, 1uL) }
        val b = launch { c.runPass(pw, 2uL) }
        // With the mutex held across the gated sync call, only the first coroutine can be
        // inside sync; the second is parked on the mutex, not inside sync.
        testScheduler.advanceUntilIdle()
        assertEquals(1, entries)
        assertEquals(1, maxConcurrentInside)

        gate.complete(Unit)
        testScheduler.advanceUntilIdle()
        a.join()
        b.join()
        assertEquals(2, entries)
        assertEquals(1, maxConcurrentInside)
    }
}
