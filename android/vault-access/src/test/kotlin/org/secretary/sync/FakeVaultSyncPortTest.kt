package org.secretary.sync

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class FakeVaultSyncPortTest {
    @Test
    fun seedsResultsAndSpiesOnInputs() = runTest {
        val fake = FakeVaultSyncPort()
        fake.syncResults += Result.success(SyncOutcome.MergedClean)

        val out = fake.sync("/state", "/vault", byteArrayOf(7), 42uL)

        assertEquals(SyncOutcome.MergedClean, out)
        val call = fake.syncCalls.single()
        assertEquals("/state", call.stateDir)
        assertEquals("/vault", call.vaultFolder)
        assertTrue(call.password.contentEquals(byteArrayOf(7)))
        assertEquals(42uL, call.nowMs)
    }

    @Test
    fun seededFailureIsThrown() = runTest {
        val fake = FakeVaultSyncPort()
        fake.commitResults += Result.failure(VaultSyncError.EvidenceStale)

        val err = runCatching {
            fake.commitDecisions("/s", "/v", byteArrayOf(), emptyList(), byteArrayOf(1), 1uL)
        }.exceptionOrNull()

        assertTrue(err is VaultSyncError.EvidenceStale)
    }
}
