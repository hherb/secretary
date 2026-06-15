package org.secretary.sync

import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Test
import uniffi.secretary.SyncOutcomeDto
import uniffi.secretary.SyncStatusDto
import uniffi.secretary.VaultException
import uniffi.secretary.VetoDecisionDto

class UniffiVaultSyncPortTest {
    @Test
    fun `status maps the dto and forwards args`() = runTest {
        var seenDir: String? = null
        var seenUuid: ByteArray? = null
        val port = UniffiVaultSyncPort(
            ioDispatcher = StandardTestDispatcher(testScheduler),
            statusFn = { dir, uuid ->
                seenDir = dir; seenUuid = uuid
                SyncStatusDto(hasState = true, deviceClocks = emptyList(), lastStateWriteMs = null)
            },
            syncFn = { _, _, _, _ -> error("syncFn should not be called in this test") },
            commitFn = { _, _, _, _, _, _ -> error("commitFn should not be called in this test") },
        )

        val status = port.status(stateDir = "/s", vaultUuid = ByteArray(16) { 1 })

        assertEquals("/s", seenDir)
        assertArrayEquals(ByteArray(16) { 1 }, seenUuid)
        assertEquals(true, status.hasState)
    }

    @Test
    fun `sync forwards password and maps the outcome`() = runTest {
        var seenPassword: ByteArray? = null
        val port = UniffiVaultSyncPort(
            ioDispatcher = StandardTestDispatcher(testScheduler),
            statusFn = { _, _ -> error("statusFn should not be called in this test") },
            syncFn = { _, _, pw, _ -> seenPassword = pw; SyncOutcomeDto.AppliedAutomatically },
            commitFn = { _, _, _, _, _, _ -> error("commitFn should not be called in this test") },
        )

        val outcome = port.sync("/s", "/v", byteArrayOf(7, 8, 9), nowMs = 5uL)

        assertArrayEquals(byteArrayOf(7, 8, 9), seenPassword)
        assertEquals(SyncOutcome.AppliedAutomatically, outcome)
    }

    @Test
    fun `commitDecisions maps domain decisions to dtos and maps the outcome`() = runTest {
        var seenDecisions: List<VetoDecisionDto>? = null
        val port = UniffiVaultSyncPort(
            ioDispatcher = StandardTestDispatcher(testScheduler),
            statusFn = { _, _ -> error("statusFn should not be called in this test") },
            syncFn = { _, _, _, _ -> error("syncFn should not be called in this test") },
            commitFn = { _, _, _, decisions, _, _ -> seenDecisions = decisions; SyncOutcomeDto.MergedClean },
        )

        val outcome = port.commitDecisions(
            stateDir = "/s", vaultFolder = "/v", password = byteArrayOf(1),
            decisions = listOf(SyncVetoDecision("rec", keepLocal = true)),
            manifestHash = byteArrayOf(2), nowMs = 5uL,
        )

        assertEquals(listOf(VetoDecisionDto(recordUuidHex = "rec", keepLocal = true)), seenDecisions)
        assertEquals(SyncOutcome.MergedClean, outcome)
    }

    @Test
    fun `a thrown VaultException is mapped to VaultSyncError`() = runTest {
        val port = UniffiVaultSyncPort(
            ioDispatcher = StandardTestDispatcher(testScheduler),
            statusFn = { _, _ -> error("statusFn should not be called in this test") },
            syncFn = { _, _, _, _ -> throw VaultException.SyncInProgress() },
            commitFn = { _, _, _, _, _, _ -> error("commitFn should not be called in this test") },
        )

        // NOTE: deviates from the planned `assertThrows(...) { runBlocking { port.sync(...) } }`.
        // `sync` offloads via `withContext(StandardTestDispatcher(testScheduler))`, and a
        // StandardTestDispatcher only runs when its scheduler is advanced by `runTest`. Nesting a
        // `runBlocking` blocks the test thread on a separate event loop that never drains
        // `testScheduler`, so the offloaded body never executes -> permanent deadlock. We instead
        // await `sync` inside the `runTest` body (which advances the scheduler) and assert on the
        // caught exception. Same intent: a thrown VaultException maps to the domain VaultSyncError.
        val thrown = try {
            port.sync("/s", "/v", byteArrayOf(1), nowMs = 0uL)
            null
        } catch (e: VaultSyncError) {
            e
        }
        assertInstanceOf(VaultSyncError.InProgress::class.java, thrown)
    }
}
