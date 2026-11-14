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
            syncFn = { _, _ -> error("syncFn should not be called in this test") },
            commitFn = { _, _, _, _ -> error("commitFn should not be called in this test") },
        )

        val status = port.status(stateDir = "/s", vaultUuid = ByteArray(16) { 1 })

        assertEquals("/s", seenDir)
        assertArrayEquals(ByteArray(16) { 1 }, seenUuid)
        assertEquals(true, status.hasState)
    }

    @Test
    fun `sync forwards its args and maps the outcome`() = runTest {
        var seen: Pair<String, ULong>? = null
        val port = UniffiVaultSyncPort(
            ioDispatcher = StandardTestDispatcher(testScheduler),
            statusFn = { _, _ -> error("statusFn should not be called in this test") },
            syncFn = { dir, now ->
                seen = dir to now
                SyncOutcomeDto.AppliedAutomatically
            },
            commitFn = { _, _, _, _ -> error("commitFn should not be called in this test") },
        )

        val outcome = port.sync("/s", nowMs = 5uL)

        assertEquals("/s" to 5uL, seen)
        assertEquals(SyncOutcome.AppliedAutomatically, outcome)
    }

    @Test
    fun `commitDecisions maps domain decisions to dtos and maps the outcome`() = runTest {
        var seenDecisions: List<VetoDecisionDto>? = null
        val port = UniffiVaultSyncPort(
            ioDispatcher = StandardTestDispatcher(testScheduler),
            statusFn = { _, _ -> error("statusFn should not be called in this test") },
            syncFn = { _, _ -> error("syncFn should not be called in this test") },
            commitFn = { _, decisions, _, _ -> seenDecisions = decisions; SyncOutcomeDto.MergedClean },
        )

        val outcome = port.commitDecisions(
            stateDir = "/s",
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
            syncFn = { _, _ -> throw VaultException.SyncInProgress() },
            commitFn = { _, _, _, _ -> error("commitFn should not be called in this test") },
        )

        // NOTE: deviates from the planned `assertThrows(...) { runBlocking { port.sync(...) } }`.
        // `sync` offloads via `withContext(StandardTestDispatcher(testScheduler))`, and a
        // StandardTestDispatcher only runs when its scheduler is advanced by `runTest`. Nesting a
        // `runBlocking` blocks the test thread on a separate event loop that never drains
        // `testScheduler`, so the offloaded body never executes -> permanent deadlock. We instead
        // await `sync` inside the `runTest` body (which advances the scheduler) and assert on the
        // caught exception. Same intent: a thrown VaultException maps to the domain VaultSyncError.
        val thrown = try {
            port.sync("/s", nowMs = 0uL)
            null
        } catch (e: VaultSyncError) {
            e
        }
        assertInstanceOf(VaultSyncError.InProgress::class.java, thrown)
    }

    @Test
    fun `status surfaces a thrown VaultException as VaultSyncError`() = runTest {
        // `status` runs INLINE (no withContext offload, unlike sync/commit), so its error path
        // is structurally distinct — this proves the shared callMappingErrors funnel fires there too.
        val port = UniffiVaultSyncPort(
            ioDispatcher = StandardTestDispatcher(testScheduler),
            statusFn = { _, _ -> throw VaultException.SyncStateCorrupt("boom") },
            syncFn = { _, _ -> error("syncFn should not be called in this test") },
            commitFn = { _, _, _, _ -> error("commitFn should not be called in this test") },
        )

        val thrown = try {
            port.status(stateDir = "/s", vaultUuid = ByteArray(16) { 1 })
            null
        } catch (e: VaultSyncError) {
            e
        }
        assertEquals(VaultSyncError.StateCorrupt("boom"), thrown)
    }

    @Test
    fun `commitDecisions surfaces a thrown VaultException as VaultSyncError`() = runTest {
        // commitDecisions offloads via withContext like sync, so we await inside the runTest body
        // (which drains testScheduler) rather than nesting runBlocking — see the sync-path note above.
        val port = UniffiVaultSyncPort(
            ioDispatcher = StandardTestDispatcher(testScheduler),
            statusFn = { _, _ -> error("statusFn should not be called in this test") },
            syncFn = { _, _ -> error("syncFn should not be called in this test") },
            commitFn = { _, _, _, _ -> throw VaultException.SyncEvidenceStale() },
        )

        val thrown = try {
            port.commitDecisions(
                stateDir = "/s",
                decisions = emptyList(), manifestHash = byteArrayOf(2), nowMs = 0uL,
            )
            null
        } catch (e: VaultSyncError) {
            e
        }
        assertInstanceOf(VaultSyncError.EvidenceStale::class.java, thrown)
    }
}
