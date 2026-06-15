package org.secretary.sync

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import uniffi.secretary.CollisionDto
import uniffi.secretary.DeviceClockDto
import uniffi.secretary.SyncOutcomeDto
import uniffi.secretary.SyncStatusDto
import uniffi.secretary.VetoDto

class SyncOutcomeMappingTest {
    @Test
    fun `maps the five singleton outcome arms 1 to 1`() {
        assertEquals(SyncOutcome.NothingToDo, mapOutcome(SyncOutcomeDto.NothingToDo))
        assertEquals(SyncOutcome.AppliedAutomatically, mapOutcome(SyncOutcomeDto.AppliedAutomatically))
        assertEquals(SyncOutcome.SilentMerge, mapOutcome(SyncOutcomeDto.SilentMerge))
        assertEquals(SyncOutcome.MergedClean, mapOutcome(SyncOutcomeDto.MergedClean))
        assertEquals(SyncOutcome.RollbackRejected, mapOutcome(SyncOutcomeDto.RollbackRejected))
    }

    @Test
    fun `maps ConflictsPending preserving vetoes collisions and manifest hash`() {
        val veto = VetoDto(
            recordUuidHex = "aa", recordType = "login", tags = listOf("t1"),
            fieldNames = listOf("password"), localLastModMs = 10uL,
            peerTombstonedAtMs = 20uL, peerDeviceHex = "bb",
        )
        val collision = CollisionDto(recordUuidHex = "cc", fieldNames = listOf("note"))
        val hash = byteArrayOf(1, 2, 3)

        val mapped = mapOutcome(SyncOutcomeDto.ConflictsPending(listOf(veto), listOf(collision), hash))

        assertTrue(mapped is SyncOutcome.ConflictsPending)
        mapped as SyncOutcome.ConflictsPending
        assertEquals(
            listOf(SyncVeto("aa", "login", listOf("t1"), listOf("password"), 10uL, 20uL, "bb")),
            mapped.vetoes,
        )
        assertEquals(listOf(SyncCollision("cc", listOf("note"))), mapped.collisions)
        assertTrue(hash.contentEquals(mapped.manifestHash))

        // Whole-value equality against an independently-constructed expected (note the SEPARATE
        // byteArrayOf instance): exercises ConflictsPending's hand-rolled content-based
        // equals/hashCode, which the field-by-field asserts above do not.
        assertEquals(
            SyncOutcome.ConflictsPending(
                listOf(SyncVeto("aa", "login", listOf("t1"), listOf("password"), 10uL, 20uL, "bb")),
                listOf(SyncCollision("cc", listOf("note"))),
                byteArrayOf(1, 2, 3),
            ),
            mapped,
        )
    }

    @Test
    fun `maps status with device clocks and optional last write`() {
        val dto = SyncStatusDto(
            hasState = true,
            deviceClocks = listOf(DeviceClockDto(deviceUuidHex = "dd", counter = 7uL)),
            lastStateWriteMs = 99uL,
        )

        val mapped = mapStatus(dto)

        assertEquals(true, mapped.hasState)
        assertEquals(listOf(DeviceClock("dd", 7uL)), mapped.deviceClocks)
        assertEquals(99uL, mapped.lastStateWriteMs)
    }

    @Test
    fun `maps status with null last write`() {
        val dto = SyncStatusDto(hasState = false, deviceClocks = emptyList(), lastStateWriteMs = null)
        assertEquals(null, mapStatus(dto).lastStateWriteMs)
    }
}
