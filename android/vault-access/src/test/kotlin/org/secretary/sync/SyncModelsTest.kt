package org.secretary.sync

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SyncModelsTest {
    @Test
    fun conflictsPendingEqualsByContent() {
        val a = SyncOutcome.ConflictsPending(emptyList(), emptyList(), byteArrayOf(1, 2, 3))
        val b = SyncOutcome.ConflictsPending(emptyList(), emptyList(), byteArrayOf(1, 2, 3))
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
    }

    @Test
    fun conflictsPendingDiffersByHash() {
        val a = SyncOutcome.ConflictsPending(emptyList(), emptyList(), byteArrayOf(1, 2, 3))
        val b = SyncOutcome.ConflictsPending(emptyList(), emptyList(), byteArrayOf(9))
        assertNotEquals(a, b)
    }

    @Test
    fun valueTypeEquality() {
        assertEquals(DeviceClock("aa", 1uL), DeviceClock("aa", 1uL))
        assertEquals(SyncVetoDecision("x", true), SyncVetoDecision("x", true))
        assertEquals(
            SyncStatus(true, listOf(DeviceClock("aa", 1uL)), 5uL),
            SyncStatus(true, listOf(DeviceClock("aa", 1uL)), 5uL),
        )
        assertEquals(
            PendingConflict(emptyList(), listOf(SyncCollision("r", listOf("f")))),
            PendingConflict(emptyList(), listOf(SyncCollision("r", listOf("f")))),
        )
    }

    @Test
    fun syncOutcomeObjectsAreDistinctSingletons() {
        assertTrue(SyncOutcome.MergedClean === SyncOutcome.MergedClean)
        assertTrue(SyncOutcome.MergedClean != SyncOutcome.NothingToDo)
    }
}
