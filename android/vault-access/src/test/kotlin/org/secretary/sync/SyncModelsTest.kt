package org.secretary.sync

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
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

    @Test
    fun conflictsPendingToStringReportsSizeNotContents() {
        val cp = SyncOutcome.ConflictsPending(emptyList(), emptyList(), byteArrayOf(1, 2, 3))
        val text = cp.toString()
        assertTrue(text.contains("3 bytes"), "toString should report byte count")
        assertFalse(text.contains("[1, 2, 3]"), "toString must not leak raw manifestHash bytes")
    }

    @Test
    fun conflictsPendingNotEqualToOtherTypesOrNull() {
        val cp = SyncOutcome.ConflictsPending(emptyList(), emptyList(), byteArrayOf(1))
        assertNotEquals(cp, "not a conflict")
        assertFalse(cp.equals(null))
    }

    @Test
    fun conflictsPendingDiffersByVetoesWhenHashEqual() {
        val veto = SyncVeto("r1", "login", emptyList(), listOf("password"), 100uL, 200uL, "dev")
        val hash = byteArrayOf(4, 4)
        val withVeto = SyncOutcome.ConflictsPending(listOf(veto), emptyList(), hash)
        val withoutVeto = SyncOutcome.ConflictsPending(emptyList(), emptyList(), hash)
        assertNotEquals(withVeto, withoutVeto)
    }
}
