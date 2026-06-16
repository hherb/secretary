package org.secretary.sync

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SyncDecisionsTest {
    private fun veto(uuid: String) =
        SyncVeto(uuid, "login", emptyList(), listOf("password"), 1uL, 2uL, "devhex")

    @Test
    fun collectDefaultsMissingToKeepLocalTrue() {
        val vetoes = listOf(veto("a"), veto("b"))
        val decisions = collectDecisions(vetoes, overrides = emptyMap())
        assertEquals(
            listOf(SyncVetoDecision("a", true), SyncVetoDecision("b", true)),
            decisions,
        )
    }

    @Test
    fun collectAppliesOverridesAndPreservesVetoOrder() {
        val vetoes = listOf(veto("a"), veto("b"), veto("c"))
        val decisions = collectDecisions(vetoes, overrides = mapOf("b" to false))
        assertEquals(
            listOf(
                SyncVetoDecision("a", true),
                SyncVetoDecision("b", false),
                SyncVetoDecision("c", true),
            ),
            decisions,
        )
    }

    @Test
    fun completeOnlyWhenEveryVetoHasExplicitOverride() {
        val vetoes = listOf(veto("a"), veto("b"))
        assertFalse(decisionsComplete(vetoes, overrides = mapOf("a" to true)))
        assertTrue(decisionsComplete(vetoes, overrides = mapOf("a" to true, "b" to false)))
    }

    @Test
    fun emptyVetoesAreTriviallyComplete() {
        assertTrue(decisionsComplete(emptyList(), overrides = emptyMap()))
        assertEquals(emptyList<SyncVetoDecision>(), collectDecisions(emptyList(), emptyMap()))
    }
}
