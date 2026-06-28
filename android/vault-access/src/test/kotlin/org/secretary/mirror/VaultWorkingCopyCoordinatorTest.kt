package org.secretary.mirror

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

private class RecordingMirror(private val order: MutableList<String>, var flushFails: Boolean = false) : WorkingCopyMirror {
    val empty = MirrorReport(emptyList(), emptyList())
    override fun materialize(): MirrorReport { order.add("materialize"); return empty }
    override fun flush(): MirrorReport {
        order.add("flush")
        if (flushFails) throw VaultMirrorException("offline")
        return empty
    }
}

private class FakeMarker(private var set: Boolean = false) : PendingFlushMarker {
    override fun isSet() = set
    override fun set() { set = true }
    override fun clear() { set = false }
}

class VaultWorkingCopyCoordinatorTest {

    @Test fun openExisting_flushes_before_materialize_when_pending() = runTest {
        val order = mutableListOf<String>()
        val marker = FakeMarker(set = true)
        val coord = VaultWorkingCopyCoordinator(RecordingMirror(order), marker) { order.add("open"); "S" }
        val s = coord.openExisting()
        assertEquals("S", s)
        assertEquals(listOf("flush", "materialize", "open"), order) // push-before-pull keystone
        assertFalse(marker.isSet(), "marker cleared after a successful push")
    }

    @Test fun openExisting_no_pending_marker_skips_flush() = runTest {
        val order = mutableListOf<String>()
        val coord = VaultWorkingCopyCoordinator(RecordingMirror(order), FakeMarker(set = false)) { order.add("open"); "S" }
        coord.openExisting()
        assertEquals(listOf("materialize", "open"), order) // no spurious flush when clean
    }

    @Test fun openExisting_pending_flush_failure_aborts_before_materialize() = runTest {
        val order = mutableListOf<String>()
        val marker = FakeMarker(set = true)
        val coord = VaultWorkingCopyCoordinator(RecordingMirror(order, flushFails = true), marker) { order.add("open"); "S" }
        var threw = false
        try { coord.openExisting() } catch (e: VaultMirrorException) { threw = true }
        assertTrue(threw, "a failed push must propagate")
        assertEquals(listOf("flush"), order) // never materialized / opened
        assertTrue(marker.isSet(), "marker stays set so the next open retries the push")
    }

    @Test fun createThenOpen_flushes_then_persists_then_opens() = runTest {
        val order = mutableListOf<String>()
        val coord = VaultWorkingCopyCoordinator(RecordingMirror(order), FakeMarker()) { order.add("open"); "S" }
        var persistedUuid: String? = null
        val s = coord.createThenOpen("deadbeef") { uuid -> order.add("persist"); persistedUuid = uuid }
        assertEquals("S", s)
        assertEquals(listOf("flush", "persist", "open"), order)
        assertEquals("deadbeef", persistedUuid)
    }

    @Test fun createThenOpen_flush_failure_sets_marker_and_propagates_without_persisting() = runTest {
        val order = mutableListOf<String>()
        val marker = FakeMarker(set = false)
        val coord = VaultWorkingCopyCoordinator(RecordingMirror(order, flushFails = true), marker) { order.add("open"); "S" }
        var persisted = false
        var threw = false
        try {
            coord.createThenOpen("deadbeef") { order.add("persist"); persisted = true }
        } catch (e: VaultMirrorException) {
            threw = true
        }
        assertTrue(threw, "a failed push must propagate so :app can route to retry")
        assertTrue(marker.isSet(), "marker set so the next openExisting pushes before pulling (no offline-create data loss)")
        assertEquals(listOf("flush"), order) // never persisted / opened
        assertFalse(persisted, "location must not be persisted when the push failed")
    }

    @Test fun afterCommit_sets_marker_on_flush_failure_and_never_throws() = runTest {
        val order = mutableListOf<String>()
        val marker = FakeMarker(set = false)
        val coord = VaultWorkingCopyCoordinator(RecordingMirror(order, flushFails = true), marker) { "S" }
        coord.afterCommit() // must not throw
        assertTrue(marker.isSet(), "flush failure marks pending")
    }

    @Test fun afterCommit_clears_marker_on_success() = runTest {
        val marker = FakeMarker(set = true)
        val coord = VaultWorkingCopyCoordinator(RecordingMirror(mutableListOf()), marker) { "S" }
        coord.afterCommit()
        assertFalse(marker.isSet(), "a successful flush clears any prior pending state")
    }
}
