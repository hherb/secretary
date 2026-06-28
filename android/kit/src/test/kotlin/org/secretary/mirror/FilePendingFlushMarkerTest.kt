package org.secretary.mirror

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.file.Path

class FilePendingFlushMarkerTest {
    @TempDir lateinit var tmp: Path

    @Test fun absent_by_default_then_set_then_clear() {
        val marker = FilePendingFlushMarker(File(tmp.toFile(), "v123.pending-flush"))
        assertFalse(marker.isSet(), "fresh marker must be unset")
        marker.set()
        assertTrue(marker.isSet(), "set() makes it present")
        marker.set() // idempotent
        assertTrue(marker.isSet())
        marker.clear()
        assertFalse(marker.isSet(), "clear() removes it")
        marker.clear() // idempotent on already-absent
        assertFalse(marker.isSet())
    }
}
