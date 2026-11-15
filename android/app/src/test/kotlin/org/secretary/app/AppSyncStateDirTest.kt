package org.secretary.app

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File

class AppSyncStateDirTest {

    @Test
    fun resolvesSyncStateSubdirOfBase() {
        val base = File("/data/user/0/org.secretary.app/files")
        assertEquals(File(base, "sync-state"), syncStateDir(base))
    }

    @Test
    fun installCreatesTheSyncStateDirAndHandsTheSameDirToTheOpens(@TempDir base: File) {
        val handed = mutableListOf<File>()
        val dir = installPlatformSyncStateDir(base) { handed += it }
        assertEquals(syncStateDir(base), dir)
        assertTrue(dir.isDirectory, "the dir must exist before the bridge is pointed at it")
        // Exactly once, and the SAME dir sync writes to — anything else leaves the check inactive.
        assertEquals(listOf(syncStateDir(base)), handed)
    }
}
