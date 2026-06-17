package org.secretary.app

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.io.File

class AppSyncStateDirTest {

    @Test
    fun resolvesSyncStateSubdirOfBase() {
        val base = File("/data/user/0/org.secretary.app/files")
        assertEquals(File(base, "sync-state"), syncStateDir(base))
    }
}
