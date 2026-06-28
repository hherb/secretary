package org.secretary.app

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File

class WorkingDirResolverTest {
    @Test
    fun `working dir is a fresh empty child of files-working keyed by name`() {
        val files = File.createTempFile("files", "").let { it.delete(); it.mkdirs(); it }
        // Pre-populate a stale dir to prove it is reset.
        val stale = File(files, "working/My Vault").apply { mkdirs(); File(this, "junk").writeText("x") }
        assertTrue(File(stale, "junk").exists())

        val dir = workingVaultDir(files, "My Vault")

        assertEquals(File(files, "working/My Vault"), dir)
        assertTrue(dir.isDirectory)
        assertTrue(dir.list()!!.isEmpty()) // emptied for the createInFolder contract
    }
}
