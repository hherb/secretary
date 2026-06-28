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

    @Test
    fun `uuid-keyed working dir is keyed by uuid and NOT reset (carries un-pushed edits)`() {
        val files = File.createTempFile("files", "").let { it.delete(); it.mkdirs(); it }
        val uuid = "00112233445566778899aabbccddeeff"
        // Pre-populate an existing working dir with an un-pushed edit; it MUST survive (unlike create).
        File(files, "working/$uuid").apply { mkdirs(); File(this, "unpushed").writeText("edit") }

        val dir = workingVaultDirForUuid(files, uuid)

        assertEquals(File(files, "working/$uuid"), dir)
        assertTrue(dir.isDirectory)
        assertTrue(File(dir, "unpushed").exists()) // NOT reset: un-pushed edits preserved
    }

    @Test
    fun `uuid-keyed working dir falls back to a stable slug when uuid is empty`() {
        val files = File.createTempFile("files", "").let { it.delete(); it.mkdirs(); it }

        val dir = workingVaultDirForUuid(files, "")

        assertEquals(File(files, "working/unknown"), dir)
        assertTrue(dir.isDirectory)
    }

    @Test
    fun `created working dir reuses the create-time name dir WITHOUT resetting it`() {
        val files = File.createTempFile("files", "").let { it.delete(); it.mkdirs(); it }
        // Simulate the just-created vault content already written by workingVaultDir at create time.
        File(files, "working/My Vault").apply { mkdirs(); File(this, "vault.toml").writeText("v") }

        val dir = createdWorkingVaultDir(files, "My Vault")

        assertEquals(File(files, "working/My Vault"), dir)
        assertTrue(dir.isDirectory)
        assertTrue(File(dir, "vault.toml").exists()) // create-then-open must NOT wipe the new vault
    }
}
