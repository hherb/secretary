package org.secretary.app

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File

class WorkingDirResolverTest {
    private fun tempFiles(): File =
        File.createTempFile("files", "").let { it.delete(); it.mkdirs(); it }

    // --- cloudVaultKey: pure function of treeUri ------------------------------------------------

    @Test
    fun `cloud vault key is a pure stable function of the treeUri`() {
        val uri = "content://com.android.externalstorage.documents/tree/primary%3AVaults%2FMine"
        assertEquals(cloudVaultKey(uri), cloudVaultKey(uri)) // deterministic
    }

    @Test
    fun `different treeUris yield different keys`() {
        val a = cloudVaultKey("content://provider/tree/folderA")
        val b = cloudVaultKey("content://provider/tree/folderB")
        assertNotEquals(a, b)
    }

    @Test
    fun `cloud vault key is non-empty filesystem-safe lowercase hex`() {
        val key = cloudVaultKey("content://provider/tree/x")
        assertEquals(64, key.length) // SHA-256 → 32 bytes → 64 hex chars
        assertTrue(key.all { it in "0123456789abcdef" })
    }

    @Test
    fun `key does NOT depend on the vault uuid - stable across known to unknown uuid transition`() {
        // The key is derived ONLY from treeUri: opening the same cloud folder before vs after its
        // uuid is learned resolves to the SAME key (this is what closes the orphan-loss path).
        val uri = "content://provider/tree/same-folder"
        val beforeUuidKnown = cloudVaultKey(uri)
        val afterUuidKnown = cloudVaultKey(uri) // treeUri unchanged → same key regardless of uuid
        assertEquals(beforeUuidKnown, afterUuidKnown)
    }

    // --- cloudWorkingVaultDir: keyed by treeUri, reset only for create -------------------------

    @Test
    fun `working dir is keyed by the treeUri-derived key`() {
        val files = tempFiles()
        val uri = "content://provider/tree/folderA"

        val dir = cloudWorkingVaultDir(files, uri, reset = false)

        assertEquals(File(files, "working/${cloudVaultKey(uri)}"), dir)
        assertTrue(dir.isDirectory)
    }

    @Test
    fun `same treeUri resolves to the same dir across opens (no orphan)`() {
        val files = tempFiles()
        val uri = "content://provider/tree/folderA"
        // First "open": leave an un-pushed edit in the working dir.
        cloudWorkingVaultDir(files, uri, reset = false).also { File(it, "unpushed").writeText("edit") }

        // Second "open" of the SAME cloud folder must land on the SAME dir, preserving the edit.
        val reopened = cloudWorkingVaultDir(files, uri, reset = false)

        assertTrue(File(reopened, "unpushed").exists()) // NOT orphaned, NOT reset
    }

    @Test
    fun `different treeUris never collide on a working dir`() {
        val files = tempFiles()
        val a = cloudWorkingVaultDir(files, "content://provider/tree/folderA", reset = false)
        val b = cloudWorkingVaultDir(files, "content://provider/tree/folderB", reset = false)
        assertNotEquals(a, b)
    }

    @Test
    fun `two distinct vaults with unknown uuid no longer collide (treeUri disambiguates)`() {
        val files = tempFiles()
        // Pre-fix both keyed by "unknown" → collision. Now keyed by treeUri → distinct.
        val one = cloudWorkingVaultDir(files, "content://provider/tree/one", reset = false)
        val two = cloudWorkingVaultDir(files, "content://provider/tree/two", reset = false)
        assertNotEquals(one, two)
    }

    @Test
    fun `create reset wipes a stale dir but open does not`() {
        val files = tempFiles()
        val uri = "content://provider/tree/folderA"
        // Stale dir from a prior interrupted create.
        cloudWorkingVaultDir(files, uri, reset = false).also { File(it, "junk").writeText("x") }

        val created = cloudWorkingVaultDir(files, uri, reset = true) // createInFolder needs an EMPTY dir
        assertTrue(created.list()!!.isEmpty())

        // A later open of the same vault (now holding content) must NOT reset.
        File(created, "vault.toml").writeText("v")
        val reopened = cloudWorkingVaultDir(files, uri, reset = false)
        assertTrue(File(reopened, "vault.toml").exists())
    }
}
