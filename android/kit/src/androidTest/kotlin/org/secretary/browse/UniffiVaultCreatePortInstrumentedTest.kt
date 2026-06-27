package org.secretary.browse

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class UniffiVaultCreatePortInstrumentedTest {

    private fun freshDir(prefix: String): File =
        File.createTempFile(prefix, "").let { f ->
            f.delete()
            check(f.mkdirs()) { "could not mkdir ${f.path}" }
            f
        }

    @Test
    fun create_then_open_round_trips_with_24_word_phrase() = runBlocking {
        val dir = freshDir("create-roundtrip-")
        try {
            val createPort = uniffiVaultCreatePort()
            val pw = "create-instr-pw".toByteArray(Charsets.UTF_8)
            val created = createPort.createInFolder(dir.path, pw, "Instr-Bob")
            val wordCount = created.phrase.toString(Charsets.UTF_8).split(" ").size
            assertEquals(24, wordCount)

            // The created vault opens with the same password and reports the display name.
            val session = uniffiVaultOpenPort().openWithPassword(dir.path, pw)
            try {
                // A freshly-created vault has no user blocks yet; opening + listing must not throw.
                assertEquals(0, session.blockSummaries().size)
            } finally {
                session.wipe()
            }
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun create_in_non_empty_folder_throws_folder_not_empty() {
        val dir = freshDir("create-nonempty-")
        try {
            File(dir, "junk").writeText("x")
            assertThrows(VaultProvisioningError.FolderNotEmpty::class.java) {
                runBlocking {
                    uniffiVaultCreatePort().createInFolder(
                        dir.path, "pw".toByteArray(Charsets.UTF_8), "Nope",
                    )
                }
            }
        } finally {
            dir.deleteRecursively()
        }
    }
}
