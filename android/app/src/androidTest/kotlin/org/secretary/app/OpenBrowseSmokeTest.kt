package org.secretary.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.secretary.browse.RevealedValue
import org.secretary.browse.VaultBrowseError
import org.secretary.browse.VaultBrowseModel
import org.secretary.browse.uniffiVaultOpenPort
import java.io.File

/**
 * First on-device exercise of the open/browse stack: production provisioning → uniffiVaultOpenPort
 * (real `openVaultWithPassword`, Argon2id) → VaultBrowseModel over the REAL native
 * libsecretary_ffi_uniffi.so. Host tests (fakes) cannot touch the .so. Metadata-only: asserts on
 * block/record metadata; never exposes a field value.
 */
@RunWith(AndroidJUnit4::class)
class OpenBrowseSmokeTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext

    // The published golden-vault KAT password — not a real secret.
    private val goldenPassword = "correct horse battery staple"

    @After fun cleanup() {
        File(context.filesDir, "golden_vault_001").deleteRecursively()
    }

    @Test
    fun open_correctPassword_listsBlocksAndRecordMetadata() = runBlocking {
        val folder = AppVaultProvisioning.stageGoldenVault(context)
        val session = uniffiVaultOpenPort().openWithPassword(folder.path, goldenPassword.toByteArray())
        val model = VaultBrowseModel(session)

        model.loadBlocks()
        val blocks = model.blocks.value
        assertTrue("golden vault has at least one block", blocks.isNotEmpty())
        assertTrue("block uuidHex is 32 hex chars", blocks.first().uuidHex.length == 32)

        model.selectBlock(blocks.first())
        val records = model.selectedRecords.value
        assertNotNull("a block read yields a (possibly empty) record list", records)
        // golden_vault_001's first block is non-empty; assert real metadata came back.
        assertTrue("first block has records", records!!.isNotEmpty())
        val first = records.first()
        assertTrue("record type is non-empty", first.type.isNotBlank())
        assertTrue("record uuidHex is 32 hex chars", first.uuidHex.length == 32)

        model.lock()
        assertTrue("lock clears blocks", model.blocks.value.isEmpty())
    }

    @Test
    fun open_wrongPassword_throwsTypedError() {
        val folder = AppVaultProvisioning.stageGoldenVault(context)
        assertThrows(VaultBrowseError.WrongPasswordOrCorrupt::class.java) {
            runBlocking {
                uniffiVaultOpenPort().openWithPassword(folder.path, "definitely-wrong".toByteArray())
            }
        }
    }

    @Test
    fun reveal_passwordField_exposesKnownPlaintext() = runBlocking {
        val folder = AppVaultProvisioning.stageGoldenVault(context)
        val session = uniffiVaultOpenPort().openWithPassword(folder.path, goldenPassword.toByteArray())
        val model = VaultBrowseModel(session)
        model.loadBlocks()
        model.selectBlock(model.blocks.value.first())

        val record = model.selectedRecords.value!!.first { it.type == "login" }
        val password = record.fields.first { it.name == "password" }
        model.reveal(record, password)

        assertEquals(
            RevealedValue.Text("hunter2"),
            model.revealed.value["${record.uuidHex}/password"],
        )

        model.lock()
        assertTrue("lock clears revealed values", model.revealed.value.isEmpty())
    }
}
