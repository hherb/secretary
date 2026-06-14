// B.4c save_block assertions for the Kotlin smoke runner.
//
// save_block mutates the on-disk vault — assertions copy golden_vault_001
// into a per-test tempdir so the read-only fixture is never touched.
// `freshWritableVault` in SmokeHelpers.kt produces the tempdir copy.
//
// Assertions retain their original 1-38 numbering from the pre-split
// Main.kt for cross-file searchability.

import uniffi.secretary.BlockInput
import uniffi.secretary.FieldInput
import uniffi.secretary.FieldInputValue
import uniffi.secretary.RecordInput
import uniffi.secretary.VaultException
import uniffi.secretary.openVaultWithPassword
import uniffi.secretary.readBlock
import uniffi.secretary.saveBlock

fun runSaveBlockAsserts(env: SmokeEnv) {
    // Assert 24: save_block insert → read_block round-trip succeeds with
    // matching record / field counts and exposed text + bytes payloads.
    var saveTmp: java.nio.file.Path? = null
    try {
        val (out, tmp) = freshWritableVault(env)
        saveTmp = tmp
        out.identity.use { id ->
            out.manifest.use { mf ->
                val input = BlockInput(
                    blockUuid = SAVE_BLOCK_NEW_BLOCK_UUID,
                    blockName = "Notes",
                    records = listOf(
                        RecordInput(
                            recordUuid = SAVE_BLOCK_NEW_RECORD_UUID,
                            recordType = "",
                            tags = emptyList(),
                            fields = listOf(
                                FieldInput("title", FieldInputValue.Text("wifi password")),
                                FieldInput(
                                    "key",
                                    FieldInputValue.Bytes(
                                        byteArrayOf(
                                            0xDE.toByte(), 0xAD.toByte(),
                                            0xBE.toByte(), 0xEF.toByte(),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                )
                saveBlock(id, mf, input, SAVE_BLOCK_DEVICE_UUID, 1_000UL)
                readBlock(id, mf, SAVE_BLOCK_NEW_BLOCK_UUID, false).use { block ->
                    val recordCount = block.recordCount()
                    val record = block.recordAt(0u)
                    val title = record?.fieldByName("title")?.exposeText()
                    val key = record?.fieldByName("key")?.exposeBytes()
                    check(
                        recordCount == 1uL
                            && title == "wifi password"
                            && key?.contentEquals(
                                byteArrayOf(
                                    0xDE.toByte(), 0xAD.toByte(),
                                    0xBE.toByte(), 0xEF.toByte(),
                                ),
                            ) == true,
                        "save_block insert → read_block round-trip (recordCount=$recordCount, title=$title)",
                    )
                }
            }
        }
    } catch (e: Throwable) {
        check(false, "save_block insert round-trip threw $e, expected to succeed")
    } finally {
        saveTmp?.let { cleanupTempVault(it) }
    }

    // Assert 25: save_block update — same block_uuid replaces the existing
    // entry; block_name advances on the second save.
    saveTmp = null
    try {
        val (out, tmp) = freshWritableVault(env)
        saveTmp = tmp
        out.identity.use { id ->
            out.manifest.use { mf ->
                saveBlock(
                    id,
                    mf,
                    BlockInput(SAVE_BLOCK_NEW_BLOCK_UUID, "v1", emptyList()),
                    SAVE_BLOCK_DEVICE_UUID,
                    1_000UL,
                )
                saveBlock(
                    id,
                    mf,
                    BlockInput(SAVE_BLOCK_NEW_BLOCK_UUID, "v2", emptyList()),
                    SAVE_BLOCK_DEVICE_UUID,
                    2_000UL,
                )
                val summary = mf.findBlock(SAVE_BLOCK_NEW_BLOCK_UUID)
                check(
                    summary?.blockName == "v2" && mf.blockCount() > 0uL,
                    "save_block update → blockName advanced (got ${summary?.blockName})",
                )
            }
        }
    } catch (e: Throwable) {
        check(false, "save_block update threw $e, expected to succeed")
    } finally {
        saveTmp?.let { cleanupTempVault(it) }
    }

    // Assert 26: save_block on a wiped manifest → VaultException.CorruptVault
    // with `manifest` in the detail.
    saveTmp = null
    try {
        val (out, tmp) = freshWritableVault(env)
        saveTmp = tmp
        out.identity.use { id ->
            // wipe the manifest BEFORE attempting the save so the bridge's
            // wipe-detection path fires.
            out.manifest.wipe()
            try {
                saveBlock(
                    id,
                    out.manifest,
                    BlockInput(SAVE_BLOCK_NEW_BLOCK_UUID, "x", emptyList()),
                    SAVE_BLOCK_DEVICE_UUID,
                    1_000UL,
                )
                check(false, "save_block on wiped manifest should have thrown VaultException.CorruptVault")
            } catch (e: VaultException.CorruptVault) {
                check(
                    e.detail.contains("manifest"),
                    "save_block on wiped manifest → CorruptVault(detail=\"${e.detail}\") names manifest",
                )
            } finally {
                out.manifest.close()
            }
        }
    } catch (e: Throwable) {
        check(false, "save_block wiped-manifest path threw setup $e")
    } finally {
        saveTmp?.let { cleanupTempVault(it) }
    }

    // Assert 27: save_block then drop handles, re-open, confirm the new
    // block is visible and readable.
    saveTmp = null
    try {
        val tmp = java.nio.file.Files.createTempDirectory("secretary_smoke_kotlin_persist_")
        saveTmp = tmp
        recursiveCopy(env.vault001Path, tmp)
        val folderPathBytes = tmp.toString().toByteArray(Charsets.UTF_8)

        // Save in an inner scope so the handles release before re-open.
        run {
            val out = openVaultWithPassword(folderPathBytes, env.password001)
            out.identity.use { id ->
                out.manifest.use { mf ->
                    saveBlock(
                        id,
                        mf,
                        BlockInput(
                            SAVE_BLOCK_NEW_BLOCK_UUID,
                            "persisted",
                            listOf(
                                RecordInput(
                                    SAVE_BLOCK_NEW_RECORD_UUID,
                                    "",
                                    emptyList(),
                                    listOf(FieldInput("k", FieldInputValue.Text("v"))),
                                ),
                            ),
                        ),
                        SAVE_BLOCK_DEVICE_UUID,
                        1_000UL,
                    )
                }
            }
        }

        val out2 = openVaultWithPassword(folderPathBytes, env.password001)
        out2.identity.use { id ->
            out2.manifest.use { mf ->
                val summary = mf.findBlock(SAVE_BLOCK_NEW_BLOCK_UUID)
                readBlock(id, mf, SAVE_BLOCK_NEW_BLOCK_UUID, false).use { block ->
                    val v = block.recordAt(0u)?.fieldByName("k")?.exposeText()
                    check(
                        summary?.blockName == "persisted" && v == "v",
                        "save_block persists → fresh open sees block (blockName=${summary?.blockName}, v=$v)",
                    )
                }
            }
        }
    } catch (e: Throwable) {
        check(false, "save_block persist-and-reopen threw $e, expected to succeed")
    } finally {
        saveTmp?.let { cleanupTempVault(it) }
    }
}
