// Block-CRUD slice assertions for the Kotlin smoke runner.
//
// Kotlin mirror of tests/swift/SmokeBlockCrud.swift — same seed, same
// pinned UUIDs, same four expectations.  create / rename / move_record
// mutate the on-disk vault, so each assertion seeds into a fresh per-
// test temp copy of golden_vault_001 via freshWritableVault (the
// read-only fixture is never touched).

import uniffi.secretary.BlockInput
import uniffi.secretary.FieldInput
import uniffi.secretary.FieldInputValue
import uniffi.secretary.RecordInput
import uniffi.secretary.VaultException
import uniffi.secretary.createBlock
import uniffi.secretary.moveRecord
import uniffi.secretary.readBlock
import uniffi.secretary.renameBlock
import uniffi.secretary.saveBlock

fun runBlockCrudAsserts(env: SmokeEnv) {
    var tmp: java.nio.file.Path? = null

    // Assert: create_block → read_block shows the given name and 0 records.
    tmp = null
    try {
        val (out, t) = freshWritableVault(env)
        tmp = t
        out.identity.use { id ->
            out.manifest.use { mf ->
                createBlock(
                    id, mf,
                    BLOCK_CRUD_BLOCK_UUID, "Secrets",
                    BLOCK_CRUD_DEVICE_UUID, 1_000UL,
                )
                readBlock(id, mf, BLOCK_CRUD_BLOCK_UUID, false).use { block ->
                    check(
                        block.blockName() == "Secrets" && block.recordCount() == 0uL,
                        "create_block → name=\"${block.blockName()}\" records=${block.recordCount()}",
                    )
                }
            }
        }
    } catch (e: Throwable) {
        check(false, "create_block round-trip threw $e")
    } finally {
        tmp?.let { cleanupTempVault(it) }
    }

    // Assert: rename_block → read_block shows new name; records survive.
    tmp = null
    try {
        val (out, t) = freshWritableVault(env)
        tmp = t
        out.identity.use { id ->
            out.manifest.use { mf ->
                // Create the block and add one record to it.
                createBlock(
                    id, mf,
                    BLOCK_CRUD_BLOCK_UUID, "OldName",
                    BLOCK_CRUD_DEVICE_UUID, 1_000UL,
                )
                saveBlock(
                    id, mf,
                    BlockInput(
                        BLOCK_CRUD_BLOCK_UUID,
                        "OldName",
                        listOf(
                            RecordInput(
                                BLOCK_CRUD_SRC_RECORD_UUID,
                                "login",
                                emptyList(),
                                listOf(FieldInput("user", FieldInputValue.Text("bob"))),
                            ),
                        ),
                    ),
                    BLOCK_CRUD_DEVICE_UUID, 2_000UL,
                )
                renameBlock(
                    id, mf,
                    BLOCK_CRUD_BLOCK_UUID, "NewName",
                    BLOCK_CRUD_DEVICE_UUID, 3_000UL,
                )
                readBlock(id, mf, BLOCK_CRUD_BLOCK_UUID, false).use { block ->
                    check(
                        block.blockName() == "NewName" && block.recordCount() == 1uL,
                        "rename_block → name=\"${block.blockName()}\" records=${block.recordCount()}",
                    )
                }
            }
        }
    } catch (e: Throwable) {
        check(false, "rename_block round-trip threw $e")
    } finally {
        tmp?.let { cleanupTempVault(it) }
    }

    // Assert: move_record → target read_block shows the record under
    // newRecordUuid; source read_block (live only) shows it gone.
    tmp = null
    try {
        val (out, t) = freshWritableVault(env)
        tmp = t
        out.identity.use { id ->
            out.manifest.use { mf ->
                // Create two empty blocks then seed a record into the source.
                createBlock(
                    id, mf,
                    BLOCK_CRUD_SRC_BLOCK_UUID, "Source",
                    BLOCK_CRUD_DEVICE_UUID, 1_000UL,
                )
                createBlock(
                    id, mf,
                    BLOCK_CRUD_TGT_BLOCK_UUID, "Target",
                    BLOCK_CRUD_DEVICE_UUID, 2_000UL,
                )
                saveBlock(
                    id, mf,
                    BlockInput(
                        BLOCK_CRUD_SRC_BLOCK_UUID,
                        "Source",
                        listOf(
                            RecordInput(
                                BLOCK_CRUD_SRC_RECORD_UUID,
                                "note",
                                emptyList(),
                                listOf(FieldInput("body", FieldInputValue.Text("secret"))),
                            ),
                        ),
                    ),
                    BLOCK_CRUD_DEVICE_UUID, 3_000UL,
                )
                moveRecord(
                    id, mf,
                    BLOCK_CRUD_SRC_BLOCK_UUID, BLOCK_CRUD_TGT_BLOCK_UUID,
                    BLOCK_CRUD_SRC_RECORD_UUID, BLOCK_CRUD_NEW_RECORD_UUID,
                    BLOCK_CRUD_DEVICE_UUID, 4_000UL,
                )
                // Target shows the record under newRecordUuid.
                val tgtCount = readBlock(id, mf, BLOCK_CRUD_TGT_BLOCK_UUID, false).use { block ->
                    block.recordCount()
                }
                // Source live-only shows the original record gone (tombstoned).
                val srcLiveCount = readBlock(id, mf, BLOCK_CRUD_SRC_BLOCK_UUID, false).use { block ->
                    block.recordCount()
                }
                check(
                    tgtCount == 1uL && srcLiveCount == 0uL,
                    "move_record → target.recordCount=$tgtCount source.liveCount=$srcLiveCount",
                )
            }
        }
    } catch (e: Throwable) {
        check(false, "move_record round-trip threw $e")
    } finally {
        tmp?.let { cleanupTempVault(it) }
    }

    // Assert: move_record same-block → throws VaultException.InvalidArgument.
    tmp = null
    try {
        val (out, t) = freshWritableVault(env)
        tmp = t
        out.identity.use { id ->
            out.manifest.use { mf ->
                createBlock(
                    id, mf,
                    BLOCK_CRUD_BLOCK_UUID, "SameBlock",
                    BLOCK_CRUD_DEVICE_UUID, 1_000UL,
                )
                try {
                    moveRecord(
                        id, mf,
                        BLOCK_CRUD_BLOCK_UUID, BLOCK_CRUD_BLOCK_UUID,
                        BLOCK_CRUD_SRC_RECORD_UUID, BLOCK_CRUD_NEW_RECORD_UUID,
                        BLOCK_CRUD_DEVICE_UUID, 2_000UL,
                    )
                    check(false, "move_record same-block should have thrown InvalidArgument")
                } catch (e: VaultException.InvalidArgument) {
                    check(true, "move_record same-block → VaultException.InvalidArgument")
                }
            }
        }
    } catch (e: Throwable) {
        if (e !is VaultException.InvalidArgument) {
            check(false, "move_record same-block setup threw $e")
        }
    } finally {
        tmp?.let { cleanupTempVault(it) }
    }
}
