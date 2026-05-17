// B.5 trash_block + restore_block assertions for the Kotlin smoke runner.
//
// Covers the soft-delete + restore lifecycle:
//   - Assert 32: trash + restore round-trip preserves the block payload
//   - Assert 33: trash_block(unknown_uuid) → VaultException.BlockNotFound
//   - Assert 34: restore_block on never-trashed UUID → BlockNotInTrash
//   - Assert 35: restore_block on live UUID (trashed → re-saved) →
//     BlockUuidAlreadyLive

import uniffi.secretary.BlockInput
import uniffi.secretary.FieldInput
import uniffi.secretary.FieldInputValue
import uniffi.secretary.RecordInput
import uniffi.secretary.VaultException
import uniffi.secretary.readBlock
import uniffi.secretary.restoreBlock
import uniffi.secretary.saveBlock
import uniffi.secretary.trashBlock

fun runTrashRestoreAsserts(env: SmokeEnv) {
    var b5Tmp: java.nio.file.Path? = null

    // Assert 32: trash → restore round-trip preserves the block.
    b5Tmp = null
    try {
        val (out, tmp) = freshWritableVault(env)
        b5Tmp = tmp
        out.identity.use { id ->
            out.manifest.use { mf ->
                saveBlock(
                    id, mf,
                    BlockInput(
                        B5_BLOCK_UUID,
                        "B.5 round-trip",
                        listOf(
                            RecordInput(
                                B5_RECORD_UUID,
                                listOf(FieldInput("title", FieldInputValue.Text("secret"))),
                            ),
                        ),
                    ),
                    B5_DEVICE_UUID, 1_000UL,
                )
                trashBlock(id, mf, B5_BLOCK_UUID, B5_DEVICE_UUID, 2_000UL)
                check(
                    mf.findBlock(B5_BLOCK_UUID) == null,
                    "trash_block: BlockEntry dropped from manifest",
                )
                restoreBlock(id, mf, B5_BLOCK_UUID, B5_DEVICE_UUID, 3_000UL)
                readBlock(id, mf, B5_BLOCK_UUID).use { block ->
                    check(
                        block.recordCount() == 1UL,
                        "restore_block: record preserved (got ${block.recordCount()})",
                    )
                }
            }
        }
    } catch (e: Throwable) {
        check(false, "B.5 round-trip threw $e")
    } finally {
        b5Tmp?.let { cleanupTempVault(it) }
    }

    // Assert 33: trash_block(unknown_uuid) → VaultException.BlockNotFound.
    b5Tmp = null
    try {
        val (out, tmp) = freshWritableVault(env)
        b5Tmp = tmp
        out.identity.use { id ->
            out.manifest.use { mf ->
                val unknownUuid = ByteArray(16) { 0xFF.toByte() }
                try {
                    trashBlock(id, mf, unknownUuid, B5_DEVICE_UUID, 1_000UL)
                    check(false, "trash_block(unknown) should have thrown BlockNotFound")
                } catch (e: VaultException.BlockNotFound) {
                    check(true, "trash_block unknown → VaultException.BlockNotFound")
                }
            }
        }
    } catch (e: Throwable) {
        if (e !is VaultException.BlockNotFound) {
            check(false, "trash_block unknown setup threw $e")
        }
    } finally {
        b5Tmp?.let { cleanupTempVault(it) }
    }

    // Assert 34: restore_block on never-trashed UUID → VaultException.BlockNotInTrash.
    b5Tmp = null
    try {
        val (out, tmp) = freshWritableVault(env)
        b5Tmp = tmp
        out.identity.use { id ->
            out.manifest.use { mf ->
                val neverTrashedUuid = ByteArray(16) { 0xEE.toByte() }
                try {
                    restoreBlock(id, mf, neverTrashedUuid, B5_DEVICE_UUID, 1_000UL)
                    check(false, "restore_block(never-trashed) should have thrown BlockNotInTrash")
                } catch (e: VaultException.BlockNotInTrash) {
                    check(true, "restore_block never-trashed → VaultException.BlockNotInTrash")
                }
            }
        }
    } catch (e: Throwable) {
        if (e !is VaultException.BlockNotInTrash) {
            check(false, "restore_block never-trashed setup threw $e")
        }
    } finally {
        b5Tmp?.let { cleanupTempVault(it) }
    }

    // Assert 35: restore_block on live UUID (trashed → re-saved) →
    // VaultException.BlockUuidAlreadyLive.
    b5Tmp = null
    try {
        val (out, tmp) = freshWritableVault(env)
        b5Tmp = tmp
        out.identity.use { id ->
            out.manifest.use { mf ->
                saveBlock(
                    id, mf,
                    BlockInput(B5_BLOCK_UUID, "v1", emptyList()),
                    B5_DEVICE_UUID, 1_000UL,
                )
                trashBlock(id, mf, B5_BLOCK_UUID, B5_DEVICE_UUID, 2_000UL)
                saveBlock(
                    id, mf,
                    BlockInput(B5_BLOCK_UUID, "v2", emptyList()),
                    B5_DEVICE_UUID, 3_000UL,
                )
                try {
                    restoreBlock(id, mf, B5_BLOCK_UUID, B5_DEVICE_UUID, 4_000UL)
                    check(false, "restore_block live-collision should have thrown BlockUuidAlreadyLive")
                } catch (e: VaultException.BlockUuidAlreadyLive) {
                    check(true, "restore_block live-collision → VaultException.BlockUuidAlreadyLive")
                }
            }
        }
    } catch (e: Throwable) {
        if (e !is VaultException.BlockUuidAlreadyLive) {
            check(false, "restore_block live-collision setup threw $e")
        }
    } finally {
        b5Tmp?.let { cleanupTempVault(it) }
    }
}
