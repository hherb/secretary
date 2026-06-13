// Record-edit slice assertions for the Kotlin smoke runner.
//
// Kotlin mirror of tests/swift/SmokeRecordEdit.swift — same seed, same
// pinned UUIDs, same edit-device, same five expectations. append / edit /
// tombstone / resurrect mutate the on-disk vault, so each assertion seeds
// into a fresh per-test temp copy of golden_vault_001 via
// freshWritableVault (the read-only fixture is never touched).

import uniffi.secretary.BlockInput
import uniffi.secretary.FieldInput
import uniffi.secretary.FieldInputValue
import uniffi.secretary.OpenVaultManifest
import uniffi.secretary.RecordContent
import uniffi.secretary.RecordInput
import uniffi.secretary.UnlockedIdentity
import uniffi.secretary.VaultException
import uniffi.secretary.appendRecord
import uniffi.secretary.editRecord
import uniffi.secretary.readBlock
import uniffi.secretary.resurrectRecord
import uniffi.secretary.saveBlock
import uniffi.secretary.tombstoneRecord

fun runRecordEditAsserts(env: SmokeEnv) {
    // Seed a one-record two-field "login" block into the open manifest.
    fun seedBlock(id: UnlockedIdentity, mf: OpenVaultManifest) {
        saveBlock(
            id, mf,
            BlockInput(
                RECORD_EDIT_BLOCK_UUID,
                "Logins",
                listOf(
                    RecordInput(
                        RECORD_EDIT_RECORD_UUID,
                        "login",
                        listOf("work"),
                        listOf(
                            FieldInput("user", FieldInputValue.Text("alice")),
                            FieldInput("pass", FieldInputValue.Text("hunter2")),
                        ),
                    ),
                ),
            ),
            RECORD_EDIT_DEVICE_UUID, 1_000UL,
        )
    }

    var tmp: java.nio.file.Path? = null

    // Assert: append_record adds a second live record → read_block sees both.
    tmp = null
    try {
        val (out, t) = freshWritableVault(env)
        tmp = t
        out.identity.use { id ->
            out.manifest.use { mf ->
                seedBlock(id, mf)
                val secondUuid = ByteArray(16) { 0xD3.toByte() }
                appendRecord(
                    id, mf,
                    RECORD_EDIT_BLOCK_UUID, secondUuid,
                    RecordContent(
                        "note", emptyList(),
                        listOf(FieldInput("body", FieldInputValue.Text("remember"))),
                    ),
                    RECORD_EDIT_DEVICE_UUID, 2_000UL,
                )
                readBlock(id, mf, RECORD_EDIT_BLOCK_UUID).use { block ->
                    check(
                        block.recordCount() == 2uL,
                        "append_record → read_block sees 2 records (got ${block.recordCount()})",
                    )
                }
            }
        }
    } catch (e: Throwable) {
        check(false, "append_record round-trip threw $e")
    } finally {
        tmp?.let { cleanupTempVault(it) }
    }

    // Assert: edit_record changes "pass" but leaves "user" untouched — the
    // untouched field keeps its prior device_uuid (per-field-clock proof).
    tmp = null
    try {
        val (out, t) = freshWritableVault(env)
        tmp = t
        out.identity.use { id ->
            out.manifest.use { mf ->
                seedBlock(id, mf)
                val editDevice = ByteArray(16) { 0x09.toByte() }
                editRecord(
                    id, mf,
                    RECORD_EDIT_BLOCK_UUID, RECORD_EDIT_RECORD_UUID,
                    RecordContent(
                        "login", listOf("work"),
                        listOf(
                            FieldInput("user", FieldInputValue.Text("alice")),   // unchanged
                            FieldInput("pass", FieldInputValue.Text("s3cret!")), // changed
                        ),
                    ),
                    editDevice, 3_000UL,
                )
                readBlock(id, mf, RECORD_EDIT_BLOCK_UUID).use { block ->
                    val record = block.recordAt(0u)
                    val pass = record?.fieldByName("pass")?.exposeText()
                    val userDevice = record?.fieldByName("user")?.deviceUuid()
                    val passDevice = record?.fieldByName("pass")?.deviceUuid()
                    check(
                        pass == "s3cret!" &&
                            userDevice?.contentEquals(RECORD_EDIT_DEVICE_UUID) == true &&
                            passDevice?.contentEquals(editDevice) == true,
                        "edit_record preserves untouched field clock (pass=${pass ?: "<null>"})",
                    )
                }
            }
        }
    } catch (e: Throwable) {
        check(false, "edit_record round-trip threw $e")
    } finally {
        tmp?.let { cleanupTempVault(it) }
    }

    // Assert: tombstone flips the record's tombstone() flag to true (the
    // record stays in read_block's projection — read_block surfaces
    // tombstoned records via record.tombstone(), it does NOT filter them
    // out); resurrect flips it back to false.
    tmp = null
    try {
        val (out, t) = freshWritableVault(env)
        tmp = t
        out.identity.use { id ->
            out.manifest.use { mf ->
                seedBlock(id, mf)
                tombstoneRecord(
                    id, mf,
                    RECORD_EDIT_BLOCK_UUID, RECORD_EDIT_RECORD_UUID,
                    RECORD_EDIT_DEVICE_UUID, 4_000UL,
                )
                val deadFlag = readBlock(id, mf, RECORD_EDIT_BLOCK_UUID).use { block ->
                    block.recordAt(0u)?.tombstone()
                }
                resurrectRecord(
                    id, mf,
                    RECORD_EDIT_BLOCK_UUID, RECORD_EDIT_RECORD_UUID,
                    RECORD_EDIT_DEVICE_UUID, 5_000UL,
                )
                val liveFlag = readBlock(id, mf, RECORD_EDIT_BLOCK_UUID).use { block ->
                    block.recordAt(0u)?.tombstone()
                }
                check(
                    deadFlag == true && liveFlag == false,
                    "tombstone→tombstone()=$deadFlag then resurrect→tombstone()=$liveFlag",
                )
            }
        }
    } catch (e: Throwable) {
        check(false, "tombstone/resurrect round-trip threw $e")
    } finally {
        tmp?.let { cleanupTempVault(it) }
    }

    // Assert: editing an unknown record uuid → VaultException.RecordNotFound.
    tmp = null
    try {
        val (out, t) = freshWritableVault(env)
        tmp = t
        out.identity.use { id ->
            out.manifest.use { mf ->
                seedBlock(id, mf)
                val unknownUuid = ByteArray(16) { 0xFF.toByte() }
                try {
                    editRecord(
                        id, mf,
                        RECORD_EDIT_BLOCK_UUID, unknownUuid,
                        RecordContent("x", emptyList(), emptyList()),
                        RECORD_EDIT_DEVICE_UUID, 6_000UL,
                    )
                    check(false, "edit_record on unknown uuid should have thrown RecordNotFound")
                } catch (e: VaultException.RecordNotFound) {
                    check(true, "edit_record unknown uuid → VaultException.RecordNotFound")
                }
            }
        }
    } catch (e: Throwable) {
        if (e !is VaultException.RecordNotFound) {
            check(false, "edit_record unknown-uuid setup threw $e")
        }
    } finally {
        tmp?.let { cleanupTempVault(it) }
    }

    // Assert: wrong-length device_uuid → VaultException.InvalidArgument.
    tmp = null
    try {
        val (out, t) = freshWritableVault(env)
        tmp = t
        out.identity.use { id ->
            out.manifest.use { mf ->
                seedBlock(id, mf)
                try {
                    tombstoneRecord(
                        id, mf,
                        RECORD_EDIT_BLOCK_UUID, RECORD_EDIT_RECORD_UUID,
                        byteArrayOf(0x07, 0x07), 7_000UL,
                    )
                    check(false, "tombstone_record wrong-length device_uuid should have thrown InvalidArgument")
                } catch (e: VaultException.InvalidArgument) {
                    check(true, "tombstone_record wrong-length → VaultException.InvalidArgument")
                }
            }
        }
    } catch (e: Throwable) {
        if (e !is VaultException.InvalidArgument) {
            check(false, "tombstone_record wrong-length setup threw $e")
        }
    } finally {
        tmp?.let { cleanupTempVault(it) }
    }
}
