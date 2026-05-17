// B.4b read_block assertions for the Kotlin smoke runner.
//
// Covers:
//   - Assert 19: read_block success → record_count == 1 + field_count == 2
//   - Assert 20: field_by_name("password").expose_text() == "hunter2"
//   - Assert 21: read_block(unknown_uuid) → VaultException.BlockNotFound
//   - Assert 22: wipe → record_count == 0

import uniffi.secretary.VaultException
import uniffi.secretary.openVaultWithPassword
import uniffi.secretary.readBlock

fun runReadBlockAsserts(env: SmokeEnv) {
    // Assert 19: read_block success → record_count == 1 + field_count == 2.
    try {
        val folderPathBytes = env.vault001Path.toString().toByteArray(Charsets.UTF_8)
        val out = openVaultWithPassword(folderPathBytes, env.password001)
        out.identity.use { id ->
            out.manifest.use { mf ->
                readBlock(id, mf, VAULT_001_BLOCK_UUID).use { block ->
                    val recordCount = block.recordCount()
                    val record = block.recordAt(0u)
                    val fieldCount = record?.fieldCount() ?: 0u
                    check(
                        recordCount == 1uL && fieldCount == 2uL,
                        "read_block success → record_count == 1 + field_count == 2 (got $recordCount, $fieldCount)",
                    )
                }
            }
        }
    } catch (e: Throwable) {
        check(false, "read_block success threw $e, expected to succeed")
    }

    // Assert 20: field_by_name("password").expose_text() == "hunter2".
    try {
        val folderPathBytes = env.vault001Path.toString().toByteArray(Charsets.UTF_8)
        val out = openVaultWithPassword(folderPathBytes, env.password001)
        out.identity.use { id ->
            out.manifest.use { mf ->
                readBlock(id, mf, VAULT_001_BLOCK_UUID).use { block ->
                    val record = block.recordAt(0u)!!
                    val pwField = record.fieldByName("password")!!
                    val secret = pwField.exposeText()
                    check(
                        secret == "hunter2",
                        "field_by_name(\"password\").expose_text() == \"hunter2\" (got \"$secret\")",
                    )
                }
            }
        }
    } catch (e: Throwable) {
        check(false, "expose_text threw $e, expected to succeed")
    }

    // Assert 21: read_block(unknown_uuid) → VaultException.BlockNotFound(uuid_hex matches).
    try {
        val folderPathBytes = env.vault001Path.toString().toByteArray(Charsets.UTF_8)
        val out = openVaultWithPassword(folderPathBytes, env.password001)
        out.identity.use { id ->
            out.manifest.use { mf ->
                val unknownUuid = ByteArray(16)
                try {
                    readBlock(id, mf, unknownUuid)
                    check(false, "read_block(unknown_uuid) should have thrown VaultException.BlockNotFound")
                } catch (e: VaultException.BlockNotFound) {
                    check(
                        e.uuidHex == "00000000000000000000000000000000",
                        "read_block(unknown_uuid) → VaultException.BlockNotFound(uuidHex=\"${e.uuidHex}\")",
                    )
                }
            }
        }
    } catch (e: Throwable) {
        check(false, "unknown UUID threw unexpected $e")
    }

    // Assert 22: wipe → record_count == 0. Note: Kotlin codegen exposes
    // both `wipe()` (explicit cascade, leaves handle alive) AND `close()`
    // (AutoCloseable destructor, releases Rust handle — calling any
    // method afterward throws IllegalStateException). We need wipe()
    // here so `recordCount()` post-call still returns the documented 0
    // sentinel rather than throwing.
    try {
        val folderPathBytes = env.vault001Path.toString().toByteArray(Charsets.UTF_8)
        val out = openVaultWithPassword(folderPathBytes, env.password001)
        out.identity.use { id ->
            out.manifest.use { mf ->
                readBlock(id, mf, VAULT_001_BLOCK_UUID).use { block ->
                    block.wipe()
                    val countAfter = block.recordCount()
                    check(
                        countAfter == 0uL,
                        "wipe → record_count == 0 (got $countAfter)",
                    )
                }
            }
        }
    } catch (e: Throwable) {
        check(false, "wipe-then-record_count threw $e, expected to succeed")
    }
}
