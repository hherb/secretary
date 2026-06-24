// B.4d share_block assertions for the Kotlin smoke runner.
//
// share_block extends a block's recipient list. Same NotAuthor exclusion
// rationale as the Swift smoke runner — cross-vault manifest staging is
// impractical at this layer (pinned at bridge unit-test layer instead).

import uniffi.secretary.BlockInput
import uniffi.secretary.FieldInput
import uniffi.secretary.FieldInputValue
import uniffi.secretary.RecordInput
import uniffi.secretary.VaultException
import uniffi.secretary.importContactCard
import uniffi.secretary.saveBlock
import uniffi.secretary.shareBlock
import uniffi.secretary.shareBlockTo

fun runShareBlockAsserts(env: SmokeEnv) {
    // Assert 28: share_block happy path — owner saves, owner shares with
    // alice, manifest entry grows from 1 to 2 recipients.
    var shareTmp: java.nio.file.Path? = null
    try {
        val aliceBytes = aliceCardBytes(env)
        val (out, tmp) = freshWritableVault(env)
        shareTmp = tmp
        out.identity.use { id ->
            out.manifest.use { mf ->
                saveBlock(
                    id, mf,
                    BlockInput(
                        blockUuid = SHARE_BLOCK_BLOCK_UUID,
                        blockName = "shared",
                        records = listOf(
                            RecordInput(
                                SHARE_BLOCK_RECORD_UUID,
                                "",
                                emptyList(),
                                listOf(FieldInput("k", FieldInputValue.Text("v"))),
                            ),
                        ),
                    ),
                    SHARE_BLOCK_DEVICE_UUID, 1_000UL,
                )
                val ownerBytes = mf.ownerCardBytes()!!
                shareBlock(
                    id, mf, SHARE_BLOCK_BLOCK_UUID,
                    listOf(ownerBytes), aliceBytes,
                    SHARE_BLOCK_DEVICE_UUID, 2_000UL,
                )
                val summary = mf.findBlock(SHARE_BLOCK_BLOCK_UUID)
                check(
                    summary?.recipientUuids?.size == 2,
                    "share_block insert → manifest grows to 2 recipients (got ${summary?.recipientUuids?.size})",
                )
            }
        }
    } catch (e: Throwable) {
        check(false, "share_block happy path threw $e, expected to succeed")
    } finally {
        shareTmp?.let { cleanupTempVault(it) }
    }

    // Assert 29: duplicate share → RecipientAlreadyPresent.
    shareTmp = null
    try {
        val aliceBytes = aliceCardBytes(env)
        val (out, tmp) = freshWritableVault(env)
        shareTmp = tmp
        out.identity.use { id ->
            out.manifest.use { mf ->
                saveBlock(
                    id, mf,
                    BlockInput(SHARE_BLOCK_BLOCK_UUID, "x", emptyList()),
                    SHARE_BLOCK_DEVICE_UUID, 1_000UL,
                )
                val ownerBytes = mf.ownerCardBytes()!!
                shareBlock(
                    id, mf, SHARE_BLOCK_BLOCK_UUID,
                    listOf(ownerBytes), aliceBytes,
                    SHARE_BLOCK_DEVICE_UUID, 2_000UL,
                )
                try {
                    shareBlock(
                        id, mf, SHARE_BLOCK_BLOCK_UUID,
                        listOf(ownerBytes, aliceBytes), aliceBytes,
                        SHARE_BLOCK_DEVICE_UUID, 3_000UL,
                    )
                    check(false, "duplicate share should have thrown RecipientAlreadyPresent")
                } catch (e: VaultException.RecipientAlreadyPresent) {
                    check(true, "share_block duplicate alice → RecipientAlreadyPresent")
                }
            }
        }
    } catch (e: Throwable) {
        // Re-raise unless already handled by the inner check().
        if (e !is VaultException.RecipientAlreadyPresent) {
            check(false, "share_block duplicate-recipient setup threw $e")
        }
    } finally {
        shareTmp?.let { cleanupTempVault(it) }
    }

    // Assert 30: empty existing list → MissingRecipientCard.
    shareTmp = null
    try {
        val aliceBytes = aliceCardBytes(env)
        val (out, tmp) = freshWritableVault(env)
        shareTmp = tmp
        out.identity.use { id ->
            out.manifest.use { mf ->
                saveBlock(
                    id, mf,
                    BlockInput(SHARE_BLOCK_BLOCK_UUID, "x", emptyList()),
                    SHARE_BLOCK_DEVICE_UUID, 1_000UL,
                )
                try {
                    shareBlock(
                        id, mf, SHARE_BLOCK_BLOCK_UUID,
                        emptyList(), aliceBytes,
                        SHARE_BLOCK_DEVICE_UUID, 2_000UL,
                    )
                    check(false, "empty existing list should have thrown MissingRecipientCard")
                } catch (e: VaultException.MissingRecipientCard) {
                    check(
                        e.recipientFingerprintHex.length == 32,
                        "share_block missing card → MissingRecipientCard(${e.recipientFingerprintHex})",
                    )
                }
            }
        }
    } catch (e: Throwable) {
        if (e !is VaultException.MissingRecipientCard) {
            check(false, "share_block missing-existing-card setup threw $e")
        }
    } finally {
        shareTmp?.let { cleanupTempVault(it) }
    }

    // Assert 32 (#206): verified safe path — import Alice by card bytes, then
    // share_block_to by UUID; manifest grows to 2 recipients. A second import
    // of the same card → ContactAlreadyExists.
    shareTmp = null
    try {
        val aliceBytes = aliceCardBytes(env)
        val (out, tmp) = freshWritableVault(env)
        shareTmp = tmp
        out.identity.use { id ->
            out.manifest.use { mf ->
                saveBlock(
                    id, mf,
                    BlockInput(SHARE_BLOCK_BLOCK_UUID, "shared", emptyList()),
                    SHARE_BLOCK_DEVICE_UUID, 1_000UL,
                )
                val summary = importContactCard(mf, aliceBytes)
                check(summary.contactUuid.size == 16, "import_contact_card -> 16-byte uuid")
                shareBlockTo(id, mf, SHARE_BLOCK_BLOCK_UUID,
                    summary.contactUuid, SHARE_BLOCK_DEVICE_UUID, 2_000UL)
                val entry = mf.findBlock(SHARE_BLOCK_BLOCK_UUID)
                check(
                    entry?.recipientUuids?.size == 2,
                    "share_block_to -> 2 recipients (got ${entry?.recipientUuids?.size})",
                )
                try {
                    importContactCard(mf, aliceBytes)
                    check(false, "duplicate import should throw ContactAlreadyExists")
                } catch (e: VaultException.ContactAlreadyExists) {
                    check(true, "duplicate import -> ContactAlreadyExists")
                }
            }
        }
    } catch (e: Throwable) {
        // Unconditional, mirroring the Swift smoke: ContactAlreadyExists is the
        // very variant the #206 guard produces, so a stray throw of it (e.g.
        // shareBlockTo erroneously rejecting) must fail the test, not be
        // swallowed. The expected duplicate-import throw is caught inline above.
        check(false, "#206 safe-path smoke threw $e")
    } finally {
        shareTmp?.let { cleanupTempVault(it) }
    }

    // Assert 31: garbage card bytes → CardDecodeFailure.
    shareTmp = null
    try {
        val aliceBytes = aliceCardBytes(env)
        val (out, tmp) = freshWritableVault(env)
        shareTmp = tmp
        out.identity.use { id ->
            out.manifest.use { mf ->
                saveBlock(
                    id, mf,
                    BlockInput(SHARE_BLOCK_BLOCK_UUID, "x", emptyList()),
                    SHARE_BLOCK_DEVICE_UUID, 1_000UL,
                )
                val garbage = ByteArray(8) { 0xff.toByte() }
                try {
                    shareBlock(
                        id, mf, SHARE_BLOCK_BLOCK_UUID,
                        listOf(garbage), aliceBytes,
                        SHARE_BLOCK_DEVICE_UUID, 2_000UL,
                    )
                    check(false, "garbage existing should have thrown CardDecodeFailure")
                } catch (e: VaultException.CardDecodeFailure) {
                    check(true, "share_block garbage existing → CardDecodeFailure")
                }
            }
        }
    } catch (e: Throwable) {
        if (e !is VaultException.CardDecodeFailure) {
            check(false, "share_block card-decode-failure setup threw $e")
        }
    } finally {
        shareTmp?.let { cleanupTempVault(it) }
    }
}
