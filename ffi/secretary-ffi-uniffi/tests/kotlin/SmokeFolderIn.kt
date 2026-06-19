// Folder-in open assertions for the Kotlin smoke runner.
//
// Covers:
//   - B.4a: open_vault_with_password (success + wrong-password + nonexistent)
//   - Issue #30 follow-up: open_vault_with_recovery (success + 3-word phrase
//     + wrong-vault phrase)
//
// Folder-in entry points take a vault folder path on disk and load
// vault.toml + identity bundle internally. The bytes-in counterpart
// lives in SmokeBytesIn.kt.

import uniffi.secretary.VaultException
import uniffi.secretary.createVaultInFolder
import uniffi.secretary.openVaultWithPassword
import uniffi.secretary.openVaultWithRecovery

fun runFolderInAsserts(env: SmokeEnv) {
    val goldenVault001Folder = env.vault001Path.toString()

    // =============================================================================
    // B.4a — folder-in open_vault_with_password asserts
    // =============================================================================

    // Assertion 16: open_vault_with_password success — identity + manifest both populated.
    // Chained .use { } cleanup matches the bytes-in idiom (SmokeBytesIn.kt:41-56)
    // and guarantees both handles close even if displayName() / blockCount() / check()
    // throws — the prior sequential-cleanup pattern leaked both handles on exception.
    try {
        val folderPath = goldenVault001Folder.toByteArray(Charsets.UTF_8)
        val out = openVaultWithPassword(folderPath, env.password001)
        out.identity.use { identity ->
            out.manifest.use { manifest ->
                val displayName = identity.displayName()
                val blockCount = manifest.blockCount()
                check(
                    displayName == EXPECTED_DISPLAY_NAME && blockCount > 0UL,
                    "open_vault_with_password success → displayName=\"$displayName\", blockCount=$blockCount",
                )
            }
        }
    } catch (e: Throwable) {
        check(false, "open_vault_with_password success threw $e, expected to succeed")
    }

    // Assertion 17: wrong password → VaultException.WrongPasswordOrCorrupt.
    try {
        val folderPath = goldenVault001Folder.toByteArray(Charsets.UTF_8)
        val wrongPassword = "definitely wrong".toByteArray(Charsets.UTF_8)
        openVaultWithPassword(folderPath, wrongPassword)
        check(false, "wrong password (vault) should have thrown VaultException.WrongPasswordOrCorrupt")
    } catch (e: VaultException.WrongPasswordOrCorrupt) {
        check(true, "open_vault_with_password wrong password → VaultException.WrongPasswordOrCorrupt")
    } catch (e: Throwable) {
        check(false, "wrong password (vault) threw $e, expected VaultException.WrongPasswordOrCorrupt")
    }

    // Assertion 18: nonexistent folder → VaultException.FolderInvalid with detail.
    try {
        val folderPath = "/tmp/__nonexistent_b4a_kotlin__".toByteArray(Charsets.UTF_8)
        openVaultWithPassword(folderPath, env.password001)
        check(false, "nonexistent folder should have thrown VaultException.FolderInvalid")
    } catch (e: VaultException.FolderInvalid) {
        val detail = e.detail.lowercase()
        check(
            detail.contains("vault.toml") || detail.contains("no such file"),
            "nonexistent folder → VaultException.FolderInvalid(detail=\"${e.detail}\")",
        )
    } catch (e: Throwable) {
        check(false, "nonexistent folder threw $e, expected VaultException.FolderInvalid")
    }

    // =============================================================================
    // Issue #30 follow-up — folder-in open_vault_with_recovery asserts
    // =============================================================================
    //
    // Mirrors asserts 16-18 (folder-in password) but exercises the
    // recovery path through the folder-in entry point. The bytes-in
    // `open_with_recovery` surface is already covered by asserts 9-12 in
    // SmokeBytesIn.kt; the folder-in `open_vault_with_recovery`
    // counterpart was missing. Pinned KAT inputs come from
    // `golden_vault_001_inputs.json` via `phraseFromInputs`.

    // Assert 36: open_vault_with_recovery success — identity + manifest both populated.
    // Same chained-.use { } cleanup as assert 16 above — see that comment.
    try {
        val folderPath = goldenVault001Folder.toByteArray(Charsets.UTF_8)
        val out = openVaultWithRecovery(folderPath, env.phrase001)
        out.identity.use { identity ->
            out.manifest.use { manifest ->
                val displayName = identity.displayName()
                val blockCount = manifest.blockCount()
                check(
                    displayName == EXPECTED_DISPLAY_NAME && blockCount > 0UL,
                    "open_vault_with_recovery success → displayName=\"$displayName\", blockCount=$blockCount",
                )
            }
        }
    } catch (e: Throwable) {
        check(false, "open_vault_with_recovery success threw $e, expected to succeed")
    }

    // Assert 37: open_vault_with_recovery 3-word phrase → VaultException.InvalidMnemonic(detail).
    try {
        val folderPath = goldenVault001Folder.toByteArray(Charsets.UTF_8)
        val bad = "only three words".toByteArray(Charsets.UTF_8)
        openVaultWithRecovery(folderPath, bad)
        check(false, "3-word phrase should have thrown VaultException.InvalidMnemonic")
    } catch (e: VaultException.InvalidMnemonic) {
        check(
            e.detail.contains("got 3"),
            "open_vault_with_recovery 3-word → VaultException.InvalidMnemonic(detail=\"${e.detail}\") mentions `got 3`",
        )
    } catch (e: Throwable) {
        check(false, "3-word phrase threw $e, expected VaultException.InvalidMnemonic")
    }

    // Assert 38: open_vault_with_recovery vault_002 phrase against vault_001 folder → WrongMnemonicOrCorrupt.
    try {
        val folderPath = goldenVault001Folder.toByteArray(Charsets.UTF_8)
        openVaultWithRecovery(folderPath, env.phrase002)
        check(false, "vault_002 phrase against vault_001 folder should have thrown VaultException.WrongMnemonicOrCorrupt")
    } catch (e: VaultException.WrongMnemonicOrCorrupt) {
        check(true, "open_vault_with_recovery wrong-vault phrase → VaultException.WrongMnemonicOrCorrupt")
    } catch (e: Throwable) {
        check(false, "wrong-vault phrase threw $e, expected VaultException.WrongMnemonicOrCorrupt")
    }

    // =============================================================================
    // create_vault_in_folder — write a complete vault on disk, then open it.
    // =============================================================================

    // Assert 39: create_vault_in_folder writes a complete, openable vault
    // (24-word recovery phrase + folder-password open succeeds → browsable).
    run {
        val tmp = kotlin.io.path.createTempDirectory("create-folder-").toFile()
        try {
            val folderPath = tmp.path.toByteArray(Charsets.UTF_8)
            val pw = "create-smoke-pw".toByteArray(Charsets.UTF_8)
            var wordCount = 0
            createVaultInFolder(folderPath, pw, "Kotlin-Create-Bob", 1_700_000_000_000UL).use { mn ->
                val phrase = mn.takePhrase()
                check(phrase != null, "create_vault_in_folder take_phrase returned null")
                if (phrase != null) {
                    // takePhrase() is `bytes?` → a ByteArray? directly (#261); decode UTF-8 to count words.
                    wordCount = phrase.toString(Charsets.UTF_8).split(" ").size
                }
            }
            val out = openVaultWithPassword(folderPath, pw)
            out.identity.use { identity ->
                out.manifest.use { _ ->
                    val name = identity.displayName()
                    check(
                        wordCount == 24 && name == "Kotlin-Create-Bob",
                        "create_vault_in_folder → 24-word phrase + openable vault (words=$wordCount, displayName=\"$name\")",
                    )
                }
            }
        } catch (e: Throwable) {
            check(false, "create_vault_in_folder smoke threw $e, expected success")
        } finally {
            tmp.deleteRecursively()
        }
    }

    // Assert 40: create_vault_in_folder on a non-empty folder → VaultException.VaultFolderNotEmpty.
    run {
        val tmp = kotlin.io.path.createTempDirectory("create-nonempty-").toFile()
        try {
            java.io.File(tmp, "junk").writeText("x")
            createVaultInFolder(
                tmp.path.toByteArray(Charsets.UTF_8),
                "pw".toByteArray(Charsets.UTF_8),
                "X",
                1_700_000_000_000UL,
            )
            check(false, "non-empty folder should have thrown VaultException.VaultFolderNotEmpty")
        } catch (e: VaultException.VaultFolderNotEmpty) {
            check(true, "create_vault_in_folder non-empty → VaultException.VaultFolderNotEmpty")
        } catch (e: Throwable) {
            check(false, "non-empty folder threw $e, expected VaultException.VaultFolderNotEmpty")
        } finally {
            tmp.deleteRecursively()
        }
    }
}
