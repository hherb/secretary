// Folder-in open assertions for the Swift smoke runner.
//
// Covers:
//   - B.4a: open_vault_with_password (success + wrong-password + nonexistent)
//   - Issue #30 follow-up: open_vault_with_recovery (success + 3-word phrase
//     + wrong-vault phrase)
//
// Folder-in entry points take a vault folder path on disk and load
// vault.toml + identity bundle internally. The bytes-in counterpart
// lives in SmokeBytesIn.swift.

import Foundation

func runFolderInAsserts(env: SmokeEnv) {
    // =============================================================================
    // B.4a — folder-in open_vault_with_password asserts
    // =============================================================================

    // Assert 16: open_vault_with_password success — identity + manifest both populated.
    do {
        let folderPath = Data(env.vault001Url.path.utf8)
        let out = try openVaultWithPassword(folderPath: folderPath, password: env.password001)
        defer { out.identity.wipe() }
        defer { out.manifest.wipe() }
        let displayName = out.identity.displayName()
        let blockCount = out.manifest.blockCount()
        check(
            displayName == expectedDisplayName && blockCount > 0,
            "open_vault_with_password success → displayName=\"\(displayName)\", blockCount=\(blockCount)"
        )
    } catch {
        check(false, "open_vault_with_password success threw \(error), expected to succeed")
    }

    // Assert 17: open_vault_with_password wrong password → VaultError.WrongPasswordOrCorrupt.
    do {
        let folderPath = Data(env.vault001Url.path.utf8)
        let wrongPassword = Data("definitely wrong".utf8)
        _ = try openVaultWithPassword(folderPath: folderPath, password: wrongPassword)
        check(false, "wrong password should have thrown VaultError.WrongPasswordOrCorrupt")
    } catch VaultError.WrongPasswordOrCorrupt {
        check(true, "open_vault_with_password wrong password → VaultError.WrongPasswordOrCorrupt")
    } catch {
        check(false, "wrong password (vault) threw \(error), expected VaultError.WrongPasswordOrCorrupt")
    }

    // Assert 18: nonexistent folder → VaultError.FolderInvalid with detail.
    do {
        let folderPath = Data("/tmp/__nonexistent_b4a_swift__".utf8)
        _ = try openVaultWithPassword(folderPath: folderPath, password: env.password001)
        check(false, "nonexistent folder should have thrown VaultError.FolderInvalid")
    } catch let e as VaultError {
        if case let .FolderInvalid(detail) = e {
            let lc = detail.lowercased()
            check(
                lc.contains("vault.toml") || lc.contains("no such file"),
                "nonexistent folder → VaultError.FolderInvalid(detail=\"\(detail)\")"
            )
        } else {
            check(false, "nonexistent folder threw wrong VaultError variant: \(e)")
        }
    } catch {
        check(false, "nonexistent folder threw \(error), expected VaultError.FolderInvalid")
    }

    // =============================================================================
    // Issue #30 follow-up — folder-in open_vault_with_recovery asserts
    // =============================================================================
    //
    // Mirrors asserts 16-18 (folder-in password) but exercises the recovery
    // path through the folder-in entry point. The bytes-in
    // `open_with_recovery` surface is already covered by asserts 9-12 in
    // SmokeBytesIn.swift; the folder-in `open_vault_with_recovery`
    // counterpart was missing. Pinned KAT inputs come from
    // `golden_vault_001_inputs.json` via `_phraseFromInputs`.

    // Assert 35: open_vault_with_recovery success — identity + manifest both populated.
    do {
        let folderPath = Data(env.vault001Url.path.utf8)
        let out = try openVaultWithRecovery(folderPath: folderPath, mnemonic: env.phrase001)
        defer { out.identity.wipe() }
        defer { out.manifest.wipe() }
        let displayName = out.identity.displayName()
        let blockCount = out.manifest.blockCount()
        check(
            displayName == expectedDisplayName && blockCount > 0,
            "open_vault_with_recovery success → displayName=\"\(displayName)\", blockCount=\(blockCount)"
        )
    } catch {
        check(false, "open_vault_with_recovery success threw \(error), expected to succeed")
    }

    // Assert 36: open_vault_with_recovery 3-word phrase → VaultError.InvalidMnemonic(detail).
    do {
        let folderPath = Data(env.vault001Url.path.utf8)
        let bad = Data("only three words".utf8)
        _ = try openVaultWithRecovery(folderPath: folderPath, mnemonic: bad)
        check(false, "3-word phrase should have thrown VaultError.InvalidMnemonic")
    } catch let e as VaultError {
        if case let .InvalidMnemonic(detail) = e {
            check(
                detail.contains("got 3"),
                "open_vault_with_recovery 3-word → VaultError.InvalidMnemonic(detail=\"\(detail)\") mentions `got 3`"
            )
        } else {
            check(false, "3-word phrase threw wrong VaultError variant: \(e)")
        }
    } catch {
        check(false, "3-word phrase threw \(error), expected VaultError.InvalidMnemonic")
    }

    // Assert 37: open_vault_with_recovery vault_002 phrase against vault_001 folder → WrongMnemonicOrCorrupt.
    do {
        let folderPath = Data(env.vault001Url.path.utf8)
        _ = try openVaultWithRecovery(folderPath: folderPath, mnemonic: env.phrase002)
        check(false, "vault_002 phrase against vault_001 folder should have thrown VaultError.WrongMnemonicOrCorrupt")
    } catch VaultError.WrongMnemonicOrCorrupt {
        check(true, "open_vault_with_recovery wrong-vault phrase → VaultError.WrongMnemonicOrCorrupt")
    } catch {
        check(false, "wrong-vault phrase threw \(error), expected VaultError.WrongMnemonicOrCorrupt")
    }

    // =============================================================================
    // create_vault_in_folder — write a complete vault on disk, then open it.
    // =============================================================================

    // Assert 38: create_vault_in_folder writes a complete, openable vault
    // (24-word recovery phrase + folder-password open succeeds → browsable).
    do {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("create-folder-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }

        let folderPath = Data(tmp.path.utf8)
        let pw = Data("create-smoke-pw".utf8)
        // createVaultInFolder returns CreatedVaultInFolder holding the one-shot
        // MnemonicOutput handle — take the phrase from the inner handle and wipe it.
        // (This block had rotted against the pre-Slice-5 MnemonicOutput-returning
        // shape; the smoke runner is not a CI gate, so it only surfaced when re-run
        // for #307.)
        let created = try createVaultInFolder(
            folderPath: folderPath,
            password: pw,
            displayName: "Swift-Create-Bob",
            createdAtMs: 1_700_000_000_000
        )
        defer { created.mnemonic.wipe() }
        let wordCount = created.mnemonic.takePhrase().map {
            String(decoding: $0, as: UTF8.self).split(separator: " ").count
        } ?? 0

        let opened = try openVaultWithPassword(folderPath: folderPath, password: pw)
        defer { opened.identity.wipe() }
        defer { opened.manifest.wipe() }
        check(
            wordCount == 24 && opened.identity.displayName() == "Swift-Create-Bob",
            "create_vault_in_folder → 24-word phrase + openable vault (words=\(wordCount), displayName=\"\(opened.identity.displayName())\")"
        )
    } catch {
        check(false, "create_vault_in_folder smoke threw \(error), expected success")
    }

    // Assert 39: create_vault_in_folder on a non-empty folder → VaultError.VaultFolderNotEmpty.
    do {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("create-nonempty-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }
        try Data("x".utf8).write(to: tmp.appendingPathComponent("junk"))

        _ = try createVaultInFolder(
            folderPath: Data(tmp.path.utf8),
            password: Data("pw".utf8),
            displayName: "X",
            createdAtMs: 1_700_000_000_000
        )
        check(false, "non-empty folder should have thrown VaultError.VaultFolderNotEmpty")
    } catch VaultError.VaultFolderNotEmpty {
        check(true, "create_vault_in_folder non-empty → VaultError.VaultFolderNotEmpty")
    } catch {
        check(false, "non-empty folder threw \(error), expected VaultError.VaultFolderNotEmpty")
    }
}
