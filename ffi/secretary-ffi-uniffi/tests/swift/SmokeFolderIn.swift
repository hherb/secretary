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
}
