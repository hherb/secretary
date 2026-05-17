// Bytes-in open assertions for the Swift smoke runner.
//
// Covers:
//   - B.0 round-trip: add(), version()
//   - B.2: open_with_password (success + 3 error paths + explicit wipe)
//   - B.3a: open_with_recovery (success + 3 error paths)
//   - B.3b: create_vault (shape + 2 round-trip paths)
//
// All assertions feed the bytes-in surface — vault.toml + identity bundle
// bytes passed directly into the bridge. The folder-in counterpart lives
// in SmokeFolderIn.swift.

import Foundation

func runBytesInAsserts(env: SmokeEnv) {
    // --- B.0: round-trip ---

    let sumSmall = add(a: 2, b: 3)
    check(sumSmall == 5, "add(2, 3) == 5 (got \(sumSmall))")

    let sumWrap = add(a: UInt32.max, b: 1)
    check(sumWrap == 0, "add(UInt32.max, 1) wraps to 0 (got \(sumWrap))")

    let v = version()
    check(
        v == EXPECTED_FORMAT_VERSION,
        "version() == \(EXPECTED_FORMAT_VERSION) (got \(v))"
    )

    // --- B.2: open_with_password assertions ---

    // Assertion 4: success path. defer { wipe() } exercises the explicit-
    // zeroize hook (`wipe`, not `close`, per uniffi 0.31 codegen — see the
    // generated UnlockedIdentity doc comment for the rename rationale).
    do {
        let identity = try openWithPassword(
            vaultTomlBytes: env.toml001,
            identityBundleBytes: env.bundle001,
            password: env.password001
        )
        defer { identity.wipe() }

        let displayName = identity.displayName()
        let uuid = identity.userUuid()
        check(
            displayName == expectedDisplayName && uuid == expectedUserUuid,
            "open_with_password success → display_name + user_uuid match pinned KAT (got displayName=\"\(displayName)\")"
        )
    } catch {
        check(false, "open_with_password success threw \(error), expected to succeed")
    }

    // Assertion 5: wrong password → WrongPasswordOrCorrupt.
    do {
        _ = try openWithPassword(
            vaultTomlBytes: env.toml001,
            identityBundleBytes: env.bundle001,
            password: "definitely wrong".data(using: .utf8)!
        )
        check(false, "wrong password should have thrown WrongPasswordOrCorrupt")
    } catch UnlockError.WrongPasswordOrCorrupt {
        check(true, "wrong password → WrongPasswordOrCorrupt")
    } catch {
        check(false, "wrong password threw \(error), expected WrongPasswordOrCorrupt")
    }

    // Assertion 6: cross-vault file pair → VaultMismatch.
    do {
        _ = try openWithPassword(
            vaultTomlBytes: env.toml001,
            identityBundleBytes: env.bundle002,
            password: env.password001
        )
        check(false, "vault_001 toml + vault_002 bundle should have thrown VaultMismatch")
    } catch UnlockError.VaultMismatch {
        check(true, "vault_001 toml + vault_002 bundle → VaultMismatch")
    } catch {
        check(false, "vault mismatch threw \(error), expected VaultMismatch")
    }

    // Assertion 7: truncated TOML → CorruptVault(detail). The truncation
    // suffix is the same distance the pytest suite uses
    // (_TRUNCATION_SUFFIX_BYTES); aligning it keeps the cross-language
    // "what counts as corrupt" surface uniform.
    do {
        let truncated = Data(env.toml001.dropLast(TRUNCATION_SUFFIX_BYTES))
        _ = try openWithPassword(
            vaultTomlBytes: truncated,
            identityBundleBytes: env.bundle001,
            password: env.password001
        )
        check(false, "truncated toml should have thrown CorruptVault")
    } catch let UnlockError.CorruptVault(detail) {
        check(true, "truncated toml → CorruptVault(detail=\"\(detail)\")")
    } catch {
        check(false, "truncated toml threw \(error), expected CorruptVault")
    }

    // Assertion 8: use-after-wipe defaults (parity with Kotlin's explicit
    // wipe() assertion). Assertion 4 above exercises wipe() via defer,
    // which fires at scope exit and leaves no opportunity to inspect
    // post-wipe state. This assertion calls wipe() in-line and verifies
    // the documented non-throwing defaults: empty displayName, 16 zero
    // bytes for userUuid, idempotent wipe.
    do {
        let identity = try openWithPassword(
            vaultTomlBytes: env.toml001,
            identityBundleBytes: env.bundle001,
            password: env.password001
        )
        identity.wipe()
        identity.wipe() // idempotent — must not throw
        let nameAfterWipe = identity.displayName()
        let uuidAfterWipe = identity.userUuid()
        check(
            nameAfterWipe == "" && uuidAfterWipe == Data(repeating: 0, count: 16),
            "explicit wipe() → use-after-wipe returns empty defaults (got displayName=\"\(nameAfterWipe)\", uuid.count=\(uuidAfterWipe.count))"
        )
    } catch {
        check(false, "explicit wipe() path threw \(error), expected to succeed")
    }

    // --- B.3a: open_with_recovery assertions ---

    // Assertion 9: recovery success path.
    do {
        let identity = try openWithRecovery(
            vaultTomlBytes: env.toml001,
            identityBundleBytes: env.bundle001,
            mnemonic: env.phrase001
        )
        defer { identity.wipe() }

        let displayName = identity.displayName()
        let uuid = identity.userUuid()
        check(
            displayName == expectedDisplayName && uuid == expectedUserUuid,
            "open_with_recovery success → display_name + user_uuid match pinned KAT (got displayName=\"\(displayName)\")"
        )
    } catch {
        check(false, "open_with_recovery success threw \(error), expected to succeed")
    }

    // Assertion 10: wrong recovery phrase → WrongMnemonicOrCorrupt.
    do {
        _ = try openWithRecovery(
            vaultTomlBytes: env.toml001,
            identityBundleBytes: env.bundle001,
            mnemonic: env.phrase002
        )
        check(false, "vault_002 phrase against vault_001 should have thrown WrongMnemonicOrCorrupt")
    } catch UnlockError.WrongMnemonicOrCorrupt {
        check(true, "vault_002 phrase against vault_001 → WrongMnemonicOrCorrupt")
    } catch {
        check(false, "wrong phrase threw \(error), expected WrongMnemonicOrCorrupt")
    }

    // Assertion 11: 3-word phrase → InvalidMnemonic(detail).
    do {
        let bad = "only three words".data(using: .utf8)!
        _ = try openWithRecovery(
            vaultTomlBytes: env.toml001,
            identityBundleBytes: env.bundle001,
            mnemonic: bad
        )
        check(false, "3-word phrase should have thrown InvalidMnemonic")
    } catch let UnlockError.InvalidMnemonic(detail) {
        check(
            detail.contains("got 3"),
            "3-word phrase → InvalidMnemonic(detail=\"\(detail)\") should mention `got 3`"
        )
    } catch {
        check(false, "3-word phrase threw \(error), expected InvalidMnemonic")
    }

    // Assertion 12: cross-vault file pair with recovery path → VaultMismatch.
    // Mnemonic correctness is irrelevant here; the vault_uuid + created_at_ms
    // comparison fires before any mnemonic parse.
    do {
        _ = try openWithRecovery(
            vaultTomlBytes: env.toml001,
            identityBundleBytes: env.bundle002,
            mnemonic: env.phrase001
        )
        check(false, "vault_001 toml + vault_002 bundle (recovery) should have thrown VaultMismatch")
    } catch UnlockError.VaultMismatch {
        check(true, "vault_001 toml + vault_002 bundle (recovery) → VaultMismatch")
    } catch {
        check(false, "vault mismatch (recovery) threw \(error), expected VaultMismatch")
    }

    // --- B.3b: create_vault assertions ---

    // Assertion 13: create_vault produces a CreateVaultOutput with the
    // expected shape — non-empty bytes for both on-disk artifacts, the
    // identity is immediately live with the display_name we passed.
    do {
        let out = try createVault(
            password: "smoke-runner-password".data(using: .utf8)!,
            displayName: "Owner",
            createdAtMs: 1_700_000_000_000
        )
        defer { out.identity.wipe() }
        defer { out.mnemonic.wipe() }
        let displayName = out.identity.displayName()
        let tomlNonEmpty = !out.vaultTomlBytes.isEmpty
        let bundleNonEmpty = !out.identityBundleBytes.isEmpty
        check(
            displayName == "Owner" && tomlNonEmpty && bundleNonEmpty,
            "create_vault shape: displayName=\"\(displayName)\" tomlBytes=\(out.vaultTomlBytes.count) bundleBytes=\(out.identityBundleBytes.count)"
        )
    } catch {
        check(false, "create_vault threw \(error), expected to succeed")
    }

    // Assertion 14: round-trip with password — the vault bytes produced by
    // create_vault re-open with the same password and yield the same
    // display_name. Pins the create→open agreement.
    do {
        let pw = "round-trip-password".data(using: .utf8)!
        let out = try createVault(
            password: pw,
            displayName: "RoundTripBob",
            createdAtMs: 1_700_000_000_000
        )
        defer { out.identity.wipe() }
        out.mnemonic.wipe()  // not used in this path
        let reopened = try openWithPassword(
            vaultTomlBytes: out.vaultTomlBytes,
            identityBundleBytes: out.identityBundleBytes,
            password: pw
        )
        defer { reopened.wipe() }
        check(
            reopened.displayName() == "RoundTripBob",
            "create→open_with_password round-trip: got displayName=\"\(reopened.displayName())\""
        )
    } catch {
        check(false, "round-trip with password threw \(error), expected to succeed")
    }

    // Assertion 15: round-trip with recovery — take the phrase, re-open via
    // the recovery path. Pins create→take→open end-to-end.
    do {
        let out = try createVault(
            password: "unused".data(using: .utf8)!,
            displayName: "RoundTripCarol",
            createdAtMs: 1_700_000_000_000
        )
        defer { out.identity.wipe() }
        defer { out.mnemonic.wipe() }
        if let phrase = out.mnemonic.takePhrase() {
            let reopened = try openWithRecovery(
                vaultTomlBytes: out.vaultTomlBytes,
                identityBundleBytes: out.identityBundleBytes,
                mnemonic: Data(phrase)
            )
            defer { reopened.wipe() }
            check(
                reopened.displayName() == "RoundTripCarol",
                "create→take_phrase→open_with_recovery: got displayName=\"\(reopened.displayName())\""
            )
        } else {
            check(false, "take_phrase returned nil on first call")
        }
    } catch {
        check(false, "round-trip with recovery threw \(error), expected to succeed")
    }
}
