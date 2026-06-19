// Bytes-in open assertions for the Kotlin smoke runner.
//
// Covers:
//   - B.0 round-trip: add(), version()
//   - B.2: open_with_password (success + 3 error paths + explicit wipe)
//   - B.3a: open_with_recovery (success + 3 error paths)
//   - B.3b: create_vault (shape + 2 round-trip paths)
//
// All assertions feed the bytes-in surface — vault.toml + identity bundle
// bytes passed directly into the bridge. The folder-in counterpart lives
// in SmokeFolderIn.kt.

import uniffi.secretary.UnlockException
import uniffi.secretary.add
import uniffi.secretary.createVault
import uniffi.secretary.openWithPassword
import uniffi.secretary.openWithRecovery
import uniffi.secretary.version

fun runBytesInAsserts(env: SmokeEnv) {
    // --- B.0: round-trip ---

    val sumSmall = add(2u, 3u)
    check(sumSmall == 5u, "add(2, 3) == 5 (got $sumSmall)")

    val sumWrap = add(UInt.MAX_VALUE, 1u)
    check(sumWrap == 0u, "add(UInt.MAX_VALUE, 1) wraps to 0 (got $sumWrap)")

    val v = version()
    check(
        v == EXPECTED_FORMAT_VERSION,
        "version() == $EXPECTED_FORMAT_VERSION (got $v)",
    )

    // --- B.2: open_with_password assertions ---

    // Assertion 4: success path. .use { } exercises uniffi 0.31's
    // auto-generated AutoCloseable on UnlockedIdentity; the closure-exit
    // hook releases the refcount, drops the Rust handle, and zeroizes
    // the underlying SecretBox. No hand-rolled extension is required.
    try {
        openWithPassword(
            vaultTomlBytes = env.toml001,
            identityBundleBytes = env.bundle001,
            password = env.password001,
        ).use { identity ->
            val displayName = identity.displayName()
            val uuid = identity.userUuid()
            check(
                displayName == EXPECTED_DISPLAY_NAME && uuid.contentEquals(EXPECTED_USER_UUID),
                "open_with_password success → display_name + user_uuid match pinned KAT (got displayName=\"$displayName\")",
            )
        }
    } catch (e: Throwable) {
        check(false, "open_with_password success threw $e, expected to succeed")
    }

    // Assertion 5: wrong password → WrongPasswordOrCorrupt.
    try {
        openWithPassword(
            vaultTomlBytes = env.toml001,
            identityBundleBytes = env.bundle001,
            password = "definitely wrong".toByteArray(Charsets.UTF_8),
        )
        check(false, "wrong password should have thrown WrongPasswordOrCorrupt")
    } catch (e: UnlockException.WrongPasswordOrCorrupt) {
        check(true, "wrong password → WrongPasswordOrCorrupt")
    } catch (e: Throwable) {
        check(false, "wrong password threw $e, expected WrongPasswordOrCorrupt")
    }

    // Assertion 6: cross-vault file pair → VaultMismatch.
    try {
        openWithPassword(
            vaultTomlBytes = env.toml001,
            identityBundleBytes = env.bundle002,
            password = env.password001,
        )
        check(false, "vault_001 toml + vault_002 bundle should have thrown VaultMismatch")
    } catch (e: UnlockException.VaultMismatch) {
        check(true, "vault_001 toml + vault_002 bundle → VaultMismatch")
    } catch (e: Throwable) {
        check(false, "vault mismatch threw $e, expected VaultMismatch")
    }

    // Assertion 7: truncated TOML → CorruptVault(detail).
    try {
        val truncated = env.toml001.copyOfRange(0, env.toml001.size - TRUNCATION_SUFFIX_BYTES)
        openWithPassword(
            vaultTomlBytes = truncated,
            identityBundleBytes = env.bundle001,
            password = env.password001,
        )
        check(false, "truncated toml should have thrown CorruptVault")
    } catch (e: UnlockException.CorruptVault) {
        check(true, "truncated toml → CorruptVault(detail=\"${e.detail}\")")
    } catch (e: Throwable) {
        check(false, "truncated toml threw $e, expected CorruptVault")
    }

    // Assertion 8: explicit wipe() path (parity with Swift's
    // defer { wipe() }). The .use { } path above exercises uniffi's
    // auto-generated AutoCloseable.close(); this assertion exercises
    // the explicit wipe() entry point so both close paths are covered
    // on Kotlin. Verifies idempotency + use-after-wipe defaults.
    try {
        val identity = openWithPassword(
            vaultTomlBytes = env.toml001,
            identityBundleBytes = env.bundle001,
            password = env.password001,
        )
        identity.wipe()
        identity.wipe() // idempotent — must not throw
        val nameAfterWipe = identity.displayName()
        val uuidAfterWipe = identity.userUuid()
        check(
            nameAfterWipe == "" && uuidAfterWipe.contentEquals(ByteArray(16)),
            "explicit wipe() → use-after-wipe returns empty defaults (got displayName=\"$nameAfterWipe\", uuid.size=${uuidAfterWipe.size})",
        )
        // Release the AutoCloseable handle so the Rust-side refcount
        // decrements; the foreign caller is responsible for this once
        // .use { } isn't carrying it.
        identity.close()
    } catch (e: Throwable) {
        check(false, "explicit wipe() path threw $e, expected to succeed")
    }

    // --- B.3a: open_with_recovery assertions ---

    // Assertion 9: recovery success path.
    try {
        openWithRecovery(
            vaultTomlBytes = env.toml001,
            identityBundleBytes = env.bundle001,
            mnemonic = env.phrase001,
        ).use { identity ->
            val displayName = identity.displayName()
            val uuid = identity.userUuid()
            check(
                displayName == EXPECTED_DISPLAY_NAME && uuid.contentEquals(EXPECTED_USER_UUID),
                "open_with_recovery success → display_name + user_uuid match pinned KAT (got displayName=\"$displayName\")",
            )
        }
    } catch (e: Throwable) {
        check(false, "open_with_recovery success threw $e, expected to succeed")
    }

    // Assertion 10: wrong recovery phrase → WrongMnemonicOrCorrupt.
    try {
        openWithRecovery(
            vaultTomlBytes = env.toml001,
            identityBundleBytes = env.bundle001,
            mnemonic = env.phrase002,
        )
        check(false, "vault_002 phrase against vault_001 should have thrown WrongMnemonicOrCorrupt")
    } catch (e: UnlockException.WrongMnemonicOrCorrupt) {
        check(true, "vault_002 phrase against vault_001 → WrongMnemonicOrCorrupt")
    } catch (e: Throwable) {
        check(false, "wrong phrase threw $e, expected WrongMnemonicOrCorrupt")
    }

    // Assertion 11: 3-word phrase → InvalidMnemonic(detail).
    try {
        val bad = "only three words".toByteArray(Charsets.UTF_8)
        openWithRecovery(
            vaultTomlBytes = env.toml001,
            identityBundleBytes = env.bundle001,
            mnemonic = bad,
        )
        check(false, "3-word phrase should have thrown InvalidMnemonic")
    } catch (e: UnlockException.InvalidMnemonic) {
        check(
            e.detail.contains("got 3"),
            "3-word phrase → InvalidMnemonic(detail=\"${e.detail}\") should mention `got 3`",
        )
    } catch (e: Throwable) {
        check(false, "3-word phrase threw $e, expected InvalidMnemonic")
    }

    // Assertion 12: cross-vault file pair with recovery path → VaultMismatch.
    try {
        openWithRecovery(
            vaultTomlBytes = env.toml001,
            identityBundleBytes = env.bundle002,
            mnemonic = env.phrase001,
        )
        check(false, "vault_001 toml + vault_002 bundle (recovery) should have thrown VaultMismatch")
    } catch (e: UnlockException.VaultMismatch) {
        check(true, "vault_001 toml + vault_002 bundle (recovery) → VaultMismatch")
    } catch (e: Throwable) {
        check(false, "vault mismatch (recovery) threw $e, expected VaultMismatch")
    }

    // --- B.3b: create_vault assertions ---

    // Assertion 13: create_vault produces a CreateVaultOutput with the
    // expected shape — non-empty bytes for both on-disk artifacts, the
    // identity is immediately live with the display_name we passed.
    try {
        val out = createVault(
            password = "smoke-runner-password".toByteArray(Charsets.UTF_8),
            displayName = "Owner",
            createdAtMs = 1_700_000_000_000UL,
        )
        out.mnemonic.use { /* immediately wipe */ }
        out.identity.use { id ->
            val displayName = id.displayName()
            val tomlNonEmpty = out.vaultTomlBytes.isNotEmpty()
            val bundleNonEmpty = out.identityBundleBytes.isNotEmpty()
            check(
                displayName == "Owner" && tomlNonEmpty && bundleNonEmpty,
                "create_vault shape: displayName=\"$displayName\" tomlBytes=${out.vaultTomlBytes.size} bundleBytes=${out.identityBundleBytes.size}",
            )
        }
    } catch (e: Throwable) {
        check(false, "create_vault threw $e, expected to succeed")
    }

    // Assertion 14: round-trip with password — the vault bytes produced by
    // create_vault re-open with the same password and yield the same
    // display_name. Pins the create→open agreement.
    try {
        val pw = "round-trip-password".toByteArray(Charsets.UTF_8)
        val out = createVault(
            password = pw,
            displayName = "RoundTripBob",
            createdAtMs = 1_700_000_000_000UL,
        )
        out.mnemonic.use { /* not used in this path */ }
        out.identity.use { _ ->
            openWithPassword(
                vaultTomlBytes = out.vaultTomlBytes,
                identityBundleBytes = out.identityBundleBytes,
                password = pw,
            ).use { reopened ->
                check(
                    reopened.displayName() == "RoundTripBob",
                    "create→open_with_password round-trip: got displayName=\"${reopened.displayName()}\"",
                )
            }
        }
    } catch (e: Throwable) {
        check(false, "round-trip with password threw $e, expected to succeed")
    }

    // Assertion 15: round-trip with recovery — take the phrase, re-open via
    // the recovery path. Pins create→take→open end-to-end.
    try {
        val out = createVault(
            password = "unused".toByteArray(Charsets.UTF_8),
            displayName = "RoundTripCarol",
            createdAtMs = 1_700_000_000_000UL,
        )
        out.identity.use { _ ->
            out.mnemonic.use { mn ->
                val phrase = mn.takePhrase()
                check(phrase != null, "take_phrase returned null on first call")
                if (phrase != null) {
                    // takePhrase() is `bytes?` → a ByteArray? directly (#261); no boxed-list conversion.
                    openWithRecovery(
                        vaultTomlBytes = out.vaultTomlBytes,
                        identityBundleBytes = out.identityBundleBytes,
                        mnemonic = phrase,
                    ).use { reopened ->
                        check(
                            reopened.displayName() == "RoundTripCarol",
                            "create→take_phrase→open_with_recovery: got displayName=\"${reopened.displayName()}\"",
                        )
                    }
                }
            }
        }
    } catch (e: Throwable) {
        check(false, "round-trip with recovery threw $e, expected to succeed")
    }
}
