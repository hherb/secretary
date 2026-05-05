// JVM-host Kotlin smoke runner for the uniffi binding pipeline.
//
// Verifies the round-trip surface defined in src/secretary.udl by
// calling the generated Kotlin wrappers (which dispatch to the cdylib
// `libsecretary_ffi_uniffi.dylib` via JNA + the C ABI). Mirrors the
// Rust unit tests in src/lib.rs and the Swift smoke runner in
// tests/swift/main.swift, so a contract change in any one language
// fails in all three places.
//
// Invocation: ffi/secretary-ffi-uniffi/tests/kotlin/run.sh

import uniffi.secretary.add
import uniffi.secretary.openWithPassword
import uniffi.secretary.openWithRecovery
import uniffi.secretary.UnlockException
import uniffi.secretary.version
import kotlin.system.exitProcess

// Vault format version pinned to the value in core/src/version.rs. A
// FORMAT_VERSION bump is a normative protocol break and must update
// this constant in lockstep with the spec — that keeps the smoke test
// honest as a cross-language contract assertion rather than a tautology.
private const val EXPECTED_FORMAT_VERSION: UShort = 1u

// Truncation distance for assertion 7 (truncated TOML → CorruptVault).
// Matches secretary-ffi-py/tests/test_smoke.py::_TRUNCATION_SUFFIX_BYTES
// and the Swift smoke runner; keeping all three pinned to the same
// value makes the cross-language "what counts as corrupt" surface uniform.
//
// Why robust under v1: vault.toml is plain TOML and contains no AEAD-
// framed payloads (those live in identity.bundle.enc), so any
// truncation must fail at TOML parse / required-field-present checks
// long before the AEAD step that produces WrongPasswordOrCorrupt. If
// a future format places AEAD content in vault.toml, re-validate
// across all four sites (bridge, pytest, Swift, Kotlin).
private const val TRUNCATION_SUFFIX_BYTES: Int = 50

// Collect failures rather than exit on first so a single run reports
// every contract that drifted, not just the first. The smoke surface
// is small now but grows in B.2+; aggregating from the start avoids
// the painful "fix one assertion, re-run, find another" loop.
private val failures: MutableList<String> = mutableListOf()

private fun check(condition: Boolean, message: String) {
    if (condition) {
        println("PASS: $message")
    } else {
        System.err.println("FAIL: $message")
        failures.add(message)
    }
}

fun main() {
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
    //
    // Fixture path comes from run.sh via SECRETARY_GOLDEN_VAULT_DIR so the
    // same on-disk vaults are exercised by the bridge crate's tests, the
    // pytest suite, and both uniffi smoke runners. Hard-coding here would
    // silently drift the moment the fixture set moves.
    val vaultDir = System.getenv("SECRETARY_GOLDEN_VAULT_DIR") ?: run {
        System.err.println(
            "error: SECRETARY_GOLDEN_VAULT_DIR not set; run via tests/kotlin/run.sh",
        )
        exitProcess(1)
    }

    val vault001Path = java.nio.file.Paths.get(vaultDir, "golden_vault_001")
    val vault002Path = java.nio.file.Paths.get(vaultDir, "golden_vault_002")

    // Wrap fixture reads in a try/catch — without it, a missing or
    // unreadable golden_vault file produces an unhandled JVM stack
    // trace; with it, we exit cleanly with the same shape Swift uses
    // ("error: failed to read golden vault fixtures: ...").
    val (toml001, bundle001, bundle002) = try {
        Triple(
            java.nio.file.Files.readAllBytes(vault001Path.resolve("vault.toml")),
            java.nio.file.Files.readAllBytes(vault001Path.resolve("identity.bundle.enc")),
            java.nio.file.Files.readAllBytes(vault002Path.resolve("identity.bundle.enc")),
        )
    } catch (e: java.io.IOException) {
        System.err.println("error: failed to read golden vault fixtures: $e")
        exitProcess(1)
    }
    val password001 = "correct horse battery staple".toByteArray(Charsets.UTF_8)

    // B.3a: extract recovery_mnemonic_phrase from golden_vault_NNN_inputs.json.
    //
    // DO NOT USE THIS PARSER FOR ANY OTHER JSON. It is a purpose-built
    // single-field reader for one specific field in one specific
    // project-controlled fixture file. It does NOT handle JSON escapes
    // (\", \\, \n, \uXXXX); the value's shape is constrained by BIP-39
    // to lowercase ASCII letters + single spaces, so escapes cannot occur.
    //
    // No JSON library is pulled in because:
    //   1. org.json (the only JSON parser bundled with Android, sometimes
    //      mistakenly assumed to be in OpenJDK) ships under the "JSON
    //      License" with the "Good not Evil" field-of-use restriction —
    //      INCOMPATIBLE with this project's AGPL-3.0-or-later licensing.
    //   2. Apache-2.0-licensed alternatives (Gson, Jackson, kotlinx
    //      .serialization) would each add a network-fetched + SHA-256-
    //      verified dep to run.sh — disproportionate infrastructure for
    //      reading one string field from one project-controlled file.
    //
    // Threat model: malformed JSON cannot compromise security here.
    // The fixture is project-controlled; the smoke runner is developer-
    // only (never shipped); the value flows only into BIP-39 validation
    // (wordlist + checksum) and AEAD decryption — both reject any
    // garbage input loudly. core/tests/common/fixture_builder.rs
    // additionally cross-checks `bip39::Mnemonic::from_entropy(entropy)
    // .to_string() == phrase` at fixture-build time, so phrase tampering
    // in the JSON cannot land silently.
    fun phraseFromInputs(name: String): ByteArray {
        val inputsPath = java.nio.file.Paths.get(vaultDir, name)
        val text = try {
            java.nio.file.Files.readString(inputsPath)
        } catch (e: Throwable) {
            System.err.println("error: failed to read $inputsPath: $e")
            exitProcess(1)
        }
        // Find `"recovery_mnemonic_phrase"`, then the next two `"`
        // characters mark the value's quoted-string boundaries.
        val keyMarker = "\"recovery_mnemonic_phrase\""
        val keyAt = text.indexOf(keyMarker)
        val openQuote = if (keyAt >= 0) text.indexOf('"', keyAt + keyMarker.length + 1) else -1
        val closeQuote = if (openQuote >= 0) text.indexOf('"', openQuote + 1) else -1
        if (closeQuote < 0) {
            System.err.println(
                "error: recovery_mnemonic_phrase missing or malformed in $inputsPath",
            )
            exitProcess(1)
        }
        return text.substring(openQuote + 1, closeQuote).toByteArray(Charsets.UTF_8)
    }

    val phrase001 = phraseFromInputs("golden_vault_001_inputs.json")
    val phrase002 = phraseFromInputs("golden_vault_002_inputs.json")

    // Pinned KAT — must match secretary-ffi-bridge's tests + pytest +
    // Swift smoke runner. Source of truth: golden_vault_001_inputs.json.
    val expectedDisplayName = "Owner"
    val expectedUserUuid = byteArrayOf(
        0xbf.toByte(), 0x08, 0xa3.toByte(), 0x30, 0x0c, 0xd9.toByte(), 0x94.toByte(), 0xb8.toByte(),
        0x77, 0xe1.toByte(), 0xa1.toByte(), 0x5b, 0xaa.toByte(), 0x28, 0xdf.toByte(), 0x35,
    )

    // Assertion 4: success path. .use { } exercises uniffi 0.31's
    // auto-generated AutoCloseable on UnlockedIdentity; the closure-exit
    // hook releases the refcount, drops the Rust handle, and zeroizes
    // the underlying SecretBox. No hand-rolled extension is required.
    try {
        openWithPassword(
            vaultTomlBytes = toml001,
            identityBundleBytes = bundle001,
            password = password001,
        ).use { identity ->
            val displayName = identity.displayName()
            val uuid = identity.userUuid()
            check(
                displayName == expectedDisplayName && uuid.contentEquals(expectedUserUuid),
                "open_with_password success → display_name + user_uuid match pinned KAT (got displayName=\"$displayName\")",
            )
        }
    } catch (e: Throwable) {
        check(false, "open_with_password success threw $e, expected to succeed")
    }

    // Assertion 5: wrong password → WrongPasswordOrCorrupt.
    try {
        openWithPassword(
            vaultTomlBytes = toml001,
            identityBundleBytes = bundle001,
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
            vaultTomlBytes = toml001,
            identityBundleBytes = bundle002,
            password = password001,
        )
        check(false, "vault_001 toml + vault_002 bundle should have thrown VaultMismatch")
    } catch (e: UnlockException.VaultMismatch) {
        check(true, "vault_001 toml + vault_002 bundle → VaultMismatch")
    } catch (e: Throwable) {
        check(false, "vault mismatch threw $e, expected VaultMismatch")
    }

    // Assertion 7: truncated TOML → CorruptVault(detail). The truncation
    // suffix is the same distance the pytest suite uses
    // (_TRUNCATION_SUFFIX_BYTES); aligning it keeps the cross-language
    // "what counts as corrupt" surface uniform.
    try {
        val truncated = toml001.copyOfRange(0, toml001.size - TRUNCATION_SUFFIX_BYTES)
        openWithPassword(
            vaultTomlBytes = truncated,
            identityBundleBytes = bundle001,
            password = password001,
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
            vaultTomlBytes = toml001,
            identityBundleBytes = bundle001,
            password = password001,
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
            vaultTomlBytes = toml001,
            identityBundleBytes = bundle001,
            mnemonic = phrase001,
        ).use { identity ->
            val displayName = identity.displayName()
            val uuid = identity.userUuid()
            check(
                displayName == expectedDisplayName && uuid.contentEquals(expectedUserUuid),
                "open_with_recovery success → display_name + user_uuid match pinned KAT (got displayName=\"$displayName\")",
            )
        }
    } catch (e: Throwable) {
        check(false, "open_with_recovery success threw $e, expected to succeed")
    }

    // Assertion 10: wrong recovery phrase → WrongMnemonicOrCorrupt.
    try {
        openWithRecovery(
            vaultTomlBytes = toml001,
            identityBundleBytes = bundle001,
            mnemonic = phrase002,
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
            vaultTomlBytes = toml001,
            identityBundleBytes = bundle001,
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
            vaultTomlBytes = toml001,
            identityBundleBytes = bundle002,
            mnemonic = phrase001,
        )
        check(false, "vault_001 toml + vault_002 bundle (recovery) should have thrown VaultMismatch")
    } catch (e: UnlockException.VaultMismatch) {
        check(true, "vault_001 toml + vault_002 bundle (recovery) → VaultMismatch")
    } catch (e: Throwable) {
        check(false, "vault mismatch (recovery) threw $e, expected VaultMismatch")
    }

    if (failures.isNotEmpty()) {
        System.err.println("FAIL: ${failures.size} of 12 assertion(s) failed")
        exitProcess(1)
    }

    println("OK: secretary uniffi Kotlin smoke runner — all assertions passed.")
}
