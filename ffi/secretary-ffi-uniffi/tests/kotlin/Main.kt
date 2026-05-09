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
import uniffi.secretary.BlockInput
import uniffi.secretary.createVault
import uniffi.secretary.FieldInput
import uniffi.secretary.FieldInputValue
import uniffi.secretary.openVaultWithPassword
import uniffi.secretary.openVaultWithRecovery
import uniffi.secretary.openWithPassword
import uniffi.secretary.openWithRecovery
import uniffi.secretary.readBlock
import uniffi.secretary.RecordInput
import uniffi.secretary.saveBlock
import uniffi.secretary.UnlockException
import uniffi.secretary.VaultException
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

// Robustness check for `phraseFromInputs` (see its docstring): exactly 24
// lowercase-ASCII words separated by single spaces — the documented shape
// for a BIP-39 24-word English phrase. Catches the edge case where the
// substring tokenizer ever latches onto an unintended location in the
// fixture JSON.
private val BIP39_PHRASE_SHAPE: Regex = Regex("^[a-z]+( [a-z]+){23}$")

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
    //
    // Robustness assertion: the post-extract `BIP39_PHRASE_SHAPE` regex
    // catches the case where the literal `"recovery_mnemonic_phrase"`
    // ever appears elsewhere in the JSON (e.g. as a value inside some
    // future doc-comment field) and the substring search latches onto
    // the wrong location — any non-phrase value fails the
    // 24-lowercase-words shape and exits loudly instead of feeding
    // garbage downstream.
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
        val value = text.substring(openQuote + 1, closeQuote)
        if (!BIP39_PHRASE_SHAPE.matches(value)) {
            System.err.println(
                "error: recovery_mnemonic_phrase in $inputsPath does not match 24-lowercase-word shape",
            )
            exitProcess(1)
        }
        return value.toByteArray(Charsets.UTF_8)
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
                    // takePhrase() returns List<UByte>? per uniffi 0.31's
                    // mapping of `sequence<u8>?`; convert to ByteArray for
                    // the `bytes` parameter on openWithRecovery.
                    val phraseBytes = ByteArray(phrase.size) { phrase[it].toByte() }
                    openWithRecovery(
                        vaultTomlBytes = out.vaultTomlBytes,
                        identityBundleBytes = out.identityBundleBytes,
                        mnemonic = phraseBytes,
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

    // =============================================================================
    // B.4a — folder-in open_vault asserts
    // =============================================================================

    val goldenVault001Folder = "$vaultDir/golden_vault_001"

    // Assertion 16: open_vault_with_password success — identity + manifest both populated.
    try {
        val folderPath = goldenVault001Folder.toByteArray(Charsets.UTF_8)
        val out = openVaultWithPassword(folderPath, password001)
        val identity = out.identity
        val manifest = out.manifest
        val displayName = identity.displayName()
        val blockCount = manifest.blockCount()
        check(
            displayName == expectedDisplayName && blockCount > 0UL,
            "open_vault_with_password success → displayName=\"$displayName\", blockCount=$blockCount",
        )
        identity.wipe()
        manifest.wipe()
        identity.close()
        manifest.close()
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
        openVaultWithPassword(folderPath, password001)
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
    // B.4b — read_block asserts
    // =============================================================================

    val vault001BlockUuid = byteArrayOf(
        0x11.toByte(), 0x22.toByte(), 0x33.toByte(), 0x44.toByte(),
        0x55.toByte(), 0x66.toByte(), 0x77.toByte(), 0x88.toByte(),
        0x99.toByte(), 0xaa.toByte(), 0xbb.toByte(), 0xcc.toByte(),
        0xdd.toByte(), 0xee.toByte(), 0xff.toByte(), 0x00.toByte(),
    )

    // Assert 19: read_block success → record_count == 1 + field_count == 2.
    try {
        val folderPathBytes = vault001Path.toString().toByteArray(Charsets.UTF_8)
        val out = openVaultWithPassword(folderPathBytes, password001)
        out.identity.use { id ->
            out.manifest.use { mf ->
                readBlock(id, mf, vault001BlockUuid).use { block ->
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
        val folderPathBytes = vault001Path.toString().toByteArray(Charsets.UTF_8)
        val out = openVaultWithPassword(folderPathBytes, password001)
        out.identity.use { id ->
            out.manifest.use { mf ->
                readBlock(id, mf, vault001BlockUuid).use { block ->
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
        val folderPathBytes = vault001Path.toString().toByteArray(Charsets.UTF_8)
        val out = openVaultWithPassword(folderPathBytes, password001)
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
        val folderPathBytes = vault001Path.toString().toByteArray(Charsets.UTF_8)
        val out = openVaultWithPassword(folderPathBytes, password001)
        out.identity.use { id ->
            out.manifest.use { mf ->
                readBlock(id, mf, vault001BlockUuid).use { block ->
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

    // =============================================================================
    // B.4c — save_block asserts
    // =============================================================================
    //
    // save_block mutates the on-disk vault — assertions copy
    // golden_vault_001 into a per-test tempdir so the read-only fixture is
    // never touched. Mirrors the bridge crate's `fresh_writable_vault`
    // helper and the Swift smoke runner's `_freshWritableVault`.

    fun freshWritableVault(): Pair<uniffi.secretary.OpenVaultOutput, java.nio.file.Path> {
        val tmp = java.nio.file.Files.createTempDirectory("secretary_b4c_kotlin_")
        java.nio.file.Files.walk(vault001Path).use { stream ->
            stream.forEach { src ->
                val rel = vault001Path.relativize(src)
                val dst = tmp.resolve(rel.toString())
                if (java.nio.file.Files.isDirectory(src)) {
                    java.nio.file.Files.createDirectories(dst)
                } else {
                    java.nio.file.Files.copy(
                        src,
                        dst,
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                    )
                }
            }
        }
        val folderPathBytes = tmp.toString().toByteArray(Charsets.UTF_8)
        val out = openVaultWithPassword(folderPathBytes, password001)
        return Pair(out, tmp)
    }

    fun cleanupTempVault(tmp: java.nio.file.Path) {
        // Recursive delete; survive missing entries (e.g. test already
        // removed something) so cleanup never masks a real assertion.
        if (!java.nio.file.Files.exists(tmp)) return
        java.nio.file.Files.walk(tmp).use { stream ->
            stream.sorted(java.util.Comparator.reverseOrder()).forEach {
                try {
                    java.nio.file.Files.deleteIfExists(it)
                } catch (_: java.io.IOException) {
                    // Cleanup is best-effort; a residual file in /tmp is
                    // harmless and the OS reaps it on reboot.
                }
            }
        }
    }

    // Pinned UUIDs / timestamps — distinct from the existing block in
    // golden_vault_001 (which is 11223344-...-ff00).
    val saveBlockNewBlockUuid = ByteArray(16) { 0xAB.toByte() }
    val saveBlockNewRecordUuid = ByteArray(16) { 0xCD.toByte() }
    val saveBlockDeviceUuid = ByteArray(16) { 0x07.toByte() }

    // Assert 24: save_block insert → read_block round-trip succeeds with
    // matching record / field counts and exposed text + bytes payloads.
    var saveTmp: java.nio.file.Path? = null
    try {
        val (out, tmp) = freshWritableVault()
        saveTmp = tmp
        out.identity.use { id ->
            out.manifest.use { mf ->
                val input = BlockInput(
                    blockUuid = saveBlockNewBlockUuid,
                    blockName = "Notes",
                    records = listOf(
                        RecordInput(
                            recordUuid = saveBlockNewRecordUuid,
                            fields = listOf(
                                FieldInput("title", FieldInputValue.Text("wifi password")),
                                FieldInput(
                                    "key",
                                    FieldInputValue.Bytes(
                                        byteArrayOf(
                                            0xDE.toByte(), 0xAD.toByte(),
                                            0xBE.toByte(), 0xEF.toByte(),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                )
                saveBlock(id, mf, input, saveBlockDeviceUuid, 1_000UL)
                readBlock(id, mf, saveBlockNewBlockUuid).use { block ->
                    val recordCount = block.recordCount()
                    val record = block.recordAt(0u)
                    val title = record?.fieldByName("title")?.exposeText()
                    val key = record?.fieldByName("key")?.exposeBytes()
                    check(
                        recordCount == 1uL
                            && title == "wifi password"
                            && key?.contentEquals(
                                byteArrayOf(
                                    0xDE.toByte(), 0xAD.toByte(),
                                    0xBE.toByte(), 0xEF.toByte(),
                                ),
                            ) == true,
                        "save_block insert → read_block round-trip (recordCount=$recordCount, title=$title)",
                    )
                }
            }
        }
    } catch (e: Throwable) {
        check(false, "save_block insert round-trip threw $e, expected to succeed")
    } finally {
        saveTmp?.let { cleanupTempVault(it) }
    }

    // Assert 25: save_block update — same block_uuid replaces the existing
    // entry; block_name advances on the second save.
    saveTmp = null
    try {
        val (out, tmp) = freshWritableVault()
        saveTmp = tmp
        out.identity.use { id ->
            out.manifest.use { mf ->
                saveBlock(
                    id,
                    mf,
                    BlockInput(saveBlockNewBlockUuid, "v1", emptyList()),
                    saveBlockDeviceUuid,
                    1_000UL,
                )
                saveBlock(
                    id,
                    mf,
                    BlockInput(saveBlockNewBlockUuid, "v2", emptyList()),
                    saveBlockDeviceUuid,
                    2_000UL,
                )
                val summary = mf.findBlock(saveBlockNewBlockUuid)
                check(
                    summary?.blockName == "v2" && mf.blockCount() > 0uL,
                    "save_block update → blockName advanced (got ${summary?.blockName})",
                )
            }
        }
    } catch (e: Throwable) {
        check(false, "save_block update threw $e, expected to succeed")
    } finally {
        saveTmp?.let { cleanupTempVault(it) }
    }

    // Assert 26: save_block on a wiped manifest → VaultException.CorruptVault
    // with `manifest` in the detail.
    saveTmp = null
    try {
        val (out, tmp) = freshWritableVault()
        saveTmp = tmp
        out.identity.use { id ->
            // wipe the manifest BEFORE attempting the save so the bridge's
            // wipe-detection path fires.
            out.manifest.wipe()
            try {
                saveBlock(
                    id,
                    out.manifest,
                    BlockInput(saveBlockNewBlockUuid, "x", emptyList()),
                    saveBlockDeviceUuid,
                    1_000UL,
                )
                check(false, "save_block on wiped manifest should have thrown VaultException.CorruptVault")
            } catch (e: VaultException.CorruptVault) {
                check(
                    e.detail.contains("manifest"),
                    "save_block on wiped manifest → CorruptVault(detail=\"${e.detail}\") names manifest",
                )
            } finally {
                out.manifest.close()
            }
        }
    } catch (e: Throwable) {
        check(false, "save_block wiped-manifest path threw setup $e")
    } finally {
        saveTmp?.let { cleanupTempVault(it) }
    }

    // Assert 27: save_block then drop handles, re-open, confirm the new
    // block is visible and readable.
    saveTmp = null
    try {
        val tmp = java.nio.file.Files.createTempDirectory("secretary_b4c_kotlin_persist_")
        saveTmp = tmp
        java.nio.file.Files.walk(vault001Path).use { stream ->
            stream.forEach { src ->
                val rel = vault001Path.relativize(src)
                val dst = tmp.resolve(rel.toString())
                if (java.nio.file.Files.isDirectory(src)) {
                    java.nio.file.Files.createDirectories(dst)
                } else {
                    java.nio.file.Files.copy(
                        src,
                        dst,
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                    )
                }
            }
        }
        val folderPathBytes = tmp.toString().toByteArray(Charsets.UTF_8)

        // Save in an inner scope so the handles release before re-open.
        run {
            val out = openVaultWithPassword(folderPathBytes, password001)
            out.identity.use { id ->
                out.manifest.use { mf ->
                    saveBlock(
                        id,
                        mf,
                        BlockInput(
                            saveBlockNewBlockUuid,
                            "persisted",
                            listOf(
                                RecordInput(
                                    saveBlockNewRecordUuid,
                                    listOf(FieldInput("k", FieldInputValue.Text("v"))),
                                ),
                            ),
                        ),
                        saveBlockDeviceUuid,
                        1_000UL,
                    )
                }
            }
        }

        val out2 = openVaultWithPassword(folderPathBytes, password001)
        out2.identity.use { id ->
            out2.manifest.use { mf ->
                val summary = mf.findBlock(saveBlockNewBlockUuid)
                readBlock(id, mf, saveBlockNewBlockUuid).use { block ->
                    val v = block.recordAt(0u)?.fieldByName("k")?.exposeText()
                    check(
                        summary?.blockName == "persisted" && v == "v",
                        "save_block persists → fresh open sees block (blockName=${summary?.blockName}, v=$v)",
                    )
                }
            }
        }
    } catch (e: Throwable) {
        check(false, "save_block persist-and-reopen threw $e, expected to succeed")
    } finally {
        saveTmp?.let { cleanupTempVault(it) }
    }

    if (failures.isNotEmpty()) {
        System.err.println("FAIL: ${failures.size} of 27 assertion(s) failed")
        exitProcess(1)
    }

    println("OK: secretary uniffi Kotlin smoke runner — all assertions passed.")
}
