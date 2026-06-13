// Shared helpers + assertion infrastructure for the Kotlin smoke runner.
//
// Split out of Main.kt per issue #72 to keep each smoke file under the
// project's 500-LOC guideline. Mirrors the Swift smoke runner's
// SmokeHelpers.swift. Owns:
//
//   - file-level mutable state (`failures`, `assertsRun`)
//   - the `check(Boolean, String)` assertion primitive
//   - shared constants (KAT values, truncation distance, expected display
//     name + user UUID, pinned UUIDs, BIP-39 phrase shape regex)
//   - `loadSmokeEnv()` — single entry point that reads SECRETARY_GOLDEN_VAULT_DIR,
//     loads golden_vault_001 / golden_vault_002 fixtures, extracts the
//     recovery mnemonic phrases, and returns a `SmokeEnv` data class
//     passed to every group function
//   - shared filesystem helpers (`recursiveCopy`, `cleanupTempVault`,
//     `freshWritableVault`, `aliceCardBytes`)
//
// Top-level `var` is file-level state — but because all Smoke*.kt files
// compile into the same jar without package separation, the file-private
// implicit default (no modifier = public) makes the state visible to
// every assertion file.

import uniffi.secretary.OpenVaultOutput
import uniffi.secretary.openVaultWithPassword
import kotlin.system.exitProcess

// =============================================================================
// Pinned KAT constants
// =============================================================================

// Vault format version pinned to the value in core/src/version.rs. A
// FORMAT_VERSION bump is a normative protocol break and must update
// this constant in lockstep with the spec — that keeps the smoke test
// honest as a cross-language contract assertion rather than a tautology.
const val EXPECTED_FORMAT_VERSION: UShort = 1u

// Truncation distance for assertion 7 (truncated TOML → CorruptVault).
// Matches secretary-ffi-py/tests/test_smoke.py::_TRUNCATION_SUFFIX_BYTES
// and the Swift smoke runner; keeping all three pinned to the same value
// makes the cross-language "what counts as corrupt" surface uniform.
//
// Why robust under v1: vault.toml is plain TOML and contains no AEAD-
// framed payloads (those live in identity.bundle.enc), so any truncation
// must fail at TOML parse / required-field-present checks long before
// the AEAD step that produces WrongPasswordOrCorrupt. If a future format
// places AEAD content in vault.toml, re-validate across all four sites
// (bridge, pytest, Swift, Kotlin).
const val TRUNCATION_SUFFIX_BYTES: Int = 50

// Robustness check for `phraseFromInputs` (see its docstring): exactly 24
// lowercase-ASCII words separated by single spaces — the documented shape
// for a BIP-39 24-word English phrase. Catches the edge case where the
// substring tokenizer ever latches onto an unintended location in the
// fixture JSON.
val BIP39_PHRASE_SHAPE: Regex = Regex("^[a-z]+( [a-z]+){23}$")

// Pinned KAT — must match secretary-ffi-bridge's tests + pytest +
// Swift smoke runner. Source of truth: golden_vault_001_inputs.json.
const val EXPECTED_DISPLAY_NAME = "Owner"

val EXPECTED_USER_UUID: ByteArray = byteArrayOf(
    0xbf.toByte(), 0x08, 0xa3.toByte(), 0x30, 0x0c, 0xd9.toByte(), 0x94.toByte(), 0xb8.toByte(),
    0x77, 0xe1.toByte(), 0xa1.toByte(), 0x5b, 0xaa.toByte(), 0x28, 0xdf.toByte(), 0x35,
)

// Pinned block UUID for the single block in golden_vault_001 — written
// at fixture-build time by core/tests/common/fixture_builder.rs and
// consumed by the read_block asserts.
val VAULT_001_BLOCK_UUID: ByteArray = byteArrayOf(
    0x11.toByte(), 0x22.toByte(), 0x33.toByte(), 0x44.toByte(),
    0x55.toByte(), 0x66.toByte(), 0x77.toByte(), 0x88.toByte(),
    0x99.toByte(), 0xaa.toByte(), 0xbb.toByte(), 0xcc.toByte(),
    0xdd.toByte(), 0xee.toByte(), 0xff.toByte(), 0x00.toByte(),
)

// Pinned UUIDs / device fingerprint for B.4c save_block + B.4d share_block.
// Distinct from the existing block in golden_vault_001 (11223344-...-ff00)
// so insert / update paths don't collide with the fixture's pre-built block.
val SAVE_BLOCK_NEW_BLOCK_UUID: ByteArray = ByteArray(16) { 0xAB.toByte() }
val SAVE_BLOCK_NEW_RECORD_UUID: ByteArray = ByteArray(16) { 0xCD.toByte() }
val SAVE_BLOCK_DEVICE_UUID: ByteArray = ByteArray(16) { 0x07.toByte() }

// share_block uses the same pinned block UUID as save_block — the share
// flow runs on a block produced by save_block in the same temp vault.
val SHARE_BLOCK_BLOCK_UUID: ByteArray = ByteArray(16) { 0xAB.toByte() }
val SHARE_BLOCK_RECORD_UUID: ByteArray = ByteArray(16) { 0xCD.toByte() }
val SHARE_BLOCK_DEVICE_UUID: ByteArray = ByteArray(16) { 0x07.toByte() }

// B.5 trash/restore uses a different block UUID to avoid collision with
// save/share flows when assertions run in sequence on the same vault.
val B5_BLOCK_UUID: ByteArray = ByteArray(16) { 0xBB.toByte() }
val B5_RECORD_UUID: ByteArray = ByteArray(16) { 0xCC.toByte() }
val B5_DEVICE_UUID: ByteArray = ByteArray(16) { 0x07.toByte() }

// Record-edit slice pinned UUIDs (mirror the Swift SmokeHelpers.swift
// recordEdit* constants). Each runRecordEditAsserts case seeds into a
// fresh temp copy of golden_vault_001, so these are isolated from the
// save/share/trash UUIDs above; kept distinct anyway for self-documentation.
val RECORD_EDIT_BLOCK_UUID = ByteArray(16) { 0xB1.toByte() }
val RECORD_EDIT_RECORD_UUID = ByteArray(16) { 0xC2.toByte() }
val RECORD_EDIT_DEVICE_UUID = ByteArray(16) { 0x07.toByte() }

// =============================================================================
// File-level mutable assertion state
// =============================================================================

// Collect failures rather than exit on first so a single run reports
// every contract that drifted, not just the first. The smoke surface
// is small now but grows in B.2+; aggregating from the start avoids
// the painful "fix one assertion, re-run, find another" loop.
val failures: MutableList<String> = mutableListOf()
var assertsRun: Int = 0

fun check(condition: Boolean, message: String) {
    assertsRun++
    if (condition) {
        println("PASS: $message")
    } else {
        System.err.println("FAIL: $message")
        failures.add(message)
    }
}

// =============================================================================
// Smoke environment
// =============================================================================

// Shared fixture state passed to every group function. Bundles the file-
// system paths to the two golden vaults plus the byte payloads + password
// bytes + recovery-mnemonic bytes pre-loaded once at startup. Threading
// this through each `runXxxAsserts(env)` call avoids re-reading the
// fixtures per assertion.
data class SmokeEnv(
    val vault001Path: java.nio.file.Path,
    val vault002Path: java.nio.file.Path,
    val toml001: ByteArray,
    val bundle001: ByteArray,
    val bundle002: ByteArray,
    val password001: ByteArray,
    val password002: ByteArray,
    val phrase001: ByteArray,
    val phrase002: ByteArray,
)

fun loadSmokeEnv(): SmokeEnv {
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
    val password002 = "correct horse battery staple two".toByteArray(Charsets.UTF_8)
    val phrase001 = phraseFromInputs(vaultDir, "golden_vault_001_inputs.json")
    val phrase002 = phraseFromInputs(vaultDir, "golden_vault_002_inputs.json")

    return SmokeEnv(
        vault001Path = vault001Path,
        vault002Path = vault002Path,
        toml001 = toml001,
        bundle001 = bundle001,
        bundle002 = bundle002,
        password001 = password001,
        password002 = password002,
        phrase001 = phrase001,
        phrase002 = phrase002,
    )
}

// =============================================================================
// Fixture-loading helpers
// =============================================================================

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
fun phraseFromInputs(vaultDir: String, name: String): ByteArray {
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

// Recursive copy of a directory tree into a fresh tempdir. Used by
// `freshWritableVault` and `aliceCardBytes` to stage a writable copy of
// golden_vault_001 / golden_vault_002 so the read-only fixtures stay
// untouched. Mirrors the bridge crate's `copy_dir_recursive` helper and
// the Swift smoke runner's `_recursiveCopy`.
fun recursiveCopy(src: java.nio.file.Path, dst: java.nio.file.Path) {
    java.nio.file.Files.walk(src).use { stream ->
        stream.forEach { from ->
            val rel = src.relativize(from)
            val to = dst.resolve(rel.toString())
            if (java.nio.file.Files.isDirectory(from)) {
                java.nio.file.Files.createDirectories(to)
            } else {
                java.nio.file.Files.copy(
                    from,
                    to,
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                )
            }
        }
    }
}

// Recursive delete; survive missing entries (e.g. test already removed
// something) so cleanup never masks a real assertion. Best-effort —
// a residual file in /tmp is harmless and the OS reaps it on reboot.
fun cleanupTempVault(tmp: java.nio.file.Path) {
    if (!java.nio.file.Files.exists(tmp)) return
    java.nio.file.Files.walk(tmp).use { stream ->
        stream.sorted(java.util.Comparator.reverseOrder()).forEach {
            try {
                java.nio.file.Files.deleteIfExists(it)
            } catch (_: java.io.IOException) {
                // best-effort
            }
        }
    }
}

// Open a fresh per-test copy of golden_vault_001 in a unique tempdir.
// Returns the OpenVaultOutput (carries identity + manifest) plus the
// tempdir Path the caller must `cleanupTempVault` on exit.
fun freshWritableVault(env: SmokeEnv): Pair<OpenVaultOutput, java.nio.file.Path> {
    val tmp = java.nio.file.Files.createTempDirectory("secretary_smoke_kotlin_")
    recursiveCopy(env.vault001Path, tmp)
    val folderPathBytes = tmp.toString().toByteArray(Charsets.UTF_8)
    val out = openVaultWithPassword(folderPathBytes, env.password001)
    return Pair(out, tmp)
}

// Extract vault_002's owner contact card bytes — used as "Alice" in
// share_block assertions. Stages vault_002 in a tempdir, opens it,
// reads `ownerCardBytes()`, and cleans up before returning.
fun aliceCardBytes(env: SmokeEnv): ByteArray {
    val tmp = java.nio.file.Files.createTempDirectory("secretary_smoke_kotlin_alice_")
    try {
        recursiveCopy(env.vault002Path, tmp)
        val folderPathBytes = tmp.toString().toByteArray(Charsets.UTF_8)
        val out = openVaultWithPassword(folderPathBytes, env.password002)
        out.identity.use {
            out.manifest.use { mf ->
                return mf.ownerCardBytes()
                    ?: throw AssertionError("vault_002 owner_card_bytes returned null")
            }
        }
    } finally {
        cleanupTempVault(tmp)
    }
}
