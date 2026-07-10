// Input resolution + hex codec + filesystem + after-chain walkers.
//
// Pure helpers — no test state. Mirrors helpers in
// core/tests/conformance_kat_helpers/fixtures.rs (Rust) and
// ConformanceHelpers.swift.

import org.json.JSONArray
import org.json.JSONObject
import uniffi.secretary.OpenVaultOutput
import kotlin.system.exitProcess

// --- #307 zero-copy secret args ---

/// uniffi 0.32's `[ByRef] bytes` secret args cross the FFI as a borrow of a
/// DIRECT `java.nio.ByteBuffer` (ForeignBytes) instead of copying through a
/// RustBuffer. Mints a fresh direct buffer per call (duplicate of the
/// Smoke runner's helper — the two runners compile as separate jars).
internal fun ByteArray.direct(): java.nio.ByteBuffer {
    val buf = java.nio.ByteBuffer.allocateDirect(size)
    buf.put(this)
    buf.flip()
    return buf
}

// --- Input resolution helpers ---

internal fun resolveSource(source: String, goldenVaultDir: String): ByteArray {
    val colon = source.indexOf(':')
    if (colon < 0) {
        System.err.println("malformed source ref: $source")
        exitProcess(1)
    }
    val file = java.io.File(goldenVaultDir, source.substring(0, colon))
    val field = source.substring(colon + 1)
    val text = try {
        file.readText()
    } catch (e: Throwable) {
        System.err.println("failed to resolve $source: $e")
        exitProcess(1)
    }
    val obj = JSONObject(text)
    val value = obj.optString(field, null)
    if (value == null) {
        System.err.println("field '$field' not found in $file")
        exitProcess(1)
    }
    return value.toByteArray(Charsets.UTF_8)
}

internal fun resolveVaultDir(inputs: JSONObject, goldenVaultDir: String): ByteArray {
    if (inputs.has("vault_dir")) {
        val rel = inputs.getString("vault_dir")
        val resolved = java.io.File(goldenVaultDir, rel).absolutePath
        return resolved.toByteArray(Charsets.UTF_8)
    }
    if (inputs.has("vault_dir_literal")) {
        return inputs.getString("vault_dir_literal").toByteArray(Charsets.UTF_8)
    }
    System.err.println("vector inputs missing vault_dir / vault_dir_literal")
    exitProcess(1)
}

internal fun resolvePassword(inputs: JSONObject, goldenVaultDir: String): ByteArray {
    if (inputs.has("password_source")) return resolveSource(inputs.getString("password_source"), goldenVaultDir)
    if (inputs.has("password_literal_utf8")) return inputs.getString("password_literal_utf8").toByteArray(Charsets.UTF_8)
    System.err.println("vector inputs missing password_source / password_literal_utf8")
    exitProcess(1)
}

internal fun resolveMnemonic(inputs: JSONObject, goldenVaultDir: String): ByteArray {
    if (inputs.has("mnemonic_source")) return resolveSource(inputs.getString("mnemonic_source"), goldenVaultDir)
    if (inputs.has("mnemonic_literal_utf8")) return inputs.getString("mnemonic_literal_utf8").toByteArray(Charsets.UTF_8)
    System.err.println("vector inputs missing mnemonic_source / mnemonic_literal_utf8")
    exitProcess(1)
}

// Resolve a `*_source` ref to the DECODED bytes of the named JSON hex field.
// Distinct from resolveSource, which returns the field's UTF-8 bytes
// verbatim: device inputs are hex-encoded in the inputs file and must be
// hex-decoded. Mirrors resolve_source_hex in
// core/tests/conformance_kat_helpers/fixtures.rs.
internal fun resolveSourceHex(source: String, goldenVaultDir: String): ByteArray {
    val utf8 = resolveSource(source, goldenVaultDir)
    return decodeHex(String(utf8, Charsets.UTF_8).trim())
}

// Resolve a device-slot uuid input. Accepts either device_uuid_source (JSON
// hex field) or device_uuid_hex (inline hex). Returns the decoded bytes
// verbatim (no length check) — the dispatch arm length-checks and
// synthesizes the InvalidArgument outcome the type-bounded &[u8; 16] bridge
// signature produces. Mirrors resolve_device_uuid in
// core/tests/conformance_kat_helpers/fixtures.rs.
internal fun resolveDeviceUuid(inputs: JSONObject, goldenVaultDir: String): ByteArray {
    if (inputs.has("device_uuid_source")) return resolveSourceHex(inputs.getString("device_uuid_source"), goldenVaultDir)
    if (inputs.has("device_uuid_hex")) return decodeHex(inputs.getString("device_uuid_hex"))
    System.err.println("open_with_device_secret vector missing device_uuid_source / device_uuid_hex")
    exitProcess(1)
}

// Resolve a device-slot secret input. Accepts either device_secret_source
// (JSON hex field) or device_secret_hex (inline hex). Returns the decoded
// bytes verbatim (no length check) — see resolveDeviceUuid. Mirrors
// resolve_device_secret in core/tests/conformance_kat_helpers/fixtures.rs.
internal fun resolveDeviceSecret(inputs: JSONObject, goldenVaultDir: String): ByteArray {
    if (inputs.has("device_secret_source")) return resolveSourceHex(inputs.getString("device_secret_source"), goldenVaultDir)
    if (inputs.has("device_secret_hex")) return decodeHex(inputs.getString("device_secret_hex"))
    System.err.println("open_with_device_secret vector missing device_secret_source / device_secret_hex")
    exitProcess(1)
}

// --- Hex codec ---

// Decode a lower-case hex string to a ByteArray. Exits on malformed input.
internal fun decodeHex(s: String): ByteArray {
    if (s.length % 2 != 0) {
        System.err.println("malformed hex (odd length): $s")
        exitProcess(1)
    }
    return ByteArray(s.length / 2) { i ->
        s.substring(i * 2, i * 2 + 2).toInt(16).toByte()
    }
}

// Encode a ByteArray to a lower-case hex string.
internal fun encodeHex(bytes: ByteArray): String =
    bytes.joinToString("") { "%02x".format(it) }

// --- v2 filesystem helpers ---

internal fun recursiveCopy(src: java.nio.file.Path, dst: java.nio.file.Path) {
    java.nio.file.Files.walk(src).use { stream ->
        stream.forEach { entry ->
            val rel = src.relativize(entry)
            val target = dst.resolve(rel.toString())
            if (java.nio.file.Files.isDirectory(entry)) {
                java.nio.file.Files.createDirectories(target)
            } else {
                java.nio.file.Files.copy(entry, target, java.nio.file.StandardCopyOption.REPLACE_EXISTING)
            }
        }
    }
}

internal fun cleanupTempVault(tmp: java.nio.file.Path) {
    if (!java.nio.file.Files.exists(tmp)) return
    java.nio.file.Files.walk(tmp).use { stream ->
        stream.sorted(java.util.Comparator.reverseOrder()).forEach {
            try {
                java.nio.file.Files.deleteIfExists(it)
            } catch (_: java.io.IOException) { /* best-effort */ }
        }
    }
}

internal fun readContactCardBytes(vaultDir: java.nio.file.Path, userUuidHex: String): ByteArray {
    require(userUuidHex.length == 32) { "userUuidHex must be 32 chars" }
    val h = userUuidHex
    val hyphenated = "${h.substring(0, 8)}-${h.substring(8, 12)}-${h.substring(12, 16)}-${h.substring(16, 20)}-${h.substring(20, 32)}.card"
    val path = vaultDir.resolve("contacts").resolve(hyphenated)
    return java.nio.file.Files.readAllBytes(path)
}

// --- after-chain walkers ---

internal fun findWritableDir(
    start: String,
    writableVaultDirs: Map<String, java.nio.file.Path>,
    vectors: JSONArray,
): java.nio.file.Path? {
    var current = start
    // Bounded by vectors.length() — an authoring-error `after:` cycle would
    // otherwise hang. Fail loudly so the cycle is fixable, not silent.
    for (step in 0..vectors.length()) {
        writableVaultDirs[current]?.let { return it }
        var parentAfter: String? = null
        for (i in 0 until vectors.length()) {
            val v = vectors.getJSONObject(i)
            if (v.optString("name", null) == current) {
                parentAfter = if (v.has("after")) v.getString("after") else null
                break
            }
        }
        current = parentAfter ?: return null
    }
    error("after-chain cycle detected starting at '$start' (depth exceeded vectors.length())")
}

internal fun findCacheAncestorName(
    start: String,
    cache: Map<String, OpenVaultOutput>,
    vectors: JSONArray,
): String? {
    var current = start
    // Cycle guard: see findWritableDir.
    for (step in 0..vectors.length()) {
        if (cache.containsKey(current)) return current
        var parentAfter: String? = null
        for (i in 0 until vectors.length()) {
            val v = vectors.getJSONObject(i)
            if (v.optString("name", null) == current) {
                parentAfter = if (v.has("after")) v.getString("after") else null
                break
            }
        }
        current = parentAfter ?: return null
    }
    error("after-chain cycle detected starting at '$start' (depth exceeded vectors.length())")
}
