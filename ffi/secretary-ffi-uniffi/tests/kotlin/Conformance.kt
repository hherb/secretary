// JVM-host Kotlin conformance KAT replay (B.6 v1 + v2).
//
// Parallels the Rust replay in core/tests/conformance_kat.rs and the
// Swift replay in tests/swift/conformance.swift. Loads
// conformance_kat.json via SECRETARY_CONFORMANCE_KAT, dispatches each
// vector through the uniffi-generated Kotlin wrappers, asserts the
// observable output matches the pinned expectation. One PASS/FAIL line
// per vector + a final summary.
//
// Invocation: ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh

import org.json.JSONArray
import org.json.JSONObject
import uniffi.secretary.BlockInput
import uniffi.secretary.FieldInput
import uniffi.secretary.FieldInputValue
import uniffi.secretary.OpenVaultManifest
import uniffi.secretary.OpenVaultOutput
import uniffi.secretary.RecordInput
import uniffi.secretary.UnlockedIdentity
import uniffi.secretary.VaultException
import uniffi.secretary.openVaultWithPassword
import uniffi.secretary.openVaultWithRecovery
import uniffi.secretary.readBlock
import uniffi.secretary.restoreBlock
import uniffi.secretary.saveBlock
import uniffi.secretary.shareBlock
import uniffi.secretary.trashBlock
import kotlin.system.exitProcess

// --- Error variant name helper (mirrors the Swift vaultErrorName helper) ---
//
// Enumerates every variant of VaultException. If uniffi adds a new variant,
// a new `is VaultException.XYZ` branch is needed here — the exhaustive
// `when` will fail to compile, acting as a tripwire the same way the
// Swift non-exhaustive-switch error does.

private fun vaultExceptionVariantName(e: VaultException): String = when (e) {
    is VaultException.WrongPasswordOrCorrupt -> "WrongPasswordOrCorrupt"
    is VaultException.WrongMnemonicOrCorrupt -> "WrongMnemonicOrCorrupt"
    is VaultException.InvalidMnemonic -> "InvalidMnemonic"
    is VaultException.VaultMismatch -> "VaultMismatch"
    is VaultException.CorruptVault -> "CorruptVault"
    is VaultException.FolderInvalid -> "FolderInvalid"
    is VaultException.BlockNotFound -> "BlockNotFound"
    is VaultException.InvalidArgument -> "InvalidArgument"
    is VaultException.SaveCryptoFailure -> "SaveCryptoFailure"
    is VaultException.NotAuthor -> "NotAuthor"
    is VaultException.RecipientAlreadyPresent -> "RecipientAlreadyPresent"
    is VaultException.MissingRecipientCard -> "MissingRecipientCard"
    is VaultException.CardDecodeFailure -> "CardDecodeFailure"
    is VaultException.BlockUuidAlreadyLive -> "BlockUuidAlreadyLive"
    is VaultException.BlockNotInTrash -> "BlockNotInTrash"
}

// Extract the detail string from VaultException variants that carry one.
// Returns null for variants that carry no detail (e.g. WrongPasswordOrCorrupt).
private fun vaultExceptionDetail(e: VaultException): String? = when (e) {
    is VaultException.InvalidMnemonic -> e.detail
    is VaultException.CorruptVault -> e.detail
    is VaultException.FolderInvalid -> e.detail
    is VaultException.InvalidArgument -> e.detail
    is VaultException.SaveCryptoFailure -> e.detail
    is VaultException.CardDecodeFailure -> e.detail
    is VaultException.BlockUuidAlreadyLive -> e.detail
    is VaultException.BlockNotInTrash -> e.detail
    // The remaining variants carry no detail string.
    is VaultException.WrongPasswordOrCorrupt,
    is VaultException.WrongMnemonicOrCorrupt,
    is VaultException.VaultMismatch,
    is VaultException.RecipientAlreadyPresent,
    is VaultException.NotAuthor,
    is VaultException.MissingRecipientCard,
    is VaultException.BlockNotFound -> null
}

// --- Input resolution helpers ---
//
// Mirrors the Swift resolveSource / resolveVaultDir / resolvePassword /
// resolveMnemonic helpers in conformance.swift.

private fun resolveSource(source: String, goldenVaultDir: String): ByteArray {
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

private fun resolveVaultDir(inputs: JSONObject, goldenVaultDir: String): ByteArray {
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

private fun resolvePassword(inputs: JSONObject, goldenVaultDir: String): ByteArray {
    if (inputs.has("password_source")) return resolveSource(inputs.getString("password_source"), goldenVaultDir)
    if (inputs.has("password_literal_utf8")) return inputs.getString("password_literal_utf8").toByteArray(Charsets.UTF_8)
    System.err.println("vector inputs missing password_source / password_literal_utf8")
    exitProcess(1)
}

private fun resolveMnemonic(inputs: JSONObject, goldenVaultDir: String): ByteArray {
    if (inputs.has("mnemonic_source")) return resolveSource(inputs.getString("mnemonic_source"), goldenVaultDir)
    if (inputs.has("mnemonic_literal_utf8")) return inputs.getString("mnemonic_literal_utf8").toByteArray(Charsets.UTF_8)
    System.err.println("vector inputs missing mnemonic_source / mnemonic_literal_utf8")
    exitProcess(1)
}

// Decode a lower-case hex string to a ByteArray. Exits on malformed input.
private fun decodeHex(s: String): ByteArray {
    if (s.length % 2 != 0) {
        System.err.println("malformed hex (odd length): $s")
        exitProcess(1)
    }
    return ByteArray(s.length / 2) { i ->
        s.substring(i * 2, i * 2 + 2).toInt(16).toByte()
    }
}

// Encode a ByteArray to a lower-case hex string.
private fun encodeHex(bytes: ByteArray): String =
    bytes.joinToString("") { "%02x".format(it) }

// --- Result-arm helpers ---
//
// Symmetric with the Swift runner's handleOpenOk / handleVaultError.
// Same parameter order, same assertion order. The cache is a mutable
// reference (Kotlin maps are reference types — no inout marker needed).
//
// `handleVaultError` is shared by every op that throws a `VaultException`
// (openVaultWithPassword, openVaultWithRecovery, readBlock) — the
// variant + detail_contains contract is uniform across them.

private fun handleOpenOk(
    out: OpenVaultOutput,
    expected: JSONObject,
    name: String,
    kind: String,
    cache: MutableMap<String, OpenVaultOutput>,
    check: (Boolean, String, String) -> Boolean,
) {
    if (kind != "ok") {
        check(false, name, "expected err, got ok")
        return
    }
    // Aggregate sub-check results so we only cache on full success.
    // Matches the Rust replay (assert_open_ok panics on mismatch and
    // cache.insert never runs) — chained read_block vectors then
    // report "predecessor did not produce a cacheable Ok" instead of
    // running against a vault whose pinned metadata didn't match.
    var allOk = true
    expected.optString("display_name", null)?.let { wantDisplay ->
        if (!check(out.identity.displayName() == wantDisplay, name,
                "display_name mismatch (got '${out.identity.displayName()}', want '$wantDisplay')")) {
            allOk = false
        }
    }
    if (expected.has("block_count")) {
        val wantBc = expected.getInt("block_count")
        if (!check(out.manifest.blockCount().toInt() == wantBc, name,
                "block_count mismatch (got ${out.manifest.blockCount()}, want $wantBc)")) {
            allOk = false
        }
    }
    expected.optString("block_uuid_hex", null)?.let { wantUuid ->
        val summaries = out.manifest.blockSummaries()
        if (summaries.isNotEmpty()) {
            if (!check(encodeHex(summaries[0].blockUuid) == wantUuid, name,
                    "block_uuid mismatch (got '${encodeHex(summaries[0].blockUuid)}', want '$wantUuid')")) {
                allOk = false
            }
        } else {
            check(false, name, "manifest has no blocks but block_uuid_hex pinned")
            allOk = false
        }
    }
    if (allOk) {
        cache[name] = out
    }
}

private fun handleVaultError(
    e: VaultException,
    expected: JSONObject,
    name: String,
    kind: String,
    check: (Boolean, String, String) -> Boolean,
) {
    if (kind != "err") {
        check(false, name, "expected ok, got err: $e")
        return
    }
    val wantVariant = expected.optString("variant", "")
    val gotVariant = vaultExceptionVariantName(e)
    check(gotVariant == wantVariant, name, "variant mismatch (got $gotVariant, expected $wantVariant)")
    expected.optString("detail_contains", null)?.let { needle ->
        val detail = vaultExceptionDetail(e) ?: ""
        check(detail.contains(needle), name, "detail '$detail' missing '$needle'")
    }
}

// --- v2 lifecycle helpers ---

private fun recursiveCopy(src: java.nio.file.Path, dst: java.nio.file.Path) {
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

private fun cleanupTempVault(tmp: java.nio.file.Path) {
    if (!java.nio.file.Files.exists(tmp)) return
    java.nio.file.Files.walk(tmp).use { stream ->
        stream.sorted(java.util.Comparator.reverseOrder()).forEach {
            try {
                java.nio.file.Files.deleteIfExists(it)
            } catch (_: java.io.IOException) { /* best-effort */ }
        }
    }
}

private fun readContactCardBytes(vaultDir: java.nio.file.Path, userUuidHex: String): ByteArray {
    require(userUuidHex.length == 32) { "userUuidHex must be 32 chars" }
    val h = userUuidHex
    val hyphenated = "${h.substring(0, 8)}-${h.substring(8, 12)}-${h.substring(12, 16)}-${h.substring(16, 20)}-${h.substring(20, 32)}.card"
    val path = vaultDir.resolve("contacts").resolve(hyphenated)
    return java.nio.file.Files.readAllBytes(path)
}

private fun findWritableDir(
    start: String,
    writableVaultDirs: Map<String, java.nio.file.Path>,
    vectors: JSONArray,
): java.nio.file.Path? {
    var current = start
    while (true) {
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
}

private fun findCacheAncestorName(
    start: String,
    cache: Map<String, OpenVaultOutput>,
    vectors: JSONArray,
): String? {
    var current = start
    while (true) {
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
}

private fun blockInputFromInputs(inputs: JSONObject): BlockInput {
    val blockUuidHex = inputs.getString("block_uuid_hex")
    val blockName = if (inputs.has("block_name")) inputs.getString("block_name") else ""
    val recordsArr = if (inputs.has("records")) inputs.getJSONArray("records") else JSONArray()
    val records = (0 until recordsArr.length()).map { i ->
        val rec = recordsArr.getJSONObject(i)
        val recordUuidHex = rec.getString("record_uuid_hex")
        val fieldsArr = if (rec.has("fields")) rec.getJSONArray("fields") else JSONArray()
        val fields = (0 until fieldsArr.length()).map { j ->
            val f = fieldsArr.getJSONObject(j)
            val fname = f.getString("name")
            val ftype = f.getString("type")
            val value: FieldInputValue = when (ftype) {
                "text" -> FieldInputValue.Text(f.getString("value_utf8"))
                "bytes" -> FieldInputValue.Bytes(decodeHex(f.getString("value_hex")))
                else -> error("unknown field type: $ftype")
            }
            FieldInput(fname, value)
        }
        RecordInput(decodeHex(recordUuidHex), fields)
    }
    return BlockInput(decodeHex(blockUuidHex), blockName, records)
}

// Returns 16-byte UUID or null if input is the wrong length / missing.
private fun uuidFromInputs(inputs: JSONObject, primary: String, bytes: String): ByteArray? {
    val raw = when {
        inputs.has(primary) -> inputs.getString(primary)
        inputs.has(bytes) -> inputs.getString(bytes)
        else -> return null
    }
    val data = decodeHex(raw)
    return if (data.size == 16) data else null
}

private fun assertPostState(
    name: String,
    identity: UnlockedIdentity,
    manifest: OpenVaultManifest,
    expected: JSONObject,
    check: (Boolean, String, String) -> Boolean,
) {
    val postState = expected.optJSONObject("post_state") ?: return
    if (postState.has("block_count")) {
        val bc = postState.getInt("block_count")
        check(manifest.blockCount().toInt() == bc, name, "post_state.block_count mismatch (got ${manifest.blockCount()}, want $bc)")
    }
    var roundTripUuid: ByteArray? = null
    if (postState.has("find_block_uuid_hex") && !postState.isNull("find_block_uuid_hex")) {
        val hexStr = postState.getString("find_block_uuid_hex")
        val uuidData = decodeHex(hexStr)
        val summary = manifest.findBlock(uuidData)
        if (summary == null) {
            check(false, name, "post_state.find_block_uuid_hex=$hexStr not in manifest")
        } else {
            check(summary.blockUuid.contentEquals(uuidData), name, "post_state.find_block returned wrong uuid")
            roundTripUuid = uuidData
        }
    }
    if (postState.has("recipient_count")) {
        val rc = postState.getInt("recipient_count")
        val uuid = roundTripUuid
        if (uuid == null) {
            check(false, name, "post_state.recipient_count requires find_block_uuid_hex")
            return
        }
        val summary = manifest.findBlock(uuid)
        if (summary == null) {
            check(false, name, "recipient_count: block not findable")
            return
        }
        check(summary.recipientUuids.size == rc, name, "post_state.recipient_count mismatch (got ${summary.recipientUuids.size}, want $rc)")
    }
    if (postState.has("read_block")) {
        val readPin = postState.getJSONObject("read_block")
        val pinnedRecords = readPin.getJSONArray("records")
        val uuid = roundTripUuid
        if (uuid == null) {
            check(false, name, "post_state.read_block requires find_block_uuid_hex")
            return
        }
        try {
            val output = readBlock(identity, manifest, uuid)
            try {
                check(output.recordCount().toInt() == pinnedRecords.length(), name, "post_state.read_block.record_count mismatch")
                for (ri in 0 until pinnedRecords.length()) {
                    val expRec = pinnedRecords.getJSONObject(ri)
                    val rec = output.recordAt(ri.toULong())
                    if (rec == null) {
                        check(false, name, "post_state.read_block.record_at($ri) returned null")
                        continue
                    }
                    try {
                        expRec.optString("record_uuid_hex", null)?.let { wantUuid ->
                            check(encodeHex(rec.recordUuid()) == wantUuid, name, "records[$ri].record_uuid mismatch")
                        }
                        expRec.optString("record_type", null)?.let { wantType ->
                            check(rec.recordType() == wantType, name, "records[$ri].record_type mismatch")
                        }
                        if (expRec.has("tags")) {
                            val expTags = expRec.getJSONArray("tags")
                            val expTagsList = (0 until expTags.length()).map { expTags.getString(it) }
                            check(rec.tags() == expTagsList, name, "records[$ri].tags mismatch")
                        }
                        if (expRec.has("fields")) {
                            val expFields = expRec.getJSONArray("fields")
                            check(rec.fieldCount().toInt() == expFields.length(), name, "records[$ri].field_count mismatch")
                            for (fi in 0 until expFields.length()) {
                                val expF = expFields.getJSONObject(fi)
                                val fh = rec.fieldAt(fi.toULong())
                                if (fh == null) {
                                    check(false, name, "records[$ri].field_at($fi) returned null")
                                    continue
                                }
                                try {
                                    expF.optString("name", null)?.let { wantName ->
                                        check(fh.name() == wantName, name, "records[$ri].fields[$fi].name mismatch")
                                    }
                                    expF.optString("type", null)?.let { ftype ->
                                        when (ftype) {
                                            "text" -> {
                                                check(fh.isText(), name, "records[$ri].fields[$fi] expected text")
                                                expF.optString("value_utf8", null)?.let { wantVal ->
                                                    check(fh.exposeText() == wantVal, name, "records[$ri].fields[$fi].value_utf8 mismatch")
                                                }
                                            }
                                            "bytes" -> {
                                                check(fh.isBytes(), name, "records[$ri].fields[$fi] expected bytes")
                                                expF.optString("value_hex", null)?.let { wantHex ->
                                                    val actual = encodeHex(fh.exposeBytes() ?: ByteArray(0))
                                                    check(actual == wantHex, name, "records[$ri].fields[$fi].value_hex mismatch")
                                                }
                                            }
                                        }
                                    }
                                } finally {
                                    fh.destroy()
                                }
                            }
                        }
                    } finally {
                        rec.destroy()
                    }
                }
            } finally {
                output.destroy()
            }
        } catch (e: Throwable) {
            check(false, name, "post_state.read_block threw $e")
        }
    }
}

// --- Main ---

fun main() {
    // --- Environment ---
    val katPath = System.getenv("SECRETARY_CONFORMANCE_KAT") ?: run {
        System.err.println("error: SECRETARY_CONFORMANCE_KAT not set; run via tests/kotlin/run_conformance.sh")
        exitProcess(1)
    }
    val goldenVaultDir = System.getenv("SECRETARY_GOLDEN_VAULT_DIR") ?: run {
        System.err.println("error: SECRETARY_GOLDEN_VAULT_DIR not set; run via tests/kotlin/run_conformance.sh")
        exitProcess(1)
    }

    val katText = try {
        java.io.File(katPath).readText()
    } catch (e: Throwable) {
        System.err.println("error: failed to read $katPath: $e")
        exitProcess(1)
    }

    val kat = try {
        JSONObject(katText)
    } catch (e: Throwable) {
        System.err.println("error: $katPath does not parse as a JSON object: $e")
        exitProcess(1)
    }

    val version = kat.optInt("version", -1)
    if (version != 1 && version != 2) {
        System.err.println("error: KAT version must be 1 or 2 (got ${kat.opt("version")})")
        exitProcess(1)
    }

    val vectors: JSONArray = kat.optJSONArray("vectors") ?: run {
        System.err.println("error: vectors array missing or wrong type")
        exitProcess(1)
    }

    // --- Replay state ---
    val failures: MutableList<String> = mutableListOf()
    var vectorsRun: Int = 0
    // Cache: vector name → OpenVaultOutput for chained read_block vectors.
    // Drained explicitly at end-of-main before exitProcess (see below) —
    // calls each cached value's .destroy() so the Rust-side handle is
    // released deterministically rather than waiting for the JVM Cleaner
    // thread. If a source vector fails, its key is absent from the map
    // and chained vectors report "predecessor did not produce a cacheable
    // Ok".
    val cache: MutableMap<String, OpenVaultOutput> = mutableMapOf()
    val tempdirs: MutableList<java.nio.file.Path> = mutableListOf()
    val writableVaultDirs: MutableMap<String, java.nio.file.Path> = mutableMapOf()

    fun check(ok: Boolean, vectorName: String, message: String): Boolean {
        if (ok) return true
        failures.add("$vectorName: $message")
        System.err.println("FAIL: $vectorName: $message")
        return false
    }

    // --- Vector dispatch loop ---

    for (i in 0 until vectors.length()) {
        vectorsRun++
        val vec: JSONObject = vectors.getJSONObject(i)

        val name = vec.optString("name", null)
        val operation = vec.optString("operation", null)
        val inputs = vec.optJSONObject("inputs")
        val expected = vec.optJSONObject("expected")
        val kind = expected?.optString("kind", null)

        if (name == null || operation == null || inputs == null || expected == null || kind == null) {
            failures.add("vector $i is malformed (missing name/operation/inputs/expected/kind)")
            System.err.println("FAIL: vector $i is malformed")
            continue
        }

        // "after" is absent on source vectors; present on read_block vectors.
        val after: String? = if (vec.has("after")) vec.getString("after") else null

        // Snapshot the failure count so we can decide whether this vector
        // produced any sub-check failures. A single PASS line is emitted
        // at the bottom of the loop iff `failures.size` is unchanged —
        // otherwise the per-vector FAIL lines from `check(...)` already
        // went to stderr and we stay silent on stdout. This prevents the
        // misleading "FAIL: ... / PASS: ..." pair for the same vector.
        val preFailureCount = failures.size

        when {
            operation == "open_vault_with_password" && after == null -> {
                val vaultDir = resolveVaultDir(inputs, goldenVaultDir)
                val password = resolvePassword(inputs, goldenVaultDir)
                try {
                    val out = openVaultWithPassword(vaultDir, password)
                    handleOpenOk(out, expected, name, kind, cache, ::check)
                } catch (e: VaultException) {
                    handleVaultError(e, expected, name, kind, ::check)
                } catch (e: Throwable) {
                    check(false, name, "unexpected non-VaultException: $e")
                }
            }

            operation == "open_vault_with_recovery" && after == null -> {
                val vaultDir = resolveVaultDir(inputs, goldenVaultDir)
                val mnemonic = resolveMnemonic(inputs, goldenVaultDir)
                try {
                    val out = openVaultWithRecovery(vaultDir, mnemonic)
                    handleOpenOk(out, expected, name, kind, cache, ::check)
                } catch (e: VaultException) {
                    handleVaultError(e, expected, name, kind, ::check)
                } catch (e: Throwable) {
                    check(false, name, "unexpected non-VaultException: $e")
                }
            }

            operation == "read_block" && after != null -> {
                val cached = cache[after]
                if (cached == null) {
                    check(false, name, "predecessor '$after' did not produce a cacheable Ok")
                    continue
                }

                // Accept either block_uuid_hex (32 hex chars == 16 bytes) or
                // block_uuid_bytes_hex (arbitrary length — used for the wrong-length test).
                val rawBytes: ByteArray = when {
                    inputs.has("block_uuid_hex") -> decodeHex(inputs.getString("block_uuid_hex"))
                    inputs.has("block_uuid_bytes_hex") -> decodeHex(inputs.getString("block_uuid_bytes_hex"))
                    else -> {
                        check(false, name, "missing block_uuid_hex / block_uuid_bytes_hex in inputs")
                        continue
                    }
                }

                try {
                    val block = readBlock(cached.identity, cached.manifest, rawBytes)
                    if (kind != "ok") {
                        check(false, name, "expected err, got ok")
                        block.destroy()
                        continue
                    }

                    val expRecords = expected.optJSONArray("records")
                    if (expRecords != null) {
                        check(block.recordCount().toInt() == expRecords.length(), name, "record_count mismatch (got ${block.recordCount()}, want ${expRecords.length()})")
                        for (ri in 0 until expRecords.length()) {
                            val expRec = expRecords.getJSONObject(ri)
                            val rec = block.recordAt(ri.toULong())
                            if (rec == null) {
                                check(false, name, "record_at($ri) returned null")
                                continue
                            }
                            expRec.optString("record_uuid_hex", null)?.let { wantUuid ->
                                check(encodeHex(rec.recordUuid()) == wantUuid, name, "records[$ri].record_uuid mismatch (got '${encodeHex(rec.recordUuid())}', want '$wantUuid')")
                            }
                            expRec.optString("record_type", null)?.let { wantType ->
                                check(rec.recordType() == wantType, name, "records[$ri].record_type mismatch (got '${rec.recordType()}', want '$wantType')")
                            }
                            if (expRec.has("tags")) {
                                val expTags = expRec.getJSONArray("tags")
                                val expTagsList = (0 until expTags.length()).map { expTags.getString(it) }
                                check(rec.tags() == expTagsList, name, "records[$ri].tags mismatch (got ${rec.tags()}, want $expTagsList)")
                            }
                            val expFields = expRec.optJSONArray("fields")
                            if (expFields != null) {
                                check(rec.fieldCount().toInt() == expFields.length(), name, "records[$ri].field_count mismatch (got ${rec.fieldCount()}, want ${expFields.length()})")
                                for (fi in 0 until expFields.length()) {
                                    val expF = expFields.getJSONObject(fi)
                                    val fh = rec.fieldAt(fi.toULong())
                                    if (fh == null) {
                                        check(false, name, "records[$ri].field_at($fi) returned null")
                                        continue
                                    }
                                    expF.optString("name", null)?.let { wantName ->
                                        check(fh.name() == wantName, name, "records[$ri].fields[$fi].name mismatch (got '${fh.name()}', want '$wantName')")
                                    }
                                    expF.optString("type", null)?.let { ftype ->
                                        when (ftype) {
                                            "text" -> {
                                                check(fh.isText(), name, "records[$ri].fields[$fi] expected text, got bytes")
                                                expF.optString("value_utf8", null)?.let { wantVal ->
                                                    check(fh.exposeText() == wantVal, name, "records[$ri].fields[$fi].value_utf8 mismatch (got '${fh.exposeText()}', want '$wantVal')")
                                                }
                                            }
                                            "bytes" -> {
                                                check(fh.isBytes(), name, "records[$ri].fields[$fi] expected bytes, got text")
                                                expF.optString("value_hex", null)?.let { wantHex ->
                                                    val actual = encodeHex(fh.exposeBytes() ?: ByteArray(0))
                                                    check(actual == wantHex, name, "records[$ri].fields[$fi].value_hex mismatch (got '$actual', want '$wantHex')")
                                                }
                                            }
                                        }
                                    }
                                    fh.destroy()
                                }
                            }
                            rec.destroy()
                        }
                    }
                    block.destroy()
                } catch (e: VaultException) {
                    handleVaultError(e, expected, name, kind, ::check)
                } catch (e: Throwable) {
                    check(false, name, "unexpected non-VaultException: $e")
                }
            }

            operation == "open_vault_with_password_writable" && after == null -> {
                val vaultName = inputs.getString("vault_dir")
                val src = java.nio.file.Paths.get(goldenVaultDir, vaultName)
                val tmp = java.nio.file.Files.createTempDirectory("secretary_conf_v2_")
                try {
                    recursiveCopy(src, tmp)
                } catch (e: Throwable) {
                    check(false, name, "recursive copy failed: $e")
                    cleanupTempVault(tmp)
                    continue
                }
                tempdirs.add(tmp)
                writableVaultDirs[name] = tmp
                val password = resolvePassword(inputs, goldenVaultDir)
                val folderPath = tmp.toString().toByteArray(Charsets.UTF_8)
                try {
                    val out = openVaultWithPassword(folderPath, password)
                    handleOpenOk(out, expected, name, kind, cache, ::check)
                } catch (e: VaultException) {
                    handleVaultError(e, expected, name, kind, ::check)
                } catch (e: Throwable) {
                    check(false, name, "unexpected non-VaultException: $e")
                }
            }

            operation == "save_block" && after != null -> {
                val cacheKey = findCacheAncestorName(after, cache, vectors)
                val cached = cacheKey?.let { cache[it] }
                if (cached == null) {
                    check(false, name, "no cached ancestor along after-chain from $after")
                    continue
                }
                // Synthesize InvalidArgument for non-16-byte device_uuid (matches uniffi behavior).
                if (inputs.has("device_uuid_bytes_hex")) {
                    val raw = decodeHex(inputs.getString("device_uuid_bytes_hex"))
                    if (raw.size != 16) {
                        if (kind != "err") {
                            check(false, name, "expected err, got synthesized InvalidArgument")
                        } else {
                            val want = expected.optString("variant", "")
                            check(want == "InvalidArgument", name, "variant mismatch (got InvalidArgument, expected $want)")
                        }
                        continue
                    }
                }
                val deviceUuid = uuidFromInputs(inputs, "device_uuid_hex", "device_uuid_bytes_hex")
                if (deviceUuid == null) {
                    check(false, name, "device_uuid resolution failed")
                    continue
                }
                val input = blockInputFromInputs(inputs)
                val nowMs = inputs.getLong("now_ms").toULong()
                try {
                    saveBlock(cached.identity, cached.manifest, input, deviceUuid, nowMs)
                    if (kind != "ok") {
                        check(false, name, "expected err, got ok")
                    } else {
                        assertPostState(name, cached.identity, cached.manifest, expected, ::check)
                    }
                } catch (e: VaultException) {
                    handleVaultError(e, expected, name, kind, ::check)
                } catch (e: Throwable) {
                    check(false, name, "unexpected non-VaultException: $e")
                }
            }

            operation == "share_block" && after != null -> {
                val writableDir = findWritableDir(after, writableVaultDirs, vectors)
                if (writableDir == null) {
                    check(false, name, "cannot find writable vault dir along after-chain from $after")
                    continue
                }
                val cacheKey = findCacheAncestorName(after, cache, vectors)
                val cached = cacheKey?.let { cache[it] }
                if (cached == null) {
                    check(false, name, "no cached ancestor along after-chain from $after")
                    continue
                }
                val blockUuid = uuidFromInputs(inputs, "block_uuid_hex", "block_uuid_bytes_hex")
                val deviceUuid = uuidFromInputs(inputs, "device_uuid_hex", "device_uuid_bytes_hex")
                if (blockUuid == null || deviceUuid == null) {
                    check(false, name, "uuid resolution failed")
                    continue
                }
                val nowMs = inputs.getLong("now_ms").toULong()
                val newRecipientHex = inputs.getString("new_recipient_user_uuid_hex")
                val newRecipient = try {
                    readContactCardBytes(writableDir, newRecipientHex)
                } catch (e: Throwable) {
                    check(false, name, "read new_recipient card failed: $e")
                    continue
                }
                val existingCards = mutableListOf<ByteArray>()
                val ownerBytes = try {
                    cached.manifest.ownerCardBytes()
                } catch (e: Throwable) {
                    check(false, name, "owner_card_bytes threw $e")
                    continue
                }
                if (ownerBytes == null) {
                    check(false, name, "owner_card_bytes returned null")
                    continue
                }
                existingCards.add(ownerBytes)
                var extrasOk = true
                if (inputs.has("existing_recipient_uuid_hexes")) {
                    val extras = inputs.getJSONArray("existing_recipient_uuid_hexes")
                    for (ei in 0 until extras.length()) {
                        try {
                            existingCards.add(readContactCardBytes(writableDir, extras.getString(ei)))
                        } catch (e: Throwable) {
                            check(false, name, "read extra existing-recipient card failed: $e")
                            extrasOk = false
                            break
                        }
                    }
                }
                if (!extrasOk) continue
                try {
                    shareBlock(cached.identity, cached.manifest, blockUuid, existingCards, newRecipient, deviceUuid, nowMs)
                    if (kind != "ok") {
                        check(false, name, "expected err, got ok")
                    } else {
                        assertPostState(name, cached.identity, cached.manifest, expected, ::check)
                    }
                } catch (e: VaultException) {
                    handleVaultError(e, expected, name, kind, ::check)
                } catch (e: Throwable) {
                    check(false, name, "unexpected non-VaultException: $e")
                }
            }

            operation == "trash_block" && after != null -> {
                val cacheKey = findCacheAncestorName(after, cache, vectors)
                val cached = cacheKey?.let { cache[it] }
                if (cached == null) {
                    check(false, name, "no cached ancestor along after-chain from $after")
                    continue
                }
                val blockUuid = uuidFromInputs(inputs, "block_uuid_hex", "block_uuid_bytes_hex")
                val deviceUuid = uuidFromInputs(inputs, "device_uuid_hex", "device_uuid_bytes_hex")
                if (blockUuid == null || deviceUuid == null) {
                    check(false, name, "uuid resolution failed")
                    continue
                }
                val nowMs = inputs.getLong("now_ms").toULong()
                try {
                    trashBlock(cached.identity, cached.manifest, blockUuid, deviceUuid, nowMs)
                    if (kind != "ok") {
                        check(false, name, "expected err, got ok")
                    } else {
                        assertPostState(name, cached.identity, cached.manifest, expected, ::check)
                    }
                } catch (e: VaultException) {
                    handleVaultError(e, expected, name, kind, ::check)
                } catch (e: Throwable) {
                    check(false, name, "unexpected non-VaultException: $e")
                }
            }

            operation == "restore_block" && after != null -> {
                val cacheKey = findCacheAncestorName(after, cache, vectors)
                val cached = cacheKey?.let { cache[it] }
                if (cached == null) {
                    check(false, name, "no cached ancestor along after-chain from $after")
                    continue
                }
                val blockUuid = uuidFromInputs(inputs, "block_uuid_hex", "block_uuid_bytes_hex")
                val deviceUuid = uuidFromInputs(inputs, "device_uuid_hex", "device_uuid_bytes_hex")
                if (blockUuid == null || deviceUuid == null) {
                    check(false, name, "uuid resolution failed")
                    continue
                }
                val nowMs = inputs.getLong("now_ms").toULong()
                try {
                    restoreBlock(cached.identity, cached.manifest, blockUuid, deviceUuid, nowMs)
                    if (kind != "ok") {
                        check(false, name, "expected err, got ok")
                    } else {
                        assertPostState(name, cached.identity, cached.manifest, expected, ::check)
                    }
                } catch (e: VaultException) {
                    handleVaultError(e, expected, name, kind, ::check)
                } catch (e: Throwable) {
                    check(false, name, "unexpected non-VaultException: $e")
                }
            }

            else -> {
                check(false, name, "unhandled operation '$operation' with after=${after?.let { "'$it'" } ?: "null"}")
            }
        }

        // Gated success print: only emit PASS if this vector added no
        // failures (see preFailureCount snapshot above).
        if (failures.size == preFailureCount) {
            println("PASS: $name")
        }
    }

    // Drain cached OpenVaultOutput handles deterministically.
    // The JVM Cleaner thread would release them eventually, but a future
    // second-pass replay (B.6 v2) could re-enter main and the handles
    // would pin Rust-side allocations for that duration. Explicit drain
    // releases them at end-of-run — see issue #63.
    cache.values.forEach { it.destroy() }
    cache.clear()
    for (tmp in tempdirs) {
        cleanupTempVault(tmp)
    }
    tempdirs.clear()

    // --- Summary ---
    if (failures.isEmpty()) {
        println("OK: secretary uniffi Kotlin conformance — all $vectorsRun/$vectorsRun vectors passed.")
        exitProcess(0)
    } else {
        System.err.println("FAIL: secretary uniffi Kotlin conformance — ${failures.size} of $vectorsRun vectors failed")
        for (f in failures) System.err.println("  - $f")
        exitProcess(1)
    }
}
