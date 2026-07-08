// JVM-host Kotlin conformance KAT replay (B.6 v1 + v2).
//
// Parallels the Rust replay in core/tests/conformance_kat.rs and the
// Swift replay in tests/swift/conformance.swift. Loads
// conformance_kat.json via SECRETARY_CONFORMANCE_KAT, dispatches each
// vector through the uniffi-generated Kotlin wrappers, asserts the
// observable output matches the pinned expectation. One PASS/FAIL line
// per vector + a final summary.
//
// Helpers live in sibling files (split per issue #67 to stay under
// the 500-LOC guideline):
//   - ConformanceErrors.kt     — VaultException variant name + detail
//   - ConformanceHelpers.kt    — input resolvers, hex codec, fs, after-walkers
//   - ConformanceInputs.kt     — uniffi BlockInput / RecordInput builders
//   - ConformanceAssertions.kt — handleOpenOk / handleVaultError / assertPostState
//
// Invocation: ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh

import org.json.JSONArray
import org.json.JSONObject
import uniffi.secretary.OpenVaultOutput
import uniffi.secretary.VaultException
import uniffi.secretary.addDeviceSlot
import uniffi.secretary.emptyTrash
import uniffi.secretary.openVaultWithPassword
import uniffi.secretary.openVaultWithRecovery
import uniffi.secretary.openWithDeviceSecret
import uniffi.secretary.purgeBlock
import uniffi.secretary.readBlock
import uniffi.secretary.restoreBlock
import uniffi.secretary.saveBlock
import uniffi.secretary.shareBlock
import uniffi.secretary.trashBlock
import kotlin.system.exitProcess

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

            operation == "open_with_device_secret" && after == null -> {
                // Device-slot open path (ADR 0009 / B.2). Resolve uuid + secret
                // first. A wrong-length input cannot reach the bridge's
                // type-bounded `&[u8; 16]` / `&[u8; 32]` signature, so the
                // binding-layer length pre-check is replicated here as a
                // SYNTHETIC InvalidArgument outcome (mirrors the read_block /
                // save_block wrong-length precedent — the open_device_secret_
                // short_secret vector passes a 31-byte secret). The synthetic
                // branch asserts directly against the vector's expected variant.
                val deviceUuid = resolveDeviceUuid(inputs, goldenVaultDir)
                val deviceSecret = resolveDeviceSecret(inputs, goldenVaultDir)
                if (deviceUuid.size != 16) {
                    check(kind == "err" && expected.optString("variant", null) == "InvalidArgument",
                        name, "wrong-length device_uuid expected synthetic InvalidArgument")
                } else if (deviceSecret.size != 32) {
                    check(kind == "err" && expected.optString("variant", null) == "InvalidArgument",
                        name, "wrong-length device_secret expected synthetic InvalidArgument")
                } else {
                    val vaultDir = resolveVaultDir(inputs, goldenVaultDir)
                    try {
                        val out = openWithDeviceSecret(vaultDir, deviceUuid, deviceSecret)
                        handleOpenOk(out, expected, name, kind, cache, ::check)
                    } catch (e: VaultException) {
                        handleVaultError(e, expected, name, kind, ::check)
                    } catch (e: Throwable) {
                        check(false, name, "unexpected non-VaultException: $e")
                    }
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
                    val block = readBlock(cached.identity, cached.manifest, rawBytes, true)
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
                // For wrong-length device_uuid, pass the bytes through to the
                // uniffi binding layer — uniffi's namespace-layer uuid_from_vec
                // check (ffi/secretary-ffi-uniffi/src/namespace.rs) is exactly
                // the surface this vector exists to pin. Do NOT short-circuit
                // here: a regression in uuid_from_vec (silent accept, rename)
                // must surface as a vector failure.
                val deviceUuid: ByteArray = when {
                    inputs.has("device_uuid_bytes_hex") -> decodeHex(inputs.getString("device_uuid_bytes_hex"))
                    else -> uuidFromInputs(inputs, "device_uuid_hex", "device_uuid_bytes_hex")
                        ?: run {
                            check(false, name, "device_uuid resolution failed")
                            continue
                        }
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

            operation == "purge_block" && after != null -> {
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
                    val report = purgeBlock(cached.identity, cached.manifest, blockUuid, deviceUuid, nowMs)
                    if (kind != "ok") {
                        check(false, name, "expected err, got ok")
                    } else {
                        assertPurgeReport(name, report, expected, ::check)
                        assertPostState(name, cached.identity, cached.manifest, expected, ::check)
                    }
                } catch (e: VaultException) {
                    handleVaultError(e, expected, name, kind, ::check)
                } catch (e: Throwable) {
                    check(false, name, "unexpected non-VaultException: $e")
                }
            }

            operation == "empty_trash" && after != null -> {
                val cacheKey = findCacheAncestorName(after, cache, vectors)
                val cached = cacheKey?.let { cache[it] }
                if (cached == null) {
                    check(false, name, "no cached ancestor along after-chain from $after")
                    continue
                }
                val deviceUuid = uuidFromInputs(inputs, "device_uuid_hex", "device_uuid_bytes_hex")
                if (deviceUuid == null) {
                    check(false, name, "uuid resolution failed")
                    continue
                }
                val nowMs = inputs.getLong("now_ms").toULong()
                try {
                    val report = emptyTrash(cached.identity, cached.manifest, deviceUuid, nowMs)
                    if (kind != "ok") {
                        check(false, name, "expected err, got ok")
                    } else {
                        assertEmptyTrashReport(name, report, expected, ::check)
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

    // --- Standalone enrol round-trip (B.2) ---
    //
    // Not a JSON vector: exercises the one-shot addDeviceSlot → takeSecret →
    // openWithDeviceSecret handle end-to-end. Enrol MUST run against a temp
    // copy — adding a slot writes a new devices/<uuid>.wrap into the vault,
    // and golden_vault_001 is a frozen KAT fixture that must never be
    // mutated. Counted as one extra "vector" in the summary.
    run {
        vectorsRun++
        val enrolName = "enrol_round_trip"
        val preEnrolFailures = failures.size
        val src = java.nio.file.Paths.get(goldenVaultDir, "golden_vault_001")
        val tmp = java.nio.file.Files.createTempDirectory("secretary_enrol_")
        tempdirs.add(tmp)
        try {
            recursiveCopy(src, tmp)
        } catch (e: Throwable) {
            check(false, enrolName, "recursive copy failed: $e")
            return@run
        }
        val folderPath = tmp.toString().toByteArray(Charsets.UTF_8)
        val password = resolveSource("golden_vault_001_inputs.json:password", goldenVaultDir)
        try {
            val enroll = addDeviceSlot(folderPath, password)
            check(enroll.deviceUuid.size == 16, enrolName, "device_uuid expected 16 bytes, got ${enroll.deviceUuid.size}")
            val secret = enroll.deviceSecret.takeSecret()
            check(secret != null, enrolName, "takeSecret() returned null on first call")
            check(secret?.size == 32, enrolName, "device_secret expected 32 bytes, got ${secret?.size ?: -1}")
            check(enroll.deviceSecret.takeSecret() == null, enrolName, "takeSecret() second call expected null (one-shot)")
            if (secret != null) {
                // takeSecret() is `bytes?` → a ByteArray? directly (#261); no boxed-list conversion.
                try {
                    val out = openWithDeviceSecret(folderPath, enroll.deviceUuid, secret)
                    check(out.identity.displayName() == "Owner", enrolName,
                        "enrol-then-open display_name mismatch (got '${out.identity.displayName()}', want 'Owner')")
                    check(out.manifest.blockCount().toInt() == 1, enrolName,
                        "enrol-then-open block_count mismatch (got ${out.manifest.blockCount()}, want 1)")
                    out.destroy()
                } catch (e: Throwable) {
                    check(false, enrolName, "openWithDeviceSecret after enrol threw $e")
                }
            }
        } catch (e: Throwable) {
            check(false, enrolName, "addDeviceSlot threw $e")
        }
        if (failures.size == preEnrolFailures) {
            println("PASS: $enrolName")
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
