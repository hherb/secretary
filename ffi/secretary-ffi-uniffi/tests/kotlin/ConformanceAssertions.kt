// Result-arm + post_state assertion helpers.
//
// `handleOpenOk` / `handleVaultError` are symmetric with the Swift runner's
// equivalents. The `check` lambda is the caller's failure aggregator —
// returns false on mismatch and appends to the runner's failures list.
//
// `assertPostState` mirrors assert_post_state in core/tests/conformance_kat_helpers/dispatch/lifecycle.rs.

import org.json.JSONObject
import uniffi.secretary.OpenVaultManifest
import uniffi.secretary.OpenVaultOutput
import uniffi.secretary.UnlockedIdentity
import uniffi.secretary.VaultException
import uniffi.secretary.readBlock

// `handleVaultError` is shared by every op that throws a `VaultException`
// (openVaultWithPassword, openVaultWithRecovery, readBlock) — the
// variant + detail_contains contract is uniform across them.

internal fun handleOpenOk(
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

internal fun handleVaultError(
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

internal fun assertPostState(
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
            val output = readBlock(identity, manifest, uuid, true)
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
