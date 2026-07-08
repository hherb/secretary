// Result-arm + post_state assertion helpers.
//
// `handleOpenOk` / `handleVaultError` are symmetric with the Kotlin runner's
// equivalents. The `check` closure is the caller's failure aggregator —
// returns false on mismatch and appends to the runner's failures list.
//
// `assertPostState` mirrors assert_post_state in core/tests/conformance_kat_helpers/dispatch/lifecycle.rs.

import Foundation

// `handleVaultError` is shared by every op that throws a `VaultError`
// (open_vault_with_password, open_vault_with_recovery, read_block) —
// the variant + detail_contains contract is uniform across them.

func handleOpenOk(
    out: OpenVaultOutput,
    expected: [String: Any],
    name: String,
    kind: String,
    cache: inout [String: OpenVaultOutput],
    check: (Bool, String, String) -> Bool
) {
    if kind != "ok" {
        _ = check(false, name, "expected err, got ok")
        return
    }
    // Aggregate sub-check results so we only cache on full success.
    // Matches the Rust replay (assert_open_ok panics on mismatch and
    // cache.insert never runs) — chained read_block vectors then
    // report "predecessor did not produce a cacheable Ok" instead of
    // running against a vault whose pinned metadata didn't match.
    var allOk = true
    if let display = expected["display_name"] as? String {
        if !check(out.identity.displayName() == display, name, "display_name mismatch") { allOk = false }
    }
    if let bc = expected["block_count"] as? Int {
        if !check(Int(out.manifest.blockCount()) == bc, name, "block_count mismatch") { allOk = false }
    }
    if let bu = expected["block_uuid_hex"] as? String {
        let summaries = out.manifest.blockSummaries()
        if !summaries.isEmpty {
            if !check(encodeHex(Data(summaries[0].blockUuid)) == bu, name, "block_uuid mismatch") { allOk = false }
        } else {
            _ = check(false, name, "manifest has no blocks but block_uuid pinned")
            allOk = false
        }
    }
    if allOk {
        cache[name] = out
    }
}

func handleVaultError(
    e: VaultError,
    expected: [String: Any],
    name: String,
    kind: String,
    check: (Bool, String, String) -> Bool
) {
    if kind != "err" {
        _ = check(false, name, "expected ok, got err: \(e)")
        return
    }
    let want = expected["variant"] as? String ?? ""
    _ = check(vaultErrorName(e) == want, name, "variant mismatch (got \(vaultErrorName(e)), expected \(want))")
    if let needle = expected["detail_contains"] as? String {
        let detail = vaultErrorDetail(e) ?? ""
        _ = check(detail.contains(needle), name, "detail '\(detail)' missing '\(needle)'")
    }
}

/// Assert post_state shape against the post-call manifest. Mirrors
/// assert_post_state in core/tests/conformance_kat_helpers/dispatch/lifecycle.rs.
func assertPostState(
    name: String,
    identity: UnlockedIdentity,
    manifest: OpenVaultManifest,
    expected: [String: Any],
    check: (Bool, String, String) -> Bool
) {
    guard let postState = expected["post_state"] as? [String: Any] else { return }
    if let bc = postState["block_count"] as? Int {
        _ = check(Int(manifest.blockCount()) == bc, name, "post_state.block_count mismatch (got \(manifest.blockCount()), want \(bc))")
    }
    var roundTripUuid: Data? = nil
    if let hexStr = postState["find_block_uuid_hex"] as? String {
        let uuidData = decodeHex(hexStr)
        if let summary = manifest.findBlock(blockUuid: uuidData) {
            _ = check(Data(summary.blockUuid) == uuidData, name, "post_state.find_block returned wrong uuid")
            roundTripUuid = uuidData
        } else {
            _ = check(false, name, "post_state.find_block_uuid_hex=\(hexStr) not in manifest")
        }
    }
    if let rc = postState["recipient_count"] as? Int {
        guard let uuid = roundTripUuid else {
            _ = check(false, name, "post_state.recipient_count requires find_block_uuid_hex")
            return
        }
        guard let summary = manifest.findBlock(blockUuid: uuid) else {
            _ = check(false, name, "recipient_count: block not findable")
            return
        }
        _ = check(summary.recipientUuids.count == rc, name, "post_state.recipient_count mismatch (got \(summary.recipientUuids.count), want \(rc))")
    }
    if let readPin = postState["read_block"] as? [String: Any],
       let pinnedRecords = readPin["records"] as? [[String: Any]]
    {
        guard let uuid = roundTripUuid else {
            _ = check(false, name, "post_state.read_block requires find_block_uuid_hex")
            return
        }
        do {
            let output = try readBlock(identity: identity, manifest: manifest, blockUuid: uuid, includeDeleted: true)
            _ = check(Int(output.recordCount()) == pinnedRecords.count, name, "post_state.read_block.record_count mismatch")
            for (i, expRec) in pinnedRecords.enumerated() {
                guard let rec = output.recordAt(idx: UInt64(i)) else {
                    _ = check(false, name, "post_state.read_block.record_at(\(i)) nil")
                    continue
                }
                if let uhex = expRec["record_uuid_hex"] as? String {
                    _ = check(encodeHex(Data(rec.recordUuid())) == uhex, name, "records[\(i)].record_uuid mismatch")
                }
                if let rtype = expRec["record_type"] as? String {
                    _ = check(rec.recordType() == rtype, name, "records[\(i)].record_type mismatch")
                }
                if let tags = expRec["tags"] as? [String] {
                    _ = check(rec.tags() == tags, name, "records[\(i)].tags mismatch")
                }
                if let fields = expRec["fields"] as? [[String: Any]] {
                    _ = check(Int(rec.fieldCount()) == fields.count, name, "records[\(i)].field_count mismatch")
                    for (j, expF) in fields.enumerated() {
                        guard let fh = rec.fieldAt(idx: UInt64(j)) else {
                            _ = check(false, name, "records[\(i)].field_at(\(j)) nil")
                            continue
                        }
                        if let fname = expF["name"] as? String {
                            _ = check(fh.name() == fname, name, "records[\(i)].fields[\(j)].name mismatch")
                        }
                        if let ftype = expF["type"] as? String {
                            if ftype == "text" {
                                _ = check(fh.isText(), name, "records[\(i)].fields[\(j)] expected text")
                                if let ev = expF["value_utf8"] as? String {
                                    _ = check(fh.exposeText() == ev, name, "records[\(i)].fields[\(j)].value_utf8 mismatch")
                                }
                            } else if ftype == "bytes" {
                                _ = check(fh.isBytes(), name, "records[\(i)].fields[\(j)] expected bytes")
                                if let ev = expF["value_hex"] as? String {
                                    let actual = encodeHex(fh.exposeBytes() ?? Data())
                                    _ = check(actual == ev, name, "records[\(i)].fields[\(j)].value_hex mismatch")
                                }
                            }
                        }
                    }
                }
            }
        } catch {
            _ = check(false, name, "post_state.read_block threw \(error)")
        }
    }
}

/// Assert a `purge_block` Ok result against the vector's pinned
/// `expected.purge_report`. Mirrors assert_purge_report in
/// core/tests/conformance_kat_helpers/dispatch/lifecycle.rs:
/// `was_shared` / `recipient_count` are exact-match (both nullable —
/// nil classifies "could not read the trash file", not "false"/"0"),
/// `files_removed_min` (if pinned) is a lower-bound assertion.
func assertPurgeReport(
    name: String,
    actual: PurgeReport,
    expected: [String: Any],
    check: (Bool, String, String) -> Bool
) {
    guard let pinned = expected["purge_report"] as? [String: Any] else { return }
    if let want = pinned["was_shared"] as? Bool {
        _ = check(actual.wasShared == want, name, "purge_report.was_shared mismatch (got \(String(describing: actual.wasShared)), want \(want))")
    }
    if let want = pinned["recipient_count"] as? Int {
        _ = check(actual.recipientCount.map { Int($0) } == want, name, "purge_report.recipient_count mismatch (got \(String(describing: actual.recipientCount)), want \(want))")
    }
    if let min = pinned["files_removed_min"] as? Int {
        _ = check(Int(actual.filesRemoved) >= min, name, "purge_report.files_removed \(actual.filesRemoved) < expected minimum \(min)")
    }
}

/// Assert an `empty_trash` Ok result against the vector's pinned
/// `expected.empty_trash_report`. Mirrors assert_empty_trash_report in
/// core/tests/conformance_kat_helpers/dispatch/lifecycle.rs:
/// `purged_count` / `shared_count` / `owner_only_count` / `unknown_count`
/// are exact-match, `files_removed_min` (if pinned) is a lower-bound
/// assertion, and `files_failed` (if pinned) is exact-match.
func assertEmptyTrashReport(
    name: String,
    actual: EmptyTrashReport,
    expected: [String: Any],
    check: (Bool, String, String) -> Bool
) {
    guard let pinned = expected["empty_trash_report"] as? [String: Any] else { return }
    // The four count fields are MANDATORY exact-match — parity with the
    // Kotlin runner's `pinned.getLong(...)` (throws if absent) and the
    // Rust reference's non-Option `u64` fields in
    // core/tests/conformance_kat_helpers/types.rs::ExpectedEmptyTrashReport
    // (asserted with bare `assert_eq!`). The `as! Int` force-cast is the
    // vector-authoring contract used throughout this runner (e.g.
    // `inputs["now_ms"] as! Int`): a vector missing one of these keys is a
    // malformed KAT and must trap loudly, never silently skip — that
    // silent skip was the exact cross-language drift this suite catches.
    let purgedWant = pinned["purged_count"] as! Int
    _ = check(Int(actual.purgedCount) == purgedWant, name, "empty_trash_report.purged_count mismatch (got \(actual.purgedCount), want \(purgedWant))")
    let sharedWant = pinned["shared_count"] as! Int
    _ = check(Int(actual.sharedCount) == sharedWant, name, "empty_trash_report.shared_count mismatch (got \(actual.sharedCount), want \(sharedWant))")
    let ownerOnlyWant = pinned["owner_only_count"] as! Int
    _ = check(Int(actual.ownerOnlyCount) == ownerOnlyWant, name, "empty_trash_report.owner_only_count mismatch (got \(actual.ownerOnlyCount), want \(ownerOnlyWant))")
    let unknownWant = pinned["unknown_count"] as! Int
    _ = check(Int(actual.unknownCount) == unknownWant, name, "empty_trash_report.unknown_count mismatch (got \(actual.unknownCount), want \(unknownWant))")
    // files_removed_min / files_failed remain optional — parity with
    // Kotlin's `has()`-guarded reads and Rust's `Option<u64>` fields.
    if let min = pinned["files_removed_min"] as? Int {
        _ = check(Int(actual.filesRemoved) >= min, name, "empty_trash_report.files_removed \(actual.filesRemoved) < expected minimum \(min)")
    }
    if let want = pinned["files_failed"] as? Int {
        _ = check(Int(actual.filesFailed) == want, name, "empty_trash_report.files_failed mismatch (got \(actual.filesFailed), want \(want))")
    }
}
