// macOS-host Swift conformance KAT replay (B.6 v1 + v2).
//
// Parallels the Rust replay in core/tests/conformance_kat.rs. Loads
// conformance_kat.json, dispatches each vector through the uniffi-
// generated Swift wrapper, asserts the observable output matches the
// pinned expectation. One PASS/FAIL line per vector + a final summary.
//
// Invocation: ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh

import Foundation

// --- Error variant name extraction (mirrors the Rust variant_name_vault helper) ---
//
// The match enumerates every variant of VaultError. If uniffi adds a new case
// the Swift compiler will emit a non-exhaustive-switch error — that's the
// intended tripwire.

func vaultErrorName(_ e: VaultError) -> String {
    switch e {
    case .WrongPasswordOrCorrupt: return "WrongPasswordOrCorrupt"
    case .WrongMnemonicOrCorrupt: return "WrongMnemonicOrCorrupt"
    case .InvalidMnemonic: return "InvalidMnemonic"
    case .VaultMismatch: return "VaultMismatch"
    case .CorruptVault: return "CorruptVault"
    case .FolderInvalid: return "FolderInvalid"
    case .BlockNotFound: return "BlockNotFound"
    case .SaveCryptoFailure: return "SaveCryptoFailure"
    case .NotAuthor: return "NotAuthor"
    case .RecipientAlreadyPresent: return "RecipientAlreadyPresent"
    case .MissingRecipientCard: return "MissingRecipientCard"
    case .CardDecodeFailure: return "CardDecodeFailure"
    case .BlockUuidAlreadyLive: return "BlockUuidAlreadyLive"
    case .BlockNotInTrash: return "BlockNotInTrash"
    case .InvalidArgument: return "InvalidArgument"
    }
}

func vaultErrorDetail(_ e: VaultError) -> String? {
    switch e {
    case .InvalidMnemonic(let d): return d
    case .CorruptVault(let d): return d
    case .FolderInvalid(let d): return d
    case .SaveCryptoFailure(let d): return d
    case .CardDecodeFailure(let d): return d
    case .BlockUuidAlreadyLive(let d): return d
    case .BlockNotInTrash(let d): return d
    case .InvalidArgument(let d): return d
    default: return nil
    }
}

// --- Input resolution helpers ---

func resolveSource(_ source: String, goldenVaultDir: String) -> Data {
    let parts = source.split(separator: ":", maxSplits: 1)
    guard parts.count == 2 else {
        FileHandle.standardError.write(Data("malformed source ref: \(source)\n".utf8))
        exit(1)
    }
    let file = URL(fileURLWithPath: goldenVaultDir).appendingPathComponent(String(parts[0]))
    let field = String(parts[1])
    guard let bytes = try? Data(contentsOf: file),
        let obj = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any],
        let str = obj[field] as? String
    else {
        FileHandle.standardError.write(Data("failed to resolve \(source)\n".utf8))
        exit(1)
    }
    return Data(str.utf8)
}

func resolveVaultDir(_ inputs: [String: Any], goldenVaultDir: String) -> Data {
    if let s = inputs["vault_dir"] as? String {
        let url = URL(fileURLWithPath: goldenVaultDir).appendingPathComponent(s)
        return Data(url.path.utf8)
    }
    if let s = inputs["vault_dir_literal"] as? String {
        return Data(s.utf8)
    }
    FileHandle.standardError.write(Data("vector inputs missing vault_dir / vault_dir_literal\n".utf8))
    exit(1)
}

func resolvePassword(_ inputs: [String: Any], goldenVaultDir: String) -> Data {
    if let s = inputs["password_source"] as? String { return resolveSource(s, goldenVaultDir: goldenVaultDir) }
    if let s = inputs["password_literal_utf8"] as? String { return Data(s.utf8) }
    FileHandle.standardError.write(Data("vector inputs missing password_*\n".utf8))
    exit(1)
}

func resolveMnemonic(_ inputs: [String: Any], goldenVaultDir: String) -> Data {
    if let s = inputs["mnemonic_source"] as? String { return resolveSource(s, goldenVaultDir: goldenVaultDir) }
    if let s = inputs["mnemonic_literal_utf8"] as? String { return Data(s.utf8) }
    FileHandle.standardError.write(Data("vector inputs missing mnemonic_*\n".utf8))
    exit(1)
}

func decodeHex(_ s: String) -> Data {
    var bytes: [UInt8] = []
    let chars = Array(s)
    var i = 0
    while i + 1 < chars.count {
        guard let b = UInt8(String(chars[i]) + String(chars[i + 1]), radix: 16) else {
            FileHandle.standardError.write(Data("malformed hex: \(s)\n".utf8))
            exit(1)
        }
        bytes.append(b)
        i += 2
    }
    return Data(bytes)
}

func encodeHex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

// --- Result-arm helpers ---
//
// Symmetric with the Kotlin runner's handleOpenOk / handleVaultError.
// Same parameter order, same assertion order. The cache is `inout`
// so handleOpenOk can insert on success.
//
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

// --- v2 lifecycle helpers ---

func recursiveCopy(_ from: URL, _ to: URL) throws {
    try FileManager.default.createDirectory(at: to, withIntermediateDirectories: true)
    for entry in try FileManager.default.contentsOfDirectory(at: from, includingPropertiesForKeys: nil) {
        var isDir: ObjCBool = false
        FileManager.default.fileExists(atPath: entry.path, isDirectory: &isDir)
        let dest = to.appendingPathComponent(entry.lastPathComponent)
        if isDir.boolValue {
            try recursiveCopy(entry, dest)
        } else {
            try FileManager.default.copyItem(at: entry, to: dest)
        }
    }
}

func readContactCardBytes(_ vaultDir: URL, _ userUuidHex: String) throws -> Data {
    precondition(userUuidHex.count == 32, "userUuidHex must be 32 chars")
    let h = userUuidHex
    let s8 = h.index(h.startIndex, offsetBy: 8)
    let s12 = h.index(h.startIndex, offsetBy: 12)
    let s16 = h.index(h.startIndex, offsetBy: 16)
    let s20 = h.index(h.startIndex, offsetBy: 20)
    let hyphenated = "\(h[..<s8])-\(h[s8..<s12])-\(h[s12..<s16])-\(h[s16..<s20])-\(h[s20...]).card"
    let path = vaultDir.appendingPathComponent("contacts").appendingPathComponent(hyphenated)
    return try Data(contentsOf: path)
}

func findWritableDir(_ start: String, writableVaultDirs: [String: URL], vectors: [[String: Any]]) -> URL? {
    var current = start
    // Bounded by vectors.count — an authoring-error `after:` cycle would
    // otherwise hang. Fail loudly so the cycle is fixable, not silent.
    for _ in 0...vectors.count {
        if let url = writableVaultDirs[current] { return url }
        guard let parentAfter = vectors.first(where: { ($0["name"] as? String) == current })?["after"] as? String else {
            return nil
        }
        current = parentAfter
    }
    fatalError("after-chain cycle detected starting at '\(start)' (depth exceeded vectors.count)")
}

func findCacheAncestorName(_ start: String, cache: [String: OpenVaultOutput], vectors: [[String: Any]]) -> String? {
    var current = start
    // Cycle guard: see findWritableDir.
    for _ in 0...vectors.count {
        if cache[current] != nil { return current }
        guard let parentAfter = vectors.first(where: { ($0["name"] as? String) == current })?["after"] as? String else {
            return nil
        }
        current = parentAfter
    }
    fatalError("after-chain cycle detected starting at '\(start)' (depth exceeded vectors.count)")
}

/// Build a BlockInput from the JSON `inputs` dict. Mirrors block_input_from_inputs
/// in core/tests/conformance_kat_helpers/dispatch.rs.
///
/// `record_uuid_hex` is the happy-path key (always 16 bytes); a vector may
/// instead provide `record_uuid_bytes_hex` with a wrong-length value to
/// exercise uniffi's namespace-layer `uuid_from_vec` length check (the
/// bridge's `RecordInput.record_uuid` is type-bounded to `[u8; 16]` in
/// Rust, but on the uniffi side it's a `Data`/`ByteArray` whose length
/// is validated inside `convert_record_input`, surfacing
/// `VaultError.InvalidArgument` symmetrically with wrong-length
/// device_uuid / block_uuid).
func blockInputFromInputs(_ inputs: [String: Any]) -> BlockInput {
    let blockUuidHex = inputs["block_uuid_hex"] as! String
    let blockName = (inputs["block_name"] as? String) ?? ""
    let records: [RecordInput] = (inputs["records"] as? [[String: Any]] ?? []).map { rec in
        let recordUuidHex = (rec["record_uuid_hex"] as? String) ?? (rec["record_uuid_bytes_hex"] as! String)
        let fields: [FieldInput] = (rec["fields"] as? [[String: Any]] ?? []).map { f in
            let fname = f["name"] as! String
            let ftype = f["type"] as! String
            let value: FieldInputValue
            switch ftype {
            case "text":
                value = .text(text: f["value_utf8"] as! String)
            case "bytes":
                value = .bytes(data: decodeHex(f["value_hex"] as! String))
            default:
                fatalError("unknown field type: \(ftype)")
            }
            return FieldInput(name: fname, value: value)
        }
        return RecordInput(recordUuid: decodeHex(recordUuidHex), fields: fields)
    }
    return BlockInput(blockUuid: decodeHex(blockUuidHex), blockName: blockName, records: records)
}

/// uuid extraction matching Rust's uuid_from_inputs. Returns nil for
/// non-16-byte input (caller surfaces synthesized InvalidArgument).
func uuidFromInputs(_ inputs: [String: Any], primary: String, bytes: String) -> Data? {
    let raw: String
    if let s = inputs[primary] as? String { raw = s }
    else if let s = inputs[bytes] as? String { raw = s }
    else { return nil }
    let data = decodeHex(raw)
    return data.count == 16 ? data : nil
}

/// Assert post_state shape against the post-call manifest. Mirrors
/// assert_post_state in core/tests/conformance_kat_helpers/dispatch.rs.
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
            let output = try readBlock(identity: identity, manifest: manifest, blockUuid: uuid)
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

// --- Main entry point ---
//
// @main provides the binary entry point and keeps all executable
// statements inside a function, satisfying Swift's rule that only
// a file named `main.swift` may have bare top-level code when
// compiling multiple source files together.

@main
struct ConformanceRunner {
    static func main() {
        // --- Path resolution ---
        guard let katPath = ProcessInfo.processInfo.environment["SECRETARY_CONFORMANCE_KAT"] else {
            FileHandle.standardError.write(
                Data("error: SECRETARY_CONFORMANCE_KAT not set; run via tests/swift/run_conformance.sh\n".utf8)
            )
            exit(1)
        }
        guard let goldenVaultDir = ProcessInfo.processInfo.environment["SECRETARY_GOLDEN_VAULT_DIR"] else {
            FileHandle.standardError.write(
                Data("error: SECRETARY_GOLDEN_VAULT_DIR not set; run via tests/swift/run_conformance.sh\n".utf8)
            )
            exit(1)
        }

        let katData: Data
        do {
            katData = try Data(contentsOf: URL(fileURLWithPath: katPath))
        } catch {
            FileHandle.standardError.write(Data("error: failed to read \(katPath): \(error)\n".utf8))
            exit(1)
        }

        guard let kat = try? JSONSerialization.jsonObject(with: katData) as? [String: Any] else {
            FileHandle.standardError.write(Data("error: \(katPath) does not parse as a JSON object\n".utf8))
            exit(1)
        }

        let version = kat["version"] as? Int ?? 0
        guard version == 1 || version == 2 else {
            FileHandle.standardError.write(Data("error: KAT version must be 1 or 2 (got \(version))\n".utf8))
            exit(1)
        }

        guard let vectors = kat["vectors"] as? [[String: Any]] else {
            FileHandle.standardError.write(Data("error: vectors array missing or wrong type\n".utf8))
            exit(1)
        }

        var failures: [String] = []
        var vectorsRun: Int = 0
        var cache: [String: OpenVaultOutput] = [:]
        var tempdirs: [URL] = []
        var writableVaultDirs: [String: URL] = [:]
        // Tempdir cleanup happens at the end of main() — Swift's defer
        // wouldn't fire on exit() so we explicitly clean before exiting.

        func check(_ ok: Bool, _ vectorName: String, _ message: String) -> Bool {
            if ok { return true }
            failures.append("\(vectorName): \(message)")
            FileHandle.standardError.write(Data("FAIL: \(vectorName): \(message)\n".utf8))
            return false
        }

        // --- Vector dispatch loop ---

        for vec in vectors {
            vectorsRun += 1
            guard let name = vec["name"] as? String,
                let operation = vec["operation"] as? String,
                let inputs = vec["inputs"] as? [String: Any],
                let expected = vec["expected"] as? [String: Any],
                let kind = expected["kind"] as? String
            else {
                failures.append("vector \(vectorsRun) is malformed")
                continue
            }
            let after = vec["after"] as? String

            // Snapshot the failure count so we can decide whether this
            // vector produced any sub-check failures. A single PASS line
            // is emitted at the bottom of the loop iff `failures.count`
            // is unchanged — otherwise the per-vector FAIL lines from
            // `check(...)` already went to stderr and we stay silent on
            // stdout. This prevents the misleading "FAIL: ... / PASS: ..."
            // pair for the same vector.
            let preFailureCount = failures.count

            switch (operation, after) {
            case ("open_vault_with_password", nil):
                let vaultDir = resolveVaultDir(inputs, goldenVaultDir: goldenVaultDir)
                let password = resolvePassword(inputs, goldenVaultDir: goldenVaultDir)
                do {
                    let out = try openVaultWithPassword(folderPath: vaultDir, password: password)
                    handleOpenOk(out: out, expected: expected, name: name, kind: kind, cache: &cache, check: check)
                } catch let e as VaultError {
                    handleVaultError(e: e, expected: expected, name: name, kind: kind, check: check)
                } catch {
                    _ = check(false, name, "unexpected non-VaultError exception: \(error)")
                }

            case ("open_vault_with_recovery", nil):
                let vaultDir = resolveVaultDir(inputs, goldenVaultDir: goldenVaultDir)
                let mnemonic = resolveMnemonic(inputs, goldenVaultDir: goldenVaultDir)
                do {
                    let out = try openVaultWithRecovery(folderPath: vaultDir, mnemonic: mnemonic)
                    handleOpenOk(out: out, expected: expected, name: name, kind: kind, cache: &cache, check: check)
                } catch let e as VaultError {
                    handleVaultError(e: e, expected: expected, name: name, kind: kind, check: check)
                } catch {
                    _ = check(false, name, "unexpected non-VaultError exception: \(error)")
                }

            case ("read_block", let predecessor?):
                guard let cached = cache[predecessor] else {
                    _ = check(false, name, "predecessor '\(predecessor)' did not produce a cacheable Ok")
                    continue
                }
                // Decide between block_uuid_hex (32 chars = 16 bytes) and block_uuid_bytes_hex (any length).
                var raw = Data()
                if let s = inputs["block_uuid_hex"] as? String { raw = decodeHex(s) }
                else if let s = inputs["block_uuid_bytes_hex"] as? String { raw = decodeHex(s) }
                else { _ = check(false, name, "missing block_uuid_*"); continue }

                do {
                    // uniffi's read_block expects a 16-byte sequence; the binding-layer
                    // wrapper rejects non-16-byte input as InvalidArgument before
                    // dispatching to the bridge.
                    let out = try readBlock(identity: cached.identity, manifest: cached.manifest, blockUuid: raw)
                    if kind != "ok" { _ = check(false, name, "expected err, got ok"); continue }
                    if let records = expected["records"] as? [[String: Any]] {
                        _ = check(Int(out.recordCount()) == records.count, name, "record_count mismatch")
                        for (i, expRec) in records.enumerated() {
                            guard let rec = out.recordAt(idx: UInt64(i)) else {
                                _ = check(false, name, "record_at(\(i)) returned nil")
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
                    }
                } catch let e as VaultError {
                    handleVaultError(e: e, expected: expected, name: name, kind: kind, check: check)
                } catch {
                    _ = check(false, name, "unexpected non-VaultError exception: \(error)")
                }

            case ("open_vault_with_password_writable", nil):
                guard let vaultName = inputs["vault_dir"] as? String else {
                    _ = check(false, name, "open_vault_with_password_writable needs vault_dir")
                    break
                }
                let src = URL(fileURLWithPath: goldenVaultDir).appendingPathComponent(vaultName)
                let tmp = FileManager.default.temporaryDirectory
                    .appendingPathComponent("secretary_conf_v2_\(UUID().uuidString)")
                do {
                    try recursiveCopy(src, tmp)
                } catch {
                    _ = check(false, name, "recursive copy failed: \(error)")
                    break
                }
                tempdirs.append(tmp)
                writableVaultDirs[name] = tmp
                let password = resolvePassword(inputs, goldenVaultDir: goldenVaultDir)
                let folderPath = Data(tmp.path.utf8)
                do {
                    let out = try openVaultWithPassword(folderPath: folderPath, password: password)
                    handleOpenOk(out: out, expected: expected, name: name, kind: kind, cache: &cache, check: check)
                } catch let e as VaultError {
                    handleVaultError(e: e, expected: expected, name: name, kind: kind, check: check)
                } catch {
                    _ = check(false, name, "unexpected non-VaultError exception: \(error)")
                }

            case ("save_block", let predecessor?):
                guard let cacheKey = findCacheAncestorName(predecessor, cache: cache, vectors: vectors),
                      let cached = cache[cacheKey] else {
                    _ = check(false, name, "no cached ancestor along after-chain from \(predecessor)")
                    break
                }
                // For wrong-length device_uuid, pass the bytes through to the
                // uniffi binding layer — uniffi's namespace-layer uuid_from_vec
                // check (ffi/secretary-ffi-uniffi/src/namespace.rs) is exactly
                // the surface this vector exists to pin. Do NOT short-circuit
                // here: a regression in uuid_from_vec (silent accept, rename)
                // must surface as a vector failure.
                let deviceUuid: Data
                if let bytes = inputs["device_uuid_bytes_hex"] as? String {
                    deviceUuid = decodeHex(bytes)
                } else if let dh = uuidFromInputs(inputs, primary: "device_uuid_hex", bytes: "device_uuid_bytes_hex") {
                    deviceUuid = dh
                } else {
                    _ = check(false, name, "device_uuid resolution failed")
                    break
                }
                let input = blockInputFromInputs(inputs)
                let nowMs = UInt64(inputs["now_ms"] as! Int)
                do {
                    try saveBlock(identity: cached.identity, manifest: cached.manifest, input: input, deviceUuid: deviceUuid, nowMs: nowMs)
                    if kind != "ok" {
                        _ = check(false, name, "expected err, got ok")
                    } else {
                        assertPostState(name: name, identity: cached.identity, manifest: cached.manifest, expected: expected, check: check)
                    }
                } catch let e as VaultError {
                    handleVaultError(e: e, expected: expected, name: name, kind: kind, check: check)
                } catch {
                    _ = check(false, name, "unexpected non-VaultError exception: \(error)")
                }

            case ("share_block", let predecessor?):
                guard let writableDir = findWritableDir(predecessor, writableVaultDirs: writableVaultDirs, vectors: vectors) else {
                    _ = check(false, name, "cannot find writable vault dir along after-chain from \(predecessor)")
                    break
                }
                guard let cacheKey = findCacheAncestorName(predecessor, cache: cache, vectors: vectors),
                      let cached = cache[cacheKey] else {
                    _ = check(false, name, "no cached ancestor along after-chain from \(predecessor)")
                    break
                }
                guard let blockUuid = uuidFromInputs(inputs, primary: "block_uuid_hex", bytes: "block_uuid_bytes_hex"),
                      let deviceUuid = uuidFromInputs(inputs, primary: "device_uuid_hex", bytes: "device_uuid_bytes_hex") else {
                    _ = check(false, name, "uuid resolution failed")
                    break
                }
                let nowMs = UInt64(inputs["now_ms"] as! Int)
                let newRecipientHex = inputs["new_recipient_user_uuid_hex"] as! String
                let newRecipient: Data
                do {
                    newRecipient = try readContactCardBytes(writableDir, newRecipientHex)
                } catch {
                    _ = check(false, name, "read new_recipient card failed: \(error)")
                    break
                }
                var existingCards: [Data] = []
                do {
                    if let ownerBytes = try cached.manifest.ownerCardBytes() {
                        existingCards.append(ownerBytes)
                    } else {
                        _ = check(false, name, "owner_card_bytes returned nil")
                        break
                    }
                } catch {
                    _ = check(false, name, "owner_card_bytes threw \(error)")
                    break
                }
                if let extras = inputs["existing_recipient_uuid_hexes"] as? [String] {
                    var extraFailed = false
                    for h in extras {
                        do {
                            existingCards.append(try readContactCardBytes(writableDir, h))
                        } catch {
                            _ = check(false, name, "read extra existing-recipient card failed: \(error)")
                            extraFailed = true
                            break
                        }
                    }
                    if extraFailed { break }
                }
                do {
                    try shareBlock(
                        identity: cached.identity,
                        manifest: cached.manifest,
                        blockUuid: blockUuid,
                        existingRecipientCards: existingCards,
                        newRecipient: newRecipient,
                        deviceUuid: deviceUuid,
                        nowMs: nowMs
                    )
                    if kind != "ok" {
                        _ = check(false, name, "expected err, got ok")
                    } else {
                        assertPostState(name: name, identity: cached.identity, manifest: cached.manifest, expected: expected, check: check)
                    }
                } catch let e as VaultError {
                    handleVaultError(e: e, expected: expected, name: name, kind: kind, check: check)
                } catch {
                    _ = check(false, name, "unexpected non-VaultError exception: \(error)")
                }

            case ("trash_block", let predecessor?):
                guard let cacheKey = findCacheAncestorName(predecessor, cache: cache, vectors: vectors),
                      let cached = cache[cacheKey] else {
                    _ = check(false, name, "no cached ancestor along after-chain from \(predecessor)")
                    break
                }
                guard let blockUuid = uuidFromInputs(inputs, primary: "block_uuid_hex", bytes: "block_uuid_bytes_hex"),
                      let deviceUuid = uuidFromInputs(inputs, primary: "device_uuid_hex", bytes: "device_uuid_bytes_hex") else {
                    _ = check(false, name, "uuid resolution failed")
                    break
                }
                let nowMs = UInt64(inputs["now_ms"] as! Int)
                do {
                    try trashBlock(identity: cached.identity, manifest: cached.manifest, blockUuid: blockUuid, deviceUuid: deviceUuid, nowMs: nowMs)
                    if kind != "ok" {
                        _ = check(false, name, "expected err, got ok")
                    } else {
                        assertPostState(name: name, identity: cached.identity, manifest: cached.manifest, expected: expected, check: check)
                    }
                } catch let e as VaultError {
                    handleVaultError(e: e, expected: expected, name: name, kind: kind, check: check)
                } catch {
                    _ = check(false, name, "unexpected non-VaultError exception: \(error)")
                }

            case ("restore_block", let predecessor?):
                guard let cacheKey = findCacheAncestorName(predecessor, cache: cache, vectors: vectors),
                      let cached = cache[cacheKey] else {
                    _ = check(false, name, "no cached ancestor along after-chain from \(predecessor)")
                    break
                }
                guard let blockUuid = uuidFromInputs(inputs, primary: "block_uuid_hex", bytes: "block_uuid_bytes_hex"),
                      let deviceUuid = uuidFromInputs(inputs, primary: "device_uuid_hex", bytes: "device_uuid_bytes_hex") else {
                    _ = check(false, name, "uuid resolution failed")
                    break
                }
                let nowMs = UInt64(inputs["now_ms"] as! Int)
                do {
                    try restoreBlock(identity: cached.identity, manifest: cached.manifest, blockUuid: blockUuid, deviceUuid: deviceUuid, nowMs: nowMs)
                    if kind != "ok" {
                        _ = check(false, name, "expected err, got ok")
                    } else {
                        assertPostState(name: name, identity: cached.identity, manifest: cached.manifest, expected: expected, check: check)
                    }
                } catch let e as VaultError {
                    handleVaultError(e: e, expected: expected, name: name, kind: kind, check: check)
                } catch {
                    _ = check(false, name, "unexpected non-VaultError exception: \(error)")
                }

            default:
                _ = check(false, name, "unhandled operation '\(operation)' with after=\(String(describing: after))")
            }

            // Gated success print: only emit PASS if this vector added no
            // failures (see preFailureCount snapshot above).
            if failures.count == preFailureCount {
                print("PASS: \(name)")
            }
        }

        // Drop cached OpenVaultOutput references so ARC releases the
        // contained UnlockedIdentity / OpenVaultManifest class instances
        // (each has a deinit that frees the Rust-side handle). `exit()`
        // below skips scope unwinding, so without this assignment the
        // class refs would linger until process termination — fine for
        // single-pass but matters for B.6 v2 second-pass replays.
        // Symmetric with the Kotlin runner's
        // `cache.values.forEach { it.destroy() }; cache.clear()`.
        cache.removeAll()
        for url in tempdirs {
            try? FileManager.default.removeItem(at: url)
        }

        if failures.isEmpty {
            print("OK: secretary uniffi Swift conformance — all \(vectorsRun)/\(vectorsRun) vectors passed.")
            exit(0)
        } else {
            FileHandle.standardError.write(
                Data("FAIL: secretary uniffi Swift conformance — \(failures.count) of \(vectorsRun) vectors failed\n".utf8)
            )
            for f in failures { FileHandle.standardError.write(Data("  - \(f)\n".utf8)) }
            cache.removeAll()
            for url in tempdirs {
                try? FileManager.default.removeItem(at: url)
            }
            exit(1)
        }
    }
}
