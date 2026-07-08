// macOS-host Swift conformance KAT replay (B.6 v1 + v2).
//
// Parallels the Rust replay in core/tests/conformance_kat.rs. Loads
// conformance_kat.json, dispatches each vector through the uniffi-
// generated Swift wrapper, asserts the observable output matches the
// pinned expectation. One PASS/FAIL line per vector + a final summary.
//
// Helpers live in sibling files (split per issue #67 to stay under
// the 500-LOC guideline):
//   - ConformanceErrors.swift     — VaultError variant name + detail
//   - ConformanceHelpers.swift    — input resolvers, hex codec, fs, after-walkers
//   - ConformanceInputs.swift     — uniffi BlockInput / RecordInput builders
//   - ConformanceAssertions.swift — handleOpenOk / handleVaultError / assertPostState
//
// Invocation: ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh

import Foundation

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

            case ("open_with_device_secret", nil):
                // Device-slot open path (ADR 0009 / B.2). Resolve uuid + secret
                // first. A wrong-length input cannot reach the bridge's
                // type-bounded `&[u8; 16]` / `&[u8; 32]` signature, so the
                // binding-layer length pre-check is replicated here as a
                // SYNTHETIC `InvalidArgument` outcome (mirrors the read_block /
                // save_block wrong-length precedent — the open_device_secret_
                // short_secret vector passes a 31-byte secret). The synthetic
                // branch asserts directly against the vector's expected variant.
                let deviceUuid = resolveDeviceUuid(inputs, goldenVaultDir: goldenVaultDir)
                let deviceSecret = resolveDeviceSecret(inputs, goldenVaultDir: goldenVaultDir)
                if deviceUuid.count != 16 {
                    _ = check(kind == "err" && (expected["variant"] as? String) == "InvalidArgument",
                              name, "wrong-length device_uuid expected synthetic InvalidArgument")
                } else if deviceSecret.count != 32 {
                    _ = check(kind == "err" && (expected["variant"] as? String) == "InvalidArgument",
                              name, "wrong-length device_secret expected synthetic InvalidArgument")
                } else {
                    let vaultDir = resolveVaultDir(inputs, goldenVaultDir: goldenVaultDir)
                    do {
                        let out = try openWithDeviceSecret(folderPath: vaultDir, deviceUuid: deviceUuid, deviceSecret: deviceSecret)
                        handleOpenOk(out: out, expected: expected, name: name, kind: kind, cache: &cache, check: check)
                    } catch let e as VaultError {
                        handleVaultError(e: e, expected: expected, name: name, kind: kind, check: check)
                    } catch {
                        _ = check(false, name, "unexpected non-VaultError exception: \(error)")
                    }
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
                    let out = try readBlock(identity: cached.identity, manifest: cached.manifest, blockUuid: raw, includeDeleted: true)
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

            case ("purge_block", let predecessor?):
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
                    let report = try purgeBlock(identity: cached.identity, manifest: cached.manifest, blockUuid: blockUuid, deviceUuid: deviceUuid, nowMs: nowMs)
                    if kind != "ok" {
                        _ = check(false, name, "expected err, got ok")
                    } else {
                        assertPurgeReport(name: name, actual: report, expected: expected, check: check)
                        assertPostState(name: name, identity: cached.identity, manifest: cached.manifest, expected: expected, check: check)
                    }
                } catch let e as VaultError {
                    handleVaultError(e: e, expected: expected, name: name, kind: kind, check: check)
                } catch {
                    _ = check(false, name, "unexpected non-VaultError exception: \(error)")
                }

            case ("empty_trash", let predecessor?):
                guard let cacheKey = findCacheAncestorName(predecessor, cache: cache, vectors: vectors),
                      let cached = cache[cacheKey] else {
                    _ = check(false, name, "no cached ancestor along after-chain from \(predecessor)")
                    break
                }
                guard let deviceUuid = uuidFromInputs(inputs, primary: "device_uuid_hex", bytes: "device_uuid_bytes_hex") else {
                    _ = check(false, name, "uuid resolution failed")
                    break
                }
                let nowMs = UInt64(inputs["now_ms"] as! Int)
                do {
                    let report = try emptyTrash(identity: cached.identity, manifest: cached.manifest, deviceUuid: deviceUuid, nowMs: nowMs)
                    if kind != "ok" {
                        _ = check(false, name, "expected err, got ok")
                    } else {
                        assertEmptyTrashReport(name: name, actual: report, expected: expected, check: check)
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

        // --- Standalone enrol round-trip (B.2) ---
        //
        // Not a JSON vector: exercises the one-shot add_device_slot →
        // take_secret → open_with_device_secret handle end-to-end. Enrol
        // MUST run against a temp copy — adding a slot writes a new
        // devices/<uuid>.wrap into the vault, and golden_vault_001 is a
        // frozen KAT fixture that must never be mutated. Counted as one
        // extra "vector" in the summary so the pass count reflects it.
        do {
            vectorsRun += 1
            let enrolName = "enrol_round_trip"
            let preEnrolFailures = failures.count
            let src = URL(fileURLWithPath: goldenVaultDir).appendingPathComponent("golden_vault_001")
            let tmp = FileManager.default.temporaryDirectory
                .appendingPathComponent("secretary_enrol_\(UUID().uuidString)")
            tempdirs.append(tmp)
            do {
                try recursiveCopy(src, tmp)
            } catch {
                _ = check(false, enrolName, "recursive copy failed: \(error)")
            }
            let folderPath = Data(tmp.path.utf8)
            let password = resolveSource("golden_vault_001_inputs.json:password", goldenVaultDir: goldenVaultDir)
            do {
                let enroll = try addDeviceSlot(folderPath: folderPath, password: password)
                _ = check(enroll.deviceUuid.count == 16, enrolName, "device_uuid expected 16 bytes, got \(enroll.deviceUuid.count)")
                let secret = enroll.deviceSecret.takeSecret()
                _ = check(secret != nil, enrolName, "takeSecret() returned nil on first call")
                _ = check(secret?.count == 32, enrolName, "device_secret expected 32 bytes, got \(secret?.count ?? -1)")
                _ = check(enroll.deviceSecret.takeSecret() == nil, enrolName, "takeSecret() second call expected nil (one-shot)")
                if let secret = secret {
                    do {
                        // takeSecret() is `bytes?` → a Data? directly (#261); pass it straight through.
                        let out = try openWithDeviceSecret(
                            folderPath: folderPath,
                            deviceUuid: enroll.deviceUuid,
                            deviceSecret: secret
                        )
                        _ = check(out.identity.displayName() == "Owner", enrolName,
                                  "enrol-then-open display_name mismatch (got '\(out.identity.displayName())', want 'Owner')")
                        _ = check(Int(out.manifest.blockCount()) == 1, enrolName,
                                  "enrol-then-open block_count mismatch (got \(out.manifest.blockCount()), want 1)")
                    } catch {
                        _ = check(false, enrolName, "open_with_device_secret after enrol threw \(error)")
                    }
                }
            } catch {
                _ = check(false, enrolName, "add_device_slot threw \(error)")
            }
            if failures.count == preEnrolFailures {
                print("PASS: \(enrolName)")
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
