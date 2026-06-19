// Shared helpers + assertion infrastructure for the Swift smoke runner.
//
// Split out of main.swift per issue #72 to keep each smoke file under
// the project's 500-LOC guideline. Mirrors the Kotlin smoke runner's
// SmokeHelpers.kt. Owns:
//
//   - module-level mutable state (`failures`, `assertsRun`)
//   - the `check(_:,_:)` assertion primitive
//   - shared constants (KAT values, truncation distance, expected
//     display name + user UUID, pinned UUIDs)
//   - `loadSmokeEnv()` — single entry point that reads SECRETARY_GOLDEN_VAULT_DIR,
//     loads golden_vault_001 / golden_vault_002 fixtures, extracts the
//     recovery mnemonic phrases, and returns a `SmokeEnv` struct passed
//     to every group function
//   - shared filesystem helpers (`_recursiveCopy`, `_freshWritableVault`,
//     `_aliceCardBytes`)
//
// Top-level `var` is module-level state visible to all Swift files in
// the same compilation unit — this matches how main.swift originally
// carried `failures` / `assertsRun` as top-level state, so call sites
// in the group files don't need to thread the counter through arguments.

import Foundation

// =============================================================================
// Pinned KAT constants
// =============================================================================

// Vault format version pinned to the value in core/src/version.rs. A
// FORMAT_VERSION bump is a normative protocol break and must update
// this constant in lockstep with the spec — that keeps the smoke test
// honest as a cross-language contract assertion rather than a tautology.
let EXPECTED_FORMAT_VERSION: UInt16 = 1

// Truncation distance for assertion 7 (truncated TOML → CorruptVault).
// Matches secretary-ffi-py/tests/test_smoke.py::_TRUNCATION_SUFFIX_BYTES
// and the Kotlin smoke runner; keeping all three pinned to the same
// value makes the cross-language "what counts as corrupt" surface uniform.
//
// Why robust under v1: vault.toml is plain TOML and contains no AEAD-
// framed payloads (those live in identity.bundle.enc), so any
// truncation must fail at TOML parse / required-field-present checks
// long before the AEAD step that produces WrongPasswordOrCorrupt. If
// a future format places AEAD content in vault.toml, re-validate
// across all four sites (bridge, pytest, Swift, Kotlin).
let TRUNCATION_SUFFIX_BYTES = 50

// Pinned KAT — must match secretary-ffi-bridge's tests + pytest +
// Kotlin smoke runner. Source of truth: golden_vault_001_inputs.json.
let expectedDisplayName = "Owner"
let expectedUserUuid = Data([
    0xbf, 0x08, 0xa3, 0x30, 0x0c, 0xd9, 0x94, 0xb8,
    0x77, 0xe1, 0xa1, 0x5b, 0xaa, 0x28, 0xdf, 0x35,
])

// Pinned block UUID for the single block in golden_vault_001 — written
// at fixture-build time by core/tests/common/fixture_builder.rs and
// consumed by the read_block asserts.
let vault001BlockUuid = Data([
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
])

// Pinned UUIDs / device fingerprint for B.4c save_block + B.4d share_block.
// Distinct from the existing block in golden_vault_001 (11223344-...-ff00)
// so insert / update paths don't collide with the fixture's pre-built block.
let saveBlockNewBlockUuid = Data(repeating: 0xAB, count: 16)
let saveBlockNewRecordUuid = Data(repeating: 0xCD, count: 16)
let saveBlockDeviceUuid = Data(repeating: 0x07, count: 16)

// record-edit slice (append/edit/tombstone/resurrect). Distinct block /
// record UUIDs so seeded blocks don't collide with the save_block flows
// when assertions run in sequence on the same fresh-copy vaults.
let recordEditBlockUuid = Data(repeating: 0xB1, count: 16)
let recordEditRecordUuid = Data(repeating: 0xC2, count: 16)
let recordEditDeviceUuid = Data(repeating: 0x07, count: 16)

// share_block uses the same pinned block UUID as save_block — the share
// flow runs on a block produced by save_block in the same temp vault.
let shareBlockBlockUuid = Data(repeating: 0xAB, count: 16)
let shareBlockRecordUuid = Data(repeating: 0xCD, count: 16)
let shareBlockDeviceUuid = Data(repeating: 0x07, count: 16)

// B.5 trash/restore uses a different block UUID to avoid collision with
// save/share flows when assertions run in sequence on the same vault.
let b5BlockUuid = Data(repeating: 0xBB, count: 16)
let b5RecordUuid = Data(repeating: 0xCC, count: 16)
let b5DeviceUuid = Data(repeating: 0x07, count: 16)

// Block-CRUD slice pinned UUIDs (mirror the Kotlin SmokeHelpers.kt
// BLOCK_CRUD_* constants). Distinct from all above to avoid collisions
// when assertions run in sequence on fresh-copy vaults.
// blockCrudBlockUuid      — used by createBlock and renameBlock tests.
// blockCrudSrcBlockUuid   — source block in moveRecord tests.
// blockCrudTgtBlockUuid   — target block in moveRecord tests.
// blockCrudSrcRecordUuid  — record seeded into source before the move.
// blockCrudNewRecordUuid  — caller-minted UUID assigned to the copy.
let blockCrudBlockUuid = Data(repeating: 0xE1, count: 16)
let blockCrudSrcBlockUuid = Data(repeating: 0xE2, count: 16)
let blockCrudTgtBlockUuid = Data(repeating: 0xE3, count: 16)
let blockCrudSrcRecordUuid = Data(repeating: 0xE4, count: 16)
let blockCrudNewRecordUuid = Data(repeating: 0xE5, count: 16)
let blockCrudDeviceUuid = Data(repeating: 0x07, count: 16)

// =============================================================================
// Module-level mutable assertion state
// =============================================================================

// Collect failures rather than exit on first so a single run reports
// every contract that drifted, not just the first. The smoke surface
// is small now but grows in B.2+; aggregating from the start avoids
// the painful "fix one assertion, re-run, find another" loop.
var failures: [String] = []
var assertsRun: Int = 0

func check(_ condition: Bool, _ message: String) {
    assertsRun += 1
    if condition {
        print("PASS: \(message)")
    } else {
        FileHandle.standardError.write(Data("FAIL: \(message)\n".utf8))
        failures.append(message)
    }
}

// =============================================================================
// Smoke environment
// =============================================================================

// Shared fixture state passed to every group function. Bundles the file-
// system paths to the two golden vaults plus the byte payloads + password
// bytes + recovery-mnemonic bytes pre-loaded once at startup. Threading
// this through each `runXxxAsserts(env:)` call avoids re-reading the
// fixtures per assertion (the originals did the reads once at top level).
struct SmokeEnv {
    let vault001Url: URL
    let vault002Url: URL
    let toml001: Data
    let bundle001: Data
    let bundle002: Data
    let password001: Data
    let password002: Data
    let phrase001: Data
    let phrase002: Data
}

func loadSmokeEnv() -> SmokeEnv {
    // Fixture path comes from run.sh via SECRETARY_GOLDEN_VAULT_DIR so the
    // same on-disk vaults are exercised by the bridge crate's tests, the
    // pytest suite, and both uniffi smoke runners. Hard-coding here would
    // silently drift the moment the fixture set moves.
    guard let vaultDir = ProcessInfo.processInfo.environment["SECRETARY_GOLDEN_VAULT_DIR"] else {
        FileHandle.standardError.write(
            Data("error: SECRETARY_GOLDEN_VAULT_DIR not set; run via tests/swift/run.sh\n".utf8)
        )
        exit(1)
    }

    let vault001Url = URL(fileURLWithPath: vaultDir).appendingPathComponent("golden_vault_001")
    let vault002Url = URL(fileURLWithPath: vaultDir).appendingPathComponent("golden_vault_002")

    let toml001: Data
    let bundle001: Data
    let bundle002: Data
    do {
        toml001 = try Data(contentsOf: vault001Url.appendingPathComponent("vault.toml"))
        bundle001 = try Data(contentsOf: vault001Url.appendingPathComponent("identity.bundle.enc"))
        bundle002 = try Data(contentsOf: vault002Url.appendingPathComponent("identity.bundle.enc"))
    } catch {
        FileHandle.standardError.write(
            Data("error: failed to read golden vault fixtures: \(error)\n".utf8)
        )
        exit(1)
    }

    let password001 = "correct horse battery staple".data(using: .utf8)!
    let password002 = "correct horse battery staple two".data(using: .utf8)!

    let inputs001Url = URL(fileURLWithPath: vaultDir).appendingPathComponent("golden_vault_001_inputs.json")
    let inputs002Url = URL(fileURLWithPath: vaultDir).appendingPathComponent("golden_vault_002_inputs.json")
    let phrase001 = _phraseFromInputs(inputs001Url)
    let phrase002 = _phraseFromInputs(inputs002Url)

    return SmokeEnv(
        vault001Url: vault001Url,
        vault002Url: vault002Url,
        toml001: toml001,
        bundle001: bundle001,
        bundle002: bundle002,
        password001: password001,
        password002: password002,
        phrase001: phrase001,
        phrase002: phrase002
    )
}

// =============================================================================
// Fixture-loading helpers
// =============================================================================

// Read `recovery_mnemonic_phrase` from a golden_vault_NNN_inputs.json file.
// Source of truth for the BIP-39 phrase used by the open_with_recovery /
// open_vault_with_recovery assertions. Exits on parse / missing-field
// failure rather than throwing — the smoke runner can't proceed without
// these and a propagated throw would obscure the cause.
func _phraseFromInputs(_ url: URL) -> Data {
    do {
        let data = try Data(contentsOf: url)
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        guard let phrase = json?["recovery_mnemonic_phrase"] as? String else {
            FileHandle.standardError.write(
                Data("error: recovery_mnemonic_phrase missing or not a string in \(url.path)\n".utf8)
            )
            exit(1)
        }
        return phrase.data(using: .utf8)!
    } catch {
        FileHandle.standardError.write(
            Data("error: failed to read \(url.path): \(error)\n".utf8)
        )
        exit(1)
    }
}

// Recursive copy of a directory tree. Used to stage a writable copy of
// golden_vault_001 / golden_vault_002 in a per-test tempdir so the
// read-only fixtures stay untouched. Mirrors the bridge crate's
// `copy_dir_recursive` helper and the Kotlin smoke runner's equivalent.
func _recursiveCopy(_ src: URL, _ dst: URL) throws {
    try FileManager.default.createDirectory(at: dst, withIntermediateDirectories: true)
    let items = try FileManager.default.contentsOfDirectory(atPath: src.path)
    for name in items {
        let from = src.appendingPathComponent(name)
        let to = dst.appendingPathComponent(name)
        var isDir: ObjCBool = false
        FileManager.default.fileExists(atPath: from.path, isDirectory: &isDir)
        if isDir.boolValue {
            try _recursiveCopy(from, to)
        } else {
            try FileManager.default.copyItem(at: from, to: to)
        }
    }
}

// Open a fresh per-test copy of golden_vault_001 in a unique tempdir.
// Returns the identity + manifest handles the caller can mutate freely,
// plus the tempdir URL the caller must `removeItem` on exit.
func _freshWritableVault(env: SmokeEnv) throws -> (UnlockedIdentity, OpenVaultManifest, URL) {
    let tmp = FileManager.default.temporaryDirectory
        .appendingPathComponent("secretary_smoke_swift_\(UUID().uuidString)")
    try _recursiveCopy(env.vault001Url, tmp)
    let folderPath = Data(tmp.path.utf8)
    let out = try openVaultWithPassword(folderPath: folderPath, password: env.password001)
    return (out.identity, out.manifest, tmp)
}

// Extract vault_002's owner contact card bytes — used as "Alice" in
// share_block assertions. Stages vault_002 in a tempdir, opens it,
// reads `owner_card_bytes()`, and cleans up before returning.
func _aliceCardBytes(env: SmokeEnv) throws -> Data {
    let tmp = FileManager.default.temporaryDirectory
        .appendingPathComponent("secretary_smoke_swift_alice_\(UUID().uuidString)")
    try _recursiveCopy(env.vault002Url, tmp)
    defer { try? FileManager.default.removeItem(at: tmp) }
    let folderPath = Data(tmp.path.utf8)
    let out = try openVaultWithPassword(folderPath: folderPath, password: env.password002)
    defer { out.identity.wipe() }
    defer { out.manifest.wipe() }
    guard let bytes = try out.manifest.ownerCardBytes() else {
        throw NSError(domain: "secretary-test", code: 1, userInfo: [
            NSLocalizedDescriptionKey: "vault_002 owner_card_bytes returned nil",
        ])
    }
    return bytes
}
