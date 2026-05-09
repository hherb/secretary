// macOS-host Swift smoke runner for the uniffi binding pipeline.
//
// Verifies the round-trip surface defined in src/secretary.udl by
// calling the generated Swift wrappers (which dispatch to the cdylib
// `libsecretary_ffi_uniffi.dylib` via the C ABI). Mirrors the Rust
// unit tests in src/lib.rs so a contract change in either language
// fails in both places.
//
// Invocation: ffi/secretary-ffi-uniffi/tests/swift/run.sh

import Foundation

// Vault format version pinned to the value in core/src/version.rs. A
// FORMAT_VERSION bump is a normative protocol break and must update
// this constant in lockstep with the spec — that keeps the smoke test
// honest as a cross-language contract assertion rather than a tautology.
let EXPECTED_FORMAT_VERSION: UInt16 = 1

// Collect failures rather than exit on first so a single run reports
// every contract that drifted, not just the first. The smoke surface
// is small now but grows in B.2+; aggregating from the start avoids
// the painful "fix one assertion, re-run, find another" loop.
var failures: [String] = []

func check(_ condition: Bool, _ message: String) {
    if condition {
        print("PASS: \(message)")
    } else {
        FileHandle.standardError.write(Data("FAIL: \(message)\n".utf8))
        failures.append(message)
    }
}

// --- Round-trip assertions ---

let sumSmall = add(a: 2, b: 3)
check(sumSmall == 5, "add(2, 3) == 5 (got \(sumSmall))")

let sumWrap = add(a: UInt32.max, b: 1)
check(sumWrap == 0, "add(UInt32.max, 1) wraps to 0 (got \(sumWrap))")

let v = version()
check(
    v == EXPECTED_FORMAT_VERSION,
    "version() == \(EXPECTED_FORMAT_VERSION) (got \(v))"
)

// --- B.2: open_with_password assertions ---
//
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

// Wrap fixture reads in a do/catch — Swift's top-level statements
// allow `try` only when the script can propagate; we'd rather report
// a clear error than blow up with an unhandled throw.
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

// B.3a: read recovery_mnemonic_phrase from golden_vault_NNN_inputs.json.
// JSON path is sibling to the golden_vault_NNN/ fixture directory.
let inputs001Url = URL(fileURLWithPath: vaultDir).appendingPathComponent("golden_vault_001_inputs.json")
let inputs002Url = URL(fileURLWithPath: vaultDir).appendingPathComponent("golden_vault_002_inputs.json")

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

let phrase001: Data = _phraseFromInputs(inputs001Url)
let phrase002: Data = _phraseFromInputs(inputs002Url)

// Pinned KAT — must match secretary-ffi-bridge's tests + pytest +
// Kotlin smoke runner. Source of truth: golden_vault_001_inputs.json.
let expectedDisplayName = "Owner"
let expectedUserUuid = Data([
    0xbf, 0x08, 0xa3, 0x30, 0x0c, 0xd9, 0x94, 0xb8,
    0x77, 0xe1, 0xa1, 0x5b, 0xaa, 0x28, 0xdf, 0x35,
])

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

// Assertion 4: success path. defer { wipe() } exercises the explicit-
// zeroize hook (`wipe`, not `close`, per uniffi 0.31 codegen — see the
// generated UnlockedIdentity doc comment for the rename rationale).
do {
    let identity = try openWithPassword(
        vaultTomlBytes: toml001,
        identityBundleBytes: bundle001,
        password: password001
    )
    defer { identity.wipe() }

    let displayName = identity.displayName()
    let uuid = identity.userUuid()
    check(
        displayName == expectedDisplayName && uuid == expectedUserUuid,
        "open_with_password success → display_name + user_uuid match pinned KAT (got displayName=\"\(displayName)\")"
    )
} catch {
    check(false, "open_with_password success threw \(error), expected to succeed")
}

// Assertion 5: wrong password → WrongPasswordOrCorrupt.
do {
    _ = try openWithPassword(
        vaultTomlBytes: toml001,
        identityBundleBytes: bundle001,
        password: "definitely wrong".data(using: .utf8)!
    )
    check(false, "wrong password should have thrown WrongPasswordOrCorrupt")
} catch UnlockError.WrongPasswordOrCorrupt {
    check(true, "wrong password → WrongPasswordOrCorrupt")
} catch {
    check(false, "wrong password threw \(error), expected WrongPasswordOrCorrupt")
}

// Assertion 6: cross-vault file pair → VaultMismatch.
do {
    _ = try openWithPassword(
        vaultTomlBytes: toml001,
        identityBundleBytes: bundle002,
        password: password001
    )
    check(false, "vault_001 toml + vault_002 bundle should have thrown VaultMismatch")
} catch UnlockError.VaultMismatch {
    check(true, "vault_001 toml + vault_002 bundle → VaultMismatch")
} catch {
    check(false, "vault mismatch threw \(error), expected VaultMismatch")
}

// Assertion 7: truncated TOML → CorruptVault(detail). The truncation
// suffix is the same distance the pytest suite uses
// (_TRUNCATION_SUFFIX_BYTES); aligning it keeps the cross-language
// "what counts as corrupt" surface uniform.
do {
    let truncated = Data(toml001.dropLast(TRUNCATION_SUFFIX_BYTES))
    _ = try openWithPassword(
        vaultTomlBytes: truncated,
        identityBundleBytes: bundle001,
        password: password001
    )
    check(false, "truncated toml should have thrown CorruptVault")
} catch let UnlockError.CorruptVault(detail) {
    check(true, "truncated toml → CorruptVault(detail=\"\(detail)\")")
} catch {
    check(false, "truncated toml threw \(error), expected CorruptVault")
}

// Assertion 8: use-after-wipe defaults (parity with Kotlin's explicit
// wipe() assertion). Assertion 4 above exercises wipe() via defer,
// which fires at scope exit and leaves no opportunity to inspect
// post-wipe state. This assertion calls wipe() in-line and verifies
// the documented non-throwing defaults: empty displayName, 16 zero
// bytes for userUuid, idempotent wipe.
do {
    let identity = try openWithPassword(
        vaultTomlBytes: toml001,
        identityBundleBytes: bundle001,
        password: password001
    )
    identity.wipe()
    identity.wipe() // idempotent — must not throw
    let nameAfterWipe = identity.displayName()
    let uuidAfterWipe = identity.userUuid()
    check(
        nameAfterWipe == "" && uuidAfterWipe == Data(repeating: 0, count: 16),
        "explicit wipe() → use-after-wipe returns empty defaults (got displayName=\"\(nameAfterWipe)\", uuid.count=\(uuidAfterWipe.count))"
    )
} catch {
    check(false, "explicit wipe() path threw \(error), expected to succeed")
}

// --- B.3a: open_with_recovery assertions ---

// Assertion 9: recovery success path.
do {
    let identity = try openWithRecovery(
        vaultTomlBytes: toml001,
        identityBundleBytes: bundle001,
        mnemonic: phrase001
    )
    defer { identity.wipe() }

    let displayName = identity.displayName()
    let uuid = identity.userUuid()
    check(
        displayName == expectedDisplayName && uuid == expectedUserUuid,
        "open_with_recovery success → display_name + user_uuid match pinned KAT (got displayName=\"\(displayName)\")"
    )
} catch {
    check(false, "open_with_recovery success threw \(error), expected to succeed")
}

// Assertion 10: wrong recovery phrase → WrongMnemonicOrCorrupt.
do {
    _ = try openWithRecovery(
        vaultTomlBytes: toml001,
        identityBundleBytes: bundle001,
        mnemonic: phrase002
    )
    check(false, "vault_002 phrase against vault_001 should have thrown WrongMnemonicOrCorrupt")
} catch UnlockError.WrongMnemonicOrCorrupt {
    check(true, "vault_002 phrase against vault_001 → WrongMnemonicOrCorrupt")
} catch {
    check(false, "wrong phrase threw \(error), expected WrongMnemonicOrCorrupt")
}

// Assertion 11: 3-word phrase → InvalidMnemonic(detail).
do {
    let bad = "only three words".data(using: .utf8)!
    _ = try openWithRecovery(
        vaultTomlBytes: toml001,
        identityBundleBytes: bundle001,
        mnemonic: bad
    )
    check(false, "3-word phrase should have thrown InvalidMnemonic")
} catch let UnlockError.InvalidMnemonic(detail) {
    check(
        detail.contains("got 3"),
        "3-word phrase → InvalidMnemonic(detail=\"\(detail)\") should mention `got 3`"
    )
} catch {
    check(false, "3-word phrase threw \(error), expected InvalidMnemonic")
}

// Assertion 12: cross-vault file pair with recovery path → VaultMismatch.
// Mnemonic correctness is irrelevant here; the vault_uuid + created_at_ms
// comparison fires before any mnemonic parse.
do {
    _ = try openWithRecovery(
        vaultTomlBytes: toml001,
        identityBundleBytes: bundle002,
        mnemonic: phrase001
    )
    check(false, "vault_001 toml + vault_002 bundle (recovery) should have thrown VaultMismatch")
} catch UnlockError.VaultMismatch {
    check(true, "vault_001 toml + vault_002 bundle (recovery) → VaultMismatch")
} catch {
    check(false, "vault mismatch (recovery) threw \(error), expected VaultMismatch")
}

// --- B.3b: create_vault assertions ---

// Assertion 13: create_vault produces a CreateVaultOutput with the
// expected shape — non-empty bytes for both on-disk artifacts, the
// identity is immediately live with the display_name we passed.
do {
    let out = try createVault(
        password: "smoke-runner-password".data(using: .utf8)!,
        displayName: "Owner",
        createdAtMs: 1_700_000_000_000
    )
    defer { out.identity.wipe() }
    defer { out.mnemonic.wipe() }
    let displayName = out.identity.displayName()
    let tomlNonEmpty = !out.vaultTomlBytes.isEmpty
    let bundleNonEmpty = !out.identityBundleBytes.isEmpty
    check(
        displayName == "Owner" && tomlNonEmpty && bundleNonEmpty,
        "create_vault shape: displayName=\"\(displayName)\" tomlBytes=\(out.vaultTomlBytes.count) bundleBytes=\(out.identityBundleBytes.count)"
    )
} catch {
    check(false, "create_vault threw \(error), expected to succeed")
}

// Assertion 14: round-trip with password — the vault bytes produced by
// create_vault re-open with the same password and yield the same
// display_name. Pins the create→open agreement.
do {
    let pw = "round-trip-password".data(using: .utf8)!
    let out = try createVault(
        password: pw,
        displayName: "RoundTripBob",
        createdAtMs: 1_700_000_000_000
    )
    defer { out.identity.wipe() }
    out.mnemonic.wipe()  // not used in this path
    let reopened = try openWithPassword(
        vaultTomlBytes: out.vaultTomlBytes,
        identityBundleBytes: out.identityBundleBytes,
        password: pw
    )
    defer { reopened.wipe() }
    check(
        reopened.displayName() == "RoundTripBob",
        "create→open_with_password round-trip: got displayName=\"\(reopened.displayName())\""
    )
} catch {
    check(false, "round-trip with password threw \(error), expected to succeed")
}

// Assertion 15: round-trip with recovery — take the phrase, re-open via
// the recovery path. Pins create→take→open end-to-end.
do {
    let out = try createVault(
        password: "unused".data(using: .utf8)!,
        displayName: "RoundTripCarol",
        createdAtMs: 1_700_000_000_000
    )
    defer { out.identity.wipe() }
    defer { out.mnemonic.wipe() }
    if let phrase = out.mnemonic.takePhrase() {
        let reopened = try openWithRecovery(
            vaultTomlBytes: out.vaultTomlBytes,
            identityBundleBytes: out.identityBundleBytes,
            mnemonic: Data(phrase)
        )
        defer { reopened.wipe() }
        check(
            reopened.displayName() == "RoundTripCarol",
            "create→take_phrase→open_with_recovery: got displayName=\"\(reopened.displayName())\""
        )
    } else {
        check(false, "take_phrase returned nil on first call")
    }
} catch {
    check(false, "round-trip with recovery threw \(error), expected to succeed")
}

// =============================================================================
// B.4a — folder-in open_vault asserts
// =============================================================================

// Assert 16: open_vault_with_password success — identity + manifest both populated.
do {
    let folderPath = Data(vault001Url.path.utf8)
    let out = try openVaultWithPassword(folderPath: folderPath, password: password001)
    defer { out.identity.wipe() }
    defer { out.manifest.wipe() }
    let displayName = out.identity.displayName()
    let blockCount = out.manifest.blockCount()
    check(
        displayName == expectedDisplayName && blockCount > 0,
        "open_vault_with_password success → displayName=\"\(displayName)\", blockCount=\(blockCount)"
    )
} catch {
    check(false, "open_vault_with_password success threw \(error), expected to succeed")
}

// Assert 17: open_vault_with_password wrong password → VaultError.WrongPasswordOrCorrupt.
do {
    let folderPath = Data(vault001Url.path.utf8)
    let wrongPassword = Data("definitely wrong".utf8)
    _ = try openVaultWithPassword(folderPath: folderPath, password: wrongPassword)
    check(false, "wrong password should have thrown VaultError.WrongPasswordOrCorrupt")
} catch VaultError.WrongPasswordOrCorrupt {
    check(true, "open_vault_with_password wrong password → VaultError.WrongPasswordOrCorrupt")
} catch {
    check(false, "wrong password (vault) threw \(error), expected VaultError.WrongPasswordOrCorrupt")
}

// Assert 18: nonexistent folder → VaultError.FolderInvalid with detail.
do {
    let folderPath = Data("/tmp/__nonexistent_b4a_swift__".utf8)
    _ = try openVaultWithPassword(folderPath: folderPath, password: password001)
    check(false, "nonexistent folder should have thrown VaultError.FolderInvalid")
} catch let e as VaultError {
    if case let .FolderInvalid(detail) = e {
        let lc = detail.lowercased()
        check(
            lc.contains("vault.toml") || lc.contains("no such file"),
            "nonexistent folder → VaultError.FolderInvalid(detail=\"\(detail)\")"
        )
    } else {
        check(false, "nonexistent folder threw wrong VaultError variant: \(e)")
    }
} catch {
    check(false, "nonexistent folder threw \(error), expected VaultError.FolderInvalid")
}

// =============================================================================
// B.4b — read_block asserts
// =============================================================================

let vault001BlockUuid = Data([
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
])

// Assert 19: read_block success — record_count == 1 + field_count == 2.
do {
    let folderPath = Data(vault001Url.path.utf8)
    let out = try openVaultWithPassword(folderPath: folderPath, password: password001)
    defer { out.identity.wipe() }
    defer { out.manifest.wipe() }
    let block = try readBlock(
        identity: out.identity,
        manifest: out.manifest,
        blockUuid: vault001BlockUuid
    )
    defer { block.wipe() }
    let recordCount = block.recordCount()
    let record = block.recordAt(idx: 0)
    let fieldCount = record?.fieldCount() ?? 0
    check(
        recordCount == 1 && fieldCount == 2,
        "read_block success → record_count == 1 + field_count == 2 (got \(recordCount), \(fieldCount))"
    )
} catch {
    check(false, "read_block success threw \(error), expected to succeed")
}

// Assert 20: field_by_name("password").expose_text() == "hunter2".
do {
    let folderPath = Data(vault001Url.path.utf8)
    let out = try openVaultWithPassword(folderPath: folderPath, password: password001)
    defer { out.identity.wipe() }
    defer { out.manifest.wipe() }
    let block = try readBlock(
        identity: out.identity,
        manifest: out.manifest,
        blockUuid: vault001BlockUuid
    )
    defer { block.wipe() }
    let record = block.recordAt(idx: 0)!
    let pwField = record.fieldByName(name: "password")!
    let secret = pwField.exposeText()
    check(
        secret == "hunter2",
        "field_by_name(\"password\").expose_text() == \"hunter2\" (got \"\(secret ?? "<nil>")\")"
    )
} catch {
    check(false, "expose_text threw \(error), expected to succeed")
}

// Assert 21: read_block(unknown_uuid) → VaultError.BlockNotFound(uuid matches).
do {
    let folderPath = Data(vault001Url.path.utf8)
    let out = try openVaultWithPassword(folderPath: folderPath, password: password001)
    defer { out.identity.wipe() }
    defer { out.manifest.wipe() }
    let unknownUuid = Data(repeating: 0, count: 16)
    _ = try readBlock(
        identity: out.identity,
        manifest: out.manifest,
        blockUuid: unknownUuid
    )
    check(false, "read_block(unknown_uuid) should have thrown VaultError.BlockNotFound")
} catch let e as VaultError {
    if case let .BlockNotFound(uuidHex) = e {
        check(
            uuidHex == "00000000000000000000000000000000",
            "read_block(unknown_uuid) → VaultError.BlockNotFound(uuid_hex=\"\(uuidHex)\")"
        )
    } else {
        check(false, "unknown UUID threw wrong VaultError variant: \(e)")
    }
} catch {
    check(false, "unknown UUID threw \(error), expected VaultError.BlockNotFound")
}

// Assert 22: wipe → record_count == 0.
do {
    let folderPath = Data(vault001Url.path.utf8)
    let out = try openVaultWithPassword(folderPath: folderPath, password: password001)
    defer { out.identity.wipe() }
    defer { out.manifest.wipe() }
    let block = try readBlock(
        identity: out.identity,
        manifest: out.manifest,
        blockUuid: vault001BlockUuid
    )
    block.wipe()
    let countAfter = block.recordCount()
    check(
        countAfter == 0,
        "wipe → record_count == 0 (got \(countAfter))"
    )
} catch {
    check(false, "wipe threw \(error), expected to succeed")
}

if !failures.isEmpty {
    FileHandle.standardError.write(
        Data("FAIL: \(failures.count) of 22 assertion(s) failed\n".utf8)
    )
    exit(1)
}

print("OK: secretary uniffi Swift smoke runner — all assertions passed.")
