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

if !failures.isEmpty {
    FileHandle.standardError.write(
        Data("FAIL: \(failures.count) of 7 assertion(s) failed\n".utf8)
    )
    exit(1)
}

print("OK: secretary uniffi Swift smoke runner — all assertions passed.")
