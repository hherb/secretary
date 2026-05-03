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

if !failures.isEmpty {
    FileHandle.standardError.write(
        Data("FAIL: \(failures.count) of 3 assertion(s) failed\n".utf8)
    )
    exit(1)
}

print("OK: secretary uniffi Swift smoke runner — all assertions passed.")
