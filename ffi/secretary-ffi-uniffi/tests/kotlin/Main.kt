// JVM-host Kotlin smoke runner for the uniffi binding pipeline.
//
// Verifies the round-trip surface defined in src/secretary.udl by
// calling the generated Kotlin wrappers (which dispatch to the cdylib
// `libsecretary_ffi_uniffi.dylib` via JNA + the C ABI). Mirrors the
// Rust unit tests in src/lib.rs and the Swift smoke runner in
// tests/swift/main.swift, so a contract change in any one language
// fails in all three places.
//
// Invocation: ffi/secretary-ffi-uniffi/tests/kotlin/run.sh

import uniffi.secretary.add
import uniffi.secretary.version
import kotlin.system.exitProcess

// Vault format version pinned to the value in core/src/version.rs. A
// FORMAT_VERSION bump is a normative protocol break and must update
// this constant in lockstep with the spec — that keeps the smoke test
// honest as a cross-language contract assertion rather than a tautology.
private const val EXPECTED_FORMAT_VERSION: UShort = 1u

// Collect failures rather than exit on first so a single run reports
// every contract that drifted, not just the first. The smoke surface
// is small now but grows in B.2+; aggregating from the start avoids
// the painful "fix one assertion, re-run, find another" loop.
private val failures: MutableList<String> = mutableListOf()

private fun check(condition: Boolean, message: String) {
    if (condition) {
        println("PASS: $message")
    } else {
        System.err.println("FAIL: $message")
        failures.add(message)
    }
}

fun main() {
    val sumSmall = add(2u, 3u)
    check(sumSmall == 5u, "add(2, 3) == 5 (got $sumSmall)")

    val sumWrap = add(UInt.MAX_VALUE, 1u)
    check(sumWrap == 0u, "add(UInt.MAX_VALUE, 1) wraps to 0 (got $sumWrap)")

    val v = version()
    check(
        v == EXPECTED_FORMAT_VERSION,
        "version() == $EXPECTED_FORMAT_VERSION (got $v)",
    )

    if (failures.isNotEmpty()) {
        System.err.println("FAIL: ${failures.size} of 3 assertion(s) failed")
        exitProcess(1)
    }

    println("OK: secretary uniffi Kotlin smoke runner — all assertions passed.")
}
