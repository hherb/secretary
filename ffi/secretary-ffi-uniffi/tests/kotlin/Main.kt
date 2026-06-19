// JVM-host Kotlin smoke runner entrypoint for the uniffi binding pipeline.
//
// Verifies the round-trip surface defined in src/secretary.udl by calling
// the generated Kotlin wrappers (which dispatch to the cdylib
// `libsecretary_ffi_uniffi.dylib` via JNA + the C ABI). Mirrors the Rust
// unit tests in src/lib.rs and the Swift smoke runner in
// tests/swift/main.swift, so a contract change in any one language fails
// in all three places.
//
// Invocation: ffi/secretary-ffi-uniffi/tests/kotlin/run.sh
//
// The Smoke* sibling files (split out per issue #72 to keep each file
// under the 500-LOC guideline) carry the actual assertion bodies; this
// driver only loads the fixture environment, calls each group function
// in order, and reports the aggregated pass/fail summary.
//
// Group order matches the bytes-in → folder-in → read → write → lifecycle
// progression of the underlying uniffi API surface.

import kotlin.system.exitProcess

fun main() {
    val env = loadSmokeEnv()

    runBytesInAsserts(env)
    runFolderInAsserts(env)
    runReadBlockAsserts(env)
    runSaveBlockAsserts(env)
    runRecordEditAsserts(env)
    runBlockCrudAsserts(env)
    runShareBlockAsserts(env)
    runTrashRestoreAsserts(env)
    runDeviceSlotAsserts(env)
    runSyncAsserts(env)

    if (failures.isNotEmpty()) {
        System.err.println("FAIL: ${failures.size} of $assertsRun assertion(s) failed")
        exitProcess(1)
    }

    println("OK: secretary uniffi Kotlin smoke runner — all assertions passed.")
}
