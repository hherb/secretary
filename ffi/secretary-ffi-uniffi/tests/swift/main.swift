// macOS-host Swift smoke runner entrypoint for the uniffi binding pipeline.
//
// Verifies the round-trip surface defined in src/secretary.udl by calling
// the generated Swift wrappers (which dispatch to the cdylib
// `libsecretary_ffi_uniffi.dylib` via the C ABI). Mirrors the Rust unit
// tests in src/lib.rs and the Kotlin smoke runner in tests/kotlin/Main.kt,
// so a contract change in any one language fails in all three places.
//
// Invocation: ffi/secretary-ffi-uniffi/tests/swift/run.sh
//
// The Smoke* sibling files (split out per issue #72 to keep each file
// under the 500-LOC guideline) carry the actual assertion bodies; this
// driver only loads the fixture environment, calls each group function
// in order, and reports the aggregated pass/fail summary.
//
// Group order matches the bytes-in → folder-in → read → write → lifecycle
// progression of the underlying uniffi API surface.

import Foundation

let env = loadSmokeEnv()

runBytesInAsserts(env: env)
runFolderInAsserts(env: env)
runReadBlockAsserts(env: env)
runSaveBlockAsserts(env: env)
runRecordEditAsserts(env: env)
runShareBlockAsserts(env: env)
runTrashRestoreAsserts(env: env)
runDeviceSlotAsserts(env: env)
runSyncAsserts(env: env)

if !failures.isEmpty {
    FileHandle.standardError.write(
        Data("FAIL: \(failures.count) of \(assertsRun) assertion(s) failed\n".utf8)
    )
    exit(1)
}

print("OK: secretary uniffi Swift smoke runner — all assertions passed.")
