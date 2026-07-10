// #187 sync parity-smoke for the projected uniffi sync surface (Kotlin mirror).
//
// Task 2 of the #187 slice projected the sync orchestration surface onto
// uniffi (sync_status / sync_vault / sync_commit_decisions, plus the
// SyncStatusDto / SyncOutcomeDto / VetoDecisionDto value types). uniffi
// generates the Kotlin wrappers (lowerCamelCased UDL names) from the same
// `src/secretary.udl` definition that drives the Swift codegen, so a
// single Rust-side change fails in all three host languages.
//
// This smoke is deliberately a *parity* check, not a full conflict
// round-trip:
//
//   - The substantive sync logic (clock math, CRDT merge, veto/collision
//     projection, rollback rejection) lives in the shared Rust core and is
//     exercised exhaustively by the Rust unit/integration tests and by the
//     stdlib-only Python conformance verifier. Re-asserting that behaviour
//     here would duplicate the core's own coverage in a language that only
//     sees the thinned FFI projection.
//   - What the host-language smokes uniquely prove is that the *binding
//     surface* is wired correctly: the functions exist, take the expected
//     argument shapes, return the expected DTO/enum shapes, and surface
//     errors as VaultException. uniffi generates Swift and Kotlin from one
//     definition, so the conflict round-trip is asserted Python-side (where
//     it can drive the real merge) while the Swift/Kotlin smokes assert the
//     projection's observable shape.
//
// This is the Kotlin mirror of tests/swift/SmokeSync.swift; the three
// assertions match one-for-one.
//
// Three assertions:
//   - Assert: sync_status on an empty state dir reports no state / no clocks.
//   - Assert: sync_vault on a fresh writable golden_vault_001 copy applies
//     automatically (single-device pass, nothing to merge).
//   - Assert: VetoDecisionDto round-trips its `keep_local` flag.

import uniffi.secretary.SyncOutcomeDto
import uniffi.secretary.VetoDecisionDto
import uniffi.secretary.syncStatus
import uniffi.secretary.syncVault

fun runSyncAsserts(env: SmokeEnv) {
    // Assert: sync_status on a fresh empty state dir → no state, no clocks.
    var stateTmp: java.nio.file.Path? = null
    try {
        val stateDir = java.nio.file.Files.createTempDirectory(
            "secretary_smoke_kotlin_syncstate_",
        )
        stateTmp = stateDir
        val status = syncStatus(stateDir.toString(), ByteArray(16) { 9 })
        check(
            !status.hasState,
            "sync_status(empty state dir): hasState == false",
        )
        check(
            status.deviceClocks.isEmpty(),
            "sync_status(empty state dir): deviceClocks empty",
        )
    } catch (e: Throwable) {
        check(false, "sync_status on empty state dir threw $e")
    } finally {
        stateTmp?.let { cleanupTempVault(it) }
    }

    // Assert: sync_vault on a fresh single-device vault applies automatically.
    var vaultTmp: java.nio.file.Path? = null
    var stateDirTmp: java.nio.file.Path? = null
    try {
        val vaultFolder = java.nio.file.Files.createTempDirectory(
            "secretary_smoke_kotlin_syncvault_",
        )
        vaultTmp = vaultFolder
        recursiveCopy(env.vault001Path, vaultFolder)

        val stateDir = java.nio.file.Files.createTempDirectory(
            "secretary_smoke_kotlin_syncvault_state_",
        )
        stateDirTmp = stateDir

        val outcome = syncVault(
            stateDir.toString(),
            vaultFolder.toString(),
            env.password001.direct(),
            1_715_000_000_000UL,
        )
        if (outcome is SyncOutcomeDto.AppliedAutomatically) {
            check(true, "sync_vault(fresh single-device): appliedAutomatically")
        } else {
            check(
                false,
                "sync_vault(fresh single-device) returned $outcome, expected AppliedAutomatically",
            )
        }
    } catch (e: Throwable) {
        check(false, "sync_vault on fresh vault threw $e")
    } finally {
        vaultTmp?.let { cleanupTempVault(it) }
        stateDirTmp?.let { cleanupTempVault(it) }
    }

    // Assert: VetoDecisionDto round-trips its keep_local flag (DTO shape).
    val decision = VetoDecisionDto(
        recordUuidHex = "ab".repeat(16),
        keepLocal = true,
    )
    check(
        decision.keepLocal,
        "VetoDecisionDto: keepLocal round-trip",
    )
}
