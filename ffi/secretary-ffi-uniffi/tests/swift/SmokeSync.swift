// #187 sync parity-smoke for the projected uniffi sync surface.
//
// Task 2 of the #187 slice projected the sync orchestration surface onto
// uniffi (sync_status / sync_vault / sync_commit_decisions, plus the
// SyncStatusDto / SyncOutcomeDto / VetoDecisionDto value types). uniffi
// generates the Swift wrappers (lowerCamelCased UDL names) from the same
// `src/secretary.udl` definition that drives the Kotlin codegen, so a
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
//     errors as VaultError. uniffi generates Swift and Kotlin from one
//     definition, so the conflict round-trip is asserted Python-side (where
//     it can drive the real merge) while the Swift/Kotlin smokes assert the
//     projection's observable shape.
//
// Three assertions:
//   - Assert: sync_status on an empty state dir reports no state / no clocks.
//   - Assert: sync_vault on a fresh writable golden_vault_001 copy applies
//     automatically (single-device pass, nothing to merge).
//   - Assert: VetoDecisionDto round-trips its `keep_local` flag.

import Foundation

func runSyncAsserts(env: SmokeEnv) {
    // Assert: sync_status on a fresh empty state dir → no state, no clocks.
    do {
        let stateDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("secretary_smoke_swift_syncstate_\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: stateDir, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: stateDir) }

        let status = try syncStatus(
            stateDir: stateDir.path,
            vaultUuid: Data(repeating: 9, count: 16)
        )
        check(
            status.hasState == false,
            "sync_status(empty state dir): hasState == false"
        )
        check(
            status.deviceClocks.isEmpty == true,
            "sync_status(empty state dir): deviceClocks empty"
        )
    } catch {
        check(false, "sync_status on empty state dir threw \(error)")
    }

    // Assert: sync_vault on a fresh single-device vault applies automatically.
    do {
        let vaultDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("secretary_smoke_swift_syncvault_\(UUID().uuidString)")
        try _recursiveCopy(env.vault001Url, vaultDir)
        defer { try? FileManager.default.removeItem(at: vaultDir) }

        let stateDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("secretary_smoke_swift_syncvault_state_\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: stateDir, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: stateDir) }

        let outcome = try syncVault(
            stateDir: stateDir.path,
            vaultFolder: vaultDir.path,
            password: env.password001,
            nowMs: 1_715_000_000_000
        )
        if case .appliedAutomatically = outcome {
            check(true, "sync_vault(fresh single-device): appliedAutomatically")
        } else {
            check(false, "sync_vault(fresh single-device) returned \(outcome), expected appliedAutomatically")
        }
    } catch {
        check(false, "sync_vault on fresh vault threw \(error)")
    }

    // Assert: VetoDecisionDto round-trips its keep_local flag (DTO shape).
    let decision = VetoDecisionDto(
        recordUuidHex: String(repeating: "ab", count: 16),
        keepLocal: true
    )
    check(
        decision.keepLocal == true,
        "VetoDecisionDto: keepLocal round-trip"
    )
}
