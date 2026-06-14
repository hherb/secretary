import XCTest
@testable import SecretaryKit
import SecretaryVaultAccess
import SecretaryVaultAccessTesting

/// Both `sync` and `commitDecisions` re-open the identity (Argon2id) and so are
/// offloaded off the calling actor via `runOffMainActor` in `UniffiVaultSyncPort`
/// — the same plumbing the open path uses. These tests prove the contract at the
/// coordinator boundary using `FakeVaultSyncPort` + `SuspensionGate`: reaching
/// past `waitUntilEntered()` while the pass is suspended is only possible if the
/// `@MainActor` test interleaved with the in-flight pass. Against a
/// synchronous-on-main-actor regression the test would deadlock → XCTest timeout
/// (a hung test is still a red CI).
final class UniffiVaultSyncPortOffMainActorTests: XCTestCase {
    private let pw: [UInt8] = [1, 2, 3]

    @MainActor
    func testMainActorIsFreeWhileSyncing() async throws {
        let gate = SuspensionGate()
        let port = FakeVaultSyncPort(syncResult: .success(.nothingToDo))
        port.gate = gate
        let coord = SyncCoordinator(port: port, stateDir: "/tmp/s", vaultFolder: "/tmp/v")

        let task = Task { try await coord.runPass(password: pw, nowMs: 0) }
        await gate.waitUntilEntered()   // sync is in flight, suspended off the main actor

        // Reaching here is the proof: this @MainActor test interleaved with the
        // in-flight pass. Had runPass blocked the main actor, the Task body could
        // not run, gate.enterAndWait() would never fire, and waitUntilEntered()
        // would hang → XCTest timeout. The spy makes the structural proof
        // load-bearing: FakeVaultSyncPort increments syncCalls BEFORE awaiting
        // the gate, so observing 1 from the still-live main actor demonstrates
        // the off-actor entry.
        XCTAssertEqual(port.syncCalls, 1, "port entered sync off the main actor while the test stayed live")

        await gate.release()
        let outcome = try await task.value
        XCTAssertEqual(outcome, .nothingToDo)
    }

    @MainActor
    func testMainActorIsFreeWhileCommitting() async throws {
        let veto = SyncVeto(recordUuidHex: "aa", recordType: "login", tags: [],
                            fieldNames: ["password"], localLastModMs: 1,
                            peerTombstonedAtMs: 2, peerDeviceHex: "bb")
        // First pass detects a conflict (no gate) so the coordinator stashes a
        // token; then the commit path is the one we hold mid-flight.
        let port = FakeVaultSyncPort(
            syncResult: .success(.conflictsPending(vetoes: [veto], collisions: [], manifestHash: [9])),
            commitResult: .success(.mergedClean))
        let coord = SyncCoordinator(port: port, stateDir: "/tmp/s", vaultFolder: "/tmp/v")
        _ = try await coord.runPass(password: pw, nowMs: 0)

        let gate = SuspensionGate()
        port.gate = gate
        let task = Task { try await coord.resolve(decisions: [], password: pw, nowMs: 0) }
        await gate.waitUntilEntered()   // commit is in flight, suspended off the main actor

        XCTAssertEqual(port.commitCalls, 1, "port entered commit off the main actor while the test stayed live")

        await gate.release()
        let outcome = try await task.value
        XCTAssertEqual(outcome, .mergedClean)
    }
}
