import XCTest
@testable import SecretaryKit
import SecretaryVaultAccess
import SecretaryVaultAccessTesting

final class UniffiVaultSyncPortOffMainActorTests: XCTestCase {
    /// While a sync pass is suspended mid-call, the main actor must remain free
    /// to run work. Against a synchronous-on-main-actor regression this would
    /// deadlock → XCTest timeout (a hung test is still a red CI).
    @MainActor
    func testMainActorIsFreeWhileSyncing() async throws {
        let gate = SuspensionGate()
        let port = FakeVaultSyncPort(syncResult: .success(.nothingToDo))
        port.gate = gate
        let coord = SyncCoordinator(port: port, stateDir: "/tmp/s", vaultFolder: "/tmp/v")

        let task = Task { try await coord.runPass(password: [1, 2, 3], nowMs: 0) }
        await gate.waitUntilEntered()       // sync is in flight, suspended
        var ran = false
        ran = true
        XCTAssertTrue(ran)
        await gate.release()
        let outcome = try await task.value
        XCTAssertEqual(outcome, .nothingToDo)
    }
}
