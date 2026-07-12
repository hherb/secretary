import XCTest
@testable import SecretaryVaultAccessUI
import SecretaryVaultAccess
import SecretaryVaultAccessTesting

@MainActor
final class RetargetableReauthGateTests: XCTestCase {
    private let t0 = MonotonicInstant(nanoseconds: 5_000_000)

    /// Records each `(window, seed)` the gate asked the factory to build and
    /// hands back a fresh `FakeWriteReauthGate` each time, so a test can see
    /// which delegate a subsequent `authorizeWrite` was routed to.
    @MainActor
    private final class RecordingFactory {
        var builds: [(window: Duration, seed: MonotonicInstant?)] = []
        var gates: [FakeWriteReauthGate] = []
        func make(_ window: Duration, _ seed: MonotonicInstant?) -> WriteReauthGate {
            builds.append((window, seed))
            let g = FakeWriteReauthGate()
            gates.append(g)
            return g
        }
    }

    func testInitBuildsDelegateOnceFromCtorArgs() {
        let f = RecordingFactory()
        _ = RetargetableReauthGate(window: .seconds(120), initialAuthAt: t0,
                                   clock: { self.t0 }, makeDelegate: f.make)
        XCTAssertEqual(f.builds.count, 1)
        XCTAssertEqual(f.builds[0].window, .seconds(120))
        XCTAssertEqual(f.builds[0].seed, t0)
    }

    func testAuthorizeForwardsToCurrentDelegate() async throws {
        let f = RecordingFactory()
        let gate = RetargetableReauthGate(window: .seconds(120), initialAuthAt: nil,
                                          clock: { self.t0 }, makeDelegate: f.make)
        try await gate.authorizeWrite(reason: "x")
        XCTAssertEqual(f.gates[0].authorizeCount, 1)
    }

    func testRetargetBuildsNewDelegateWithNewWindowSeededAtNow() {
        let f = RecordingFactory()
        var now = t0
        let gate = RetargetableReauthGate(window: .seconds(120), initialAuthAt: nil,
                                          clock: { now }, makeDelegate: f.make)
        now = t0.advanced(by: .seconds(10))
        gate.retarget(window: .seconds(600))
        XCTAssertEqual(f.builds.count, 2)
        XCTAssertEqual(f.builds[1].window, .seconds(600), "delegate rebuilt with the new window")
        XCTAssertEqual(f.builds[1].seed, now,
                       "new window seeded at now (retarget only runs after a successful gated save → user present)")
    }

    func testAuthorizeForwardsToNewDelegateAfterRetarget() async throws {
        let f = RecordingFactory()
        let gate = RetargetableReauthGate(window: .seconds(120), initialAuthAt: nil,
                                          clock: { self.t0 }, makeDelegate: f.make)
        gate.retarget(window: .seconds(600))
        try await gate.authorizeWrite(reason: "x")
        XCTAssertEqual(f.gates[0].authorizeCount, 0, "old delegate no longer used")
        XCTAssertEqual(f.gates[1].authorizeCount, 1, "current delegate is the retargeted one")
    }

    func testForwardsAuthorizeFailure() async {
        let f = RecordingFactory()
        let gate = RetargetableReauthGate(window: .seconds(120), initialAuthAt: nil,
                                          clock: { self.t0 }, makeDelegate: f.make)
        f.gates[0].failNext = .reauthFailed("cancelled")
        do { try await gate.authorizeWrite(reason: "x"); XCTFail("should propagate the delegate's throw") }
        catch { XCTAssertEqual(error as? VaultAccessError, .reauthFailed("cancelled")) }
    }
}
