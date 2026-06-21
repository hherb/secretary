import XCTest
@testable import SecretaryVaultAccessUI
import SecretaryVaultAccess
import SecretaryVaultAccessTesting

@MainActor
final class GraceWindowReauthGateTests: XCTestCase {
    // Arbitrary monotonic origin; the gate only reads differences from it.
    private let t0 = MonotonicInstant(nanoseconds: 2_000_000)
    private let window: Duration = .seconds(30)

    private func at(_ seconds: Int) -> MonotonicInstant { t0.advanced(by: .seconds(seconds)) }

    func testNotEnrolledIsNoOp() async throws {
        let auth = FakeBiometricAuthorizer(isEnrolled: false)
        let gate = GraceWindowReauthGate(authorizer: auth, clock: { self.t0 })
        try await gate.authorizeWrite(reason: "x")
        XCTAssertEqual(auth.authorizeCount, 0, "no SE key ⇒ never prompt")
    }

    func testEnrolledNeverAuthedPromptsOnce() async throws {
        let auth = FakeBiometricAuthorizer(isEnrolled: true)
        let gate = GraceWindowReauthGate(authorizer: auth, clock: { self.t0 })
        try await gate.authorizeWrite(reason: "x")
        XCTAssertEqual(auth.authorizeCount, 1)
    }

    func testWithinGraceDoesNotReprompt() async throws {
        var t = t0
        let auth = FakeBiometricAuthorizer(isEnrolled: true)
        let gate = GraceWindowReauthGate(authorizer: auth, window: window, clock: { t })
        try await gate.authorizeWrite(reason: "x")     // prompts, lastAuthAt = t0
        t = at(10)
        try await gate.authorizeWrite(reason: "x")     // within grace
        XCTAssertEqual(auth.authorizeCount, 1)
    }

    func testPastGraceReprompts() async throws {
        var t = t0
        let auth = FakeBiometricAuthorizer(isEnrolled: true)
        let gate = GraceWindowReauthGate(authorizer: auth, window: window, clock: { t })
        try await gate.authorizeWrite(reason: "x")     // prompt 1
        t = at(31)
        try await gate.authorizeWrite(reason: "x")     // prompt 2
        XCTAssertEqual(auth.authorizeCount, 2)
    }

    func testFailureLeavesClockUnchanged() async throws {
        var t = t0
        let auth = FakeBiometricAuthorizer(isEnrolled: true)
        auth.failNextAuthorize = VaultAccessError.reauthFailed("cancelled")
        let gate = GraceWindowReauthGate(authorizer: auth, window: window, clock: { t })
        do { try await gate.authorizeWrite(reason: "x"); XCTFail("should throw") }
        catch {}
        // lastAuthAt was NOT advanced, so the next write still prompts immediately.
        t = at(1)
        try await gate.authorizeWrite(reason: "x")
        XCTAssertEqual(auth.authorizeCount, 2)
    }

    func testInitialAuthAtSeedsGrace() async throws {
        let auth = FakeBiometricAuthorizer(isEnrolled: true)
        // Seeded as just-authed (e.g. a device-unlock open); first write is free.
        let gate = GraceWindowReauthGate(authorizer: auth, window: window,
                                         clock: { self.t0 }, initialAuthAt: self.t0)
        try await gate.authorizeWrite(reason: "x")
        XCTAssertEqual(auth.authorizeCount, 0)
    }
}
