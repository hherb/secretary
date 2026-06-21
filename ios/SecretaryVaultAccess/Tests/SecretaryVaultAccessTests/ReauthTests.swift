import XCTest
@testable import SecretaryVaultAccess

final class ReauthTests: XCTestCase {
    // Arbitrary monotonic origin; only differences from it matter.
    private let t0 = MonotonicInstant(nanoseconds: 1_000_000)
    private let window: Duration = .seconds(30)

    private func at(_ seconds: Int) -> MonotonicInstant { t0.advanced(by: .seconds(seconds)) }

    func testNeverAuthedNeedsReauth() {
        XCTAssertTrue(needsReauth(lastAuthAt: nil, now: t0, window: window))
    }

    func testWithinWindowDoesNotNeedReauth() {
        XCTAssertFalse(needsReauth(lastAuthAt: t0, now: at(29), window: window))
    }

    func testAtExactWindowNeedsReauth() {
        XCTAssertTrue(needsReauth(lastAuthAt: t0, now: at(30), window: window),
                      "boundary is inclusive: exactly `window` ⇒ re-auth")
    }

    func testPastWindowNeedsReauth() {
        XCTAssertTrue(needsReauth(lastAuthAt: t0, now: at(31), window: window))
    }

    func testV1DefaultIsThirtySeconds() {
        XCTAssertEqual(ReauthWindow.v1Default, .seconds(30))
    }

    func testReauthFailedEquatable() {
        XCTAssertEqual(VaultAccessError.reauthFailed("x"), .reauthFailed("x"))
        XCTAssertNotEqual(VaultAccessError.reauthFailed("x"), .reauthFailed("y"))
    }
}
