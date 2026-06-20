import XCTest
@testable import SecretaryVaultAccess

final class ReauthTests: XCTestCase {
    private let t0 = Date(timeIntervalSince1970: 1_000_000)

    func testNeverAuthedNeedsReauth() {
        XCTAssertTrue(needsReauth(lastAuthAt: nil, now: t0, window: 30))
    }

    func testWithinWindowDoesNotNeedReauth() {
        let last = t0
        let now = t0.addingTimeInterval(29)
        XCTAssertFalse(needsReauth(lastAuthAt: last, now: now, window: 30))
    }

    func testAtExactWindowNeedsReauth() {
        let last = t0
        let now = t0.addingTimeInterval(30)
        XCTAssertTrue(needsReauth(lastAuthAt: last, now: now, window: 30),
                      "boundary is inclusive: exactly `window` ⇒ re-auth")
    }

    func testPastWindowNeedsReauth() {
        XCTAssertTrue(needsReauth(lastAuthAt: t0, now: t0.addingTimeInterval(31), window: 30))
    }

    func testV1DefaultIsThirtySeconds() {
        XCTAssertEqual(ReauthWindow.v1Default, 30)
    }

    func testReauthFailedEquatable() {
        XCTAssertEqual(VaultAccessError.reauthFailed("x"), .reauthFailed("x"))
        XCTAssertNotEqual(VaultAccessError.reauthFailed("x"), .reauthFailed("y"))
    }
}
