import XCTest
import SecretaryVaultAccess
@testable import SecretaryVaultAccessUI

final class ReauthSeedingTests: XCTestCase {
    func testBiometricUnlockSeedsWithNow() {
        let now = MonotonicInstant(nanoseconds: 42)
        XCTAssertEqual(reauthInitialAuthAt(biometricUnlock: true, now: now), now)
    }

    func testPasswordOrRecoveryDoesNotSeed() {
        let now = MonotonicInstant(nanoseconds: 42)
        XCTAssertNil(reauthInitialAuthAt(biometricUnlock: false, now: now))
    }
}
