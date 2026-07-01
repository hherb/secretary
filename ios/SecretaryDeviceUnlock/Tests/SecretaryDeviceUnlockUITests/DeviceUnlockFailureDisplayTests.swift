import XCTest
import SecretaryDeviceUnlock
@testable import SecretaryDeviceUnlockUI

final class DeviceUnlockFailureDisplayTests: XCTestCase {
    func testUserCancelledIsSilent() {
        XCTAssertEqual(deviceUnlockFailureDisplay(.userCancelled), .silent)
    }

    func testNonCancelFailuresSurfaceAMessage() {
        // Every non-cancel case must produce a non-empty message — never silent.
        let nonCancel: [DeviceUnlockError] = [
            .biometryUnavailable, .biometryNotEnrolled, .biometryLockout,
            .authenticationFailed, .notEnrolled, .vaultSlotMismatch,
            .wrappedSecretCorrupt, .wrongDeviceSecretOrCorrupt,
            .vault(.other("x")), .enclave("domain=… code=…"),
        ]
        for err in nonCancel {
            guard case let .message(text) = deviceUnlockFailureDisplay(err) else {
                return XCTFail("\(err) must surface a message, not be silent")
            }
            XCTAssertFalse(text.isEmpty, "\(err) produced an empty message")
        }
    }
}
