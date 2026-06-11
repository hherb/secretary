import XCTest
import SecretaryDeviceUnlock
@testable import SecretaryDeviceUnlockUI

final class DeviceUnlockStateTests: XCTestCase {
    func testStatesAreEquatable() {
        XCTAssertEqual(DeviceUnlockState.busy(.unlocking), .busy(.unlocking))
        XCTAssertNotEqual(DeviceUnlockState.busy(.unlocking), .busy(.enrolling))
        XCTAssertEqual(DeviceUnlockState.unlocked(vaultUuidHex: "ab"),
                       .unlocked(vaultUuidHex: "ab"))
        XCTAssertEqual(DeviceUnlockState.failed(.userCancelled, detail: "d"),
                       .failed(.userCancelled, detail: "d"))
        XCTAssertNotEqual(DeviceUnlockState.failed(.userCancelled, detail: "d"),
                          .failed(.userCancelled, detail: nil))
    }
}
