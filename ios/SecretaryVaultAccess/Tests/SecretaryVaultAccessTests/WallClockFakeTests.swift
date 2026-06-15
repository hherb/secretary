import XCTest
import SecretaryVaultAccess
import SecretaryVaultAccessTesting

final class WallClockFakeTests: XCTestCase {
    func testReturnsSeededValueAndIsSettable() {
        let clock = FakeWallClock(nowMs: 1_000)
        XCTAssertEqual(clock.nowMs(), 1_000)
        clock.currentMs = 2_500
        XCTAssertEqual(clock.nowMs(), 2_500)
    }
}
