import XCTest
@testable import SecretaryVaultAccess

final class MonotonicInstantTests: XCTestCase {
    func testOrdersByNanoseconds() {
        XCTAssertLessThan(MonotonicInstant(nanoseconds: 1), MonotonicInstant(nanoseconds: 2))
    }

    func testAdvanceByDurationAddsWholeNanoseconds() {
        let t = MonotonicInstant(nanoseconds: 1_000)
        XCTAssertEqual(t.advanced(by: .milliseconds(2)), MonotonicInstant(nanoseconds: 2_001_000))
    }

    func testDurationToLaterInstantIsNonNegative() {
        let a = MonotonicInstant(nanoseconds: 1_000)
        let b = MonotonicInstant(nanoseconds: 4_000)
        XCTAssertEqual(a.duration(to: b), .nanoseconds(3_000))
    }

    func testDefaultDebounceWindowIsTwoSeconds() {
        XCTAssertEqual(ChangeDetectionTuning.defaultDebounceWindow, .milliseconds(2_000))
    }
}
