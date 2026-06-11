import XCTest
@testable import SecretaryVaultAccess

final class ModelsTests: XCTestCase {
    func testAutoHideIntervalIsPositive() {
        XCTAssertGreaterThan(RevealPolicy.autoHideSeconds, 0)
    }
}
