import XCTest
@testable import SecretaryVaultAccess

final class MovePolicyTests: XCTestCase {
    func testHiddenWhenZeroOrOneBlock() {
        XCTAssertFalse(MovePolicy.hasMoveTargets(blockCount: 0))
        XCTAssertFalse(MovePolicy.hasMoveTargets(blockCount: 1))
    }

    func testShownOnceASecondBlockExists() {
        XCTAssertTrue(MovePolicy.hasMoveTargets(blockCount: 2))
        XCTAssertTrue(MovePolicy.hasMoveTargets(blockCount: 3))
    }
}
