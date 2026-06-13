import XCTest
@testable import SecretaryVaultAccess

final class PasswordMatchTests: XCTestCase {
    func testMatchingNonEmpty() {
        XCTAssertTrue(passwordsMatch(Array("hunter2".utf8), Array("hunter2".utf8)))
    }

    func testEmptyDoesNotMatch() {
        // An empty password is not a valid create credential even if "confirmed".
        XCTAssertFalse(passwordsMatch([], []))
    }

    func testMismatch() {
        XCTAssertFalse(passwordsMatch(Array("a".utf8), Array("b".utf8)))
    }
}
