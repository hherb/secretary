import XCTest
@testable import SecretaryVaultAccess

final class RecoveryPhraseTests: XCTestCase {
    func testTrimsAndCollapsesInternalWhitespace() {
        XCTAssertEqual(
            RecoveryPhrase.normalize("  wall   annual\tclay\nzebra "),
            "wall annual clay zebra")
    }

    func testLowercases() {
        XCTAssertEqual(RecoveryPhrase.normalize("Wall ANNUAL Clay"), "wall annual clay")
    }

    func testEmptyAndWhitespaceOnly() {
        XCTAssertEqual(RecoveryPhrase.normalize("   \n\t "), "")
        XCTAssertEqual(RecoveryPhrase.normalize(""), "")
    }
}
