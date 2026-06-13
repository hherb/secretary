import XCTest
@testable import SecretaryVaultAccess

final class VaultNameTests: XCTestCase {
    func testValidName() {
        XCTAssertEqual(validateVaultName("My Vault"), .valid("My Vault"))
    }

    func testTrimsSurroundingWhitespace() {
        XCTAssertEqual(validateVaultName("  vault  "), .valid("vault"))
    }

    func testEmptyIsRejected() {
        XCTAssertEqual(validateVaultName(""), .invalid(.empty))
        XCTAssertEqual(validateVaultName("   "), .invalid(.empty))
    }

    func testPathSeparatorIsRejected() {
        XCTAssertEqual(validateVaultName("a/b"), .invalid(.containsSeparator))
    }

    func testDotNamesAreRejected() {
        XCTAssertEqual(validateVaultName("."), .invalid(.reservedName))
        XCTAssertEqual(validateVaultName(".."), .invalid(.reservedName))
    }

    func testNullByteIsRejected() {
        XCTAssertEqual(validateVaultName("a\u{0}b"), .invalid(.containsSeparator))
    }

    func testTrimThenReservedOrdering() {
        // Whitespace is trimmed first, then reserved-name check fires: " . " → "." → .reservedName.
        XCTAssertEqual(validateVaultName(" . "), .invalid(.reservedName))
    }

    func testLeadingSlashRejected() {
        XCTAssertEqual(validateVaultName("/absolute"), .invalid(.containsSeparator))
    }

    func testBareNullByteRejected() {
        XCTAssertEqual(validateVaultName("\u{0}"), .invalid(.containsSeparator))
    }
}
