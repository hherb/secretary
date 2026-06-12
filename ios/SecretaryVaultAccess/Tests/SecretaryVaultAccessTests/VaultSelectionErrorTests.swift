import XCTest
import SecretaryVaultAccess

final class VaultSelectionErrorTests: XCTestCase {
    func testErrorIsEquatable() {
        XCTAssertEqual(VaultSelectionError.noVaultSelected, .noVaultSelected)
        XCTAssertEqual(VaultSelectionError.locationUnavailable("x"),
                       .locationUnavailable("x"))
        XCTAssertNotEqual(VaultSelectionError.locationUnavailable("x"),
                          .locationUnavailable("y"))
    }
}
