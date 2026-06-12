import XCTest
import SecretaryVaultAccess

final class VaultLocationTests: XCTestCase {
    func testStoresDisplayNameAndBookmark() {
        let loc = VaultLocation(displayName: "MyVault", bookmark: Data([0x01, 0x02]))
        XCTAssertEqual(loc.displayName, "MyVault")
        XCTAssertEqual(loc.bookmark, Data([0x01, 0x02]))
    }

    func testEquatableByValue() {
        let a = VaultLocation(displayName: "V", bookmark: Data([0xAA]))
        let b = VaultLocation(displayName: "V", bookmark: Data([0xAA]))
        let c = VaultLocation(displayName: "V", bookmark: Data([0xBB]))
        XCTAssertEqual(a, b)
        XCTAssertNotEqual(a, c)
        let d = VaultLocation(displayName: "W", bookmark: Data([0xAA]))
        XCTAssertNotEqual(a, d)  // same bookmark, different displayName → not equal
    }
}
