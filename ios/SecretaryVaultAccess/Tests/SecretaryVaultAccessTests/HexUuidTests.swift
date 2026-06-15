import XCTest
import SecretaryVaultAccess

final class HexUuidTests: XCTestCase {
    func testDecodes32CharHexTo16Bytes() {
        let bytes = HexUuid.bytes(fromHex: "000102030405060708090a0b0c0d0e0f")
        XCTAssertEqual(bytes, [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15])
    }
    func testAcceptsUppercase() {
        XCTAssertEqual(HexUuid.bytes(fromHex: "AABB"), [0xAA, 0xBB])
    }
    func testRejectsOddLength() {
        XCTAssertNil(HexUuid.bytes(fromHex: "abc"))
    }
    func testRejectsNonHex() {
        XCTAssertNil(HexUuid.bytes(fromHex: "zz"))
    }
    func testEmptyStringDecodesToEmpty() {
        XCTAssertEqual(HexUuid.bytes(fromHex: ""), [])
    }
}
