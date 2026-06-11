import XCTest
@testable import SecretaryVaultAccess

final class ModelsTests: XCTestCase {
    func testAutoHideIntervalIsPositive() {
        XCTAssertGreaterThan(RevealPolicy.autoHideSeconds, 0)
    }

    func testBlockSummaryUuidHexIsLowercaseNoDashes() {
        let s = BlockSummary(
            uuid: [0x00, 0x11, 0xab, 0xcd] + Array(repeating: 0xff, count: 12),
            name: "Logins", createdAtMs: 1, lastModMs: 2)
        XCTAssertEqual(s.uuidHex, "0011abcd" + String(repeating: "ff", count: 12))
    }

    func testRecordViewUuidHexAndFieldKinds() throws {
        let field = FieldView(name: "password", kind: .text) { .text("hunter2") }
        let rec = RecordView(
            uuid: Array(repeating: 0x01, count: 16),
            type: "login", tags: ["work"], fields: [field])
        XCTAssertEqual(rec.uuidHex, String(repeating: "01", count: 16))
        XCTAssertEqual(rec.fields.first?.kind, .text)
        XCTAssertEqual(try rec.fields.first?.reveal(), .text("hunter2"))
    }

    func testRevealedValueEquatable() {
        XCTAssertEqual(RevealedValue.bytes([1, 2, 3]), .bytes([1, 2, 3]))
        XCTAssertNotEqual(RevealedValue.text("a"), .text("b"))
    }
}
