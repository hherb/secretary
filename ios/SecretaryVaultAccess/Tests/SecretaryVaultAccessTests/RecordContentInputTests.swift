// ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/RecordContentInputTests.swift
import XCTest
import SecretaryVaultAccess

final class RecordContentInputTests: XCTestCase {
    func testValidContentPassesValidation() {
        let c = RecordContentInput(
            recordType: "login", tags: ["work"],
            fields: [
                FieldContentInput(name: "user", value: .text("alice")),
                FieldContentInput(name: "key", value: .bytes([0xDE, 0xAD])),
            ])
        XCTAssertNil(c.validate())
    }

    func testEmptyFieldNameIsRejected() {
        let c = RecordContentInput(recordType: "login", tags: [],
            fields: [FieldContentInput(name: "  ", value: .text("x"))])
        XCTAssertEqual(c.validate(), .emptyFieldName)
    }

    func testDuplicateFieldNamesAreRejected() {
        let c = RecordContentInput(recordType: "login", tags: [],
            fields: [
                FieldContentInput(name: "user", value: .text("a")),
                FieldContentInput(name: "user", value: .text("b")),
            ])
        XCTAssertEqual(c.validate(), .duplicateFieldName("user"))
    }

    func testEmptyRecordIsValid() {
        XCTAssertNil(RecordContentInput(recordType: "", tags: [], fields: []).validate())
    }
}
