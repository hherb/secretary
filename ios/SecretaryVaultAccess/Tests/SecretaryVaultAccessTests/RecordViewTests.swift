// ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/RecordViewTests.swift
import XCTest
import SecretaryVaultAccess

final class RecordViewTests: XCTestCase {
    func testTombstoneDefaultsFalse() {
        let r = RecordView(uuid: [0x01], type: "login", tags: [], fields: [])
        XCTAssertFalse(r.tombstone)
    }
    func testTombstoneCanBeSet() {
        let r = RecordView(uuid: [0x01], type: "login", tags: [], fields: [], tombstone: true)
        XCTAssertTrue(r.tombstone)
    }
}
