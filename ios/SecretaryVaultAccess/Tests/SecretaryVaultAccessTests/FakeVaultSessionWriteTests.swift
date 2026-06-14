import XCTest
import SecretaryVaultAccess
import SecretaryVaultAccessTesting

final class FakeVaultSessionWriteTests: XCTestCase {
    private let block: [UInt8] = [0xB1]
    private func freshSession() -> FakeVaultSession {
        FakeVaultSession(
            vaultUuidHex: "feed",
            blocks: [BlockSummary(uuid: block, name: "Logins", createdAtMs: 0, lastModMs: 0)],
            recordsByBlock: [block: []])
    }

    func testAppendAddsLiveRecord() throws {
        let s = freshSession()
        let newUuid = try s.appendRecord(
            blockUuid: block,
            content: RecordContentInput(recordType: "login", tags: ["w"],
                fields: [FieldContentInput(name: "user", value: .text("alice"))]))
        let records = try s.readBlock(blockUuid: block, includeDeleted: false)
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(records[0].uuid, newUuid)
        XCTAssertFalse(records[0].tombstone)
        XCTAssertEqual(records[0].fields.first?.name, "user")
    }

    func testEditReplacesFieldsKeepingUuid() throws {
        let s = freshSession()
        let id = try s.appendRecord(blockUuid: block,
            content: RecordContentInput(recordType: "login", tags: [],
                fields: [FieldContentInput(name: "user", value: .text("alice"))]))
        try s.editRecord(blockUuid: block, recordUuid: id,
            content: RecordContentInput(recordType: "login", tags: ["x"],
                fields: [FieldContentInput(name: "user", value: .text("bob"))]))
        let rec = try XCTUnwrap(try s.readBlock(blockUuid: block, includeDeleted: false).first)
        XCTAssertEqual(rec.uuid, id)
        XCTAssertEqual(rec.tags, ["x"])
        guard case .text(let v) = try XCTUnwrap(rec.fields.first).reveal() else {
            return XCTFail("expected text")
        }
        XCTAssertEqual(v, "bob")
    }

    func testTombstoneThenResurrectTogglesFlag() throws {
        let s = freshSession()
        let id = try s.appendRecord(blockUuid: block,
            content: RecordContentInput(recordType: "login", tags: [], fields: []))
        try s.tombstoneRecord(blockUuid: block, recordUuid: id)
        // includeDeleted: true — the tombstoned record is withheld otherwise.
        XCTAssertTrue(try XCTUnwrap(try s.readBlock(blockUuid: block, includeDeleted: true).first).tombstone)
        try s.resurrectRecord(blockUuid: block, recordUuid: id)
        // Now live again; the default live-only read sees it.
        XCTAssertFalse(try XCTUnwrap(try s.readBlock(blockUuid: block, includeDeleted: false).first).tombstone)
    }

    func testEditUnknownRecordThrowsRecordNotFound() throws {
        let s = freshSession()
        XCTAssertThrowsError(try s.editRecord(blockUuid: block, recordUuid: [0xFF],
            content: RecordContentInput(recordType: "x", tags: [], fields: []))) { err in
            guard case VaultAccessError.recordNotFound = err else {
                return XCTFail("expected .recordNotFound, got \(err)")
            }
        }
    }

    func testTombstoneAlreadyTombstonedThrowsRecordNotFound() throws {
        let s = freshSession()
        let id = try s.appendRecord(blockUuid: block,
            content: RecordContentInput(recordType: "login", tags: [], fields: []))
        try s.tombstoneRecord(blockUuid: block, recordUuid: id)
        XCTAssertThrowsError(try s.tombstoneRecord(blockUuid: block, recordUuid: id)) { err in
            guard case VaultAccessError.recordNotFound = err else {
                return XCTFail("expected .recordNotFound, got \(err)")
            }
        }
    }
}
