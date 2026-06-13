// ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/RecordEditViewModelTests.swift
import XCTest
@testable import SecretaryVaultAccessUI
import SecretaryVaultAccess
import SecretaryVaultAccessTesting

@MainActor
final class RecordEditViewModelTests: XCTestCase {
    private let block: [UInt8] = [0xB1]
    private func session(_ records: [RecordView] = []) -> FakeVaultSession {
        FakeVaultSession(
            vaultUuidHex: "feed",
            blocks: [BlockSummary(uuid: block, name: "Logins", createdAtMs: 0, lastModMs: 0)],
            recordsByBlock: [block: records])
    }

    func testAddCommitWritesRecord() throws {
        let s = session()
        let vm = RecordEditViewModel(session: s, blockUuid: block, mode: .add)
        vm.recordType = "login"
        vm.addField()
        vm.fields[0].name = "user"
        vm.fields[0].rawText = "alice"
        vm.commit()
        XCTAssertTrue(vm.committed)
        XCTAssertNil(vm.error)
        XCTAssertEqual(try s.readBlock(blockUuid: block).count, 1)
    }

    func testDuplicateFieldNameBlocksCommit() throws {
        let s = session()
        let vm = RecordEditViewModel(session: s, blockUuid: block, mode: .add)
        vm.addField(); vm.fields[0].name = "user"; vm.fields[0].rawText = "a"
        vm.addField(); vm.fields[1].name = "user"; vm.fields[1].rawText = "b"
        vm.commit()
        XCTAssertFalse(vm.committed)
        XCTAssertEqual(vm.error, .invalidArgument("duplicate field name: user"))
        XCTAssertEqual(try s.readBlock(blockUuid: block).count, 0)  // nothing written
    }

    func testBadHexInBytesFieldBlocksCommit() throws {
        let s = session()
        let vm = RecordEditViewModel(session: s, blockUuid: block, mode: .add)
        vm.addField()
        vm.fields[0].name = "key"
        vm.setKind(at: 0, .bytes)
        vm.fields[0].rawText = "zz"  // not hex
        vm.commit()
        XCTAssertFalse(vm.committed)
        XCTAssertEqual(vm.error, .invalidArgument("field 'key' is not valid hex"))
    }

    func testEditPrefillsFromRecordThenCommitsEdit() throws {
        let id: [UInt8] = [0xC1]
        let existing = RecordView(
            uuid: id, type: "login", tags: ["w"],
            fields: [FieldView(name: "user", kind: .text) { .text("alice") }])
        let s = session([existing])
        let vm = RecordEditViewModel(session: s, blockUuid: block, mode: .edit(recordUuid: id))
        try vm.loadForEdit(record: existing)
        XCTAssertEqual(vm.recordType, "login")
        XCTAssertEqual(vm.fields.first?.rawText, "alice")
        vm.fields[0].rawText = "bob"
        vm.commit()
        XCTAssertTrue(vm.committed)
        guard case .text(let v) = try XCTUnwrap(try s.readBlock(blockUuid: block).first?.fields.first).reveal() else {
            return XCTFail("expected text")
        }
        XCTAssertEqual(v, "bob")
    }
}
