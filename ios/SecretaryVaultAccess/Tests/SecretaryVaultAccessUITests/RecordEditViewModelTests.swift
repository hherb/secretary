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
        XCTAssertEqual(try s.readBlock(blockUuid: block, includeDeleted: false).count, 1)
    }

    func testDuplicateFieldNameBlocksCommit() throws {
        let s = session()
        let vm = RecordEditViewModel(session: s, blockUuid: block, mode: .add)
        vm.addField(); vm.fields[0].name = "user"; vm.fields[0].rawText = "a"
        vm.addField(); vm.fields[1].name = "user"; vm.fields[1].rawText = "b"
        vm.commit()
        XCTAssertFalse(vm.committed)
        XCTAssertEqual(vm.error, .invalidArgument("duplicate field name: user"))
        XCTAssertEqual(try s.readBlock(blockUuid: block, includeDeleted: false).count, 0)  // nothing written
    }

    func testBadHexInBytesFieldBlocksCommit() throws {
        let s = session()
        let vm = RecordEditViewModel(session: s, blockUuid: block, mode: .add)
        vm.addField()
        vm.fields[0].name = "key"
        vm.fields[0].kind = .bytes
        vm.fields[0].rawText = "zz"  // not hex
        vm.commit()
        XCTAssertFalse(vm.committed)
        XCTAssertEqual(vm.error, .invalidArgument("field 'key' is not valid hex"))
    }

    func testValidHexInBytesFieldCommitsAndRoundTrips() throws {
        let s = session()
        let vm = RecordEditViewModel(session: s, blockUuid: block, mode: .add)
        vm.recordType = "key"
        vm.addField()
        vm.fields[0].name = "secret"
        vm.fields[0].kind = .bytes
        vm.fields[0].rawText = "de ad be ef"  // spaced hex must parse
        vm.commit()
        XCTAssertTrue(vm.committed)
        XCTAssertNil(vm.error)
        let rec = try XCTUnwrap(try s.readBlock(blockUuid: block, includeDeleted: false).first)
        guard case .bytes(let b) = try XCTUnwrap(rec.fields.first).reveal() else {
            return XCTFail("expected bytes")
        }
        XCTAssertEqual(b, [0xDE, 0xAD, 0xBE, 0xEF])
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
        guard case .text(let v) = try XCTUnwrap(try s.readBlock(blockUuid: block, includeDeleted: false).first?.fields.first).reveal() else {
            return XCTFail("expected text")
        }
        XCTAssertEqual(v, "bob")
    }

    func testLoadFailureSurfacesErrorAndBlocksCommit() throws {
        let id: [UInt8] = [0xD1]
        // A field whose reveal throws (simulates a corrupt/undecryptable field).
        let bad = RecordView(uuid: id, type: "login", tags: [],
            fields: [FieldView(name: "user", kind: .text) {
                throw VaultAccessError.corruptVault("boom")
            }])
        let s = session([bad])
        let vm = RecordEditViewModel(session: s, blockUuid: block, mode: .edit(recordUuid: id))
        vm.load(record: bad)                       // non-throwing wrapper
        XCTAssertTrue(vm.loadFailed)
        XCTAssertEqual(vm.error, .corruptVault("boom"))
        vm.commit()                                // must be refused
        XCTAssertFalse(vm.committed)
        // the record in the fake still has its original single field (not clobbered)
        XCTAssertEqual(try s.readBlock(blockUuid: block, includeDeleted: false).first?.fields.count, 1)
    }

    func testCommitIncludesTagsAndFiltersBlanks() throws {
        let s = session()
        let vm = RecordEditViewModel(session: s, blockUuid: block, mode: .add)
        vm.recordType = "login"
        vm.tags = ["work", "  ", "personal"]
        vm.addField(); vm.fields[0].name = "user"; vm.fields[0].rawText = "alice"
        vm.commit()
        XCTAssertTrue(vm.committed)
        let rec = try XCTUnwrap(try s.readBlock(blockUuid: block, includeDeleted: false).first)
        XCTAssertEqual(rec.tags, ["work", "personal"])
    }

    func testLoadSuccessClearsLoadFailedAndAllowsCommit() throws {
        let id: [UInt8] = [0xD2]
        let good = RecordView(uuid: id, type: "login", tags: ["w"],
            fields: [FieldView(name: "user", kind: .text) { .text("alice") }])
        let s = session([good])
        let vm = RecordEditViewModel(session: s, blockUuid: block, mode: .edit(recordUuid: id))
        vm.load(record: good)
        XCTAssertFalse(vm.loadFailed)
        vm.fields[0].rawText = "bob"
        vm.commit()
        XCTAssertTrue(vm.committed)
    }
}
