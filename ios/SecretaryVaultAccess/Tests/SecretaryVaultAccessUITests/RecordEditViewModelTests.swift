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

    func testAddCommitWritesRecord() async throws {
        let s = session()
        let vm = RecordEditViewModel(session: s, blockUuid: block, mode: .add, gate: FakeWriteReauthGate())
        vm.recordType = "login"
        vm.addField()
        vm.fields[0].name = "user"
        vm.fields[0].rawText = "alice"
        await vm.commit()
        XCTAssertTrue(vm.committed)
        XCTAssertNil(vm.error)
        XCTAssertEqual(try s.readBlock(blockUuid: block, includeDeleted: false).count, 1)
    }

    func testDuplicateFieldNameBlocksCommit() async throws {
        let s = session()
        let vm = RecordEditViewModel(session: s, blockUuid: block, mode: .add, gate: FakeWriteReauthGate())
        vm.addField(); vm.fields[0].name = "user"; vm.fields[0].rawText = "a"
        vm.addField(); vm.fields[1].name = "user"; vm.fields[1].rawText = "b"
        await vm.commit()
        XCTAssertFalse(vm.committed)
        XCTAssertEqual(vm.error, .invalidArgument("duplicate field name: user"))
        XCTAssertEqual(try s.readBlock(blockUuid: block, includeDeleted: false).count, 0)  // nothing written
    }

    func testBadHexInBytesFieldBlocksCommit() async throws {
        let s = session()
        let vm = RecordEditViewModel(session: s, blockUuid: block, mode: .add, gate: FakeWriteReauthGate())
        vm.addField()
        vm.fields[0].name = "key"
        vm.fields[0].kind = .bytes
        vm.fields[0].rawText = "zz"  // not hex
        await vm.commit()
        XCTAssertFalse(vm.committed)
        XCTAssertEqual(vm.error, .invalidArgument("field 'key' is not valid hex"))
    }

    func testValidHexInBytesFieldCommitsAndRoundTrips() async throws {
        let s = session()
        let vm = RecordEditViewModel(session: s, blockUuid: block, mode: .add, gate: FakeWriteReauthGate())
        vm.recordType = "key"
        vm.addField()
        vm.fields[0].name = "secret"
        vm.fields[0].kind = .bytes
        vm.fields[0].rawText = "de ad be ef"  // spaced hex must parse
        await vm.commit()
        XCTAssertTrue(vm.committed)
        XCTAssertNil(vm.error)
        let rec = try XCTUnwrap(try s.readBlock(blockUuid: block, includeDeleted: false).first)
        guard case .bytes(let b) = try XCTUnwrap(rec.fields.first).reveal() else {
            return XCTFail("expected bytes")
        }
        XCTAssertEqual(b, [0xDE, 0xAD, 0xBE, 0xEF])
    }

    func testEditPrefillsFromRecordThenCommitsEdit() async throws {
        let id: [UInt8] = [0xC1]
        let existing = RecordView(
            uuid: id, type: "login", tags: ["w"],
            fields: [FieldView(name: "user", kind: .text) { .text("alice") }])
        let s = session([existing])
        let vm = RecordEditViewModel(session: s, blockUuid: block, mode: .edit(recordUuid: id), gate: FakeWriteReauthGate())
        try vm.loadForEdit(record: existing)
        XCTAssertEqual(vm.recordType, "login")
        XCTAssertEqual(vm.fields.first?.rawText, "alice")
        vm.fields[0].rawText = "bob"
        await vm.commit()
        XCTAssertTrue(vm.committed)
        guard case .text(let v) = try XCTUnwrap(try s.readBlock(blockUuid: block, includeDeleted: false).first?.fields.first).reveal() else {
            return XCTFail("expected text")
        }
        XCTAssertEqual(v, "bob")
    }

    func testLoadFailureSurfacesErrorAndBlocksCommit() async throws {
        let id: [UInt8] = [0xD1]
        // A field whose reveal throws (simulates a corrupt/undecryptable field).
        let bad = RecordView(uuid: id, type: "login", tags: [],
            fields: [FieldView(name: "user", kind: .text) {
                throw VaultAccessError.corruptVault("boom")
            }])
        let s = session([bad])
        let vm = RecordEditViewModel(session: s, blockUuid: block, mode: .edit(recordUuid: id), gate: FakeWriteReauthGate())
        vm.load(record: bad)                       // non-throwing wrapper
        XCTAssertTrue(vm.loadFailed)
        XCTAssertEqual(vm.error, .corruptVault("boom"))
        await vm.commit()                          // must be refused
        XCTAssertFalse(vm.committed)
        // the record in the fake still has its original single field (not clobbered)
        XCTAssertEqual(try s.readBlock(blockUuid: block, includeDeleted: false).first?.fields.count, 1)
    }

    func testCommitIncludesTagsAndFiltersBlanks() async throws {
        let s = session()
        let vm = RecordEditViewModel(session: s, blockUuid: block, mode: .add, gate: FakeWriteReauthGate())
        vm.recordType = "login"
        vm.tags = ["work", "  ", "personal"]
        vm.addField(); vm.fields[0].name = "user"; vm.fields[0].rawText = "alice"
        await vm.commit()
        XCTAssertTrue(vm.committed)
        let rec = try XCTUnwrap(try s.readBlock(blockUuid: block, includeDeleted: false).first)
        XCTAssertEqual(rec.tags, ["work", "personal"])
    }

    func testLoadSuccessClearsLoadFailedAndAllowsCommit() async throws {
        let id: [UInt8] = [0xD2]
        let good = RecordView(uuid: id, type: "login", tags: ["w"],
            fields: [FieldView(name: "user", kind: .text) { .text("alice") }])
        let s = session([good])
        let vm = RecordEditViewModel(session: s, blockUuid: block, mode: .edit(recordUuid: id), gate: FakeWriteReauthGate())
        vm.load(record: good)
        XCTAssertFalse(vm.loadFailed)
        vm.fields[0].rawText = "bob"
        await vm.commit()
        XCTAssertTrue(vm.committed)
    }

    func testSecondCommitAfterSuccessDoesNotAppendAgain() async throws {
        let s = session()
        let vm = RecordEditViewModel(session: s, blockUuid: block, mode: .add, gate: FakeWriteReauthGate())
        vm.recordType = "login"; vm.addField(); vm.fields[0].name = "user"; vm.fields[0].rawText = "alice"
        await vm.commit()
        XCTAssertTrue(vm.committed)
        await vm.commit()   // render-gap re-tap: committed guard must block a second append
        XCTAssertEqual(try s.readBlock(blockUuid: block, includeDeleted: false).count, 1)
        XCTAssertFalse(vm.isWriting)
    }

    func testCommitBlockedByReauthDoesNotWrite() async {
        let s = FakeVaultSession(vaultUuidHex: "00", blocks: [],
                                 recordsByBlock: [block: []])
        let gate = FakeWriteReauthGate()
        gate.failNext = .reauthFailed("cancelled")
        let vm = RecordEditViewModel(session: s, blockUuid: block, mode: .add, gate: gate)
        vm.recordType = "login"
        vm.fields = [EditableField(name: "u", kind: .text, rawText: "v")]
        await vm.commit()
        XCTAssertEqual(vm.error, .reauthFailed("cancelled"))
        XCTAssertFalse(vm.committed, "a refused re-auth must not commit")
        // FakeVaultSession appended nothing: the block is still empty.
        XCTAssertEqual(try s.readBlock(blockUuid: block, includeDeleted: true).count, 0)
    }

    func testCommitProceedsWhenReauthAuthorizes() async {
        let s = FakeVaultSession(vaultUuidHex: "00", blocks: [],
                                 recordsByBlock: [block: []])
        let gate = FakeWriteReauthGate()       // pass-through
        let vm = RecordEditViewModel(session: s, blockUuid: block, mode: .add, gate: gate)
        vm.recordType = "login"
        vm.fields = [EditableField(name: "u", kind: .text, rawText: "v")]
        await vm.commit()
        XCTAssertNil(vm.error)
        XCTAssertTrue(vm.committed)
        XCTAssertEqual(gate.authorizeCount, 1)
    }
}
