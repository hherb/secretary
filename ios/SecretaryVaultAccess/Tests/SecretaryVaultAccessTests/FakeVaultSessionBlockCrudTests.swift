import XCTest
import SecretaryVaultAccess
import SecretaryVaultAccessTesting

final class FakeVaultSessionBlockCrudTests: XCTestCase {
    private func make() -> (FakeVaultSession, BlockSummary, RecordView) {
        let block = BlockSummary(uuid: [7], name: "Logins", createdAtMs: 1, lastModMs: 2)
        let rec = RecordView(uuid: Array(repeating: 2, count: 16),
                             type: "login", tags: [],
                             fields: [FieldView(name: "u", kind: .text) { .text("v") }])
        let s = FakeVaultSession(vaultUuidHex: "ab", blocks: [block], recordsByBlock: [[7]: [rec]])
        return (s, block, rec)
    }

    func testCreateBlockAddsEmptyBlock() throws {
        let (s, _, _) = make()
        let uuid = try s.createBlock(blockName: "New")
        XCTAssertTrue(s.blockSummaries().contains { $0.uuid == uuid && $0.name == "New" })
        XCTAssertEqual(try s.readBlock(blockUuid: uuid, includeDeleted: true).count, 0)
    }

    func testRenameBlockChangesName() throws {
        let (s, block, _) = make()
        try s.renameBlock(blockUuid: block.uuid, newName: "Renamed")
        XCTAssertEqual(s.blockSummaries().first { $0.uuid == block.uuid }?.name, "Renamed")
    }

    func testRenameUnknownBlockThrowsBlockNotFound() {
        let (s, _, _) = make()
        XCTAssertThrowsError(try s.renameBlock(blockUuid: [0xFF], newName: "x")) {
            guard case VaultAccessError.blockNotFound = $0 else { return XCTFail("got \($0)") }
        }
    }

    func testMoveRecordCopiesToTargetAndTombstonesSource() throws {
        let (s, src, rec) = make()
        let target = try s.createBlock(blockName: "Target")
        let newUuid = try s.moveRecord(sourceBlockUuid: src.uuid,
                                       targetBlockUuid: target, sourceRecordUuid: rec.uuid)
        // live copy in target under a fresh uuid:
        let inTarget = try s.readBlock(blockUuid: target, includeDeleted: false)
        XCTAssertEqual(inTarget.count, 1)
        XCTAssertEqual(inTarget.first?.uuid, newUuid)
        // source record tombstoned (withheld unless includeDeleted):
        XCTAssertEqual(try s.readBlock(blockUuid: src.uuid, includeDeleted: false).count, 0)
        XCTAssertEqual(try s.readBlock(blockUuid: src.uuid, includeDeleted: true).count, 1)
    }

    func testMoveUnknownRecordThrowsRecordNotFound() throws {
        let (s, src, _) = make()
        let target = try s.createBlock(blockName: "Target")
        XCTAssertThrowsError(try s.moveRecord(sourceBlockUuid: src.uuid,
                                              targetBlockUuid: target,
                                              sourceRecordUuid: [0xEE])) {
            guard case VaultAccessError.recordNotFound = $0 else { return XCTFail("got \($0)") }
        }
    }

    func testFailNextWriteInjectsOneError() {
        let (s, _, _) = make()
        s.failNextWrite = .other("boom")
        XCTAssertThrowsError(try s.createBlock(blockName: "x"))
        XCTAssertNoThrow(try s.createBlock(blockName: "y"), "injection is one-shot")
    }
}
