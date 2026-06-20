import XCTest
import SecretaryVaultAccess
import SecretaryVaultAccessTesting
@testable import SecretaryVaultAccessUI

@MainActor
final class VaultBrowseViewModelBlockCrudTests: XCTestCase {
    private func make() -> (FakeVaultSession, BlockSummary, RecordView) {
        let block = BlockSummary(uuid: [7], name: "Logins", createdAtMs: 1, lastModMs: 2)
        let rec = RecordView(uuid: Array(repeating: 2, count: 16),
                             type: "login", tags: [],
                             fields: [FieldView(name: "u", kind: .text) { .text("v") }])
        let s = FakeVaultSession(vaultUuidHex: "ab", blocks: [block], recordsByBlock: [[7]: [rec]])
        return (s, block, rec)
    }

    func testCreateBlockHappyPathAddsBlockAndClearsDialog() {
        let (s, _, _) = make()
        let vm = VaultBrowseViewModel(session: s)
        vm.loadBlocks()
        vm.startCreateBlock()
        XCTAssertEqual(vm.blockNameDialog, .create)
        vm.confirmBlockName("Archive")
        XCTAssertNil(vm.blockNameDialog, "dialog cleared on success")
        XCTAssertTrue(vm.blocks.contains { $0.name == "Archive" })
        XCTAssertNil(vm.error)
    }

    func testConfirmBlankNameKeepsDialogOpenAndSurfacesInvalidArgument() {
        let (s, _, _) = make()
        let vm = VaultBrowseViewModel(session: s)
        vm.loadBlocks()
        let before = vm.blocks.count
        vm.startCreateBlock()
        vm.confirmBlockName("   ")
        XCTAssertEqual(vm.blockNameDialog, .create, "blank name must not close the dialog")
        XCTAssertEqual(vm.blocks.count, before, "blank name must not write")
        guard case .invalidArgument = vm.error else { return XCTFail("expected invalidArgument, got \(String(describing: vm.error))") }
    }

    func testCreateBlockWriteFailureKeepsDialogOpen() {
        let (s, _, _) = make()
        s.failNextWrite = .other("disk full")
        let vm = VaultBrowseViewModel(session: s)
        vm.loadBlocks()
        vm.startCreateBlock()
        vm.confirmBlockName("Archive")
        XCTAssertEqual(vm.blockNameDialog, .create, "failed write must keep the dialog open")
        XCTAssertNotNil(vm.error)
    }

    func testCancelBlockNameDialogClearsIt() {
        let (s, _, _) = make()
        let vm = VaultBrowseViewModel(session: s)
        vm.startCreateBlock()
        vm.cancelBlockNameDialog()
        XCTAssertNil(vm.blockNameDialog)
    }

    func testRenameBlockHappyPathRenamesAndClearsDialog() {
        let (s, block, _) = make()
        let vm = VaultBrowseViewModel(session: s)
        vm.loadBlocks()
        vm.startRenameBlock(block)
        XCTAssertEqual(vm.blockNameDialog, .rename(block: block))
        vm.confirmBlockName("Renamed")
        XCTAssertNil(vm.blockNameDialog)
        XCTAssertTrue(vm.blocks.contains { $0.uuid == block.uuid && $0.name == "Renamed" })
        XCTAssertNil(vm.error)
    }

    func testRenameBlockWriteFailureKeepsDialogOpen() {
        let (s, block, _) = make()
        let vm = VaultBrowseViewModel(session: s)
        vm.loadBlocks()
        vm.startRenameBlock(block)
        s.failNextWrite = .other("disk full")
        vm.confirmBlockName("Renamed")
        XCTAssertEqual(vm.blockNameDialog, .rename(block: block))
        XCTAssertNotNil(vm.error)
    }

    func testMoveRecordHappyPathTombstonesSourceAndClearsPicker() {
        let (s, src, rec) = make()
        let vm = VaultBrowseViewModel(session: s)
        vm.loadBlocks()
        let targetUuid = try! s.createBlock(blockName: "Target")  // pre-seed a target block
        vm.loadBlocks()
        let target = vm.blocks.first { $0.uuid == targetUuid }!
        vm.selectBlock(src)
        vm.startMoveRecord(rec)
        XCTAssertEqual(vm.movingRecord?.uuid, rec.uuid)
        vm.confirmMove(target: target)
        XCTAssertNil(vm.movingRecord, "picker cleared on success")
        XCTAssertNil(vm.error)
        // source re-read shows the record tombstoned (withheld while showDeleted is off):
        XCTAssertEqual(vm.visibleRecords.count, 0)
        XCTAssertEqual(try! s.readBlock(blockUuid: target.uuid, includeDeleted: false).count, 1)
    }

    func testMoveToSameBlockKeepsPickerOpenAndSurfacesInvalidArgument() {
        let (s, src, rec) = make()
        let vm = VaultBrowseViewModel(session: s)
        vm.loadBlocks(); vm.selectBlock(src)
        vm.startMoveRecord(rec)
        vm.confirmMove(target: src)  // same block
        XCTAssertEqual(vm.movingRecord?.uuid, rec.uuid, "same-block move must keep the picker open")
        guard case .invalidArgument = vm.error else { return XCTFail("expected invalidArgument, got \(String(describing: vm.error))") }
    }

    func testMoveWriteFailureKeepsPickerOpen() {
        let (s, src, rec) = make()
        let vm = VaultBrowseViewModel(session: s)
        vm.loadBlocks()
        let targetUuid = try! s.createBlock(blockName: "Target"); vm.loadBlocks()
        let target = vm.blocks.first { $0.uuid == targetUuid }!
        vm.selectBlock(src); vm.startMoveRecord(rec)
        s.failNextWrite = .other("disk full")
        vm.confirmMove(target: target)
        XCTAssertEqual(vm.movingRecord?.uuid, rec.uuid)
        XCTAssertNotNil(vm.error)
    }

    func testLockResetsDialogAndMovingRecord() {
        let (s, src, rec) = make()
        let vm = VaultBrowseViewModel(session: s)
        vm.loadBlocks(); vm.selectBlock(src)
        vm.startCreateBlock()
        vm.startMoveRecord(rec)
        vm.lock()
        XCTAssertNil(vm.blockNameDialog)
        XCTAssertNil(vm.movingRecord)
    }
}
