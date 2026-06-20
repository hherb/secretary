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

    func testCreateBlockHappyPathAddsBlockAndClearsDialog() async {
        let (s, _, _) = make()
        let vm = VaultBrowseViewModel(session: s, gate: FakeWriteReauthGate())
        vm.loadBlocks()
        vm.startCreateBlock()
        XCTAssertEqual(vm.blockNameDialog, .create)
        await vm.confirmBlockName("Archive")
        XCTAssertNil(vm.blockNameDialog, "dialog cleared on success")
        XCTAssertTrue(vm.blocks.contains { $0.name == "Archive" })
        XCTAssertNil(vm.error)
    }

    func testConfirmBlankNameKeepsDialogOpenAndSurfacesInvalidArgument() async {
        let (s, _, _) = make()
        let vm = VaultBrowseViewModel(session: s, gate: FakeWriteReauthGate())
        vm.loadBlocks()
        let before = vm.blocks.count
        vm.startCreateBlock()
        await vm.confirmBlockName("   ")
        XCTAssertEqual(vm.blockNameDialog, .create, "blank name must not close the dialog")
        XCTAssertEqual(vm.blocks.count, before, "blank name must not write")
        guard case .invalidArgument = vm.error else { return XCTFail("expected invalidArgument, got \(String(describing: vm.error))") }
    }

    func testCreateBlockWriteFailureKeepsDialogOpen() async {
        let (s, _, _) = make()
        s.failNextWrite = .other("disk full")
        let vm = VaultBrowseViewModel(session: s, gate: FakeWriteReauthGate())
        vm.loadBlocks()
        vm.startCreateBlock()
        await vm.confirmBlockName("Archive")
        XCTAssertEqual(vm.blockNameDialog, .create, "failed write must keep the dialog open")
        XCTAssertEqual(vm.error, .other("disk full"))
    }

    func testCancelBlockNameDialogClearsIt() {
        let (s, _, _) = make()
        let vm = VaultBrowseViewModel(session: s, gate: FakeWriteReauthGate())
        vm.startCreateBlock()
        XCTAssertEqual(vm.blockNameDialog, .create, "dialog must be open before cancel")
        vm.cancelBlockNameDialog()
        XCTAssertNil(vm.blockNameDialog)
    }

    func testRenameBlockHappyPathRenamesAndClearsDialog() async {
        let (s, block, _) = make()
        let vm = VaultBrowseViewModel(session: s, gate: FakeWriteReauthGate())
        vm.loadBlocks()
        vm.startRenameBlock(block)
        XCTAssertEqual(vm.blockNameDialog, .rename(block: block))
        await vm.confirmBlockName("Renamed")
        XCTAssertNil(vm.blockNameDialog)
        XCTAssertTrue(vm.blocks.contains { $0.uuid == block.uuid && $0.name == "Renamed" })
        XCTAssertNil(vm.error)
    }

    func testRenameBlockWriteFailureKeepsDialogOpen() async {
        let (s, block, _) = make()
        let vm = VaultBrowseViewModel(session: s, gate: FakeWriteReauthGate())
        vm.loadBlocks()
        vm.startRenameBlock(block)
        s.failNextWrite = .other("disk full")
        await vm.confirmBlockName("Renamed")
        XCTAssertEqual(vm.blockNameDialog, .rename(block: block))
        XCTAssertEqual(vm.error, .other("disk full"))
    }

    func testMoveRecordHappyPathTombstonesSourceAndClearsPicker() async {
        let (s, src, rec) = make()
        let vm = VaultBrowseViewModel(session: s, gate: FakeWriteReauthGate())
        vm.loadBlocks()
        let targetUuid = try! s.createBlock(blockName: "Target")  // pre-seed a target block
        vm.loadBlocks()
        let target = vm.blocks.first { $0.uuid == targetUuid }!
        vm.selectBlock(src)
        vm.startMoveRecord(rec)
        XCTAssertEqual(vm.movingRecord?.uuid, rec.uuid)
        await vm.confirmMove(target: target)
        XCTAssertNil(vm.movingRecord, "picker cleared on success")
        XCTAssertNil(vm.error)
        // source re-read shows the record tombstoned (withheld while showDeleted is off):
        XCTAssertEqual(vm.visibleRecords.count, 0)
        XCTAssertEqual(try! s.readBlock(blockUuid: target.uuid, includeDeleted: false).count, 1)
    }

    func testMoveToSameBlockKeepsPickerOpenAndSurfacesInvalidArgument() async {
        let (s, src, rec) = make()
        let vm = VaultBrowseViewModel(session: s, gate: FakeWriteReauthGate())
        vm.loadBlocks(); vm.selectBlock(src)
        vm.startMoveRecord(rec)
        await vm.confirmMove(target: src)  // same block
        XCTAssertEqual(vm.movingRecord?.uuid, rec.uuid, "same-block move must keep the picker open")
        guard case .invalidArgument = vm.error else { return XCTFail("expected invalidArgument, got \(String(describing: vm.error))") }
    }

    func testMoveWriteFailureKeepsPickerOpen() async {
        let (s, src, rec) = make()
        let vm = VaultBrowseViewModel(session: s, gate: FakeWriteReauthGate())
        vm.loadBlocks()
        let targetUuid = try! s.createBlock(blockName: "Target"); vm.loadBlocks()
        let target = vm.blocks.first { $0.uuid == targetUuid }!
        vm.selectBlock(src); vm.startMoveRecord(rec)
        s.failNextWrite = .other("disk full")
        await vm.confirmMove(target: target)
        XCTAssertEqual(vm.movingRecord?.uuid, rec.uuid)
        XCTAssertEqual(vm.error, .other("disk full"))
    }

    func testLockResetsDialogAndMovingRecord() {
        let (s, src, rec) = make()
        let vm = VaultBrowseViewModel(session: s, gate: FakeWriteReauthGate())
        vm.loadBlocks(); vm.selectBlock(src)
        vm.startCreateBlock()
        vm.startMoveRecord(rec)
        vm.lock()
        XCTAssertNil(vm.blockNameDialog)
        XCTAssertNil(vm.movingRecord)
    }

    func testConfirmBlockNameBlockedByReauthDoesNotWrite() async {
        let s = make().0
        let gate = FakeWriteReauthGate()
        gate.failNext = .reauthFailed("cancelled")
        let vm = VaultBrowseViewModel(session: s, gate: gate)
        vm.loadBlocks()
        let before = vm.blocks.count
        vm.startCreateBlock()
        await vm.confirmBlockName("New")
        XCTAssertEqual(vm.error, .reauthFailed("cancelled"))
        XCTAssertEqual(vm.blocks.count, before, "no block created on refused re-auth")
        XCTAssertNotNil(vm.blockNameDialog, "dialog stays open on a refused write")
    }

    func testNotEnrolledGateWritesAsBefore() async {
        let s = make().0
        let vm = VaultBrowseViewModel(session: s, gate: FakeWriteReauthGate())   // pass-through
        vm.loadBlocks()
        let before = vm.blocks.count
        vm.startCreateBlock()
        await vm.confirmBlockName("New")
        XCTAssertNil(vm.error)
        XCTAssertEqual(vm.blocks.count, before + 1)
        XCTAssertNil(vm.blockNameDialog)
    }
}
