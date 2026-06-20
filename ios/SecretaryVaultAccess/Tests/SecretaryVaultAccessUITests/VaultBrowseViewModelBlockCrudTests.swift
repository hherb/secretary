import XCTest
import SecretaryVaultAccess
import SecretaryVaultAccessTesting
@testable import SecretaryVaultAccessUI

/// A `WriteReauthGate` that parks `authorizeWrite` in the `SuspensionGate` until
/// the test releases it. Used to prove that a second write action arriving while
/// the first is suspended at the biometric prompt is rejected without triggering a
/// second prompt or write.
@MainActor
private final class SuspendingReauthGate: WriteReauthGate {
    private(set) var callCount = 0
    private let suspension = SuspensionGate()

    func authorizeWrite(reason: String) async throws {
        callCount += 1
        await suspension.enterAndWait()
    }

    /// Suspend the caller until `authorizeWrite` has been entered (the gate is parked).
    func waitUntilEntered() async { await suspension.waitUntilEntered() }

    /// Release the parked `authorizeWrite`, allowing it to return normally.
    func resumeAuth() async { await suspension.release() }
}

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
        XCTAssertEqual(gate.authorizeCount, 1, "the gate must be consulted before the write is refused")
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

    /// Regression: a second write action arriving while the biometric gate is suspended
    /// must be rejected without triggering a second prompt or write. Prior to the fix
    /// the `isWriting` guard lived inside `guardedWrite`, which ran AFTER the gate await,
    /// so a concurrent action could race through the gate and queue a second prompt.
    func testSecondWriteRejectedWhileGateIsSuspended() async {
        let s = make().0
        let gate = SuspendingReauthGate()
        let vm = VaultBrowseViewModel(session: s, gate: gate)
        vm.loadBlocks()
        let blockCountBefore = vm.blocks.count
        vm.startCreateBlock()

        // Start the first write in a background Task — it will park inside the gate.
        let firstTask = Task { await vm.confirmBlockName("First") }

        // Wait until the gate has the first call parked.
        await gate.waitUntilEntered()

        // Assert the re-entrancy guard is already raised.
        XCTAssertTrue(vm.isWriting, "isWriting must be true while biometric prompt is pending")

        // Attempt a second write synchronously on the main actor — should be rejected.
        // confirmBlockName is async but runs on @MainActor; we need a dialog to be open
        // so drive confirmMove instead (delete also works but needs a block selection).
        // Simplest: try a second confirmBlockName — blockNameDialog is .create, name is valid.
        await vm.confirmBlockName("Second")

        // The gate must NOT have been entered a second time.
        XCTAssertEqual(gate.callCount, 1, "second action must not reach the gate while first is suspended")
        // No new block must have been created yet.
        XCTAssertEqual(vm.blocks.count, blockCountBefore, "no write must have occurred during suspension")

        // Release the gate so the first write can complete.
        await gate.resumeAuth()
        await firstTask.value

        // First write succeeded.
        XCTAssertNil(vm.error)
        XCTAssertEqual(vm.blocks.count, blockCountBefore + 1)
        XCTAssertTrue(vm.blocks.contains { $0.name == "First" }, "block 'First' must exist")
        XCTAssertFalse(vm.blocks.contains { $0.name == "Second" }, "block 'Second' must not exist")
        XCTAssertNil(vm.blockNameDialog, "dialog cleared on success")
    }
}
