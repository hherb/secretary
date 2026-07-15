import XCTest
import SecretaryVaultAccess
import SecretaryVaultAccessTesting
@testable import SecretaryVaultAccessUI

/// Host tests for the VM's block-name warn wiring: it must pick the correct
/// create/rename exclude-uuid and delegate to the pure predicate, and the
/// write path must stay warn-but-allow (a colliding name still writes).
@MainActor
final class VaultBrowseViewModelBlockNameWarnTests: XCTestCase {
    private func block(_ b: UInt8, _ name: String) -> BlockSummary {
        BlockSummary(uuid: Array(repeating: b, count: 16), name: name, createdAtMs: 0, lastModMs: 0)
    }
    private func makeVM(blocks: [BlockSummary]) -> VaultBrowseViewModel {
        let s = FakeVaultSession(vaultUuidHex: "ab", blocks: blocks, recordsByBlock: [:])
        let vm = VaultBrowseViewModel(session: s, gate: FakeWriteReauthGate())
        vm.loadBlocks()
        return vm
    }

    func testCreateModeCollisionWarns() {
        let vm = makeVM(blocks: [block(0x11, "Work")])
        vm.startCreateBlock()
        XCTAssertTrue(vm.blockNameCollides("Work"))
    }

    func testCreateModeUniqueDoesNotWarn() {
        let vm = makeVM(blocks: [block(0x11, "Work")])
        vm.startCreateBlock()
        XCTAssertFalse(vm.blockNameCollides("Finance"))
    }

    func testBlankNeverWarns() {
        let vm = makeVM(blocks: [block(0x11, "Work")])
        vm.startCreateBlock()
        XCTAssertFalse(vm.blockNameCollides("   "))
    }

    func testRenameToOwnNameDoesNotWarn() {
        let work = block(0x11, "Work")
        let vm = makeVM(blocks: [work, block(0x22, "Personal")])
        vm.startRenameBlock(work)
        XCTAssertFalse(vm.blockNameCollides("Work"), "renaming a block to its own name is not a collision")
    }

    func testRenameToOtherExistingNameWarns() {
        let work = block(0x11, "Work")
        let vm = makeVM(blocks: [work, block(0x22, "Personal")])
        vm.startRenameBlock(work)
        XCTAssertTrue(vm.blockNameCollides("Personal"))
    }

    func testCollidingCreateStillWritesTheDuplicate() async {
        let vm = makeVM(blocks: [block(0x11, "Work")])
        vm.startCreateBlock()
        await vm.confirmBlockName("Work")   // warn-but-allow: the write still happens
        XCTAssertNil(vm.blockNameDialog, "dialog clears on a successful (allowed) duplicate write")
        XCTAssertNil(vm.error)
        XCTAssertEqual(vm.blocks.filter { $0.name == "Work" }.count, 2, "the duplicate name is written")
    }

    /// The block-name sheet renders `viewModel.error` inline (a full-screen sheet
    /// would otherwise hide the list's error section on a failed write). Opening the
    /// sheet must therefore clear any PRE-existing, unrelated error so a stale
    /// message (from a prior reveal/read/write) never greets a fresh create/rename.
    func testOpeningCreateDialogClearsAStaleError() async {
        let s = FakeVaultSession(vaultUuidHex: "ab", blocks: [block(0x11, "Work")], recordsByBlock: [:])
        let vm = VaultBrowseViewModel(session: s, gate: FakeWriteReauthGate())
        vm.loadBlocks()
        s.failNextWrite = .other("boom")
        vm.startCreateBlock()
        await vm.confirmBlockName("X")            // fails → error set, dialog stays open
        XCTAssertNotNil(vm.error, "precondition: a failed write set an error")
        vm.cancelBlockNameDialog()
        vm.startCreateBlock()                     // reopening must clear the stale error
        XCTAssertNil(vm.error, "opening the block-name dialog clears any prior error")
    }

    func testOpeningRenameDialogClearsAStaleError() async {
        let work = block(0x11, "Work")
        let s = FakeVaultSession(vaultUuidHex: "ab", blocks: [work], recordsByBlock: [:])
        let vm = VaultBrowseViewModel(session: s, gate: FakeWriteReauthGate())
        vm.loadBlocks()
        s.failNextWrite = .other("boom")
        vm.startCreateBlock()
        await vm.confirmBlockName("X")            // fails → error set
        XCTAssertNotNil(vm.error, "precondition: a failed write set an error")
        vm.cancelBlockNameDialog()
        vm.startRenameBlock(work)                 // reopening (rename) must clear the stale error
        XCTAssertNil(vm.error, "opening the rename dialog clears any prior error")
    }
}
