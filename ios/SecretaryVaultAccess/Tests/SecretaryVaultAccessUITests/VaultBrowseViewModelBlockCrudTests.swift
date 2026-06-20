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
}
