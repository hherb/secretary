import XCTest
import SecretaryVaultAccess
import SecretaryVaultAccessTesting
@testable import SecretaryVaultAccessUI

@MainActor
final class VaultBrowseViewModelTests: XCTestCase {
    private func makeSession(revealCounter: @escaping () -> Void)
        -> (FakeVaultSession, BlockSummary, RecordView) {
        let block = BlockSummary(uuid: [7], name: "Logins", createdAtMs: 1, lastModMs: 2)
        let field = FieldView(name: "password", kind: .text) {
            revealCounter(); return .text("s3cret")
        }
        let rec = RecordView(uuid: Array(repeating: 2, count: 16),
                             type: "login", tags: [], fields: [field])
        let session = FakeVaultSession(vaultUuidHex: "ab",
                                       blocks: [block],
                                       recordsByBlock: [[7]: [rec]])
        return (session, block, rec)
    }

    func testLoadBlocksThenSelectReadsRecordsWithoutRevealing() throws {
        var reveals = 0
        let (session, block, _) = makeSession { reveals += 1 }
        let vm = VaultBrowseViewModel(session: session, gate: FakeWriteReauthGate())
        vm.loadBlocks()
        XCTAssertEqual(vm.blocks, [block])
        vm.selectBlock(block)
        XCTAssertEqual(vm.records?.count, 1)
        XCTAssertEqual(session.readCount, 1)
        XCTAssertEqual(reveals, 0, "reading a block must not reveal any field")
    }

    func testRevealStoresValueThenHideDropsIt() throws {
        var reveals = 0
        let (session, block, rec) = makeSession { reveals += 1 }
        let vm = VaultBrowseViewModel(session: session, gate: FakeWriteReauthGate())
        vm.loadBlocks(); vm.selectBlock(block)
        let field = try XCTUnwrap(vm.records?.first?.fields.first)

        vm.reveal(record: rec, field: field)
        XCTAssertEqual(reveals, 1)
        XCTAssertEqual(vm.revealedValue(recordUuidHex: rec.uuidHex, fieldName: "password"), .text("s3cret"))

        vm.hide(recordUuidHex: rec.uuidHex, fieldName: "password")
        XCTAssertNil(vm.revealedValue(recordUuidHex: rec.uuidHex, fieldName: "password"))
    }

    func testLockClearsRevealedAndWipesSession() throws {
        let (session, block, rec) = makeSession {}
        let vm = VaultBrowseViewModel(session: session, gate: FakeWriteReauthGate())
        vm.loadBlocks(); vm.selectBlock(block)
        let field = try XCTUnwrap(vm.records?.first?.fields.first)
        vm.reveal(record: rec, field: field)

        vm.lock()
        XCTAssertNil(vm.revealedValue(recordUuidHex: rec.uuidHex, fieldName: "password"))
        XCTAssertEqual(session.wipeCount, 1)
    }

    func testHideAllClearsRevealedWithoutWipingSession() throws {
        let (session, block, rec) = makeSession {}
        let vm = VaultBrowseViewModel(session: session, gate: FakeWriteReauthGate())
        vm.loadBlocks(); vm.selectBlock(block)
        let field = try XCTUnwrap(vm.records?.first?.fields.first)
        vm.reveal(record: rec, field: field)
        XCTAssertNotNil(vm.revealedValue(recordUuidHex: rec.uuidHex, fieldName: "password"))

        // Backgrounding path: drop plaintext but DO NOT wipe/lock the session.
        vm.hideAll()
        XCTAssertNil(vm.revealedValue(recordUuidHex: rec.uuidHex, fieldName: "password"))
        XCTAssertEqual(session.wipeCount, 0, "hideAll must not wipe the session")
    }

    func testSelectUnknownBlockSurfacesTypedError() {
        let session = FakeVaultSession(vaultUuidHex: "ab", blocks: [], recordsByBlock: [:])
        let vm = VaultBrowseViewModel(session: session, gate: FakeWriteReauthGate())
        vm.selectBlock(BlockSummary(uuid: [0xde], name: "x", createdAtMs: 0, lastModMs: 0))
        XCTAssertEqual(vm.error, .blockNotFound("de"))
        XCTAssertNil(vm.records)
    }

    func testHasMoveTargetsFalseWithSingleBlock() {
        let block = BlockSummary(uuid: [7], name: "Logins", createdAtMs: 1, lastModMs: 2)
        let session = FakeVaultSession(vaultUuidHex: "ab", blocks: [block], recordsByBlock: [:])
        let vm = VaultBrowseViewModel(session: session, gate: FakeWriteReauthGate())
        vm.loadBlocks()
        XCTAssertFalse(vm.hasMoveTargets)
    }

    func testHasMoveTargetsTrueWithTwoBlocks() {
        let logins = BlockSummary(uuid: [7], name: "Logins", createdAtMs: 1, lastModMs: 2)
        let cards = BlockSummary(uuid: [8], name: "Cards", createdAtMs: 1, lastModMs: 2)
        let session = FakeVaultSession(vaultUuidHex: "ab", blocks: [logins, cards], recordsByBlock: [:])
        let vm = VaultBrowseViewModel(session: session, gate: FakeWriteReauthGate())
        vm.loadBlocks()
        XCTAssertTrue(vm.hasMoveTargets)
    }

    // MARK: - session sync (#101)

    func testReloadFromDiskReloadsBlocks() throws {
        var reveals = 0
        let (session, block, _) = makeSession { reveals += 1 }
        let vm = VaultBrowseViewModel(session: session, gate: FakeWriteReauthGate())
        vm.loadBlocks(); vm.selectBlock(block)
        let merged = BlockSummary(uuid: [8], name: "Merged", createdAtMs: 3, lastModMs: 4)
        session.blocksAfterRefresh = [block, merged]
        let readsBefore = session.readCount

        XCTAssertTrue(vm.reloadFromDisk(stateDir: "/state"))

        XCTAssertEqual(session.refreshCount, 1)
        XCTAssertEqual(session.lastRefreshStateDir, "/state")
        XCTAssertEqual(vm.blocks, [block, merged])
        XCTAssertEqual(session.readCount, readsBefore + 1, "open block re-read")
        XCTAssertNil(vm.error)
    }

    func testReloadFromDiskFailureSurfacesErrorAndKeepsBlocks() {
        let (session, block, _) = makeSession {}
        let vm = VaultBrowseViewModel(session: session, gate: FakeWriteReauthGate())
        vm.loadBlocks()
        session.blocksAfterRefresh = []
        session.failNextRefresh = .corruptVault("rollback")

        XCTAssertFalse(vm.reloadFromDisk(stateDir: "/state"),
                       "a refused refresh must report failure so a sheet stays open")

        XCTAssertEqual(vm.error, .corruptVault("rollback"))
        XCTAssertEqual(vm.blocks, [block], "a refused refresh must not reload")
    }

    func testVaultChangedOnDiskErrorSurfacesOnWrite() async {
        let (session, _, _) = makeSession {}
        let vm = VaultBrowseViewModel(session: session, gate: FakeWriteReauthGate())
        vm.loadBlocks()
        session.failNextWrite = .vaultChangedOnDisk
        vm.startCreateBlock()

        await vm.confirmBlockName("Archive")

        XCTAssertEqual(vm.error, .vaultChangedOnDisk)
        XCTAssertEqual(vm.blockNameDialog, .create, "refused write keeps the dialog open")
    }

    func testReloadFromDiskClearsStaleVaultChangedOnDiskWithNoBlockSelected() async {
        let (session, _, _) = makeSession {}
        let vm = VaultBrowseViewModel(session: session, gate: FakeWriteReauthGate())
        vm.loadBlocks()
        session.failNextWrite = .vaultChangedOnDisk
        vm.startCreateBlock()
        await vm.confirmBlockName("Archive")
        XCTAssertEqual(vm.error, .vaultChangedOnDisk)

        vm.reloadFromDisk(stateDir: "/state")

        XCTAssertNil(vm.error, "a successful reload must drop the refused-write message")
    }

    func testLoadBlocksDoesNotClearVaultChangedOnDisk() async {
        let (session, _, _) = makeSession {}
        let vm = VaultBrowseViewModel(session: session, gate: FakeWriteReauthGate())
        vm.loadBlocks()
        session.failNextWrite = .vaultChangedOnDisk
        vm.startCreateBlock()
        await vm.confirmBlockName("Archive")

        vm.loadBlocks()

        XCTAssertEqual(vm.error, .vaultChangedOnDisk,
                       "a plain re-read of the stale handle must keep the warning (M2)")
    }

    func testSessionRefreshedClearsOnlyVaultChangedOnDisk() async {
        let (session, _, _) = makeSession {}
        let vm = VaultBrowseViewModel(session: session, gate: FakeWriteReauthGate())
        vm.loadBlocks()
        session.failNextWrite = .vaultChangedOnDisk
        vm.startCreateBlock()
        await vm.confirmBlockName("Archive")
        vm.sessionRefreshed()
        XCTAssertNil(vm.error)

        session.failNextWrite = .corruptVault("x")
        vm.startCreateBlock()
        await vm.confirmBlockName("Archive")
        vm.sessionRefreshed()
        XCTAssertEqual(vm.error, .corruptVault("x"), "unrelated errors stay visible")
    }
}
