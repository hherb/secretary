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
        let vm = VaultBrowseViewModel(session: session)
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
        let vm = VaultBrowseViewModel(session: session)
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
        let vm = VaultBrowseViewModel(session: session)
        vm.loadBlocks(); vm.selectBlock(block)
        let field = try XCTUnwrap(vm.records?.first?.fields.first)
        vm.reveal(record: rec, field: field)

        vm.lock()
        XCTAssertNil(vm.revealedValue(recordUuidHex: rec.uuidHex, fieldName: "password"))
        XCTAssertEqual(session.wipeCount, 1)
    }

    func testSelectUnknownBlockSurfacesTypedError() {
        let session = FakeVaultSession(vaultUuidHex: "ab", blocks: [], recordsByBlock: [:])
        let vm = VaultBrowseViewModel(session: session)
        vm.selectBlock(BlockSummary(uuid: [0xde], name: "x", createdAtMs: 0, lastModMs: 0))
        XCTAssertEqual(vm.error, .blockNotFound("de"))
        XCTAssertNil(vm.records)
    }
}
