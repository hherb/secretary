// ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultBrowseViewModelDeletedTests.swift
import XCTest
@testable import SecretaryVaultAccessUI
import SecretaryVaultAccess
import SecretaryVaultAccessTesting

@MainActor
final class VaultBrowseViewModelDeletedTests: XCTestCase {
    private let block: [UInt8] = [0xB1]

    private func session(_ records: [RecordView]) -> FakeVaultSession {
        FakeVaultSession(
            vaultUuidHex: "feed",
            blocks: [BlockSummary(uuid: block, name: "Logins", createdAtMs: 0, lastModMs: 0)],
            recordsByBlock: [block: records])
    }

    private func record(_ b: UInt8, tombstone: Bool) -> RecordView {
        RecordView(uuid: [b], type: "login", tags: [], fields: [], tombstone: tombstone)
    }

    func testVisibleRecordsHideTombstonedByDefault() {
        let vm = VaultBrowseViewModel(session: session([record(1, tombstone: false),
                                                        record(2, tombstone: true)]))
        vm.loadBlocks()
        vm.selectBlock(vm.blocks[0])
        XCTAssertEqual(vm.visibleRecords.map(\.uuid), [[1]])
    }

    func testShowDeletedRevealsTombstoned() {
        let vm = VaultBrowseViewModel(session: session([record(1, tombstone: false),
                                                        record(2, tombstone: true)]))
        vm.loadBlocks(); vm.selectBlock(vm.blocks[0])
        vm.showDeleted = true
        XCTAssertEqual(vm.visibleRecords.map(\.uuid), [[1], [2]])
    }

    func testDeleteThenRestoreUpdatesVisibility() throws {
        let vm = VaultBrowseViewModel(session: session([record(1, tombstone: false)]))
        vm.loadBlocks(); vm.selectBlock(vm.blocks[0])
        vm.delete(record: vm.visibleRecords[0])
        XCTAssertTrue(vm.visibleRecords.isEmpty)          // gone from live list
        vm.showDeleted = true
        XCTAssertEqual(vm.visibleRecords.count, 1)
        vm.restore(record: vm.visibleRecords[0])
        vm.showDeleted = false
        XCTAssertEqual(vm.visibleRecords.count, 1)        // back in live list
    }

    func testMakeEditViewModelNilBeforeSelectThenNonNilAfter() {
        let vm = VaultBrowseViewModel(session: session([record(1, tombstone: false)]))
        XCTAssertNil(vm.makeEditViewModel(mode: .add))
        vm.loadBlocks(); vm.selectBlock(vm.blocks[0])
        XCTAssertNotNil(vm.makeEditViewModel(mode: .add))
    }

    func testRefreshRereadsSelectedBlock() throws {
        let s = session([record(1, tombstone: false)])
        let vm = VaultBrowseViewModel(session: s)
        vm.loadBlocks(); vm.selectBlock(vm.blocks[0])
        // mutate underneath the VM via the same session, then refresh
        try s.appendRecord(blockUuid: vm.blocks[0].uuid,
            content: RecordContentInput(recordType: "note", tags: [], fields: []))
        XCTAssertEqual(vm.visibleRecords.count, 1)  // not yet refreshed
        vm.refresh()
        XCTAssertEqual(vm.visibleRecords.count, 2)  // refresh picked up the append
    }

    func testRefreshNoOpWhenNoBlockSelected() {
        let vm = VaultBrowseViewModel(session: session([record(1, tombstone: false)]))
        vm.refresh()  // must not crash / not set error
        XCTAssertNil(vm.error)
    }
}
