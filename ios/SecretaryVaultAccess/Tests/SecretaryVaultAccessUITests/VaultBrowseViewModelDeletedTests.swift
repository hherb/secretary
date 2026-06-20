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

    func testRecordsHideTombstonedByDefault() {
        let vm = VaultBrowseViewModel(session: session([record(1, tombstone: false),
                                                        record(2, tombstone: true)]),
                                      gate: FakeWriteReauthGate())
        vm.loadBlocks(); vm.selectBlock(vm.blocks[0])
        // The gate (modeled by the fake) withheld the tombstoned record.
        XCTAssertEqual(vm.visibleRecords.map(\.uuid), [[1]])
    }

    func testTogglingShowDeletedRereadsWithFlag() {
        let s = session([record(1, tombstone: false), record(2, tombstone: true)])
        let vm = VaultBrowseViewModel(session: s, gate: FakeWriteReauthGate())
        vm.loadBlocks(); vm.selectBlock(vm.blocks[0])
        XCTAssertEqual(s.lastIncludeDeleted, false)   // initial read was live-only
        let readsBefore = s.readCount
        vm.showDeleted = true
        XCTAssertGreaterThan(s.readCount, readsBefore) // toggling re-read
        XCTAssertEqual(s.lastIncludeDeleted, true)     // with the new flag
        XCTAssertEqual(vm.visibleRecords.map(\.uuid), [[1], [2]])
    }

    func testDeleteThenRestoreUpdatesVisibility() async {
        let vm = VaultBrowseViewModel(session: session([record(1, tombstone: false)]),
                                      gate: FakeWriteReauthGate())
        vm.loadBlocks(); vm.selectBlock(vm.blocks[0])
        await vm.delete(record: vm.visibleRecords[0])
        XCTAssertTrue(vm.visibleRecords.isEmpty)       // gone from live list
        vm.showDeleted = true
        XCTAssertEqual(vm.visibleRecords.count, 1)     // re-read shows it
        await vm.restore(record: vm.visibleRecords[0])
        vm.showDeleted = false
        XCTAssertEqual(vm.visibleRecords.count, 1)     // back in live list
    }

    func testMakeEditViewModelNilBeforeSelectThenNonNilAfter() {
        let vm = VaultBrowseViewModel(session: session([record(1, tombstone: false)]),
                                      gate: FakeWriteReauthGate())
        XCTAssertNil(vm.makeEditViewModel(mode: .add))
        vm.loadBlocks(); vm.selectBlock(vm.blocks[0])
        XCTAssertNotNil(vm.makeEditViewModel(mode: .add))
    }

    func testRefreshRereadsSelectedBlock() throws {
        let s = session([record(1, tombstone: false)])
        let vm = VaultBrowseViewModel(session: s, gate: FakeWriteReauthGate())
        vm.loadBlocks(); vm.selectBlock(vm.blocks[0])
        try s.appendRecord(blockUuid: vm.blocks[0].uuid,
            content: RecordContentInput(recordType: "note", tags: [], fields: []))
        XCTAssertEqual(vm.visibleRecords.count, 1)  // not yet refreshed
        vm.refresh()
        XCTAssertEqual(vm.visibleRecords.count, 2)  // refresh picked up the append
    }

    func testRefreshNoOpWhenNoBlockSelected() {
        let vm = VaultBrowseViewModel(session: session([record(1, tombstone: false)]),
                                      gate: FakeWriteReauthGate())
        vm.refresh()
        XCTAssertNil(vm.error)
    }

    func testIsWritingFalseAtRestAndAfterDelete() async {
        let vm = VaultBrowseViewModel(session: session([record(1, tombstone: false)]),
                                      gate: FakeWriteReauthGate())
        vm.loadBlocks(); vm.selectBlock(vm.blocks[0])
        XCTAssertFalse(vm.isWriting)              // false at rest
        await vm.delete(record: vm.visibleRecords[0])
        XCTAssertFalse(vm.isWriting)              // defer reset ran on synchronous path
    }
}
