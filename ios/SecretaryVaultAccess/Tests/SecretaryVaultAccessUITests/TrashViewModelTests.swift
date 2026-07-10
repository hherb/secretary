import XCTest
@testable import SecretaryVaultAccessUI
import SecretaryVaultAccess
import SecretaryVaultAccessTesting

@MainActor
final class TrashViewModelTests: XCTestCase {
    private func tb(_ b: UInt8, at ms: UInt64) -> TrashedBlockInfo {
        TrashedBlockInfo(blockUuid: [b], blockName: "n\(b)",
                         tombstonedAtMs: ms, tombstonedBy: [0])
    }

    func testLoadSortsNewestFirst() {
        let port = FakeTrashPort(trashedBlocks: [tb(1, at: 100), tb(2, at: 300)])
        let vm = TrashViewModel(port: port, gate: FakeWriteReauthGate())
        vm.load()
        XCTAssertEqual(vm.entries.map { $0.tombstonedAtMs }, [300, 100])
    }

    func testPurgeGatesThenRemoves() async {
        let port = FakeTrashPort(trashedBlocks: [tb(1, at: 100)])
        let gate = FakeWriteReauthGate()
        let vm = TrashViewModel(port: port, gate: gate)
        vm.load()
        await vm.purge(uuid: [1])
        XCTAssertEqual(gate.authorizeCount, 1)
        XCTAssertEqual(port.purgedUuids, [[1]])
        XCTAssertTrue(vm.entries.isEmpty)
        XCTAssertNil(vm.error)
    }

    func testPurgeBlockedByReauthDoesNotWrite() async {
        let port = FakeTrashPort(trashedBlocks: [tb(1, at: 100)])
        let gate = FakeWriteReauthGate()
        gate.failNext = .reauthFailed("cancelled")
        let vm = TrashViewModel(port: port, gate: gate)
        vm.load()
        await vm.purge(uuid: [1])
        XCTAssertEqual(vm.error, .reauthFailed("cancelled"))
        XCTAssertEqual(port.purgedUuids, [], "no purge on refused re-auth")
        XCTAssertEqual(vm.entries.count, 1, "entry stays listed")
        XCTAssertEqual(gate.authorizeCount, 1)
    }

    func testEmptyTrashGatesReloadsAndDiscardsReport() async {
        let port = FakeTrashPort(trashedBlocks: [tb(1, at: 100), tb(2, at: 200)])
        let gate = FakeWriteReauthGate()
        let vm = TrashViewModel(port: port, gate: gate)
        vm.load()
        await vm.emptyTrash()
        XCTAssertEqual(gate.authorizeCount, 1)
        XCTAssertEqual(port.emptyTrashCount, 1)
        XCTAssertTrue(vm.entries.isEmpty)
    }

    func testPreviewRetentionIsUngated() {
        let port = FakeTrashPort(
            expiredEntries: [ExpiredEntryInfo(blockUuid: [1], tombstonedAtMs: 0,
                                              ageMs: 100 * 86_400_000)])
        let gate = FakeWriteReauthGate()
        let vm = TrashViewModel(port: port, gate: gate)
        vm.previewRetention()
        XCTAssertEqual(port.previewCount, 1)
        XCTAssertEqual(gate.authorizeCount, 0, "preview is a read; no re-auth")
        XCTAssertEqual(vm.preview?.count, 1)
    }

    func testRunRetentionUsesDefaultWindowAndGates() async {
        let port = FakeTrashPort(
            expiredEntries: [ExpiredEntryInfo(blockUuid: [1], tombstonedAtMs: 0, ageMs: 1)],
            defaultWindowMs: 90 * 86_400_000)
        let gate = FakeWriteReauthGate()
        let vm = TrashViewModel(port: port, gate: gate)
        await vm.runRetention()
        XCTAssertEqual(gate.authorizeCount, 1)
        XCTAssertEqual(port.autoPurgeWindows, [90 * 86_400_000])
    }
}
