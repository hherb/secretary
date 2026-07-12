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

    func testRestoreGatesThenRemoves() async {
        let port = FakeTrashPort(trashedBlocks: [tb(1, at: 100), tb(2, at: 200)])
        let gate = FakeWriteReauthGate()
        let vm = TrashViewModel(port: port, gate: gate)
        vm.load()
        await vm.restore(uuid: [1])
        XCTAssertEqual(gate.authorizeCount, 1)
        XCTAssertEqual(port.restoredUuids, [[1]])
        XCTAssertEqual(vm.entries.map { $0.blockUuid }, [[2]], "restored block leaves the list")
        XCTAssertNil(vm.error)
    }

    func testRestoreBlockedByReauthDoesNotWrite() async {
        let port = FakeTrashPort(trashedBlocks: [tb(1, at: 100)])
        let gate = FakeWriteReauthGate()
        gate.failNext = .reauthFailed("cancelled")
        let vm = TrashViewModel(port: port, gate: gate)
        vm.load()
        await vm.restore(uuid: [1])
        XCTAssertEqual(vm.error, .reauthFailed("cancelled"))
        XCTAssertEqual(port.restoredUuids, [], "no restore on refused re-auth")
        XCTAssertEqual(vm.entries.count, 1, "entry stays listed")
        XCTAssertEqual(gate.authorizeCount, 1)
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

    func testEmptyTrashGatesReloadsAndSetsNotice() async {
        let port = FakeTrashPort(trashedBlocks: [tb(1, at: 100), tb(2, at: 200)])
        let gate = FakeWriteReauthGate()
        let vm = TrashViewModel(port: port, gate: gate)
        vm.load()
        await vm.emptyTrash()
        XCTAssertEqual(gate.authorizeCount, 1)
        XCTAssertEqual(port.emptyTrashCount, 1)
        XCTAssertTrue(vm.entries.isEmpty)
        XCTAssertEqual(vm.purgeNotice, PurgeNotice(text: "Purged 2 items", severity: .success))
    }

    func testEmptyTrashWarnsWhenFilesFailed() async {
        let port = FakeTrashPort(trashedBlocks: [tb(1, at: 100), tb(2, at: 200)])
        port.emptyTrashFilesFailed = 1
        let vm = TrashViewModel(port: port, gate: FakeWriteReauthGate())
        vm.load()
        await vm.emptyTrash()
        XCTAssertEqual(vm.purgeNotice,
                       PurgeNotice(text: "Purged 2 items · 1 file could not be removed", severity: .warning))
    }

    func testPurgeSetsDeletedForeverNotice() async {
        let port = FakeTrashPort(trashedBlocks: [tb(1, at: 100)])
        let vm = TrashViewModel(port: port, gate: FakeWriteReauthGate())
        vm.load()
        await vm.purge(uuid: [1])
        XCTAssertEqual(vm.purgeNotice, PurgeNotice(text: "Deleted forever", severity: .success))
    }

    func testRefusedReauthClearsPriorNoticeAndSetsNone() async {
        let port = FakeTrashPort(trashedBlocks: [tb(1, at: 100), tb(2, at: 200)])
        let gate = FakeWriteReauthGate()
        let vm = TrashViewModel(port: port, gate: gate)
        vm.load()
        await vm.emptyTrash()                       // sets a notice
        XCTAssertNotNil(vm.purgeNotice)
        gate.failNext = .reauthFailed("cancelled")
        await vm.purge(uuid: [2])                    // refused: no new notice, prior cleared
        XCTAssertNil(vm.purgeNotice)
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

    func testClearPreviewResetsCachedPreview() {
        let port = FakeTrashPort(
            expiredEntries: [ExpiredEntryInfo(blockUuid: [1], tombstonedAtMs: 0,
                                              ageMs: 100 * 86_400_000)])
        let vm = TrashViewModel(port: port, gate: FakeWriteReauthGate())
        vm.previewRetention()
        XCTAssertNotNil(vm.preview)
        vm.clearPreview()
        XCTAssertNil(vm.preview, "cleared so a reopened sheet shows its loading state")
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
        XCTAssertEqual(vm.purgeNotice, PurgeNotice(text: "Purged 1 item", severity: .success))
    }

    func testRunRetentionWarnsWhenFilesFailed() async {
        let port = FakeTrashPort(
            expiredEntries: [ExpiredEntryInfo(blockUuid: [1], tombstonedAtMs: 0, ageMs: 1),
                             ExpiredEntryInfo(blockUuid: [2], tombstonedAtMs: 0, ageMs: 1)])
        port.retentionFilesFailed = 1
        let vm = TrashViewModel(port: port, gate: FakeWriteReauthGate())
        await vm.runRetention()
        XCTAssertEqual(vm.purgeNotice,
                       PurgeNotice(text: "Purged 2 items · 1 file could not be removed", severity: .warning))
    }

    // MARK: per-vault retention window (settings integration)

    func testUsesPerVaultRetentionWindowFromSettings() async {
        let port = FakeTrashPort(
            expiredEntries: [ExpiredEntryInfo(blockUuid: [1], tombstonedAtMs: 0, ageMs: 1)],
            defaultWindowMs: 90 * 86_400_000)
        let settings = FakeSettingsPort(settings: VaultSettings(
            autoLockTimeoutMs: 600_000, requirePasswordBeforeEdits: true,
            reauthGraceWindowMs: 120_000, retentionWindowMs: 30 * 86_400_000))   // 30 d, not the 90 d default
        let vm = TrashViewModel(port: port, settingsPort: settings, gate: FakeWriteReauthGate())
        vm.load()
        XCTAssertEqual(vm.retentionWindowMs, 30 * 86_400_000, "accessor reflects the per-vault window")
        vm.previewRetention()
        XCTAssertEqual(port.previewWindows, [30 * 86_400_000], "preview uses the per-vault window")
        await vm.runRetention()
        XCTAssertEqual(port.autoPurgeWindows, [30 * 86_400_000], "commit uses the per-vault window")
    }

    func testFallsBackToDefaultWhenSettingsReadFails() {
        let port = FakeTrashPort(defaultWindowMs: 90 * 86_400_000)
        let settings = FakeSettingsPort()
        settings.failNextRead = .corruptVault("x")
        let vm = TrashViewModel(port: port, settingsPort: settings, gate: FakeWriteReauthGate())
        vm.load()
        XCTAssertEqual(vm.retentionWindowMs, 90 * 86_400_000, "settings read error → frozen default")
        XCTAssertNil(vm.error, "a settings read failure must not block the Trash list")
    }
}
