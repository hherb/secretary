// VaultSyncViewModelTests.swift
import XCTest
import SecretaryVaultAccess
import SecretaryVaultAccessTesting
@testable import SecretaryVaultAccessUI

@MainActor
final class VaultSyncViewModelTests: XCTestCase {

    private func coordinator(_ port: FakeVaultSyncPort) -> SyncCoordinator {
        SyncCoordinator(port: port, stateDir: "/state", vaultFolder: "/vault")
    }

    private func makeVM(
        port: FakeVaultSyncPort,
        vaultUuid: [UInt8]? = [UInt8](repeating: 7, count: 16),
        hook: FakeSyncMonitorHook? = nil
    ) -> VaultSyncViewModel {
        VaultSyncViewModel(coordinator: coordinator(port),
                           wallClock: FakeWallClock(nowMs: 42),
                           vaultUuid: vaultUuid,
                           monitor: hook)
    }

    func testSyncAtUnlockNothingToDoStaysIdle() async {
        let port = FakeVaultSyncPort(syncResult: .success(.nothingToDo))
        let hook = FakeSyncMonitorHook()
        let vm = makeVM(port: port, hook: hook)

        await vm.syncAtUnlock(password: Array("pw".utf8))

        XCTAssertFalse(vm.isSyncing)
        XCTAssertFalse(vm.reviewNeeded)
        XCTAssertNil(vm.pendingConflict)
        XCTAssertFalse(vm.conflictSheetPresented)
        XCTAssertEqual(port.syncCalls, 1)
        XCTAssertEqual(port.lastSyncPassword, Array("pw".utf8))
        XCTAssertEqual(port.lastSyncStateDir, "/state")
        XCTAssertEqual(hook.muteCalls, 1)         // muted before the (possibly-writing) pass
        XCTAssertEqual(hook.acknowledgeCalls, 1)  // success → acknowledge
    }

    func testSyncAtUnlockConflictFlipsReviewNoSheet() async {
        let veto = SyncVeto(recordUuidHex: "aa", recordType: "login", tags: [],
                            fieldNames: ["password"], localLastModMs: 1,
                            peerTombstonedAtMs: 2, peerDeviceHex: "bb")
        let port = FakeVaultSyncPort(syncResult: .success(
            .conflictsPending(vetoes: [veto], collisions: [], manifestHash: [9])))
        let hook = FakeSyncMonitorHook()
        let vm = makeVM(port: port, hook: hook)

        await vm.syncAtUnlock(password: Array("pw".utf8))

        XCTAssertTrue(vm.reviewNeeded)
        XCTAssertNil(vm.pendingConflict)             // detail NOT surfaced at unlock
        XCTAssertFalse(vm.conflictSheetPresented)
        XCTAssertFalse(vm.passwordSheetPresented)
        XCTAssertEqual(vm.badge, .reviewNeeded)
        XCTAssertEqual(hook.acknowledgeCalls, 1)
    }

    func testSyncAtUnlockFailureSetsErrorNoAcknowledge() async {
        let port = FakeVaultSyncPort(syncResult: .failure(.wrongPasswordOrCorrupt))
        let hook = FakeSyncMonitorHook()
        let vm = makeVM(port: port, hook: hook)

        await vm.syncAtUnlock(password: Array("bad".utf8))

        XCTAssertEqual(vm.lastError, .wrongPasswordOrCorrupt)
        XCTAssertFalse(vm.reviewNeeded)
        XCTAssertEqual(hook.muteCalls, 1)            // mute happened before the pass
        XCTAssertEqual(hook.acknowledgeCalls, 0)     // failure → no acknowledge
    }
}
