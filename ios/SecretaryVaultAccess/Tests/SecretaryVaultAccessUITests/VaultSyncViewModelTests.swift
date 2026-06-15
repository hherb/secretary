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

    func testPendingChangesRaisedUpdatesBadge() {
        let vm = makeVM(port: FakeVaultSyncPort())
        vm.pendingChangesRaised()
        XCTAssertEqual(vm.badge, .changesDetected)
    }

    func testBeginInteractiveSyncPresentsPasswordSheet() {
        let vm = makeVM(port: FakeVaultSyncPort())
        vm.beginInteractiveSync()
        XCTAssertTrue(vm.passwordSheetPresented)
    }

    func testInteractivePassCleanDismissesAndClears() async {
        let port = FakeVaultSyncPort(syncResult: .success(.mergedClean))
        let vm = makeVM(port: port)
        vm.beginInteractiveSync()
        vm.pendingChangesRaised()                    // badge was changesDetected

        await vm.runInteractivePass(password: Array("pw".utf8))

        XCTAssertFalse(vm.passwordSheetPresented)
        XCTAssertFalse(vm.conflictSheetPresented)
        XCTAssertNil(vm.pendingConflict)
        XCTAssertFalse(vm.reviewNeeded)
    }

    func testInteractivePassConflictPresentsConflictSheet() async {
        let veto = SyncVeto(recordUuidHex: "aa", recordType: "login", tags: ["t"],
                            fieldNames: ["password"], localLastModMs: 1,
                            peerTombstonedAtMs: 2, peerDeviceHex: "bb")
        let port = FakeVaultSyncPort(syncResult: .success(
            .conflictsPending(vetoes: [veto], collisions: [], manifestHash: [9])))
        let vm = makeVM(port: port)
        vm.beginInteractiveSync()

        await vm.runInteractivePass(password: Array("pw".utf8))

        XCTAssertFalse(vm.passwordSheetPresented)    // password sheet dismissed
        XCTAssertTrue(vm.conflictSheetPresented)     // conflict sheet up
        XCTAssertEqual(vm.pendingConflict?.vetoes.first?.recordUuidHex, "aa")
        XCTAssertTrue(vm.reviewNeeded)
    }

    func testInteractivePassFailureKeepsPasswordSheetOpen() async {
        let port = FakeVaultSyncPort(syncResult: .failure(.inProgress))
        let vm = makeVM(port: port)
        vm.beginInteractiveSync()

        await vm.runInteractivePass(password: Array("pw".utf8))

        XCTAssertEqual(vm.lastError, .inProgress)
        XCTAssertTrue(vm.passwordSheetPresented)     // stays open for retry
        XCTAssertFalse(vm.conflictSheetPresented)
    }

    /// Drives a conflict into the stash, then resolves it. Returns the VM + port.
    private func vmWithStashedConflict(
        commitResult: Result<SyncOutcome, VaultSyncError>
    ) async -> (VaultSyncViewModel, FakeVaultSyncPort) {
        let veto = SyncVeto(recordUuidHex: "aa", recordType: "login", tags: [],
                            fieldNames: ["password"], localLastModMs: 1,
                            peerTombstonedAtMs: 2, peerDeviceHex: "bb")
        let port = FakeVaultSyncPort(
            syncResult: .success(.conflictsPending(vetoes: [veto], collisions: [],
                                                   manifestHash: [9])),
            commitResult: commitResult)
        let vm = makeVM(port: port)
        vm.beginInteractiveSync()
        await vm.runInteractivePass(password: Array("pw".utf8))   // stash the conflict
        return (vm, port)
    }

    func testResolveSuccessCommitsAndClears() async {
        let (vm, port) = await vmWithStashedConflict(commitResult: .success(.mergedClean))
        let decision = SyncVetoDecision(recordUuidHex: "aa", keepLocal: true)

        await vm.resolve(decisions: [decision], password: Array("pw".utf8))

        XCTAssertEqual(port.commitCalls, 1)
        XCTAssertEqual(port.lastCommitDecisions, [decision])
        XCTAssertEqual(port.lastCommitManifestHash, [9])    // freshness token replayed
        XCTAssertFalse(vm.conflictSheetPresented)
        XCTAssertNil(vm.pendingConflict)
        XCTAssertFalse(vm.reviewNeeded)
        XCTAssertNil(vm.lastError)
    }

    func testResolveEvidenceStaleKeepsSheetOpen() async {
        let (vm, _) = await vmWithStashedConflict(commitResult: .failure(.evidenceStale))
        let decision = SyncVetoDecision(recordUuidHex: "aa", keepLocal: false)

        await vm.resolve(decisions: [decision], password: Array("pw".utf8))

        XCTAssertEqual(vm.lastError, .evidenceStale)
        XCTAssertTrue(vm.conflictSheetPresented)            // stays open for retry
        XCTAssertNotNil(vm.pendingConflict)
    }

    func testCancelConflictDismissesButKeepsReviewNeeded() async {
        let (vm, _) = await vmWithStashedConflict(commitResult: .success(.mergedClean))
        vm.cancelConflict()
        XCTAssertFalse(vm.conflictSheetPresented)
        XCTAssertNil(vm.pendingConflict)
        XCTAssertTrue(vm.reviewNeeded)                      // badge still flags review
    }

    func testBadgeIsSyncingMidPass() async {
        let gate = SuspensionGate()
        let port = FakeVaultSyncPort(syncResult: .success(.nothingToDo))
        port.gate = gate
        let vm = makeVM(port: port)

        let task = Task { await vm.runInteractivePass(password: Array("pw".utf8)) }
        await gate.waitUntilEntered()
        XCTAssertEqual(vm.badge, .syncing)
        XCTAssertTrue(vm.isSyncing)
        await gate.release()
        await task.value
        XCTAssertFalse(vm.isSyncing)
    }
}
