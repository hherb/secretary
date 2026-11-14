// VaultSyncViewModelTests.swift
import XCTest
import SecretaryVaultAccess
import SecretaryVaultAccessTesting
@testable import SecretaryVaultAccessUI

@MainActor
final class VaultSyncViewModelTests: XCTestCase {

    private func coordinator(_ port: FakeVaultSyncPort) -> SyncCoordinator {
        SyncCoordinator(port: port, stateDir: "/state")
    }

    private func makeVM(
        port: FakeVaultSyncPort,
        gate: FakeWriteReauthGate = FakeWriteReauthGate(),
        vaultUuid: [UInt8]? = [UInt8](repeating: 7, count: 16),
        hook: FakeSyncMonitorHook? = nil,
        onVaultChanged: (@MainActor () -> Void)? = nil
    ) -> VaultSyncViewModel {
        VaultSyncViewModel(coordinator: coordinator(port),
                           wallClock: FakeWallClock(nowMs: 42),
                           gate: gate,
                           vaultUuid: vaultUuid,
                           monitor: hook,
                           onVaultChanged: onVaultChanged)
    }

    private let veto = SyncVeto(recordUuidHex: "aa", recordType: "login", tags: ["t"],
                                fieldNames: ["password"], localLastModMs: 1,
                                peerTombstonedAtMs: 2, peerDeviceHex: "bb")

    // MARK: - sync-at-unlock (never gated)

    func testSyncAtUnlockNothingToDoStaysIdle() async {
        let port = FakeVaultSyncPort(syncResult: .success(.nothingToDo))
        let hook = FakeSyncMonitorHook()
        let vm = makeVM(port: port, hook: hook)

        await vm.syncAtUnlock()

        XCTAssertFalse(vm.isSyncing)
        XCTAssertFalse(vm.reviewNeeded)
        XCTAssertNil(vm.pendingConflict)
        XCTAssertFalse(vm.conflictSheetPresented)
        XCTAssertEqual(port.syncCalls, 1)
        XCTAssertEqual(port.lastSyncStateDir, "/state")
        XCTAssertEqual(hook.muteCalls, 1)         // muted before the (possibly-writing) pass
        XCTAssertEqual(hook.acknowledgeCalls, 1)  // success → acknowledge
    }

    func testSyncAtUnlockDoesNotAskGate() async {
        let port = FakeVaultSyncPort(syncResult: .success(.mergedClean))
        let gate = FakeWriteReauthGate()
        gate.failNext = .reauthFailed("would refuse")   // proves the gate is never consulted
        let vm = makeVM(port: port, gate: gate)

        await vm.syncAtUnlock()

        XCTAssertEqual(gate.authorizeCount, 0)
        XCTAssertEqual(port.syncCalls, 1)
        XCTAssertNil(vm.lastError)
    }

    func testSyncAtUnlockConflictFlipsReviewNoSheet() async {
        let port = FakeVaultSyncPort(syncResult: .success(
            .conflictsPending(vetoes: [veto], collisions: [], manifestHash: [9])))
        let hook = FakeSyncMonitorHook()
        let vm = makeVM(port: port, hook: hook)

        await vm.syncAtUnlock()

        XCTAssertTrue(vm.reviewNeeded)
        XCTAssertNil(vm.pendingConflict)             // detail NOT surfaced at unlock
        XCTAssertFalse(vm.conflictSheetPresented)
        XCTAssertEqual(vm.badge, .reviewNeeded)
        XCTAssertEqual(hook.acknowledgeCalls, 1)
    }

    func testSyncAtUnlockFailureSetsErrorNoAcknowledge() async {
        let port = FakeVaultSyncPort(syncResult: .failure(.inProgress))
        let hook = FakeSyncMonitorHook()
        let vm = makeVM(port: port, hook: hook)

        await vm.syncAtUnlock()

        XCTAssertEqual(vm.lastError, .inProgress)
        XCTAssertFalse(vm.reviewNeeded)
        XCTAssertEqual(hook.muteCalls, 1)            // mute happened before the pass
        XCTAssertEqual(hook.acknowledgeCalls, 0)     // failure → no acknowledge
    }

    func testPendingChangesRaisedUpdatesBadge() {
        let vm = makeVM(port: FakeVaultSyncPort())
        vm.pendingChangesRaised()
        XCTAssertEqual(vm.badge, .changesDetected)
    }

    // MARK: - Sync now (gated)

    func testSyncNowAsksGateThenRunsPass() async {
        let port = FakeVaultSyncPort(syncResult: .success(.mergedClean))
        let gate = FakeWriteReauthGate()
        let vm = makeVM(port: port, gate: gate)

        await vm.syncNow()

        XCTAssertEqual(gate.authorizeCount, 1)
        XCTAssertEqual(gate.lastReason, "Confirm syncing this vault")
        XCTAssertEqual(port.syncCalls, 1)
        XCTAssertNil(vm.lastError)
    }

    func testSyncNowGateRefusalRunsNoPass() async {
        let port = FakeVaultSyncPort(syncResult: .success(.mergedClean))
        let gate = FakeWriteReauthGate()
        gate.failNext = .reauthFailed("cancelled")
        var changed = 0
        let vm = makeVM(port: port, gate: gate, onVaultChanged: { changed += 1 })

        await vm.syncNow()

        XCTAssertEqual(port.syncCalls, 0)
        XCTAssertEqual(changed, 0)
        XCTAssertFalse(vm.isSyncing)
        guard case .reauthFailed = vm.lastError else {
            return XCTFail("expected .reauthFailed, got \(String(describing: vm.lastError))")
        }
    }

    func testSyncNowCleanClearsConflictState() async {
        let port = FakeVaultSyncPort(syncResult: .success(.mergedClean))
        let vm = makeVM(port: port)
        vm.pendingChangesRaised()

        await vm.syncNow()

        XCTAssertFalse(vm.conflictSheetPresented)
        XCTAssertNil(vm.pendingConflict)
        XCTAssertFalse(vm.reviewNeeded)
    }

    func testSyncNowConflictPresentsConflictSheet() async {
        let port = FakeVaultSyncPort(syncResult: .success(
            .conflictsPending(vetoes: [veto], collisions: [], manifestHash: [9])))
        let vm = makeVM(port: port)

        await vm.syncNow()

        XCTAssertTrue(vm.conflictSheetPresented)
        XCTAssertEqual(vm.pendingConflict?.vetoes.first?.recordUuidHex, "aa")
        XCTAssertTrue(vm.reviewNeeded)
    }

    func testSyncNowFailureSetsError() async {
        let port = FakeVaultSyncPort(syncResult: .failure(.inProgress))
        let vm = makeVM(port: port)

        await vm.syncNow()

        XCTAssertEqual(vm.lastError, .inProgress)
        XCTAssertFalse(vm.conflictSheetPresented)
    }

    /// A second "Sync now" tap while the first tap's re-auth prompt is still up is
    /// dropped: no second prompt and no second pass.
    func testSecondSyncNowTapWhileThePromptIsUpIsDropped() async {
        let port = FakeVaultSyncPort(syncResult: .success(.nothingToDo))
        let gate = FakeWriteReauthGate()
        let prompt = SuspensionGate()
        gate.suspension = prompt
        let vm = makeVM(port: port, gate: gate)

        let first = Task { await vm.syncNow() }
        await prompt.waitUntilEntered()
        await vm.syncNow()
        await prompt.release()
        await first.value

        XCTAssertEqual(gate.authorizeCount, 1)
        XCTAssertEqual(port.syncCalls, 1)
    }

    // MARK: - onVaultChanged

    func testOnVaultChangedFiresAfterMergedCleanNotAfterRollbackOrConflict() async {
        let cases: [(SyncOutcome, Bool)] = [
            (.mergedClean, true),
            (.silentMerge, true),
            (.appliedAutomatically, true),
            (.nothingToDo, true),
            (.rollbackRejected, false),
            (.conflictsPending(vetoes: [veto], collisions: [], manifestHash: [9]), false),
        ]
        for (outcome, expected) in cases {
            for unlock in [true, false] {
                var changed = 0
                let vm = makeVM(port: FakeVaultSyncPort(syncResult: .success(outcome)),
                                onVaultChanged: { changed += 1 })
                if unlock { await vm.syncAtUnlock() } else { await vm.syncNow() }
                XCTAssertEqual(changed, expected ? 1 : 0, "\(outcome) unlock=\(unlock)")
            }
        }
        var failed = 0
        let vm = makeVM(port: FakeVaultSyncPort(syncResult: .failure(.inProgress)),
                        onVaultChanged: { failed += 1 })
        await vm.syncNow()
        XCTAssertEqual(failed, 0, "a thrown pass changes nothing")
    }

    func testOnVaultChangedFiresAfterCleanResolve() async {
        var changed = 0
        let (vm, _) = await vmWithStashedConflict(commitResult: .success(.mergedClean),
                                                  onVaultChanged: { changed += 1 })
        XCTAssertEqual(changed, 0)                   // the paused pass changed nothing

        await vm.resolve(decisions: [SyncVetoDecision(recordUuidHex: "aa", keepLocal: true)])

        XCTAssertEqual(changed, 1)
    }

    func testViewModelRetainsOnVaultChangedHook() async {
        // The hook is the only reference to its closure in production; holding it
        // weakly would make the browse reload silently no-op.
        final class Box { var calls = 0 }
        weak var weakBox: Box?
        let vm: VaultSyncViewModel = {
            let box = Box()
            weakBox = box
            return makeVM(port: FakeVaultSyncPort(syncResult: .success(.mergedClean)),
                          onVaultChanged: { box.calls += 1 })
        }()
        XCTAssertNotNil(weakBox, "VM must strongly retain onVaultChanged")
        await vm.syncAtUnlock()
        XCTAssertEqual(weakBox?.calls, 1)
    }

    // MARK: - resolve (gated)

    /// Drives a conflict into the stash, then returns the VM + port for a resolve.
    private func vmWithStashedConflict(
        commitResult: Result<SyncOutcome, VaultSyncError>,
        gate: FakeWriteReauthGate = FakeWriteReauthGate(),
        onVaultChanged: (@MainActor () -> Void)? = nil
    ) async -> (VaultSyncViewModel, FakeVaultSyncPort) {
        let port = FakeVaultSyncPort(
            syncResult: .success(.conflictsPending(vetoes: [veto], collisions: [],
                                                   manifestHash: [9])),
            commitResult: commitResult)
        let vm = makeVM(port: port, gate: gate, onVaultChanged: onVaultChanged)
        await vm.syncNow()   // stash the conflict
        return (vm, port)
    }

    func testResolveSuccessCommitsAndClears() async {
        let (vm, port) = await vmWithStashedConflict(commitResult: .success(.mergedClean))
        let decision = SyncVetoDecision(recordUuidHex: "aa", keepLocal: true)

        await vm.resolve(decisions: [decision])

        XCTAssertEqual(port.commitCalls, 1)
        XCTAssertEqual(port.lastCommitDecisions, [decision])
        XCTAssertEqual(port.lastCommitManifestHash, [9])    // freshness token replayed
        XCTAssertEqual(port.lastCommitStateDir, "/state")
        XCTAssertFalse(vm.conflictSheetPresented)
        XCTAssertNil(vm.pendingConflict)
        XCTAssertFalse(vm.reviewNeeded)
        XCTAssertNil(vm.lastError)
    }

    func testResolveIsGated() async {
        let gate = FakeWriteReauthGate()
        let (vm, port) = await vmWithStashedConflict(commitResult: .success(.mergedClean),
                                                     gate: gate)
        XCTAssertEqual(gate.authorizeCount, 1)              // the syncNow that stashed

        // Approved: one more prompt, then the commit.
        await vm.resolve(decisions: [SyncVetoDecision(recordUuidHex: "aa", keepLocal: true)])
        XCTAssertEqual(gate.authorizeCount, 2)
        XCTAssertEqual(gate.lastReason, "Confirm syncing this vault")
        XCTAssertEqual(port.commitCalls, 1)

        // Refused: no commit, sheet state untouched.
        let gate2 = FakeWriteReauthGate()
        let (vm2, port2) = await vmWithStashedConflict(commitResult: .success(.mergedClean),
                                                       gate: gate2)
        gate2.failNext = .reauthFailed("cancelled")
        await vm2.resolve(decisions: [SyncVetoDecision(recordUuidHex: "aa", keepLocal: true)])
        XCTAssertEqual(port2.commitCalls, 0)
        XCTAssertTrue(vm2.conflictSheetPresented)
        XCTAssertNotNil(vm2.pendingConflict)
        guard case .reauthFailed = vm2.lastError else {
            return XCTFail("expected .reauthFailed, got \(String(describing: vm2.lastError))")
        }
    }

    func testResolveEvidenceStaleKeepsSheetOpen() async {
        let (vm, _) = await vmWithStashedConflict(commitResult: .failure(.evidenceStale))

        await vm.resolve(decisions: [SyncVetoDecision(recordUuidHex: "aa", keepLocal: false)])

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
        let suspension = SuspensionGate()
        let port = FakeVaultSyncPort(syncResult: .success(.nothingToDo))
        port.gate = suspension
        let vm = makeVM(port: port)

        let task = Task { await vm.syncNow() }
        await suspension.waitUntilEntered()
        XCTAssertEqual(vm.badge, .syncing)
        XCTAssertTrue(vm.isSyncing)
        await suspension.release()
        await task.value
        XCTAssertFalse(vm.isSyncing)
    }

    func testViewModelRetainsMonitorHookForPasses() async {
        // Regression: the VM must STRONGLY retain its monitor hook. If it holds the
        // hook weakly, the only production instance (a local in makeVaultSync)
        // deallocates immediately and muteSelfWrite/acknowledge silently no-op.
        weak var weakHook: FakeSyncMonitorHook?
        let port = FakeVaultSyncPort(syncResult: .success(.nothingToDo))
        let vm: VaultSyncViewModel = {
            let hook = FakeSyncMonitorHook()
            weakHook = hook
            return VaultSyncViewModel(
                coordinator: SyncCoordinator(port: port, stateDir: "/s"),
                wallClock: FakeWallClock(nowMs: 1),
                gate: FakeWriteReauthGate(),
                vaultUuid: nil,
                monitor: hook)
        }()                                  // local `hook` strong ref ends here
        XCTAssertNotNil(weakHook, "VM must strongly retain its monitor hook")
        await vm.syncAtUnlock()
        XCTAssertEqual(weakHook?.muteCalls, 1)
        XCTAssertEqual(weakHook?.acknowledgeCalls, 1)
    }
}
