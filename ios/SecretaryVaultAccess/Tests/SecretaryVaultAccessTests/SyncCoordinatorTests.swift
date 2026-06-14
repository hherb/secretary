import XCTest
@testable import SecretaryVaultAccess
import SecretaryVaultAccessTesting

final class SyncCoordinatorTests: XCTestCase {
    private let pw: [UInt8] = Array("correct horse battery staple".utf8)
    private func makeVeto() -> SyncVeto {
        SyncVeto(recordUuidHex: "aa", recordType: "login", tags: [],
                 fieldNames: ["password"], localLastModMs: 1,
                 peerTombstonedAtMs: 2, peerDeviceHex: "bb")
    }

    func testRunPassPassesSafeArmThroughAndLeavesNoPendingConflict() async throws {
        let port = FakeVaultSyncPort(syncResult: .success(.appliedAutomatically))
        let coord = SyncCoordinator(port: port, stateDir: "/tmp/s", vaultFolder: "/tmp/v")
        let outcome = try await coord.runPass(password: pw, nowMs: 0)
        XCTAssertEqual(outcome, .appliedAutomatically)
        let pending = await coord.pendingConflict
        XCTAssertNil(pending)
        XCTAssertEqual(port.syncCalls, 1)
        XCTAssertEqual(port.lastSyncPassword, pw)
        XCTAssertEqual(port.lastSyncStateDir, "/tmp/s")
        XCTAssertEqual(port.lastSyncVaultFolder, "/tmp/v")
    }

    func testRunPassOnConflictStashesDetail() async throws {
        let veto = makeVeto()
        let port = FakeVaultSyncPort(syncResult: .success(
            .conflictsPending(vetoes: [veto], collisions: [], manifestHash: [7, 7, 7])))
        let coord = SyncCoordinator(port: port, stateDir: "/tmp/s", vaultFolder: "/tmp/v")
        let outcome = try await coord.runPass(password: pw, nowMs: 0)
        XCTAssertEqual(outcome, .conflictsPending(vetoes: [veto], collisions: [], manifestHash: [7, 7, 7]))
        let pending = await coord.pendingConflict
        XCTAssertEqual(pending, PendingConflict(vetoes: [veto], collisions: []))
    }

    func testResolveUsesStashedTokenAndDecisions() async throws {
        let veto = makeVeto()
        let port = FakeVaultSyncPort(
            syncResult: .success(.conflictsPending(vetoes: [veto], collisions: [], manifestHash: [7, 7, 7])),
            commitResult: .success(.mergedClean))
        let coord = SyncCoordinator(port: port, stateDir: "/tmp/s", vaultFolder: "/tmp/v")
        _ = try await coord.runPass(password: pw, nowMs: 0)
        let decisions = [SyncVetoDecision(recordUuidHex: "aa", keepLocal: true)]
        let outcome = try await coord.resolve(decisions: decisions, password: pw, nowMs: 0)
        XCTAssertEqual(outcome, .mergedClean)
        XCTAssertEqual(port.commitCalls, 1)
        XCTAssertEqual(port.lastCommitManifestHash, [7, 7, 7])
        XCTAssertEqual(port.lastCommitDecisions, decisions)
        XCTAssertEqual(port.lastCommitPassword, pw)
        XCTAssertEqual(port.lastCommitVaultFolder, "/tmp/v")
        let pending = await coord.pendingConflict
        XCTAssertNil(pending)
    }

    func testResolveWithoutPendingConflictThrowsAndMakesNoFfiCall() async {
        let port = FakeVaultSyncPort()
        let coord = SyncCoordinator(port: port, stateDir: "/tmp/s", vaultFolder: "/tmp/v")
        do {
            _ = try await coord.resolve(decisions: [], password: pw, nowMs: 0)
            XCTFail("expected noPendingConflict")
        } catch let e as VaultSyncError {
            XCTAssertEqual(e, .noPendingConflict)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
        XCTAssertEqual(port.commitCalls, 0)
    }

    func testResolveStaleTokenPropagatesErrorAndPreservesStash() async throws {
        let veto = makeVeto()
        let port = FakeVaultSyncPort(
            syncResult: .success(.conflictsPending(vetoes: [veto], collisions: [], manifestHash: [7])),
            commitResult: .failure(.evidenceStale))
        let coord = SyncCoordinator(port: port, stateDir: "/tmp/s", vaultFolder: "/tmp/v")
        _ = try await coord.runPass(password: pw, nowMs: 0)
        do {
            _ = try await coord.resolve(decisions: [], password: pw, nowMs: 0)
            XCTFail("expected evidenceStale")
        } catch let e as VaultSyncError {
            XCTAssertEqual(e, .evidenceStale)
        }
        let pending = await coord.pendingConflict
        XCTAssertEqual(pending, PendingConflict(vetoes: [veto], collisions: []))
    }

    func testResolveReRaisingConflictReplacesStash() async throws {
        let vetoA = SyncVeto(recordUuidHex: "aa", recordType: "login", tags: [],
                             fieldNames: ["password"], localLastModMs: 1,
                             peerTombstonedAtMs: 2, peerDeviceHex: "bb")
        let vetoB = SyncVeto(recordUuidHex: "cc", recordType: "note", tags: [],
                             fieldNames: ["body"], localLastModMs: 3,
                             peerTombstonedAtMs: 4, peerDeviceHex: "dd")
        let port = FakeVaultSyncPort(
            syncResult: .success(.conflictsPending(vetoes: [vetoA], collisions: [], manifestHash: [1])),
            commitResult: .success(.conflictsPending(vetoes: [vetoB], collisions: [], manifestHash: [2])))
        let coord = SyncCoordinator(port: port, stateDir: "/tmp/s", vaultFolder: "/tmp/v")
        _ = try await coord.runPass(password: pw, nowMs: 0)
        let outcome = try await coord.resolve(decisions: [], password: pw, nowMs: 0)
        XCTAssertEqual(outcome, .conflictsPending(vetoes: [vetoB], collisions: [], manifestHash: [2]))
        // commit replayed the FIRST pass's token; stash now reflects the re-raised conflict
        XCTAssertEqual(port.lastCommitManifestHash, [1])
        let pending = await coord.pendingConflict
        XCTAssertEqual(pending, PendingConflict(vetoes: [vetoB], collisions: []))
    }

    func testRunPassClearsAStalePendingConflictOnASafeArm() async throws {
        let veto = makeVeto()
        let conflictPort = FakeVaultSyncPort(
            syncResult: .success(.conflictsPending(vetoes: [veto], collisions: [], manifestHash: [7])))
        let coord = SyncCoordinator(port: conflictPort, stateDir: "/tmp/s", vaultFolder: "/tmp/v")
        _ = try await coord.runPass(password: pw, nowMs: 0)
        let firstPending = await coord.pendingConflict
        XCTAssertNotNil(firstPending)
        let safePort = FakeVaultSyncPort(syncResult: .success(.nothingToDo))
        let coord2 = SyncCoordinator(port: safePort, stateDir: "/tmp/s", vaultFolder: "/tmp/v")
        _ = try await coord2.runPass(password: pw, nowMs: 0)
        let secondPending = await coord2.pendingConflict
        XCTAssertNil(secondPending)
    }

    func testStatusForwardsToPort() async throws {
        let status = SyncStatus(hasState: true,
                                deviceClocks: [DeviceClock(deviceUuidHex: "aa", counter: 3)],
                                lastStateWriteMs: 99)
        let port = FakeVaultSyncPort(statusResult: .success(status))
        let coord = SyncCoordinator(port: port, stateDir: "/tmp/s", vaultFolder: "/tmp/v")
        let got = try await coord.status(vaultUuid: Array(repeating: 9, count: 16))
        XCTAssertEqual(got, status)
        XCTAssertEqual(port.statusCalls, 1)
        XCTAssertEqual(port.lastStatusVaultUuid, Array(repeating: 9, count: 16))
    }
}
