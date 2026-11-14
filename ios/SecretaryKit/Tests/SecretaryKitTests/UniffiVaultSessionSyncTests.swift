import XCTest
@testable import SecretaryKit
import SecretaryVaultAccess
import SecretaryVaultAccessTesting
import SecretaryVaultAccessUI

/// `UniffiVaultSession`'s `VaultSyncPort` conformance (#101): sync through the
/// open session's own handles, no password.
///
/// Two halves:
/// - **Real FFI** (golden-vault temp copy): a pass runs on the session's handles,
///   a repeat pass is `.nothingToDo`, `refreshFromDisk` works, and a wiped session
///   short-circuits every entry point before touching the zeroized handles.
/// - **Coordinator boundary** (`FakeVaultSyncPort` + `SuspensionGate`): a
///   `@MainActor` caller interleaves with an in-flight pass. The real conformer's
///   `runOffMainActor` wrap is the same helper the #227 open-path tests cover.
final class UniffiVaultSessionSyncTests: XCTestCase {
    private let goldenPassword = "correct horse battery staple"
    private var tmp: URL!
    private var vaultCopy: URL!
    private var stateDir: URL!

    private struct FixedDeviceUuid: DeviceUuidProviding {
        let value: [UInt8]
        func deviceUuid(forVaultHex vaultHex: String) throws -> [UInt8] { value }
    }

    override func setUpWithError() throws {
        let bundled = try XCTUnwrap(
            Bundle.module.url(forResource: "golden_vault_001", withExtension: nil),
            "golden_vault_001 not bundled — run ios/scripts/build-xcframework.sh")
        tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("gv-sessionsync-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        vaultCopy = tmp.appendingPathComponent("golden_vault_001", isDirectory: true)
        try FileManager.default.copyItem(at: bundled, to: vaultCopy)
        stateDir = tmp.appendingPathComponent("state", isDirectory: true)
        try FileManager.default.createDirectory(at: stateDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let tmp { try? FileManager.default.removeItem(at: tmp) }
    }

    private func openSession() throws -> UniffiVaultSession {
        let out = try SecretaryKit.openVaultWithPassword(
            folderPath: Data(vaultCopy.path.utf8), password: Data(goldenPassword.utf8))
        return UniffiVaultSession(
            output: out, deviceUuids: FixedDeviceUuid(value: [UInt8](repeating: 0x5A, count: 16)))
    }

    // MARK: - Real FFI

    func testSessionSyncRunsWithoutPasswordAndRepeatIsNothingToDo() async throws {
        let session = try openSession()
        defer { session.wipe() }
        let port: VaultSyncPort = session

        let first = try await port.sync(stateDir: stateDir.path, nowMs: 1_000)
        XCTAssertNotEqual(first, .rollbackRejected)
        let second = try await port.sync(stateDir: stateDir.path, nowMs: 2_000)
        XCTAssertEqual(second, .nothingToDo, "a repeat pass over unchanged disk does nothing")

        XCTAssertFalse(session.blockSummaries().isEmpty, "handles still live after the pass")
        try session.refreshFromDisk(stateDir: stateDir.path)
        XCTAssertFalse(session.blockSummaries().isEmpty)
    }

    /// Replaces the manual GUI check for the macOS Reload action (#101): a second
    /// writer makes A's write refuse, and `refreshFromDisk` adopts B's change.
    func testReloadFromDiskAdoptsAnotherWritersChange() throws {
        let a = try openSession()
        let b = try openSession()
        defer { a.wipe(); b.wipe() }

        let bBlock = try b.createBlock(blockName: "FromB")
        XCTAssertThrowsError(try a.createBlock(blockName: "FromA")) { error in
            XCTAssertEqual(error as? VaultAccessError, .vaultChangedOnDisk)
        }
        XCTAssertFalse(a.blockSummaries().contains { $0.uuid == bBlock },
                       "A's handle still holds the pre-B manifest before the refresh")

        try a.refreshFromDisk(stateDir: stateDir.path)
        XCTAssertTrue(a.blockSummaries().contains { $0.uuid == bBlock })
        XCTAssertNoThrow(try a.createBlock(blockName: "FromA"))
    }

    /// The macOS record-edit Reload flow (#101, I2), at the view-model layer the
    /// Mac sheet drives (the Mac app target has no test target): a record-edit
    /// save is refused because another writer changed the vault, the owning
    /// browse VM's `reloadFromDisk` refreshes the shared session, and a retry
    /// through a fresh edit VM (the sheet is dismissed on Reload) succeeds.
    @MainActor
    func testRefusedRecordEditSaveThenReloadThenRetrySucceeds() async throws {
        let a = try openSession()
        let b = try openSession()
        defer { a.wipe(); b.wipe() }
        let browse = VaultBrowseViewModel(session: a, gate: FakeWriteReauthGate())
        browse.loadBlocks()
        let block = try XCTUnwrap(browse.blocks.first)
        browse.selectBlock(block)
        _ = try b.createBlock(blockName: "FromB-\(UUID().uuidString)")

        let refused = try XCTUnwrap(browse.makeEditViewModel(mode: .add))
        fill(refused)
        await refused.commit()
        XCTAssertEqual(refused.error, .vaultChangedOnDisk)
        XCTAssertFalse(refused.committed)

        browse.reloadFromDisk(stateDir: stateDir.path)
        XCTAssertNil(browse.error)

        let retry = try XCTUnwrap(browse.makeEditViewModel(mode: .add))
        fill(retry)
        await retry.commit()
        XCTAssertNil(retry.error)
        XCTAssertTrue(retry.committed, "the retry after Reload writes")
    }

    @MainActor
    private func fill(_ vm: RecordEditViewModel) {
        vm.recordType = "login"
        vm.fields = [EditableField(name: "username", kind: .text, rawText: UUID().uuidString)]
    }

    func testWipedSessionShortCircuitsSyncCommitAndRefresh() async throws {
        let session = try openSession()
        session.wipe()

        do {
            _ = try await session.sync(stateDir: stateDir.path, nowMs: 1)
            XCTFail("sync on a wiped session must throw")
        } catch let e as VaultSyncError {
            XCTAssertEqual(e, .failed("sync on a wiped session"))
        }
        do {
            _ = try await session.commitDecisions(stateDir: stateDir.path, decisions: [],
                                                  manifestHash: [UInt8](repeating: 0, count: 32),
                                                  nowMs: 1)
            XCTFail("commit on a wiped session must throw")
        } catch let e as VaultSyncError {
            XCTAssertEqual(e, .failed("sync on a wiped session"))
        }
        XCTAssertThrowsError(try session.refreshFromDisk(stateDir: stateDir.path)) { error in
            XCTAssertEqual(error as? VaultAccessError, .other("read on a wiped session"))
        }
    }

    // MARK: - Coordinator boundary (main actor stays live)

    @MainActor
    func testMainActorIsFreeWhileSyncing() async throws {
        let gate = SuspensionGate()
        let port = FakeVaultSyncPort(syncResult: .success(.nothingToDo))
        port.gate = gate
        let coord = SyncCoordinator(port: port, stateDir: "/tmp/s")

        let task = Task { try await coord.runPass(nowMs: 0) }
        await gate.waitUntilEntered()   // sync is in flight, suspended off the main actor

        // Reaching here is the proof: had runPass blocked the main actor, the Task
        // body could not run and waitUntilEntered() would hang → XCTest timeout.
        XCTAssertEqual(port.syncCalls, 1, "port entered sync off the main actor while the test stayed live")

        await gate.release()
        let outcome = try await task.value
        XCTAssertEqual(outcome, .nothingToDo)
    }

    @MainActor
    func testMainActorIsFreeWhileCommitting() async throws {
        let veto = SyncVeto(recordUuidHex: "aa", recordType: "login", tags: [],
                            fieldNames: ["password"], localLastModMs: 1,
                            peerTombstonedAtMs: 2, peerDeviceHex: "bb")
        let port = FakeVaultSyncPort(
            syncResult: .success(.conflictsPending(vetoes: [veto], collisions: [], manifestHash: [9])),
            commitResult: .success(.mergedClean))
        let coord = SyncCoordinator(port: port, stateDir: "/tmp/s")
        _ = try await coord.runPass(nowMs: 0)

        let gate = SuspensionGate()
        port.gate = gate
        let task = Task { try await coord.resolve(decisions: [], nowMs: 0) }
        await gate.waitUntilEntered()   // commit is in flight, suspended off the main actor

        XCTAssertEqual(port.commitCalls, 1, "port entered commit off the main actor while the test stayed live")

        await gate.release()
        let outcome = try await task.value
        XCTAssertEqual(outcome, .mergedClean)
    }
}
