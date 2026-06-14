import XCTest
@testable import SecretaryVaultAccess

final class SyncModelsTests: XCTestCase {
    func testSyncOutcomeEqualityDiscriminatesVariants() {
        XCTAssertEqual(SyncOutcome.nothingToDo, SyncOutcome.nothingToDo)
        XCTAssertNotEqual(SyncOutcome.nothingToDo, SyncOutcome.appliedAutomatically)
        XCTAssertNotEqual(SyncOutcome.silentMerge, SyncOutcome.mergedClean)
        XCTAssertNotEqual(SyncOutcome.mergedClean, SyncOutcome.rollbackRejected)
    }

    func testConflictsPendingEqualityIncludesPayload() {
        let veto = SyncVeto(recordUuidHex: "aa", recordType: "login", tags: ["x"],
                            fieldNames: ["password"], localLastModMs: 10,
                            peerTombstonedAtMs: 20, peerDeviceHex: "bb")
        let a = SyncOutcome.conflictsPending(vetoes: [veto], collisions: [], manifestHash: [1, 2, 3])
        let b = SyncOutcome.conflictsPending(vetoes: [veto], collisions: [], manifestHash: [1, 2, 3])
        let c = SyncOutcome.conflictsPending(vetoes: [veto], collisions: [], manifestHash: [9, 9, 9])
        XCTAssertEqual(a, b)
        XCTAssertNotEqual(a, c)
    }

    func testVaultSyncErrorEquatable() {
        XCTAssertEqual(VaultSyncError.evidenceStale, VaultSyncError.evidenceStale)
        XCTAssertEqual(VaultSyncError.stateCorrupt("x"), VaultSyncError.stateCorrupt("x"))
        XCTAssertNotEqual(VaultSyncError.stateCorrupt("x"), VaultSyncError.stateCorrupt("y"))
        XCTAssertNotEqual(VaultSyncError.inProgress, VaultSyncError.noPendingConflict)
    }
}
