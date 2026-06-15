import XCTest
import SecretaryVaultAccess

final class SyncBadgeStateTests: XCTestCase {
    private func status(_ ms: UInt64?) -> SyncStatus {
        SyncStatus(hasState: ms != nil, deviceClocks: [], lastStateWriteMs: ms)
    }

    func testSyncingWinsOverEverything() {
        let s = syncBadgeState(inProgress: true, pendingChanges: true,
                               hasPendingConflict: true, status: status(123))
        XCTAssertEqual(s, .syncing)
    }
    func testReviewNeededBeatsChangesAndSynced() {
        let s = syncBadgeState(inProgress: false, pendingChanges: true,
                               hasPendingConflict: true, status: status(123))
        XCTAssertEqual(s, .reviewNeeded)
    }
    func testChangesDetectedBeatsSynced() {
        let s = syncBadgeState(inProgress: false, pendingChanges: true,
                               hasPendingConflict: false, status: status(123))
        XCTAssertEqual(s, .changesDetected)
    }
    func testSyncedWhenStatusHasWriteTime() {
        let s = syncBadgeState(inProgress: false, pendingChanges: false,
                               hasPendingConflict: false, status: status(123))
        XCTAssertEqual(s, .synced(sinceMs: 123))
    }
    func testNeverSyncedWhenNoStatus() {
        let s = syncBadgeState(inProgress: false, pendingChanges: false,
                               hasPendingConflict: false, status: nil)
        XCTAssertEqual(s, .neverSynced)
    }
    func testNeverSyncedWhenStatusHasNoWriteTime() {
        let s = syncBadgeState(inProgress: false, pendingChanges: false,
                               hasPendingConflict: false, status: status(nil))
        XCTAssertEqual(s, .neverSynced)
    }
}
