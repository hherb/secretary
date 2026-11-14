import XCTest
@testable import SecretaryVaultAccessUI
import SecretaryVaultAccess

final class SyncErrorMessageTests: XCTestCase {
    // The browse Sync section and the conflict sheet used to render
    // `String(describing:)`, i.e. `reauthFailed("cancelled")` (#101 review, T7).
    func testReauthFailedUsesFixedCopy() {
        XCTAssertEqual(syncErrorMessage(.reauthFailed("cancelled")), "Sync wasn’t authorized.")
    }

    func testCarriedDiagnosticIsNeverInterpolated() {
        let sentinel = "diag_sentinel_\(UUID().uuidString)"
        let carrying: [VaultSyncError] = [
            .stateCorrupt(sentinel), .invalidArgument(sentinel), .failed(sentinel),
            .reauthFailed(sentinel),
        ]
        for e in carrying {
            XCTAssertFalse(syncErrorMessage(e).contains(sentinel), "case \(e) leaked its payload")
        }
    }

    func testFoldedCaseKeepsTheDamagePossibilityVisible() {
        XCTAssertTrue(syncErrorMessage(.wrongPasswordOrCorrupt).contains("damaged"))
    }
}
