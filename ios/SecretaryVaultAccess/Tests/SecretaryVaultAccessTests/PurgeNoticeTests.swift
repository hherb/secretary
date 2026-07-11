import XCTest
@testable import SecretaryVaultAccess

final class PurgeNoticeTests: XCTestCase {
    func testSinglePurge() {
        XCTAssertEqual(formatPurgeNotice(.singlePurge),
                       PurgeNotice(text: "Deleted forever", severity: .success))
    }
    func testEmptyTrashSingular() {
        XCTAssertEqual(formatPurgeNotice(.emptyTrash(purgedCount: 1, filesFailed: 0)),
                       PurgeNotice(text: "Purged 1 item", severity: .success))
    }
    func testEmptyTrashPlural() {
        XCTAssertEqual(formatPurgeNotice(.emptyTrash(purgedCount: 4, filesFailed: 0)),
                       PurgeNotice(text: "Purged 4 items", severity: .success))
    }
    func testOneFailedFileWarnsSingular() {
        XCTAssertEqual(formatPurgeNotice(.emptyTrash(purgedCount: 4, filesFailed: 1)),
                       PurgeNotice(text: "Purged 4 items · 1 file could not be removed", severity: .warning))
    }
    func testFailedFilesWarnPlural() {
        XCTAssertEqual(formatPurgeNotice(.retention(purgedCount: 4, filesFailed: 2)),
                       PurgeNotice(text: "Purged 4 items · 2 files could not be removed", severity: .warning))
    }
    func testRetentionNoop() {
        XCTAssertEqual(formatPurgeNotice(.retention(purgedCount: 0, filesFailed: 0)),
                       PurgeNotice(text: "No items were past the retention window", severity: .success))
    }
    func testEmptyTrashNoop() {
        XCTAssertEqual(formatPurgeNotice(.emptyTrash(purgedCount: 0, filesFailed: 0)),
                       PurgeNotice(text: "Trash was already empty", severity: .success))
    }
}
