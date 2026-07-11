import XCTest
@testable import SecretaryVaultAccess

final class TrashFormattingTests: XCTestCase {
    private func tb(_ b: UInt8, at ms: UInt64) -> TrashedBlockInfo {
        TrashedBlockInfo(blockUuid: [b], blockName: "n\(b)",
                         tombstonedAtMs: ms, tombstonedBy: [0])
    }

    func testSortTrashedNewestFirst() {
        let sorted = sortTrashed([tb(1, at: 100), tb(2, at: 300), tb(3, at: 200)])
        XCTAssertEqual(sorted.map { $0.tombstonedAtMs }, [300, 200, 100])
    }

    func testEmptyTrashConfirmBodySingular() {
        XCTAssertEqual(emptyTrashConfirmBody(count: 1),
            "The 1 item in trash will be permanently deleted. This cannot be undone.")
    }

    func testEmptyTrashConfirmBodyPlural() {
        XCTAssertEqual(emptyTrashConfirmBody(count: 4),
            "All 4 items in trash will be permanently deleted. This cannot be undone.")
    }

    func testRetentionSummaryEmpty() {
        // 90 days in ms
        let ninetyDays: UInt64 = 90 * 86_400_000
        XCTAssertEqual(retentionSummary(entries: [], windowMs: ninetyDays),
            "No trashed items are older than 90 days.")
    }

    func testRetentionSummaryNonEmpty() {
        let ninetyDays: UInt64 = 90 * 86_400_000
        let e = [ExpiredEntryInfo(blockUuid: [1], tombstonedAtMs: 0,
                                  ageMs: 100 * 86_400_000)]
        XCTAssertEqual(retentionSummary(entries: e, windowMs: ninetyDays),
            "1 item trashed more than 90 days ago will be permanently deleted (oldest: 100 days).")
    }

    func testMsToDays() {
        XCTAssertEqual(msToDays(90 * 86_400_000), 90)
    }

    func testMsToDaysRoundsToNearest() {
        // 90.5 days rounds up to 91 (matches desktop Math.round)
        XCTAssertEqual(msToDays(90 * 86_400_000 + 43_200_000), 91)
        // 90.4 days rounds down to 90
        XCTAssertEqual(msToDays(90 * 86_400_000 + 34_560_000), 90)
    }
}
