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

    func testFormatTrashedWhenIsLocaleAwareMediumStyle() {
        // 2021-01-01T00:00:00Z. Medium style is CLDR-version dependent, so assert the
        // calendar parts (short month + year) rather than an exact string.
        let s = formatTrashedWhen(1_609_459_200_000,
                                  timeZone: TimeZone(identifier: "UTC")!,
                                  locale: Locale(identifier: "en_US_POSIX"))
        XCTAssertTrue(s.contains("2021"), s)
        XCTAssertTrue(s.contains("Jan"), s)
    }

    func testFormatTrashedWhenHonorsInjectedTimeZoneAcrossMidnight() {
        // 2021-01-01T02:00:00Z renders Jan 1 2021 in UTC but Dec 31 2020 in
        // America/Los_Angeles (UTC-8) — proving the zone parameter is honored.
        let ms: UInt64 = 1_609_459_200_000 + 2 * 3_600_000
        let posix = Locale(identifier: "en_US_POSIX")
        let utcDay = formatTrashedWhen(ms, timeZone: TimeZone(identifier: "UTC")!, locale: posix)
        let laDay = formatTrashedWhen(ms, timeZone: TimeZone(identifier: "America/Los_Angeles")!, locale: posix)
        XCTAssertTrue(utcDay.contains("2021"), utcDay)
        XCTAssertTrue(laDay.contains("2020"), laDay)
        XCTAssertNotEqual(utcDay, laDay)
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
