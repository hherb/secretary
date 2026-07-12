import XCTest
import SecretaryVaultAccess

/// Pure conversion + clamp coverage for the Settings controls. Bounds mirror the
/// bridge schema (retention 1…3650 d default 90; grace 0…60 min default 2).
final class SettingsConversionsTests: XCTestCase {
    private let bounds = SettingsBounds(
        retentionDefaultMs: 90 * 86_400_000,
        retentionMinMs: 86_400_000,          // 1 day
        retentionMaxMs: 3650 * 86_400_000,   // 3650 days
        reauthGraceDefaultMs: 120_000,       // 2 min
        reauthGraceMinMs: 0,
        reauthGraceMaxMs: 3_600_000)         // 60 min

    func testRetentionDaysRoundTrip() {
        XCTAssertEqual(retentionDaysFromMs(90 * 86_400_000), 90)
        XCTAssertEqual(msFromRetentionDays(90), 90 * 86_400_000)
        XCTAssertEqual(retentionDaysFromMs(msFromRetentionDays(365)), 365)
    }

    func testRetentionDaysRoundsToNearest() {
        // 90.4 d → 90; 90.6 d → 91 (round half up, parity with desktop Math.round).
        XCTAssertEqual(retentionDaysFromMs(90 * 86_400_000 + 86_400_000 * 4 / 10), 90)
        XCTAssertEqual(retentionDaysFromMs(90 * 86_400_000 + 86_400_000 * 6 / 10), 91)
    }

    func testGraceMinutesRoundTrip() {
        XCTAssertEqual(graceMinutesFromMs(120_000), 2)
        XCTAssertEqual(msFromGraceMinutes(2), 120_000)
        XCTAssertEqual(graceMinutesFromMs(msFromGraceMinutes(45)), 45)
    }

    func testGraceMinutesRoundsToNearest() {
        XCTAssertEqual(graceMinutesFromMs(90_000), 2)   // 1.5 min → 2 (round half up)
        XCTAssertEqual(graceMinutesFromMs(89_000), 1)   // 1.48 min → 1
        XCTAssertEqual(graceMinutesFromMs(0), 0)        // "re-auth every write"
    }

    func testClampRetentionDays() {
        XCTAssertEqual(clampRetentionDays(0, bounds: bounds), 1, "below min → 1 day")
        XCTAssertEqual(clampRetentionDays(-100, bounds: bounds), 1)
        XCTAssertEqual(clampRetentionDays(9999, bounds: bounds), 3650, "above max → 3650")
        XCTAssertEqual(clampRetentionDays(90, bounds: bounds), 90, "in-range unchanged")
    }

    func testClampGraceMinutes() {
        XCTAssertEqual(clampGraceMinutes(-5, bounds: bounds), 0, "below min → 0")
        XCTAssertEqual(clampGraceMinutes(999, bounds: bounds), 60, "above max → 60")
        XCTAssertEqual(clampGraceMinutes(2, bounds: bounds), 2, "in-range unchanged")
    }

    func testSavedBanner() {
        XCTAssertEqual(settingsSavedBanner(), SettingsBanner(text: "Settings saved"))
    }
}
