import XCTest
@testable import SecretaryVaultAccessUI

final class SettingsEditBufferTests: XCTestCase {

    // MARK: seed

    func testInitStartsEmpty() {
        let b = SettingsEditBuffer()
        XCTAssertEqual(b.retentionText, "")
        XCTAssertEqual(b.graceText, "")
    }

    func testSeedRendersUngroupedDigits() {
        // The largest in-range retention is the interesting case: a grouping locale
        // would render 3650 as "3,650", which `parsed()` deliberately rejects. Seed
        // must therefore always emit bare digits, or a seed→parse round trip breaks.
        var b = SettingsEditBuffer()
        b.seed(retentionDays: 3650, graceMinutes: 0)
        XCTAssertEqual(b.retentionText, "3650")
        XCTAssertEqual(b.graceText, "0")
    }

    func testSeedThenParseRoundTrips() {
        var b = SettingsEditBuffer()
        b.seed(retentionDays: 3650, graceMinutes: 60)
        XCTAssertEqual(b.parsed(), SettingsEdits(retentionDays: 3650, graceMinutes: 60))
    }

    // MARK: parsed

    func testParsesPlainIntegers() {
        var b = SettingsEditBuffer()
        b.retentionText = "45"
        b.graceText = "7"
        XCTAssertEqual(b.parsed(), SettingsEdits(retentionDays: 45, graceMinutes: 7))
    }

    func testTrimsSurroundingWhitespace() {
        var b = SettingsEditBuffer()
        b.retentionText = " 45 "
        b.graceText = "\t7 "
        XCTAssertEqual(b.parsed(), SettingsEdits(retentionDays: 45, graceMinutes: 7))
    }

    func testRejectsClearedField() {
        // The second #459 hole: a cleared field must NOT silently fall back to the
        // previously committed value.
        var b = SettingsEditBuffer()
        b.retentionText = ""
        b.graceText = "7"
        XCTAssertNil(b.parsed(), "cleared retention must not parse")

        b.retentionText = "45"
        b.graceText = ""
        XCTAssertNil(b.parsed(), "cleared grace must not parse")
    }

    func testRejectsWhitespaceOnlyField() {
        var b = SettingsEditBuffer()
        b.retentionText = "   "
        b.graceText = "7"
        XCTAssertNil(b.parsed())
    }

    func testRejectsNonNumericTextInEitherField() {
        // "3,650" is the load-bearing one: it is exactly what a grouping locale
        // would produce, and accepting it would reintroduce silent coercion.
        for bad in ["abc", "1.5", "3,650", "45d", "0x1f"] {
            var b = SettingsEditBuffer()
            b.retentionText = bad
            b.graceText = "7"
            XCTAssertNil(b.parsed(), "retention \(bad) must not parse")

            b.retentionText = "45"
            b.graceText = bad
            XCTAssertNil(b.parsed(), "grace \(bad) must not parse")
        }
    }

    func testAcceptsSignedValuesForTheClampToAbsorb() {
        // `Int(_:)` accepts a sign; out-of-range values are the view model's clamp
        // to deal with, not a parse failure. Pinned so the split of responsibility
        // stays deliberate.
        var b = SettingsEditBuffer()
        b.retentionText = "-5"
        b.graceText = "+7"
        XCTAssertEqual(b.parsed(), SettingsEdits(retentionDays: -5, graceMinutes: 7))
    }
}
