import XCTest
@testable import SecretaryVaultAccessUI
import SecretaryVaultAccess
import SecretaryVaultAccessTesting

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

@MainActor
final class CommitSettingsEditsTests: XCTestCase {
    /// A view model over the standard fakes. `commitSettingsEdits` never touches the
    /// gate (it runs strictly before any `save()`), so the gate here only has to
    /// exist — its behaviour is exercised in `SettingsViewModelTests`.
    private func makeVM() -> SettingsViewModel {
        let gate = RetargetableReauthGate(
            window: .seconds(120),
            initialAuthAt: nil,
            clock: { MonotonicInstant(nanoseconds: 7_000_000) },
            makeDelegate: { _, _ in FakeWriteReauthGate() })
        return SettingsViewModel(port: FakeSettingsPort(), gate: gate)
    }

    func testCommitPushesTypedValuesIntoViewModel() {
        let vm = makeVM()
        var b = SettingsEditBuffer()
        b.retentionText = "45"
        b.graceText = "7"

        XCTAssertTrue(commitSettingsEdits(&b, into: vm))
        XCTAssertEqual(vm.retentionDays, 45)
        XCTAssertEqual(vm.graceMinutes, 7)
    }

    func testCommitClampsAndReSeedsBufferToClampedValues() {
        // Display == what is written. Out-of-range input clamps, and the fields are
        // rewritten to the CLAMPED values rather than left showing what was typed —
        // otherwise the screen would claim 9999 days while 3650 was persisted.
        let vm = makeVM()
        var b = SettingsEditBuffer()
        b.retentionText = "9999"
        b.graceText = "999"

        XCTAssertTrue(commitSettingsEdits(&b, into: vm))
        XCTAssertEqual(vm.retentionDays, 3650)
        XCTAssertEqual(vm.graceMinutes, 60)
        XCTAssertEqual(b.retentionText, "3650")
        XCTAssertEqual(b.graceText, "60")
    }

    func testCommitWritesNothingOnUnparseableInput() {
        // The #459 regression test. A refused commit is all-or-nothing: neither the
        // view model nor the buffer moves, so the caller cannot go on to save a
        // value the user never typed.
        let vm = makeVM()
        vm.setRetentionDays(45)
        vm.setGraceMinutes(7)
        var b = SettingsEditBuffer()
        b.retentionText = "abc"
        b.graceText = "30"

        XCTAssertFalse(commitSettingsEdits(&b, into: vm))
        XCTAssertEqual(vm.retentionDays, 45, "no write on a refused commit")
        XCTAssertEqual(vm.graceMinutes, 7, "the PARSEABLE field must not be committed either")
        XCTAssertEqual(b.retentionText, "abc", "buffer left as typed so the user can correct it")
        XCTAssertEqual(b.graceText, "30")
    }

    func testCommitOnClearedFieldDoesNotWriteStaleValue() {
        // The cleared-field hole, end to end: the old value must not be re-written
        // behind a visibly empty box.
        let vm = makeVM()
        vm.setGraceMinutes(30)
        var b = SettingsEditBuffer()
        b.seed(retentionDays: vm.retentionDays, graceMinutes: vm.graceMinutes)
        b.graceText = ""

        XCTAssertFalse(commitSettingsEdits(&b, into: vm))
        XCTAssertEqual(vm.graceMinutes, 30, "stale value not re-written")
        XCTAssertEqual(b.graceText, "", "still empty — the view surfaces an input error")
    }
}
