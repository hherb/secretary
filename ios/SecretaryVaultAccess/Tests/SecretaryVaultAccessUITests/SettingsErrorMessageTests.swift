import XCTest
@testable import SecretaryVaultAccessUI
import SecretaryVaultAccess

final class SettingsErrorMessageTests: XCTestCase {
    // `.reauthFailed` / `.invalidArgument` fire ONLY on save() (re-auth and range-validation
    // never occur on a read), so their "settings were not saved." wording is correct and stays —
    // only the shared fallback, reachable from load(), was mis-worded (#421). See below.
    func testReauthFailedUsesSaveWordedCopy() {
        XCTAssertEqual(
            settingsErrorMessage(.reauthFailed("x")),
            "Re-authentication didn’t complete — settings were not saved.")
    }

    func testInvalidArgumentUsesRangeCopy() {
        XCTAssertEqual(
            settingsErrorMessage(.invalidArgument("x")),
            "That value is out of range — settings were not saved.")
    }

    func testGenericLoadOrSaveErrorUsesNeutralUpdateCopyNotSave() {
        // A hard read error surfaced from load() must NOT read "save" (#421).
        XCTAssertEqual(
            settingsErrorMessage(.corruptVault("boom")),
            "Couldn’t update settings. Please try again.")
    }
}
