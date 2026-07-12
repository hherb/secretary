import XCTest
@testable import SecretaryVaultAccessUI
import SecretaryVaultAccess

final class SettingsErrorMessageTests: XCTestCase {
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
