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

final class DeviceSlotErrorMessageTests: XCTestCase {
    // `deviceSlotErrorMessage` is the "Forget this device" sibling of
    // `settingsErrorMessage` — same shape (a re-auth arm + a neutral fallback), but
    // worded about forgetting a device rather than saving settings, since
    // `DeviceSlotViewModel.error` renders inside a "This Mac" / "This device"
    // section, not the settings-save banner.
    func testReauthFailedUsesForgetWordedCopy() {
        XCTAssertEqual(
            deviceSlotErrorMessage(.reauthFailed("x")),
            "Re-authentication didn’t complete — this device was not forgotten.")
    }

    func testGenericRevocationErrorUsesForgetNeutralCopy() {
        // Exact-string equality against a sentinel-free constant doubles as the
        // anti-oracle check: if the carried diagnostic ("boom") were interpolated,
        // this assertion would fail.
        XCTAssertEqual(
            deviceSlotErrorMessage(.corruptVault("boom")),
            "Couldn’t forget this device. Please try again.")
    }
}
