import XCTest
import SecretaryVaultAccess
import SecretaryVaultAccessTesting

final class SettingsPortFakesTests: XCTestCase {
    func testReadReturnsSeed() throws {
        let port = FakeSettingsPort()
        XCTAssertEqual(try port.readSettings(), FakeSettingsPort.defaultSettings)
        XCTAssertEqual(port.readCount, 1)
    }

    func testWriteRecordsAndUpdatesSeed() throws {
        let port = FakeSettingsPort()
        let updated = VaultSettings(autoLockTimeoutMs: 600_000, requirePasswordBeforeEdits: true,
                                    reauthGraceWindowMs: 300_000, retentionWindowMs: 30 * 86_400_000)
        try port.writeSettings(updated)
        XCTAssertEqual(port.writtenSettings, [updated])
        XCTAssertEqual(try port.readSettings(), updated, "later read reflects the write")
    }

    func testFailNextReadThrowsOnceThenClears() {
        let port = FakeSettingsPort()
        port.failNextRead = .corruptVault("x")
        XCTAssertThrowsError(try port.readSettings())
        XCTAssertNoThrow(try port.readSettings())
    }

    func testFailNextWriteThrowsOnceAndDoesNotRecord() {
        let port = FakeSettingsPort()
        port.failNextWrite = .invalidArgument("out of range")
        XCTAssertThrowsError(try port.writeSettings(FakeSettingsPort.defaultSettings))
        XCTAssertTrue(port.writtenSettings.isEmpty, "no record on injected failure")
        XCTAssertNoThrow(try port.writeSettings(FakeSettingsPort.defaultSettings))
    }

    func testBoundsReturnsSeed() {
        let port = FakeSettingsPort()
        XCTAssertEqual(port.settingsBounds(), FakeSettingsPort.defaultBounds)
    }
}
