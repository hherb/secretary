import XCTest
@testable import SecretaryKit
import SecretaryVaultAccess

/// Real-FFI round-trip for the settings adapter: open a TEMP COPY of
/// golden_vault_001 (never the tracked fixture), read the (absent → default)
/// settings, write a retention + grace change, and read it back — proving the
/// `UniffiVaultSession: SettingsPort` field mapping + device-uuid/now resolution
/// + error mapping work end-to-end over the generated bindings. Staging mirrors
/// `BlockCrudRoundTripIntegrationTests`.
final class SettingsRoundTripIntegrationTests: XCTestCase {
    private let goldenPassword = "correct horse battery staple"
    private var vaultCopy: URL!

    override func setUpWithError() throws {
        let bundled = try XCTUnwrap(
            Bundle.module.url(forResource: "golden_vault_001", withExtension: nil),
            "golden_vault_001 not bundled — run ios/scripts/build-xcframework.sh")
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("gv-settings-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        vaultCopy = tmp.appendingPathComponent("golden_vault_001", isDirectory: true)
        try FileManager.default.copyItem(at: bundled, to: vaultCopy)
    }

    override func tearDownWithError() throws {
        if let vaultCopy {
            try? FileManager.default.removeItem(at: vaultCopy.deletingLastPathComponent())
        }
    }

    private var path: Data { Data(vaultCopy.path.utf8) }

    private struct FixedDeviceUuid: DeviceUuidProviding {
        let value: [UInt8]
        func deviceUuid(forVaultHex vaultHex: String) throws -> [UInt8] { value }
    }

    private func openSession() throws -> UniffiVaultSession {
        let out = try SecretaryKit.openVaultWithPassword(
            folderPath: path, password: Data(goldenPassword.utf8))
        return UniffiVaultSession(output: out,
                                  deviceUuids: FixedDeviceUuid(value: [UInt8](repeating: 0x5A, count: 16)))
    }

    func testSettingsRoundTripPreservesUneditedFields() throws {
        let session = try openSession()
        defer { session.wipe() }

        // golden_vault_001 has no settings block → schema defaults.
        let initial = try session.readSettings()
        XCTAssertEqual(initial, VaultSettings(
            autoLockTimeoutMs: 600_000, requirePasswordBeforeEdits: true,
            reauthGraceWindowMs: 120_000, retentionWindowMs: 90 * 86_400_000),
            "absent settings block yields the schema defaults")

        // Change only retention + grace; the two unedited fields are preserved.
        let updated = VaultSettings(
            autoLockTimeoutMs: initial.autoLockTimeoutMs,
            requirePasswordBeforeEdits: initial.requirePasswordBeforeEdits,
            reauthGraceWindowMs: 5 * 60_000,       // 5 min
            retentionWindowMs: 30 * 86_400_000)    // 30 days
        try session.writeSettings(updated)

        XCTAssertEqual(try session.readSettings(), updated,
                       "settings persisted + round-tripped byte-for-byte over the real FFI")
    }

    func testSettingsBoundsReflectSchema() throws {
        let session = try openSession()
        defer { session.wipe() }
        XCTAssertEqual(session.settingsBounds(), SettingsBounds(
            retentionDefaultMs: 90 * 86_400_000, retentionMinMs: 86_400_000, retentionMaxMs: 3650 * 86_400_000,
            reauthGraceDefaultMs: 120_000, reauthGraceMinMs: 0, reauthGraceMaxMs: 3_600_000))
    }
}
