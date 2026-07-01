import XCTest
@testable import SecretaryKit
import SecretaryVaultAccess
import SecretaryVaultAccessUI
import SecretaryDeviceUnlockTesting

/// Real-FFI: mint a device slot on a TEMP COPY of golden_vault_001, then open
/// the vault with `UniffiVaultOpenPort.openWithDeviceSecret` and confirm the
/// resulting session is browse-capable (lists blocks) — proving the device open
/// yields the SAME session shape as the password path.
final class DeviceSecretOpenRoundTripTests: XCTestCase {
    private let goldenPassword = "correct horse battery staple"
    private var vaultCopy: URL!

    override func setUpWithError() throws {
        let bundled = try XCTUnwrap(
            Bundle.module.url(forResource: "golden_vault_001", withExtension: nil),
            "golden_vault_001 not bundled — run ios/scripts/build-xcframework.sh")
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("gv-devopen-\(UUID().uuidString)", isDirectory: true)
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

    func testOpenWithDeviceSecretYieldsBrowseCapableSession() async throws {
        // Mint a device slot via the real slot port (returns uuid + secret).
        let slotPort = UniffiVaultDeviceSlotPort()
        let slot = try slotPort.addDeviceSlot(vaultPath: path, password: Array(goldenPassword.utf8))

        // Open with the device secret through the port under test.
        let port = UniffiVaultOpenPort()
        let session = try await port.openWithDeviceSecret(
            vaultPath: path, deviceUuid: slot.deviceUuid, deviceSecret: slot.deviceSecret)
        defer { session.wipe() }

        // Browse-capable: it exposes the manifest's blocks (golden vault has ≥1).
        XCTAssertFalse(session.blockSummaries().isEmpty,
                       "device-secret session must list golden-vault blocks")
        XCTAssertEqual(session.vaultUuidHex.count, 32, "vault uuid hex is 16 bytes")
    }
}
