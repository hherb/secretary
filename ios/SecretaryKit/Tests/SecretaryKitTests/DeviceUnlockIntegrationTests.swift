import XCTest
@testable import SecretaryKit
import SecretaryDeviceUnlock
import SecretaryDeviceUnlockTesting

/// Drives the FULL B.3 orchestration through the REAL B.2 FFI on a simulator,
/// using a fake enclave (so no biometric hardware is needed) against a writable
/// copy of golden_vault_001. Proves enroll → (fake) SE-wrap → release → real
/// open_with_device_secret actually opens the vault, and that disenroll removes
/// the on-disk wrap file.
final class DeviceUnlockIntegrationTests: XCTestCase {
    private let goldenPassword = "correct horse battery staple"
    private var vaultCopy: URL!

    override func setUpWithError() throws {
        let bundled = try XCTUnwrap(
            Bundle.module.url(forResource: "golden_vault_001", withExtension: nil),
            "golden_vault_001 not bundled — run ios/scripts/build-xcframework.sh")
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("gv-b3-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        vaultCopy = tmp.appendingPathComponent("golden_vault_001", isDirectory: true)
        try FileManager.default.copyItem(at: bundled, to: vaultCopy)
    }

    override func tearDownWithError() throws {
        if let vaultCopy { try? FileManager.default.removeItem(at: vaultCopy.deletingLastPathComponent()) }
    }

    func testEnrollUnlockDisenrollAgainstRealFFI() async throws {
        let path = Data(vaultCopy.path.utf8)
        let port = UniffiVaultDeviceSlotPort()
        let enclave = InMemoryDeviceSecretEnclave()
        let metadata = InMemoryEnrollmentMetadataStore()
        let coord = DeviceUnlockCoordinator(slotPort: port, enclave: enclave, metadata: metadata)

        // Enroll with the real password → real device slot minted + wrapped (fake enclave).
        try coord.enroll(vaultPath: path, vaultId: "golden", password: [UInt8](goldenPassword.utf8))
        XCTAssertTrue(coord.isEnrolled)

        // Unlock via the device secret → real open_with_device_secret.
        let opened = try await coord.unlock(vaultPath: path, vaultId: "golden", reason: "Unlock")
        defer { opened.wipe() }
        let expected = try pinnedVaultUuid()
        XCTAssertEqual(opened.vaultUuid, [UInt8](expected),
                       "device-secret open must yield the pinned golden vault UUID")

        // Capture the enrolled uuid for the direct-port probe BEFORE disenroll clears metadata.
        let enrolledUuid = try XCTUnwrap(try metadata.load()).deviceUuid

        // Disenroll → slot deleted, enclave + metadata cleared.
        try coord.disenroll(vaultPath: path)
        XCTAssertFalse(coord.isEnrolled)

        // (a) A subsequent coordinator unlock is .notEnrolled (metadata cleared).
        do {
            _ = try await coord.unlock(vaultPath: path, vaultId: "golden", reason: "Unlock")
            XCTFail("expected .notEnrolled after disenroll")
        } catch let e as DeviceUnlockError {
            XCTAssertEqual(e, .notEnrolled)
        }

        // (b) The wrap file is actually gone: the real port now throws DeviceSlotNotFound.
        XCTAssertThrowsError(
            try port.openWithDeviceSecret(vaultPath: path, deviceUuid: enrolledUuid,
                                          deviceSecret: Array(repeating: 0, count: 32))
        ) { err in
            XCTAssertEqual(err as? VaultSlotError, .deviceSlotNotFound,
                           "devices/<uuid>.wrap must be deleted from disk by disenroll")
        }
    }

    /// Pinned vault_uuid from the bundled inputs JSON → 16 bytes (no hardcoded array).
    private func pinnedVaultUuid() throws -> Data {
        let url = try XCTUnwrap(
            Bundle.module.url(forResource: "golden_vault_001_inputs", withExtension: "json"))
        let json = try JSONSerialization.jsonObject(with: Data(contentsOf: url))
        let dict = try XCTUnwrap(json as? [String: Any])
        let dashed = try XCTUnwrap(dict["vault_uuid"] as? String)
        let hex = dashed.replacingOccurrences(of: "-", with: "")
        var bytes = [UInt8]()
        var i = hex.startIndex
        while i < hex.endIndex {
            let j = try XCTUnwrap(hex.index(i, offsetBy: 2, limitedBy: hex.endIndex))
            bytes.append(try XCTUnwrap(UInt8(hex[i..<j], radix: 16)))
            i = j
        }
        XCTAssertEqual(bytes.count, 16)
        return Data(bytes)
    }
}
