import XCTest
@testable import SecretaryKit
import SecretaryVaultAccess

/// Covers the three device-secret arms added to `mapVaultAccessError` (#284
/// review). `WrongDeviceSecretOrCorrupt` / `DeviceSlotNotFound` must fold into
/// the SAME anti-oracle case; `DeviceUuidMismatch` must surface distinctly as
/// `.corruptVault` since it is a tamper/relabel signal, not a credential issue.
final class VaultErrorMappingDeviceTests: XCTestCase {
    func testWrongDeviceSecretOrCorruptMapsToWrongDeviceSecretOrCorrupt() {
        let mapped = mapVaultAccessError(.WrongDeviceSecretOrCorrupt)
        XCTAssertEqual(mapped, .wrongDeviceSecretOrCorrupt)
    }

    func testDeviceSlotNotFoundFoldsIntoWrongDeviceSecretOrCorrupt() {
        let mapped = mapVaultAccessError(.DeviceSlotNotFound)
        XCTAssertEqual(mapped, .wrongDeviceSecretOrCorrupt)
    }

    func testDeviceUuidMismatchMapsToCorruptVaultWithDetail() {
        let mapped = mapVaultAccessError(.DeviceUuidMismatch(detail: "x"))
        XCTAssertEqual(mapped, .corruptVault("x"))
    }
}
