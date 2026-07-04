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

    // #374: the open path promotes crash residue out of CorruptVault into
    // these two dedicated arms. With no repair UI on iOS they must map back to
    // `.corruptVault` (pre-#374 classification), NOT slide into `.other`.
    func testVaultNeedsRepairMapsToCorruptVault() {
        let mapped = mapVaultAccessError(.VaultNeedsRepair(blockUuidHex: "11223344-5566-7788-99aa-bbccddeeff00"))
        guard case .corruptVault(let detail) = mapped else {
            return XCTFail("expected .corruptVault, got \(mapped)")
        }
        XCTAssertTrue(detail.contains("11223344"))
    }

    func testRepairRejectedMapsToCorruptVaultWithDetail() {
        let mapped = mapVaultAccessError(
            .RepairRejected(blockUuidHex: "11223344-5566-7788-99aa-bbccddeeff00", detail: "clock Concurrent"))
        guard case .corruptVault(let detail) = mapped else {
            return XCTFail("expected .corruptVault, got \(mapped)")
        }
        XCTAssertTrue(detail.contains("clock Concurrent"))
    }
}
