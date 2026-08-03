import XCTest
import SecretaryDeviceUnlock
import SecretaryVaultAccess
@testable import SecretaryKit

final class SecretFreeErrorConformanceTests: XCTestCase {
    /// SECURITY (#467): `DeviceUnlockError` reaches an untyped fold arm via the
    /// re-auth gate (`BiometricAuthorizer.authorize` → `GraceWindowReauthGate`),
    /// but it lives in `SecretaryDeviceUnlock`, which `SecretaryVaultAccess` does
    /// not depend on — so `SecretaryVaultAccessTests` structurally cannot see this
    /// conformance. Its absence would silently degrade every biometric-gate
    /// diagnostic to `<undisclosed …>`.
    func testDeviceUnlockErrorConforms() {
        XCTAssertTrue(DeviceUnlockError.userCancelled is SecretFreeError)
    }

    /// The conformance must also be what `diagnosticDetail` actually picks up —
    /// a conformance that exists but is not found by the dynamic cast would be
    /// worthless.
    func testDeviceUnlockErrorRendersItsDescription() {
        XCTAssertEqual(diagnosticDetail(DeviceUnlockError.biometryLockout),
                       String(describing: DeviceUnlockError.biometryLockout))
    }
}
