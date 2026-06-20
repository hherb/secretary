import XCTest
@testable import SecretaryKit
import SecretaryVaultAccess
import SecretaryDeviceUnlock
import SecretaryDeviceUnlockTesting

final class EnclaveBiometricAuthorizerTests: XCTestCase {
    func testNotEnrolledReflectsEnclave() {
        let enclave = InMemoryDeviceSecretEnclave()       // nothing stored ⇒ not enrolled
        let auth = EnclaveBiometricAuthorizer(enclave: enclave)
        XCTAssertFalse(auth.isEnrolled)
    }

    func testAuthorizeReleasesAndSucceedsWhenEnrolled() async throws {
        let enclave = InMemoryDeviceSecretEnclave()
        try enclave.store(secret: [UInt8](repeating: 7, count: 32))
        let auth = EnclaveBiometricAuthorizer(enclave: enclave)
        XCTAssertTrue(auth.isEnrolled)
        try await auth.authorize(reason: "Confirm")       // drives release(); secret discarded
    }
}
