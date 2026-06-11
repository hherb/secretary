import XCTest
import SecretaryDeviceUnlock
import SecretaryDeviceUnlockTesting

final class DiagnosticPassthroughTests: XCTestCase {
    private func makeCoordinator(enclave: InMemoryDeviceSecretEnclave)
        -> DeviceUnlockCoordinator {
        DeviceUnlockCoordinator(
            slotPort: FakeVaultDeviceSlotPort(),
            enclave: enclave,
            metadata: InMemoryEnrollmentMetadataStore())
    }

    func testCoordinatorForwardsEnclaveReleaseDiagnostic() {
        let enclave = InMemoryDeviceSecretEnclave()
        enclave.releaseDiagnostic = "domain=NSOSStatusErrorDomain code=-128 mappedTo=userCancelled"
        let coord = makeCoordinator(enclave: enclave)
        XCTAssertEqual(coord.lastReleaseDiagnostic,
                       "domain=NSOSStatusErrorDomain code=-128 mappedTo=userCancelled")
    }

    func testDiagnosticDefaultsToNil() {
        XCTAssertNil(makeCoordinator(enclave: InMemoryDeviceSecretEnclave()).lastReleaseDiagnostic)
    }
}
