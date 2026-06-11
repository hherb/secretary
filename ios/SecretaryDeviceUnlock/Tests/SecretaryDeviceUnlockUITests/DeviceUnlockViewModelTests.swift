import XCTest
import SecretaryDeviceUnlock
import SecretaryDeviceUnlockTesting
@testable import SecretaryDeviceUnlockUI

@MainActor
final class DeviceUnlockViewModelTests: XCTestCase {
    private let pw: [UInt8] = Array("pw".utf8)

    private func makeVM(
        port: FakeVaultDeviceSlotPort = FakeVaultDeviceSlotPort(),
        enclave: InMemoryDeviceSecretEnclave = InMemoryDeviceSecretEnclave(),
        metadata: InMemoryEnrollmentMetadataStore = InMemoryEnrollmentMetadataStore()
    ) -> DeviceUnlockViewModel {
        let coord = DeviceUnlockCoordinator(slotPort: port, enclave: enclave, metadata: metadata)
        return DeviceUnlockViewModel(coordinator: coord, vaultPath: Data("p".utf8), vaultId: "v")
    }

    func testRefreshStatusNotEnrolled() {
        let vm = makeVM()
        vm.refreshStatus()
        XCTAssertEqual(vm.state, .notEnrolled)
    }

    func testEnrollSuccess() async {
        let vm = makeVM()
        await vm.enroll(password: pw)
        XCTAssertEqual(vm.state, .enrolled)
    }

    func testEnrollFailureSurfacesTypedError() async {
        let port = FakeVaultDeviceSlotPort(addResult: .failure(.invalidArgument("bad")))
        let vm = makeVM(port: port)
        await vm.enroll(password: pw)
        XCTAssertEqual(vm.state, .failed(.vault(.invalidArgument("bad")), detail: nil))
    }

    func testUnlockSuccessShowsVaultUuidHex() async {
        // Default fake open returns vaultUuid = 16 × 0xEF. The enclave must hold a
        // secret, else `release` throws .notEnrolled before the open is reached.
        let enclave = InMemoryDeviceSecretEnclave()
        try? enclave.store(secret: Array(repeating: 0xCD, count: 32))
        let metadata = InMemoryEnrollmentMetadataStore(
            enrollment: DeviceEnrollment(vaultId: "v", deviceUuid: Array(repeating: 0xAB, count: 16)))
        let vm = makeVM(enclave: enclave, metadata: metadata)
        await vm.unlock(reason: "Unlock")
        XCTAssertEqual(vm.state, .unlocked(vaultUuidHex: String(repeating: "ef", count: 16)))
    }

    func testUnlockFailureCarriesReleaseDiagnostic() async {
        let enclave = InMemoryDeviceSecretEnclave()
        enclave.releaseError = .userCancelled
        enclave.releaseDiagnostic = "domain=NSOSStatusErrorDomain code=-128 mappedTo=userCancelled"
        let metadata = InMemoryEnrollmentMetadataStore(
            enrollment: DeviceEnrollment(vaultId: "v", deviceUuid: Array(repeating: 0xAB, count: 16)))
        let vm = makeVM(enclave: enclave, metadata: metadata)
        await vm.unlock(reason: "Unlock")
        XCTAssertEqual(
            vm.state,
            .failed(.userCancelled,
                    detail: "domain=NSOSStatusErrorDomain code=-128 mappedTo=userCancelled"))
    }

    func testUnlockNotEnrolled() async {
        let vm = makeVM()  // empty metadata
        await vm.unlock(reason: "Unlock")
        XCTAssertEqual(vm.state, .failed(.notEnrolled, detail: nil))
    }

    func testDisenrollReturnsToNotEnrolled() async {
        let metadata = InMemoryEnrollmentMetadataStore(
            enrollment: DeviceEnrollment(vaultId: "v", deviceUuid: Array(repeating: 0xAB, count: 16)))
        let enclave = InMemoryDeviceSecretEnclave()
        try? enclave.store(secret: Array(repeating: 0xCD, count: 32))
        let vm = makeVM(enclave: enclave, metadata: metadata)
        await vm.disenroll()
        XCTAssertEqual(vm.state, .notEnrolled)
    }
}
