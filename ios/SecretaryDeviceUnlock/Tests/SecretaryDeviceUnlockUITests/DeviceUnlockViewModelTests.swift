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
}
