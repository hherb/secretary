import XCTest
@testable import SecretaryVaultAccessUI
import SecretaryVaultAccess
import SecretaryVaultAccessTesting

@MainActor
final class DeviceSlotViewModelTests: XCTestCase {

    // MARK: ordering — the load-bearing property of this slice

    /// Re-auth MUST happen BEFORE the forget. After `forgetThisDevice()` the
    /// enclave key is gone, `EnclaveBiometricAuthorizer.isEnrolled` goes false,
    /// and `GraceWindowReauthGate.authorizeWrite` short-circuits on its
    /// `guard authorizer.isEnrolled else { return }` — so a gate call made after
    /// the forget authorizes nothing at all. Transposing the two must fail here.
    func testForgetAuthorizesBeforeForgetting() async {
        let log = CallLog()
        let port = RecordingDeviceSlotPort(log: log)
        let gate = RecordingGate(log: log)
        let vm = DeviceSlotViewModel(port: port, gate: gate)

        await vm.forget()

        XCTAssertEqual(log.calls, ["authorizeWrite", "forgetThisDevice"])
    }

    // MARK: gate refusal

    func testGateRefusalDoesNotForget() async {
        let port = FakeDeviceSlotPort()
        let gate = FakeWriteReauthGate()
        gate.failNext = .reauthFailed("cancelled")
        let vm = DeviceSlotViewModel(port: port, gate: gate)

        await vm.forget()

        XCTAssertEqual(port.forgetCallCount, 0)
        XCTAssertNotEqual(vm.state, .forgotten)
        XCTAssertEqual(vm.error, .reauthFailed("cancelled"))
    }

    // MARK: port failure

    /// A failed revocation must NOT reach `.forgotten`, because the view locks the
    /// session on `.forgotten`. Locking after a failed forget would strand the user
    /// out of a session whose credential is still perfectly valid.
    func testPortFailureDoesNotReachForgotten() async {
        let port = FakeDeviceSlotPort()
        port.forgetError = .other("keychain denied")
        let gate = FakeWriteReauthGate()
        let vm = DeviceSlotViewModel(port: port, gate: gate)

        await vm.forget()

        XCTAssertNotEqual(vm.state, .forgotten)
        XCTAssertEqual(vm.error, .other("keychain denied"))
        XCTAssertEqual(gate.authorizeCount, 1)
    }

    // MARK: success

    func testSuccessReachesForgotten() async {
        let port = FakeDeviceSlotPort()
        let gate = FakeWriteReauthGate()
        let vm = DeviceSlotViewModel(port: port, gate: gate)

        await vm.forget()

        XCTAssertEqual(vm.state, .forgotten)
        XCTAssertEqual(port.forgetCallCount, 1)
        XCTAssertNil(vm.error)
        XCTAssertFalse(vm.isBusy)
    }

    /// A failed attempt must leave the VM retryable: `forget()` again after the
    /// injected one-shot error clears must succeed and reach `.forgotten`.
    func testRetryAfterFailureSucceeds() async {
        let port = FakeDeviceSlotPort()
        port.forgetError = .other("transient")
        let gate = FakeWriteReauthGate()
        let vm = DeviceSlotViewModel(port: port, gate: gate)

        await vm.forget()
        XCTAssertNotEqual(vm.state, .forgotten)

        await vm.forget()

        XCTAssertEqual(vm.state, .forgotten)
        XCTAssertEqual(port.forgetCallCount, 1)
        XCTAssertNil(vm.error)
    }

    // MARK: idempotence guard

    /// Once forgotten, a second call must be a no-op — the slot is already gone and
    /// the gate is now a no-op, so a second pass would revoke nothing while looking
    /// like it succeeded.
    func testForgetAfterForgottenIsANoOp() async {
        let port = FakeDeviceSlotPort()
        let gate = FakeWriteReauthGate()
        let vm = DeviceSlotViewModel(port: port, gate: gate)

        await vm.forget()
        await vm.forget()

        XCTAssertEqual(port.forgetCallCount, 1)
        XCTAssertEqual(gate.authorizeCount, 1)
    }

    // MARK: concurrency guard

    /// A second `forget()` arriving while the first is still awaiting the biometric
    /// prompt must be rejected by the `isBusy` guard — not queued into a second
    /// revocation. Driven deterministically by re-entering from inside the gate's
    /// own await, which is exactly the window a real Touch ID prompt holds open.
    func testConcurrentForgetIsGuarded() async {
        let port = FakeDeviceSlotPort()
        let gate = ReentrantGate()
        let vm = DeviceSlotViewModel(port: port, gate: gate)
        gate.onAuthorize = { [weak vm] in
            // Re-entrant attempt: `isBusy` is true and `state` is still `.idle`,
            // so only the `isBusy` guard can reject this.
            await vm?.forget()
        }

        await vm.forget()

        XCTAssertEqual(gate.authorizeCount, 1, "re-entrant forget must not re-authorize")
        XCTAssertEqual(port.forgetCallCount, 1, "re-entrant forget must not revoke twice")
        XCTAssertEqual(vm.state, .forgotten)
    }

    // MARK: enrollment snapshot

    func testIsEnrolledIsSnapshottedFromPort() {
        let enrolled = DeviceSlotViewModel(port: FakeDeviceSlotPort(isEnrolled: true),
                                           gate: FakeWriteReauthGate())
        let notEnrolled = DeviceSlotViewModel(port: FakeDeviceSlotPort(isEnrolled: false),
                                              gate: FakeWriteReauthGate())

        XCTAssertTrue(enrolled.isEnrolled)
        XCTAssertFalse(notEnrolled.isEnrolled)
    }

    /// `isEnrolled` is a snapshot taken at init — it must not re-read the port on
    /// access, so the view can consult it freely during a body evaluation without
    /// paying a Keychain read per render.
    func testIsEnrolledDoesNotRePollThePort() {
        let port = FakeDeviceSlotPort(isEnrolled: true)
        let vm = DeviceSlotViewModel(port: port, gate: FakeWriteReauthGate())

        port.isEnrolled = false

        XCTAssertTrue(vm.isEnrolled, "isEnrolled must be a snapshot, not a live read")
    }

    // MARK: factory

    /// The factory must wire the browse VM's OWN gate, so the forget path shares the
    /// one gate instance every other writer uses and they cannot drift apart. Proven
    /// by observing the injected gate double's call count after a forget.
    func testFactoryUsesBrowseViewModelGate() async {
        let gate = FakeWriteReauthGate()
        let session = FakeVaultSession(vaultUuidHex: "ab", blocks: [], recordsByBlock: [:])
        let browse = VaultBrowseViewModel(session: session, gate: gate)
        let port = FakeDeviceSlotPort()

        let vm = browse.makeDeviceSlotViewModel(port: port)
        await vm.forget()

        XCTAssertEqual(gate.authorizeCount, 1)
        XCTAssertEqual(port.forgetCallCount, 1)
    }

    // MARK: - Ordering-test doubles

    /// Shared append-only call log so the gate and the port record into ONE
    /// sequence, making their relative order assertable. `@unchecked Sendable` for
    /// the same single-thread reason as the package's other fakes.
    private final class CallLog: @unchecked Sendable {
        var calls: [String] = []
    }

    private final class RecordingGate: WriteReauthGate, @unchecked Sendable {
        let log: CallLog
        init(log: CallLog) { self.log = log }
        func authorizeWrite(reason: String) async throws {
            log.calls.append("authorizeWrite")
        }
    }

    private final class RecordingDeviceSlotPort: DeviceSlotPort, @unchecked Sendable {
        let log: CallLog
        var isEnrolled: Bool { true }
        init(log: CallLog) { self.log = log }
        func forgetThisDevice() throws {
            log.calls.append("forgetThisDevice")
        }
    }

    /// Gate double that runs a caller-supplied callback from INSIDE its await, so a
    /// re-entrant `forget()` can be driven deterministically without continuations.
    private final class ReentrantGate: WriteReauthGate, @unchecked Sendable {
        private(set) var authorizeCount = 0
        var onAuthorize: (() async -> Void)?
        func authorizeWrite(reason: String) async throws {
            authorizeCount += 1
            if let cb = onAuthorize { onAuthorize = nil; await cb() }
        }
    }
}
