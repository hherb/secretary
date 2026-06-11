import Foundation
import Combine
import SecretaryDeviceUnlock

/// Drives the device-unlock screen. Holds only the (injected) coordinator, so it
/// is fully host-testable with the in-memory fakes. `@MainActor` because it
/// publishes UI state; the heavy password KDF at `enroll` briefly blocks the
/// main actor (acceptable for the walking-skeleton — a background-offload
/// refinement is a noted follow-up).
@MainActor
public final class DeviceUnlockViewModel: ObservableObject {
    @Published public private(set) var state: DeviceUnlockState = .idle

    private let coordinator: DeviceUnlockCoordinator
    private let vaultPath: Data
    private let vaultId: String

    public init(coordinator: DeviceUnlockCoordinator, vaultPath: Data, vaultId: String) {
        self.coordinator = coordinator
        self.vaultPath = vaultPath
        self.vaultId = vaultId
    }

    /// Synchronous, prompt-free status check (no biometric).
    public func refreshStatus() {
        state = coordinator.isEnrolled ? .enrolled : .notEnrolled
    }

    public func enroll(password: [UInt8]) async {
        state = .busy(.enrolling)
        do {
            try coordinator.enroll(vaultPath: vaultPath, vaultId: vaultId, password: password)
            state = .enrolled
        } catch {
            state = .failed(asDeviceUnlockError(error), detail: nil)
        }
    }

    public func unlock(reason: String) async {
        state = .busy(.unlocking)
        do {
            let opened = try await coordinator.unlock(
                vaultPath: vaultPath, vaultId: vaultId, reason: reason)
            let hex = opened.vaultUuid.map { String(format: "%02x", $0) }.joined()
            opened.wipe()  // release the opened vault's secret material immediately
            state = .unlocked(vaultUuidHex: hex)
        } catch {
            // Read the diagnostic right after the failed release (synchronous on
            // the main actor — no interleaving).
            state = .failed(asDeviceUnlockError(error),
                            detail: coordinator.lastReleaseDiagnostic)
        }
    }

    public func disenroll() async {
        state = .busy(.disenrolling)
        do {
            try coordinator.disenroll(vaultPath: vaultPath)
            state = .notEnrolled
        } catch {
            state = .failed(asDeviceUnlockError(error), detail: nil)
        }
    }

    /// The coordinator surfaces `DeviceUnlockError` for enclave/slot failures and
    /// rethrows the metadata store's untyped error as-is; wrap the latter so the
    /// UI always has a typed case to render.
    private func asDeviceUnlockError(_ error: Error) -> DeviceUnlockError {
        (error as? DeviceUnlockError) ?? .enclave(String(describing: error))
    }
}
