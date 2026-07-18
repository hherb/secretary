import Combine
import SecretaryVaultAccess

/// Host-testable view model for revoking THIS device's per-device wrap slot
/// (ADR 0009) — the "Forget this Mac" / "Forget this device" action.
///
/// Security ordering (load-bearing): re-auth is requested BEFORE the revocation,
/// and the caller locks the session only on `.forgotten`.
///
/// The re-auth gate proves presence by driving the SAME per-vault Secure-Enclave
/// key that the revocation deletes (`makeRetargetableReauthGate` builds an
/// `EnclaveBiometricAuthorizer` over `makePerVaultDeviceUnlock(...).enclave`), and
/// `GraceWindowReauthGate.authorizeWrite` opens with
/// `guard authorizer.isEnrolled else { return }`. Two consequences:
///
///  1. Gating AFTER the revocation would gate nothing — the guard returns early
///     once the enclave key is gone.
///  2. The session MUST lock after a successful revocation. Otherwise the rest of
///     the session runs with `authorizeWrite` as a permanent no-op, silently
///     ungating every later record edit, trash purge, and settings save with no
///     user-visible signal.
///
/// Consequence (2) is why `forget()` reaches `.forgotten` ONLY on full success:
/// the view treats that state as "now lock", so a failed revocation must never
/// reach it — locking then would strand the user out of a session whose
/// credential is still valid.
///
/// Platform-neutral by construction (the re-auth reason says "this device", not
/// "this Mac") so the iOS Settings screen can adopt it unchanged.
@MainActor
public final class DeviceSlotViewModel: ObservableObject {
    public enum State: Equatable {
        case idle
        /// Revocation completed. The view's contract: dismiss, then lock.
        case forgotten
    }

    @Published public private(set) var state: State = .idle
    @Published public private(set) var isBusy = false
    @Published public private(set) var error: VaultAccessError?

    /// Snapshotted at init: `port.isEnrolled` costs a Keychain read plus an enclave
    /// probe, and the view consults this during body evaluation to decide whether to
    /// render the section at all. A stale snapshot is benign — the underlying
    /// revocation tolerates an already-gone slot.
    public let isEnrolled: Bool

    private let port: DeviceSlotPort
    private let gate: WriteReauthGate

    public init(port: DeviceSlotPort, gate: WriteReauthGate) {
        self.port = port
        self.gate = gate
        self.isEnrolled = port.isEnrolled
    }

    /// Gated revocation: re-auth → revoke → `.forgotten`. Non-throwing; failures
    /// fold into `error`, matching `SettingsViewModel.save()`.
    ///
    /// `isBusy` is set before the gate await so a second invocation during the
    /// biometric prompt is rejected. The `.forgotten` guard makes a post-success
    /// call a no-op: the slot is already gone AND the gate is now a no-op, so a
    /// second pass would revoke nothing while appearing to succeed.
    public func forget() async {
        guard !isBusy, state != .forgotten else { return }
        isBusy = true
        error = nil
        defer { isBusy = false }

        // Re-auth FIRST — the gate is still live here. See the type doc.
        do {
            try await gate.authorizeWrite(reason: "Confirm removing biometric unlock from this device")
        } catch let e as VaultAccessError {
            error = e
            return                              // refused ⇒ nothing revoked, no lock
        } catch {
            self.error = .reauthFailed(String(describing: error))
            return
        }

        do {
            try port.forgetThisDevice()
        } catch let e as VaultAccessError {
            error = e
            return                              // failed ⇒ still enrolled, no lock
        } catch {
            self.error = .other(String(describing: error))
            return
        }

        state = .forgotten
    }
}
