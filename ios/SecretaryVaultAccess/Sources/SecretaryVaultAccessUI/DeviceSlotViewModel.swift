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
/// Consequence (2) is why `forget()` reaches `.forgotten` on full success, AND
/// on a partial failure that already tore down the local credential before
/// throwing: the view treats that state as "now lock", and `port.isEnrolled`
/// (re-read, not the init snapshot) discriminates the two failure shapes — a
/// revocation that changed nothing locally must never reach it, since locking
/// then would strand the user out of a session whose credential is still
/// valid, but one that already destroyed the credential must ALWAYS reach it,
/// since the gate is already a permanent no-op regardless of the throw.
///
/// Platform-neutral by construction (the re-auth reason says "this device", not
/// "this Mac") so the iOS Settings screen can adopt it unchanged.
@MainActor
public final class DeviceSlotViewModel: ObservableObject {
    public enum State: Equatable {
        case idle
        /// This device's local credential is gone and the session MUST be locked.
        /// Reached both on a full successful revocation AND on a partial failure
        /// that already tore down the enclave key before throwing (see `forget()`).
        /// The view's contract: dismiss, then lock.
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
            // Local teardown may have partly landed even though the revocation as a
            // whole failed: `enclave.clear()` deletes the wrapped blob and the SE key,
            // throwing only after attempting both. So if the credential is gone the
            // gate is ALREADY a permanent no-op and the session must not continue,
            // error or not.
            //
            // Why `port.isEnrolled` is a SOUND discriminator — it is an implication
            // between the two predicates, not a case analysis:
            //   gate  G = enclave.isEnrolled                     (blob presence alone)
            //   port  D = enclave.isEnrolled && metadata != nil
            // so D ⟹ G, and contrapositively ¬G ⟹ ¬D. The gate can therefore never
            // be dead while `port.isEnrolled` still reads true — there is no false
            // negative in the dangerous direction, structurally.
            //
            // The converse is not tight, and deliberately so: D can be false while
            // the gate lives (e.g. a transient metadata read error, which
            // `coordinator.isEnrolled` flattens to nil via `try?`). That over-locks
            // a session whose credential is intact — fail-safe, costing only a
            // master-password re-entry. Erring the other way would not be safe.
            if !port.isEnrolled { state = .forgotten }
            return                              // failed ⇒ check above decides the lock
        } catch {
            self.error = .other(String(describing: error))
            if !port.isEnrolled { state = .forgotten }
            return                              // failed ⇒ check above decides the lock
        }

        state = .forgotten
    }
}
