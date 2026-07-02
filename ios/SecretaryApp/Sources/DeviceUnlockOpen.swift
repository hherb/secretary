import Foundation
import SecretaryDeviceUnlock
import SecretaryDeviceUnlockUI
import SecretaryVaultAccess
import SecretaryVaultAccessUI
import SecretaryKit

/// Outcome of a biometric device-unlock open attempt.
enum DeviceUnlockOpenResult {
    /// Opened successfully; `gate` is already seeded with the unlock instant (#284).
    case opened(VaultSession, gate: GraceWindowReauthGate)
    /// User cancelled the biometric prompt — return to Unlock quietly (#341).
    case cancelled
    /// A real failure — surface this typed message on the Unlock screen (#341).
    case failed(String)
}

/// Release the device secret behind a biometric prompt, open the vault with it,
/// verify the opened vault matches the enrollment, and build a grace-window gate
/// seeded at the unlock instant. Extracted out of `SecretaryApp.body` to keep
/// that view small and this flow readable.
///
/// `@MainActor`: `GraceWindowReauthGate` is itself `@MainActor`-isolated, so
/// constructing it (on the success path) must happen on the main actor. The
/// caller is a SwiftUI view's `Task { }`, which already starts on the main
/// actor, so this adds no extra hop for the common case.
enum DeviceUnlockOpen {
    @MainActor
    static func open(
        coordinator: DeviceUnlockCoordinator,
        openPort: VaultOpenPort,
        vaultPath: Data,
        reason: String
    ) async -> DeviceUnlockOpenResult {
        do {
            var cred = try await coordinator.releaseCredential(reason: reason)
            let session: VaultSession
            do {
                session = try await openPort.openWithDeviceSecret(
                    vaultPath: vaultPath, deviceUuid: cred.deviceUuid, deviceSecret: cred.secret)
            } catch {
                zeroize(&cred.secret)
                // A device-secret open failure is not a biometric cancel; surface it.
                let display = (error as? VaultAccessError).map(vaultAccessFailureMessage)
                    ?? "Couldn’t open the vault. Unlock with your password."
                return .failed(display)
            }
            zeroize(&cred.secret)

            // Defense-in-depth: the opened vault must be the enrolled one.
            guard session.vaultUuidHex == cred.enrolledVaultId else {
                session.wipe()
                return .failed("This device’s biometric enrollment is for a different vault.")
            }

            let gate = GraceWindowReauthGate(
                authorizer: EnclaveBiometricAuthorizer(
                    enclave: makePerVaultDeviceUnlock(vaultPath: vaultPath).enclave),
                clock: MonotonicInstant.now,
                initialAuthAt: reauthInitialAuthAt(biometricUnlock: true, now: MonotonicInstant.now()))
            return .opened(session, gate: gate)
        } catch let e as DeviceUnlockError {
            switch deviceUnlockFailureDisplay(e) {
            case .silent:            return .cancelled
            case .message(let text): return .failed(text)
            }
        } catch {
            return .failed("Biometric unlock failed. Unlock with your password.")
        }
    }
}

/// A short user-facing message for a device-secret open failure (anti-oracle:
/// wrong-secret and corruption are folded — do not distinguish).
private func vaultAccessFailureMessage(_ e: VaultAccessError) -> String {
    switch e {
    case .wrongDeviceSecretOrCorrupt:
        return "The device key couldn’t open this vault. Unlock with your password."
    case .folderInvalid:
        return "The vault folder is missing or unreadable."
    default:
        return "Couldn’t open the vault. Unlock with your password."
    }
}
