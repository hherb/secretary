import Foundation
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Build the shared retargetable re-auth gate for an opened session, seeded with
/// the persisted grace window (or the schema default when the vault has no settings
/// block / on a read error). One instance is shared by every writer (record edit,
/// trash, settings save); a Settings save retargets it live.
///
/// `biometricUnlock` seeds the initial window's last-auth instant — a device unlock
/// counts as presence (first write is free), a password open does not.
///
/// Hoisted from the iOS app target into SecretaryKit (D.5.2) so the iOS app and the
/// macOS app share one factory. It builds only on cross-platform symbols
/// (`makePerVaultDeviceUnlock`, `EnclaveBiometricAuthorizer` — both in SecretaryKit;
/// `RetargetableReauthGate`, `GraceWindowReauthGate`, `SettingsPort`,
/// `MonotonicInstant`, `reauthInitialAuthAt` — in SecretaryVaultAccess/UI). It lives
/// in SecretaryKit (not SecretaryVaultAccessUI) because it depends on
/// `makePerVaultDeviceUnlock`/`EnclaveBiometricAuthorizer`; hoisting it into
/// SecretaryVaultAccessUI would invert the package dependency (a cycle).
@MainActor
public func makeRetargetableReauthGate(session: VaultSession,
                                       vaultPath: Data,
                                       biometricUnlock: Bool) -> RetargetableReauthGate {
    let authorizer = EnclaveBiometricAuthorizer(
        enclave: makePerVaultDeviceUnlock(vaultPath: vaultPath).enclave)
    let graceMs = (try? (session as? SettingsPort)?.readSettings())?.reauthGraceWindowMs
        ?? SecretaryKit.reauthWindowDefaultMs()
    let initialAuthAt = reauthInitialAuthAt(biometricUnlock: biometricUnlock, now: MonotonicInstant.now())
    return RetargetableReauthGate(
        window: .milliseconds(Int(graceMs)),
        initialAuthAt: initialAuthAt,
        clock: MonotonicInstant.now) { window, seed in
            GraceWindowReauthGate(authorizer: authorizer, window: window,
                                  clock: MonotonicInstant.now, initialAuthAt: seed)
        }
}
