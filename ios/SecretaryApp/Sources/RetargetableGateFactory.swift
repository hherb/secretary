import Foundation
import SecretaryVaultAccess
import SecretaryVaultAccessUI
import SecretaryKit

/// Build the shared retargetable re-auth gate for an opened session, seeded with
/// the **persisted** grace window (or the 2-min schema default when the vault has
/// no settings block / on a read error). One instance is shared by every writer
/// (record edit, trash, settings save); a Settings save retargets it live.
///
/// `biometricUnlock` seeds the initial window's last-auth instant — a device
/// unlock counts as presence (first write is free), a password open does not.
///
/// Honoring the persisted grace window at open is why this reads settings here:
/// a user who set a longer window gets it on every reopen, and the effective
/// default (2 min) matches the schema + desktop rather than the old hard-coded
/// 30 s (deliberate, user-approved 2026-07-12).
@MainActor
func makeRetargetableReauthGate(session: VaultSession,
                                vaultPath: Data,
                                biometricUnlock: Bool) -> RetargetableReauthGate {
    let authorizer = EnclaveBiometricAuthorizer(
        enclave: makePerVaultDeviceUnlock(vaultPath: vaultPath).enclave)
    // Persisted grace, or the projected 2-min default (readSettings already
    // returns the schema default for an absent block; the `??` only covers a
    // non-SettingsPort session or a hard read error).
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
