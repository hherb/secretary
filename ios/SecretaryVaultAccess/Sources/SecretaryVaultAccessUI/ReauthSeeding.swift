import SecretaryVaultAccess

/// The `initialAuthAt` to seed `GraceWindowReauthGate` with, given how the vault
/// was just opened. A biometric device-unlock proves biometric presence at
/// `now`, so the first write within the grace window is free (#284). A password
/// or recovery open proves NO biometric presence, so the gate must NOT be
/// pre-seeded (the first write should prompt if the device is enrolled).
///
/// Pure: the caller supplies `now` from `MonotonicInstant.now()` (SecretaryKit),
/// sharing the gate's monotonic base.
public func reauthInitialAuthAt(biometricUnlock: Bool, now: MonotonicInstant) -> MonotonicInstant? {
    biometricUnlock ? now : nil
}
