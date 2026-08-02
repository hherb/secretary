import SecretaryDeviceUnlock
import SecretaryVaultAccess

// Cross-package `SecretFreeError` conformances (#467).
//
// They live HERE, not in `SecretaryVaultAccess`, because `SecretaryVaultAccess`
// does not depend on `SecretaryDeviceUnlock` — `SecretaryKit` is the lowest
// target that sees both. Swift registers conformances process-globally, so the
// `as? SecretFreeError` cast inside `SecretaryVaultAccessUI` finds this one at
// runtime even though that module cannot see the declaration.
//
// `@retroactive` is required and correct: this module owns neither the type nor
// the protocol. It is also a useful marker — it says out loud that a conformance
// is being asserted across a boundary the type's own author never saw.

/// Biometric / Secure-Enclave gate failures. Every case is a fixed sentinel
/// except `.enclave(String)`, which carries a `Security.framework` OSStatus
/// description, and `.vault(VaultSlotError)`, which carries slot-shape state.
/// No wrapped secret, device secret, or key material is ever placed in either.
extension DeviceUnlockError: @retroactive SecretFreeError {}
