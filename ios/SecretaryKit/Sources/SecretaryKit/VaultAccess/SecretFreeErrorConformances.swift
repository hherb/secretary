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

/// Biometric / Secure-Enclave gate failures. No wrapped secret, device secret,
/// or key material is ever placed in any case — audited across all twelve
/// `.enclave` construction sites in `SecureEnclaveDeviceSecretStore`.
///
/// The payloads are NOT uniformly "a Security.framework OSStatus description",
/// as an earlier version of this comment claimed. Precisely:
///   - fixed literals (`:56`, `:59`);
///   - `OSStatus` values (`:105`, `:108`, `:179`, `:192`);
///   - `CFError.localizedDescription` (`:64`, `:123`, `:138`);
///   - `NSError.localizedDescription` (`:216`, `:224`, `:239`, `:249`) — from
///     `LAError` and `NSOSStatusErrorDomain`, but the `default:` arms accept
///     ANY domain, so this is an Apple-framework string of unbounded origin.
///
/// That last group is why the conformance is scoped to what the enclave store
/// actually builds. It is safe because every path is an Apple framework's own
/// message about a key operation — none is derived from vault content. A new
/// `.enclave` construction site that interpolates anything else breaks that,
/// and nothing enforces it; see the `asDeviceUnlockError` fallback in
/// `SecretaryDeviceUnlockUI`, which deliberately carries a TYPE NAME rather
/// than a description for exactly this reason.
extension DeviceUnlockError: @retroactive SecretFreeError {}

// NOT CONFORMED, and not conformable: `UniffiInternalError`.
//
// It is the single most-reachable type at the fold sites — every uniffi adapter
// catches only `VaultError`, so a `UniffiInternalError` (including
// `.rustPanic(String)`, which carries the Rust panic message) propagates
// untouched to 12 of the 23 fold sites and 2 of the 7 app-layer sites. It is
// declared `fileprivate` in the GENERATED `secretary.swift`, so it can never be
// conformed from here, and regenerating the bindings would overwrite any edit.
//
// Default-deny therefore does the right thing: a Rust panic logs as
// `<undisclosed UniffiInternalError domain=… code=0>` and the panic text is
// withheld (it lives in `userInfo`, which `diagnosticDetail` does not read).
// The cost is a diagnostic dead end for the failure mode most worth diagnosing.
// Recovering it would mean catching `UniffiInternalError` in the adapters and
// re-throwing a typed, reviewed error — a separate change, not a conformance.
