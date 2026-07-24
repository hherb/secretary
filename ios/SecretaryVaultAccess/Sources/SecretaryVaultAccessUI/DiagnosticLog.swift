import Foundation
import os

// Diagnostic logging seam for `SecretaryVaultAccessUI` view-model fold sites (#456).
//
// The view models fold an *untyped* underlying failure into a typed error's carried
// `String` at their catch-all `catch` arms (`.other` / `.reauthFailed` /
// `.createFailed` / `.failed` / `.unavailable`). #454 deliberately keeps that carried
// `String` out of the user-facing copy, so without a logger the only record of what
// went wrong lives on an in-memory enum value that nothing surfaces. This seam is that
// logger: a pure, host-tested formatter plus a thin `os.Logger` edge.

/// The unified-log destination for fold-site diagnostics. The app layers use
/// `com.secretary.app` / `com.secretary.macapp`; this shared package uses its own
/// `com.secretary.vaultaccess` subsystem so its lines filter cleanly in Console.app.
private let vaultAccessUILog = Logger(
    subsystem: "com.secretary.vaultaccess",
    category: "vault-access-ui"
)

/// Build the one-line diagnostic string logged at a fold site.
///
/// Shape: `"[<fileID>:<line> <function>] <String(describing: underlying)>"`.
///
/// The ONLY dynamic component is `String(describing: underlying)`; the site
/// identifiers are compile-time `StaticString` / `UInt`. Keeping this a pure function
/// makes the "what content is emitted" decision host-testable in isolation, which is
/// what proves the logged content stays diagnostic-only — no `.localizedDescription`
/// or other interpolation can slip in (see `DiagnosticLogTests`).
func foldedErrorDiagnostic(
    underlying: Error,
    fileID: StaticString,
    function: StaticString,
    line: UInt
) -> String {
    "[\(fileID):\(line) \(function)] \(String(describing: underlying))"
}

/// Log, at `.error` level, the underlying error folded at an untyped catch-all site.
///
/// `privacy: .public` is DELIBERATE (#456). The underlying errors folded at the call
/// sites are, exhaustively today: `FfiVaultError` (uniffi), Foundation file errors,
/// `DeviceUnlockError`, `VaultSyncError`, and `VaultSelectionError` — carrying
/// uuids / paths / labels / reasons, never vault plaintext, a password, a mnemonic,
/// or key bytes. This is the same `String(describing:)` the enum already retains in
/// memory (#454); logging it only newly exposes it to the unified log store, which is
/// why "diagnostic-only" must hold before choosing `.public`.
///
/// If you add a new error source that could carry a secret, sanitize it AT THAT
/// SOURCE (or drop to `privacy: .private` / `.sensitive` there) — do NOT widen this
/// seam silently. Calling this from a fold site keeps the pure view models
/// host-testable: it returns `Void`, never throws, and has no observable effect on
/// view-model state, so a fold's behaviour under `swift test` is unchanged (the
/// emitted unified-log line, if any, is invisible to the tests).
func logFoldedError(
    _ underlying: Error,
    fileID: StaticString = #fileID,
    function: StaticString = #function,
    line: UInt = #line
) {
    vaultAccessUILog.error(
        "\(foldedErrorDiagnostic(underlying: underlying, fileID: fileID, function: function, line: line), privacy: .public)"
    )
}
