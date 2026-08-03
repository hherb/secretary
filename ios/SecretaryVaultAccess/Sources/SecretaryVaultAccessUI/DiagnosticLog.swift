import Foundation
import SecretaryVaultAccess
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
/// Shape: `"[<fileID>:<line> <function>] <diagnosticDetail(underlying)>"`.
///
/// The ONLY dynamic component is `diagnosticDetail(underlying)`; the site
/// identifiers are compile-time `StaticString` / `UInt`. Keeping this a pure
/// function makes the "what content is emitted" decision host-testable in
/// isolation, which is what proves the logged content stays diagnostic-only — no
/// `.localizedDescription` or other interpolation can slip in (see
/// `DiagnosticLogTests`).
func foldedErrorDiagnostic(
    underlying: Error,
    fileID: StaticString,
    function: StaticString,
    line: UInt
) -> String {
    "[\(fileID):\(line) \(function)] \(diagnosticDetail(underlying))"
}

/// Log the underlying error folded at an untyped catch-all site, and return the
/// same gated detail for the typed error's carried payload.
///
/// ONE application of ONE policy. Because the caller writes
/// `self.error = .other(foldDiagnostic(error))`, two things become structurally
/// true rather than merely conventional:
///
/// 1. the `.public` log line and the carried payload CANNOT disagree; and
/// 2. a new fold site cannot set a folded payload without also logging — the gap
///    that nothing previously forced a new catch-all arm to call the logger at all.
///
/// `privacy: .public` is DELIBERATE (#456): it overrides `os.Logger`'s default
/// redaction so the diagnostic survives into a sysdiagnose (a `.private` value is
/// not persisted to the log store, defeating the purpose). What makes it SAFE is
/// no longer an enumeration of today's reachable error types — it is
/// `diagnosticDetail`'s default-deny (#467): an error type nobody has reviewed and
/// conformed to `SecretFreeError` is never described. To restore detail for a new
/// error source, conform it (redacting at source if any case can carry a secret);
/// do NOT widen this seam.
///
/// Returns `String` and never throws, so a fold's behaviour under `swift test` is
/// unchanged — the emitted unified-log line, if any, is invisible to the tests.
@discardableResult
func foldDiagnostic(
    _ error: Error,
    fileID: StaticString = #fileID,
    function: StaticString = #function,
    line: UInt = #line
) -> String {
    vaultAccessUILog.error(
        "\(foldedErrorDiagnostic(underlying: error, fileID: fileID, function: function, line: line), privacy: .public)"
    )
    return diagnosticDetail(error)
}
