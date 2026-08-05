import Foundation

/// A claim, made at the conformance site, that this error type's diagnostic text
/// carries NO secret — no vault plaintext, password, mnemonic, or key bytes — and
/// is therefore safe to emit at `os.Logger`'s `privacy: .public` (#467).
///
/// `privacy: .public` disables the unified log's default redaction so a diagnostic
/// survives into a sysdiagnose (#456). That is sound only while every error able
/// to reach such a site is secret-free. Before #467 that was maintained by a doc
/// comment; this protocol makes it structural and FAIL-CLOSED — an error type that
/// does not conform is never described (see `diagnosticDetail`).
///
/// Conforming is a SECURITY DECISION, reviewed like any other. Two forms:
///
///     // wholly secret-free — take the default rendering
///     extension DeviceUuidStoreError: SecretFreeError {}
///
///     // secret-free EXCEPT one case — redact AT SOURCE
///     extension FieldDecodeError: SecretFreeError {
///         public var diagnosticDescription: String {
///             switch self {
///             case .badUTF8: return "badUTF8"
///             case .value:   return "value(<redacted>)"
///             }
///         }
///     }
///
/// The second form is what makes this a rendering protocol rather than a bare
/// marker: a type safe in nine cases and secret-bearing in one keeps the nine
/// instead of being excluded wholesale.
public protocol SecretFreeError: Error {
    /// Secret-free one-line diagnostic text for this error.
    var diagnosticDescription: String { get }
}

public extension SecretFreeError {
    /// Default: the full Swift description, associated values included.
    /// Override whenever any case can carry a secret.
    var diagnosticDescription: String { String(describing: self) }
}

/// Render `error` for a `privacy: .public` log line. This is the ONLY sanctioned
/// way to do so — enforced by `ios/scripts/check-public-log-hygiene.sh`.
///
/// DEFAULT-DENY: a type that has not been reviewed and conformed to
/// `SecretFreeError` is never described. It degrades to a marker naming the type
/// plus the bridged `NSError` domain and code — enough to identify WHICH case
/// fired, and enough to tell a developer exactly which type to review and conform.
///
/// `userInfo` is deliberately NOT read: it is the only part of an `NSError` that
/// can carry arbitrary caller-supplied content.
///
/// The `NSError` bridge also closes a real trap. A Foundation file error arrives
/// in a `catch` with dynamic type `NSError`, so `error as? SecretFreeError` FAILS
/// even when `CocoaError` conforms — without this branch every real file error
/// would render as an opaque marker. Conforming `NSError` itself would also work
/// but hands a blanket allow to every bridged error; domain+code keeps the
/// diagnostic value without the blanket.
public func diagnosticDetail(_ error: Error) -> String {
    if let safe = error as? SecretFreeError { return safe.diagnosticDescription }
    let ns = error as NSError
    return "<undisclosed \(type(of: error)) domain=\(ns.domain) code=\(ns.code)>"
}

// MARK: - Reviewed conformances (this package)
//
// Each line below is a reviewed claim that the type's `String(describing:)`
// carries no secret. Adding one is a security decision — see `SecretFreeError`.
// No `@retroactive` is needed even for the stdlib type: the warning fires only
// when the declaring module owns NEITHER the type NOR the protocol, and the
// protocol is ours.

/// Paths, uuids, and short reason labels; never a credential. The three folded
/// "…OrCorrupt" cases carry nothing at all — EXCEPT `.invalidArgument`, which is
/// redacted below.
extension VaultAccessError: SecretFreeError {
    /// `.invalidArgument` is the one case whose payload is built from VAULT
    /// PLAINTEXT: `RecordEditViewModel` interpolates a decrypted record's field
    /// name into it (`"field '<name>' is not valid hex"`,
    /// `"duplicate field name: <name>"`). A field name is exactly what
    /// `SecretFreeError` promises never to emit, so it is redacted AT SOURCE —
    /// the second conformance form the protocol exists to make possible.
    ///
    /// Do NOT "fix" this by relying on catch-arm ordering. It is true today that
    /// every one of the 23 fold sites has a `catch let e as VaultAccessError` arm
    /// ahead of its catch-all, so a `VaultAccessError` never reaches
    /// `foldDiagnostic` — but nothing tests or enforces that, and one reordered or
    /// deleted arm would put a user's field name in the unified log store. The
    /// redaction holds regardless of which site does the rendering.
    ///
    /// `.corruptVault` is NO LONGER redacted. Its payload is a Rust-side error
    /// string passed through by `VaultErrorMapping`, and until #474 at least one
    /// of those strings embedded vault plaintext: `RecordError::DuplicateKey`
    /// formatted the decrypted CBOR field name into its message. #474 made every
    /// `core` error payload data-free by construction — plaintext-bearing
    /// payloads carry a `&'static str` hint plus an ordinal, and the `ciborium`
    /// message is discarded at the boundary — and
    /// `scripts/check-error-payload-hygiene.py` fails CI if a new variant
    /// reintroduces a runtime `String`. Restoring this redaction would throw
    /// away every corruption diagnostic for no remaining benefit.
    ///
    /// `.invalidArgument` above is NOT covered by that guarantee and must stay
    /// redacted: its payload is SWIFT-authored, not Rust-authored — see #473.
    ///
    /// Every other case is rendered in full. `.invalidMnemonic` is safe because
    /// the core emits a word index rather than the word; `.folderInvalid` carries
    /// filesystem paths, which the threat model already treats as disclosed;
    /// `.other` / `.reauthFailed` are built either from fixed labels or from
    /// `diagnosticDetail` itself, so they are already gated at construction.
    public var diagnosticDescription: String {
        switch self {
        case .invalidArgument:
            return "invalidArgument(<redacted>)"
        default:
            return String(describing: self)
        }
    }
}

/// Sync-pass failures: lock state, state-decode reasons, FFI shape errors.
extension VaultSyncError: SecretFreeError {}

/// Selection failures: a bookmark-resolution reason string. No credential.
extension VaultSelectionError: SecretFreeError {}

/// An `OSStatus` or a byte length. The device UUID is a PUBLIC per-device
/// fingerprint (see `DeviceUuidStore`), not key material.
extension DeviceUuidStoreError: SecretFreeError {}

/// Stdlib cancellation sentinel — no payload at all.
extension CancellationError: SecretFreeError {}
