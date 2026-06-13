import Foundation

/// True iff `password` and `confirm` are byte-equal AND non-empty. Gates the
/// create wizard's credentials step (desktop D.1.3 parity: both fields filled
/// and identical; no password-strength rule). This is a UX confirm-match check,
/// NOT a secret comparison against stored material, so constant-time is not
/// required here.
public func passwordsMatch(_ password: [UInt8], _ confirm: [UInt8]) -> Bool {
    !password.isEmpty && password == confirm
}
