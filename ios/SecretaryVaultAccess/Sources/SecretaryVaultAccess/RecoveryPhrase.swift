import Foundation

/// Normalizes user-typed BIP-39 recovery phrases before handing them to the
/// FFI: trims, lowercases, and collapses any run of whitespace to one space.
/// The canonical BIP-39 word list is all-lowercase and single-space-joined, so
/// this removes the most common copy/paste and keyboard-autocapitalization
/// noise without altering the words themselves.
public enum RecoveryPhrase {
    public static func normalize(_ raw: String) -> String {
        raw.lowercased()
            .split(whereSeparator: { $0.isWhitespace })
            .joined(separator: " ")
    }
}
