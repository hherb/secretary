import Foundation

/// Why a vault name is rejected by `validateVaultName`.
public enum VaultNameError: Equatable {
    /// Empty or whitespace-only.
    case empty
    /// Contains a path separator (`/`) or NUL — would escape the chosen parent.
    case containsSeparator
    /// The reserved directory names `.` or `..`.
    case reservedName
}

/// Result of validating a user-typed vault (sub)folder name. The `.valid`
/// payload is the trimmed name actually used for `mkdir`.
public enum ValidatedVaultName: Equatable {
    case valid(String)
    case invalid(VaultNameError)
}

/// Validate a vault folder name the user typed in the create wizard. The name
/// becomes a fresh subfolder inside the picked parent, so it must be a single
/// path component: non-empty, no separators / NUL, and not the reserved `.`/`..`.
/// Mirrors desktop D.1.3's `joinSubfolder` traversal guard.
public func validateVaultName(_ raw: String) -> ValidatedVaultName {
    let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
    if trimmed.isEmpty { return .invalid(.empty) }
    if trimmed.contains("/") || trimmed.contains("\u{0}") { return .invalid(.containsSeparator) }
    if trimmed == "." || trimmed == ".." { return .invalid(.reservedName) }
    return .valid(trimmed)
}
