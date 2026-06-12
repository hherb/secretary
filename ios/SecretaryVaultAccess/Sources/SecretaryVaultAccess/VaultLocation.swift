import Foundation

/// A remembered vault location: a human-readable `displayName` plus an opaque
/// security-scoped `bookmark` produced by the platform file picker. The bookmark
/// is NOT secret — it is a path-style token with no key material — so persisting
/// it (e.g. in `UserDefaults`) carries no secret-residue risk. No vault key or
/// credential ever flows through this type.
public struct VaultLocation: Equatable {
    public let displayName: String
    public let bookmark: Data

    public init(displayName: String, bookmark: Data) {
        self.displayName = displayName
        self.bookmark = bookmark
    }
}
