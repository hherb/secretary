import Foundation

/// Typed failures from the vault-selection layer. Kept distinct from
/// `VaultAccessError` (which models opening/browsing a vault): selection failures
/// are about *locating* a vault, not credential checks, so there is no anti-oracle
/// conflation concern here.
///
/// There is deliberately NO `.accessDenied` case. On iOS,
/// `startAccessingSecurityScopedResource()` returning `false` is not a reliable
/// "denied" signal — it is also benign-false for in-sandbox paths (the demo vault,
/// test temp dirs) where access works anyway. So a genuine lack of access is not
/// swallowed here; it surfaces loudly downstream as the FFI's typed open error
/// (`VaultAccessError.folderInvalid` / `.wrongPasswordOrCorrupt`) when the open is
/// attempted. This preserves the project's no-silent-failure posture without
/// hard-failing the benign case.
public enum VaultSelectionError: Error, Equatable {
    /// `beginAccess` was called with no vault remembered.
    case noVaultSelected
    /// The persisted bookmark could not be resolved to a folder (vault moved/deleted).
    case locationUnavailable(String)
}
