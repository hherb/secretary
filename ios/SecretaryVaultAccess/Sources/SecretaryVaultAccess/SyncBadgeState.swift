import Foundation

/// What the sync badge shows. Pure presentation state derived from the VM's
/// inputs; carries no secrets.
public enum SyncBadgeState: Equatable, Sendable {
    case neverSynced
    case synced(sinceMs: UInt64)   // from SyncStatus.lastStateWriteMs
    case changesDetected           // monitor raised pendingChanges
    case reviewNeeded              // a prior pass returned conflictsPending
    case syncing
}

/// Derive the badge state. Precedence (first match wins): in-progress →
/// conflict awaiting review → advisory change detected → last-synced → never.
public func syncBadgeState(
    inProgress: Bool,
    pendingChanges: Bool,
    hasPendingConflict: Bool,
    status: SyncStatus?
) -> SyncBadgeState {
    if inProgress { return .syncing }
    if hasPendingConflict { return .reviewNeeded }
    if pendingChanges { return .changesDetected }
    if let ms = status?.lastStateWriteMs { return .synced(sinceMs: ms) }
    return .neverSynced
}
