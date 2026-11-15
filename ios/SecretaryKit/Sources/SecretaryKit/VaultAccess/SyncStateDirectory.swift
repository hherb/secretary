import Foundation

/// Subdirectory names for the on-disk sync state, mirroring desktop's
/// `data_dir()/secretary/sync`. Named to avoid magic string literals.
private enum SyncStatePath {
    static let appFolder = "secretary"
    static let syncFolder = "sync"
}

/// Derive `<applicationSupport>/secretary/sync` and create it if absent. The
/// directory lives in the app's own sandbox (always accessible, no security
/// scope). Pure derivation + one `createDirectory` call (the only IO).
public func defaultSyncStateDir(applicationSupport: URL) throws -> URL {
    let dir = applicationSupport
        .appendingPathComponent(SyncStatePath.appFolder, isDirectory: true)
        .appendingPathComponent(SyncStatePath.syncFolder, isDirectory: true)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    return dir
}

/// Resolve the production sync state dir under the real Application Support base.
public func defaultSyncStateDir() throws -> URL {
    let base = try FileManager.default.url(for: .applicationSupportDirectory,
                                           in: .userDomainMask,
                                           appropriateFor: nil, create: true)
    return try defaultSyncStateDir(applicationSupport: base)
}

/// Make `defaultSyncStateDir()` the bridge's sync-state dir for this process
/// (#746), so its open-time rollback check and repair read the same baseline
/// this app's sync calls and "Reset and open" write. Call once at app startup,
/// before any open: the bridge refuses a set after its first read.
public func installPlatformSyncStateDir() throws {
    try setPlatformStateDir(stateDir: defaultSyncStateDir().path)
}
