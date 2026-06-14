import Foundation

/// One device's vector-clock entry — public metadata, never secret.
/// Mirrors the bridge `DeviceClockDto`.
public struct DeviceClock: Equatable {
    public let deviceUuidHex: String
    public let counter: UInt64
    public init(deviceUuidHex: String, counter: UInt64) {
        self.deviceUuidHex = deviceUuidHex
        self.counter = counter
    }
}

/// Read-only sync status for a vault. Mirrors the bridge `SyncStatusDto`.
public struct SyncStatus: Equatable {
    public let hasState: Bool
    public let deviceClocks: [DeviceClock]
    public let lastStateWriteMs: UInt64?
    public init(hasState: Bool, deviceClocks: [DeviceClock], lastStateWriteMs: UInt64?) {
        self.hasState = hasState
        self.deviceClocks = deviceClocks
        self.lastStateWriteMs = lastStateWriteMs
    }
}

/// A tombstone dispute awaiting a human decision. Metadata-only by construction
/// (the bridge projects field *names*, never values) — no plaintext secret here.
public struct SyncVeto: Equatable {
    public let recordUuidHex: String
    public let recordType: String
    public let tags: [String]
    public let fieldNames: [String]
    public let localLastModMs: UInt64
    public let peerTombstonedAtMs: UInt64
    public let peerDeviceHex: String
    public init(recordUuidHex: String, recordType: String, tags: [String],
                fieldNames: [String], localLastModMs: UInt64,
                peerTombstonedAtMs: UInt64, peerDeviceHex: String) {
        self.recordUuidHex = recordUuidHex
        self.recordType = recordType
        self.tags = tags
        self.fieldNames = fieldNames
        self.localLastModMs = localLastModMs
        self.peerTombstonedAtMs = peerTombstonedAtMs
        self.peerDeviceHex = peerDeviceHex
    }
}

/// Metadata-only field-level collision summary for the "auto-merged" notice.
public struct SyncCollision: Equatable {
    public let recordUuidHex: String
    public let fieldNames: [String]
    public init(recordUuidHex: String, fieldNames: [String]) {
        self.recordUuidHex = recordUuidHex
        self.fieldNames = fieldNames
    }
}

/// Caller's per-record decision. `keepLocal == true` rejects the peer tombstone;
/// `false` accepts the delete.
public struct SyncVetoDecision: Equatable {
    public let recordUuidHex: String
    public let keepLocal: Bool
    public init(recordUuidHex: String, keepLocal: Bool) {
        self.recordUuidHex = recordUuidHex
        self.keepLocal = keepLocal
    }
}

/// Result of one sync pass. Mirrors the bridge `SyncOutcomeDto`.
public enum SyncOutcome: Equatable {
    /// Disk clock == local highest-seen. No change.
    case nothingToDo
    /// Disk strictly dominates local. State advanced; no vault write.
    case appliedAutomatically
    /// Concurrent but no surviving block divergence. State advanced; no write.
    case silentMerge
    /// Concurrent, diverging, zero vetoes → merged result committed.
    case mergedClean
    /// Disk strictly dominated by local (rollback). Nothing changed.
    case rollbackRejected
    /// Concurrent, diverging, tombstone vetoes need a human. NOT committed.
    /// `manifestHash` is the opaque freshness token to pass back to commit.
    case conflictsPending(vetoes: [SyncVeto], collisions: [SyncCollision], manifestHash: [UInt8])
}

/// The pending conflict detail surfaced after a `runPass` that paused.
/// The freshness token is held privately by the coordinator and intentionally
/// NOT exposed here — callers never thread it themselves.
public struct PendingConflict: Equatable {
    public let vetoes: [SyncVeto]
    public let collisions: [SyncCollision]
    public init(vetoes: [SyncVeto], collisions: [SyncCollision]) {
        self.vetoes = vetoes
        self.collisions = collisions
    }
}
