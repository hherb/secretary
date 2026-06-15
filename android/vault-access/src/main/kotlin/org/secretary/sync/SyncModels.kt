package org.secretary.sync

/** Vector-clock entry. Never secret — public metadata. */
data class DeviceClock(val deviceUuidHex: String, val counter: ULong)

/** Read-only sync status snapshot. */
data class SyncStatus(
    val hasState: Boolean,
    val deviceClocks: List<DeviceClock>,
    val lastStateWriteMs: ULong?,
)

/**
 * Tombstone-dispute projection. Field [fieldNames] are NAMES only — never values
 * (anti-oracle / metadata-only discipline).
 */
data class SyncVeto(
    val recordUuidHex: String,
    val recordType: String,
    val tags: List<String>,
    val fieldNames: List<String>,
    val localLastModMs: ULong,
    val peerTombstonedAtMs: ULong,
    val peerDeviceHex: String,
)

/** Field-level last-writer-wins collision notice (field NAMES only). */
data class SyncCollision(val recordUuidHex: String, val fieldNames: List<String>)

/** The caller's per-record veto decision. `keepLocal == true` rejects the peer tombstone. */
data class SyncVetoDecision(val recordUuidHex: String, val keepLocal: Boolean)

/** A paused pass's conflict detail, surfaced for interactive resolution. */
data class PendingConflict(val vetoes: List<SyncVeto>, val collisions: List<SyncCollision>)

/**
 * Result of one sync pass. Arms map 1:1 to the uniffi `SyncOutcomeDto` so the future
 * `UniffiVaultSyncPort` adapter is a straight transcription.
 */
sealed interface SyncOutcome {
    data object NothingToDo : SyncOutcome
    data object AppliedAutomatically : SyncOutcome
    data object SilentMerge : SyncOutcome
    data object MergedClean : SyncOutcome
    data object RollbackRejected : SyncOutcome

    /**
     * A tombstone dispute paused the pass without writing. [manifestHash] is the opaque
     * TOCTOU freshness token replayed into `commitDecisions`. Not a `data class`: it carries
     * a [ByteArray], so equality/hashing are content-based via explicit overrides.
     */
    class ConflictsPending(
        val vetoes: List<SyncVeto>,
        val collisions: List<SyncCollision>,
        val manifestHash: ByteArray,
    ) : SyncOutcome {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is ConflictsPending) return false
            return vetoes == other.vetoes &&
                collisions == other.collisions &&
                manifestHash.contentEquals(other.manifestHash)
        }

        override fun hashCode(): Int {
            var result = vetoes.hashCode()
            result = 31 * result + collisions.hashCode()
            result = 31 * result + manifestHash.contentHashCode()
            return result
        }

        override fun toString(): String =
            "ConflictsPending(vetoes=$vetoes, collisions=$collisions, " +
                "manifestHash=${manifestHash.size} bytes)"
    }
}
