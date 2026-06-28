package org.secretary.mirror

/**
 * Thrown by [VaultWorkingCopyCoordinator.createThenOpen] when an offline-create push fails AND the
 * pending-flush marker could not be persisted (best-effort [PendingFlushMarker.set] swallowed an
 * I/O failure). On this one path the marker is the load-bearing guard against a later
 * materialize-clobber of the only copy of the freshly-created vault, so its loss is escalated
 * louder than a normal (recoverable) offline-create failure. (#327)
 */
class PendingFlushNotPersisted(val createdVaultUuidHex: String, cause: Throwable) :
    Exception("offline-created vault $createdVaultUuidHex could not be synced or marked for retry", cause)

/**
 * Orchestrates the per-session working-copy lifecycle that lets the POSIX-only core operate on a
 * path-less SAF cloud folder, enforcing the one ordering rule the shim guarantees:
 *
 *   **push-before-pull** — before pulling cloud→working, always flush any pending local edits.
 *
 * Pure of Android/SAF/FFI: [mirror], [marker], and [openAndSync] are injected, so the ordering is
 * host-testable with order-recording fakes. The coordinator NEVER merges — merge stays entirely in
 * the audited Rust core ([openAndSync] runs the existing sync pass); this type only decides which
 * bytes move and in what order.
 *
 * @param S the opaque opened-session handle the caller hands to Browse (e.g. a BrowseSession).
 * @param openAndSync materialized working copy is on disk when this runs: it unlocks + runs the
 *   existing sync_vault_in/makeVaultSync pass against the working dir and returns the browse handle.
 */
class VaultWorkingCopyCoordinator<S>(
    private val mirror: WorkingCopyMirror,
    private val marker: PendingFlushMarker,
    private val openAndSync: suspend () -> S,
) {
    /**
     * Open a remembered cloud vault. If a prior flush failed (marker set), push the un-pushed
     * working-copy edits FIRST; only on a successful push do we clear the marker and pull. A failed
     * push propagates and we do NOT materialize (pulling would risk clobbering un-pushed edits) — the
     * marker stays set so the next open retries. With no pending marker the working copy is already
     * clean, so we skip straight to materialize → open+sync.
     */
    suspend fun openExisting(): S {
        if (marker.isSet()) {
            mirror.flush()   // throws on failure → no materialize, marker stays set (push-before-pull)
            marker.clear()
        }
        mirror.materialize()
        return openAndSync()
    }

    /**
     * Push the just-created working copy up to its fresh cloud folder, persist the location keyed by
     * [createdVaultUuidHex], then open it into Browse. (The create itself already wrote the working
     * dir; the caller passes the new uuid from CreatedVault.)
     *
     * If the push fails (offline create: the new vault lives ONLY in the working dir, cloud is still
     * empty), set the pending marker before re-propagating so the next [openExisting] does
     * push-before-pull instead of materialize-first. Without the marker, the next open would diff an
     * empty cloud against the full working copy and DELETE the only copy of the freshly-created vault
     * — silent, irrecoverable data loss. The exception still propagates (`:app` routes to
     * unlock/retry); the marker is the only added behavior. Mirrors [afterCommit]'s discipline.
     */
    suspend fun createThenOpen(createdVaultUuidHex: String, persistLocation: (vaultUuidHex: String) -> Unit): S {
        try {
            mirror.flush()
        } catch (e: Exception) {
            marker.set()
            if (!marker.isSet()) {
                // The marker is the load-bearing guard for the offline-create reopen path; if it could not
                // persist, escalate so :app can warn instead of silently leaving the vault unprotected. (#327)
                throw PendingFlushNotPersisted(createdVaultUuidHex, e)
            }
            throw e
        }
        persistLocation(createdVaultUuidHex)
        return openAndSync()
    }

    /**
     * Flush after a successful commit. Success clears any prior pending state; failure sets the
     * pending marker (non-blocking "saved locally, not yet synced") so the next [openExisting]
     * retries the push before pulling. NEVER throws — a failed background flush must not crash Browse.
     */
    suspend fun afterCommit() {
        try {
            mirror.flush()
            marker.clear()
        } catch (e: Exception) {
            marker.set()
        }
    }
}
