package org.secretary.sync

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Threads the two-call inspect→commit sync round-trip and holds the freshness token +
 * conflict detail privately between the two calls. One coordinator drives one vault.
 *
 * Concurrency: guarded by a non-reentrant [Mutex] held ACROSS the suspending port call.
 * This intentionally diverges from the iOS reentrant `actor`: a second concurrent
 * `runPass`/`resolve` blocks until the first completes rather than interleaving — stronger
 * (non-interleaving) serialization. It cannot deadlock because the public methods never
 * call one another. The per-vault FFI lockfile (surfaced as [VaultSyncError.InProgress])
 * remains the cross-process guard; this [Mutex] is the in-process single-driver guarantee.
 * All four methods share the mutex, so a [status]/[pendingConflict] read blocks behind an
 * in-flight pass — intended, since one coordinator drives one vault serially.
 *
 * Secret hygiene: the password is forwarded to the port per call and never retained. Only
 * the manifest-hash freshness token (not a secret) and conflict METADATA are stashed.
 */
class SyncCoordinator(
    private val port: VaultSyncPort,
    private val stateDir: String,
    private val vaultFolder: String,
) {
    private val mutex = Mutex()
    private var stashedToken: ByteArray? = null
    private var stashedConflict: PendingConflict? = null

    /** The conflict detail of a currently-paused pass, or null if none is stashed. */
    suspend fun pendingConflict(): PendingConflict? = mutex.withLock { stashedConflict }

    /** Read-only device-clock status. */
    suspend fun status(vaultUuid: ByteArray): SyncStatus =
        mutex.withLock { port.status(stateDir, vaultUuid) }

    /**
     * Run one inspect pass. On [SyncOutcome.ConflictsPending] the token + conflict are
     * stashed for [resolve]; every other arm clears any prior stash.
     */
    suspend fun runPass(password: ByteArray, nowMs: ULong): SyncOutcome = mutex.withLock {
        val outcome = port.sync(stateDir, vaultFolder, password, nowMs)
        applyStash(outcome)
        outcome
    }

    /**
     * Commit veto decisions for the paused pass, replaying the stashed freshness token.
     * Throws [VaultSyncError.NoPendingConflict] if nothing is stashed. A resolved arm clears
     * the stash; another [SyncOutcome.ConflictsPending] re-stashes the new token; a thrown
     * error (e.g. [VaultSyncError.EvidenceStale]) propagates and PRESERVES the stash so the
     * caller can retry `resolve` without a fresh `runPass`.
     */
    suspend fun resolve(
        decisions: List<SyncVetoDecision>,
        password: ByteArray,
        nowMs: ULong,
    ): SyncOutcome = mutex.withLock {
        val token = stashedToken ?: throw VaultSyncError.NoPendingConflict
        val outcome = port.commitDecisions(stateDir, vaultFolder, password, decisions, token, nowMs)
        applyStash(outcome)
        outcome
    }

    /** Stash on a paused pass; clear on any resolved/safe arm. Not called on a thrown error. */
    private fun applyStash(outcome: SyncOutcome) {
        if (outcome is SyncOutcome.ConflictsPending) {
            stashedToken = outcome.manifestHash
            stashedConflict = PendingConflict(outcome.vetoes, outcome.collisions)
        } else {
            stashedToken = null
            stashedConflict = null
        }
    }
}
