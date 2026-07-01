package org.secretary.browse

/**
 * A [WriteReauthGate] whose delegate can be swapped after construction. Used by the cloud open path
 * (#340): a remembered SAF cloud vault's UUID is unknown before the open, so the real gate cannot be
 * chosen up front. The caller hands this placeholder (delegating to [NoopReauthGate]) to the open,
 * then calls [retarget] once `onVaultUuidLearned` resolves the UUID.
 *
 * [seed] records the unlock instant and forwards it; [retarget] seeds the incoming delegate with that
 * instant if the wrapper was already seeded, so the grace window opens from the unlock time regardless
 * of whether [seed] or [retarget] runs first (in production `onVaultUuidLearned` — hence [retarget] —
 * fires before `openBrowseWithSync` seeds the gate). This makes correctness a LOCAL invariant rather
 * than one relying on call ordering.
 *
 * NOT thread-safe: plain mutable state, single-threaded by construction (all callers on the main
 * dispatcher), identical to [GraceWindowReauthGate].
 */
class RetargetableReauthGate : WriteReauthGate {
    private var delegate: WriteReauthGate = NoopReauthGate
    private var seededAtMs: Long? = null

    override suspend fun authorizeWrite(reason: String) = delegate.authorizeWrite(reason)

    override fun seed(nowMs: Long) {
        seededAtMs = nowMs
        delegate.seed(nowMs)
    }

    override fun reset() {
        seededAtMs = null
        delegate.reset()
    }

    /** Swap the delegate; re-seed it with the recorded instant if the wrapper was already seeded. */
    fun retarget(newGate: WriteReauthGate) {
        delegate = newGate
        seededAtMs?.let { newGate.seed(it) }
    }
}
