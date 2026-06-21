package org.secretary.browse

/**
 * The presence gate the write VMs depend on. `authorizeWrite` returns normally when the write may
 * proceed (gate disabled, within the grace window, or proof succeeded) and THROWS a
 * [DeviceUnlockError] when the user cancels or biometry fails. Mirror of iOS `WriteReauthGate`.
 *
 * `seed`/`reset` default to no-ops so [NoopReauthGate] and host tests need not implement them.
 */
interface WriteReauthGate {
    /** Prove presence for a write described by [reason]; throws [DeviceUnlockError] on cancel/failure. */
    suspend fun authorizeWrite(reason: String)

    /** Open the grace window at [nowMs] (call right after a successful unlock). */
    fun seed(nowMs: Long) {}

    /** Drop any prior proof so the next write prompts again (call on lock). */
    fun reset() {}
}

/**
 * The biometric presence primitive, abstracted so the gate is host-testable over a fake. The real
 * impl ([CoordinatorBiometricAuthorizer]) wraps the shipped device-unlock path.
 */
interface BiometricAuthorizer {
    /** True iff a device secret is enrolled (a Keystore key exists to release). Cheap, no prompt. */
    val isEnrolled: Boolean

    /** Prove presence (real impl: a biometric prompt explained by [reason]); throws
     *  [DeviceUnlockError] on cancel/lockout/failure. */
    suspend fun authorize(reason: String)
}

/**
 * Grace-window write gate. Active only when a device secret is enrolled; within [windowMs] of the
 * last successful proof a write is silently authorized. The proof timestamp advances ONLY on success,
 * so a cancelled/failed prompt never opens the window. Pure (no I/O); [clock] and [authorizer] are
 * injected for host tests. Mirror of iOS `GraceWindowReauthGate`.
 */
class GraceWindowReauthGate(
    private val authorizer: BiometricAuthorizer,
    private val clock: () -> Long,
    private val windowMs: Long = ReauthWindow.V1_DEFAULT_MS,
) : WriteReauthGate {
    private var lastAuthAtMs: Long? = null

    override suspend fun authorizeWrite(reason: String) {
        if (!authorizer.isEnrolled) return                          // no enrollment → no gate
        if (!needsReauth(lastAuthAtMs, clock(), windowMs)) return   // inside the grace window
        authorizer.authorize(reason)                                // throws on cancel/failure
        lastAuthAtMs = clock()                                      // advance ONLY on success
    }

    override fun seed(nowMs: Long) { lastAuthAtMs = nowMs }
    override fun reset() { lastAuthAtMs = null }
}

/** A gate that authorizes everything. The default for VMs constructed without write re-auth
 *  (host tests, and any session with no enrolled device secret). */
object NoopReauthGate : WriteReauthGate {
    override suspend fun authorizeWrite(reason: String) {}
}
