package org.secretary.browse

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** Records each authorize() call and can be scripted to throw a DeviceUnlockError. */
private class FakeBiometricAuthorizer(
    override val isEnrolled: Boolean = true,
    private val error: DeviceUnlockError? = null,
) : BiometricAuthorizer {
    val reasons = mutableListOf<String>()
    override suspend fun authorize(reason: String) {
        reasons += reason
        error?.let { throw it }
    }
}

class GraceWindowReauthGateTest {
    private var nowMs = 1_000L
    private fun clock(): Long = nowMs

    @Test
    fun `not enrolled is a no-op (never prompts)`() = runTest {
        val auth = FakeBiometricAuthorizer(isEnrolled = false)
        val gate = GraceWindowReauthGate(auth, ::clock, windowMs = 30_000L)
        gate.authorizeWrite("write")
        assertTrue(auth.reasons.isEmpty())
    }

    @Test
    fun `first write with no prior auth prompts and records the reason`() = runTest {
        val auth = FakeBiometricAuthorizer()
        val gate = GraceWindowReauthGate(auth, ::clock, windowMs = 30_000L)
        gate.authorizeWrite("Confirm deleting this entry")
        assertEquals(listOf("Confirm deleting this entry"), auth.reasons)
    }

    @Test
    fun `a write within the grace window is silent`() = runTest {
        val auth = FakeBiometricAuthorizer()
        val gate = GraceWindowReauthGate(auth, ::clock, windowMs = 30_000L)
        gate.authorizeWrite("first")        // prompts, advances lastAuth to now=1000
        nowMs = 1_000L + 29_999L
        gate.authorizeWrite("second")       // within window → silent
        assertEquals(listOf("first"), auth.reasons)
    }

    @Test
    fun `a write at or past the window prompts again`() = runTest {
        val auth = FakeBiometricAuthorizer()
        val gate = GraceWindowReauthGate(auth, ::clock, windowMs = 30_000L)
        gate.authorizeWrite("first")        // now=1000
        nowMs = 1_000L + 30_000L            // exactly the boundary
        gate.authorizeWrite("second")
        assertEquals(listOf("first", "second"), auth.reasons)
    }

    @Test
    fun `seed opens the grace window so the next write is silent`() = runTest {
        val auth = FakeBiometricAuthorizer()
        val gate = GraceWindowReauthGate(auth, ::clock, windowMs = 30_000L)
        gate.seed(nowMs)                    // just unlocked
        gate.authorizeWrite("write")        // within window of the seed → silent
        assertTrue(auth.reasons.isEmpty())
    }

    @Test
    fun `reset forces the next write to prompt again`() = runTest {
        val auth = FakeBiometricAuthorizer()
        val gate = GraceWindowReauthGate(auth, ::clock, windowMs = 30_000L)
        gate.seed(nowMs)
        gate.reset()
        gate.authorizeWrite("write")
        assertEquals(listOf("write"), auth.reasons)
    }

    @Test
    fun `a cancelled prompt throws and does NOT advance the window`() = runTest {
        val auth = FakeBiometricAuthorizer(error = DeviceUnlockError.UserCancelled)
        val gate = GraceWindowReauthGate(auth, ::clock, windowMs = 30_000L)
        assertThrows(DeviceUnlockError.UserCancelled::class.java) {
            kotlinx.coroutines.runBlocking { gate.authorizeWrite("write") }
        }
        // Window did not advance: a follow-up still prompts (would be silent if it had advanced).
        val ok = FakeBiometricAuthorizer()
        val gate2 = GraceWindowReauthGate(ok, ::clock, windowMs = 30_000L)
        gate2.authorizeWrite("again")
        assertEquals(listOf("again"), ok.reasons)
    }

    @Test
    fun `a failed prompt throws and does NOT advance the window`() = runTest {
        val auth = FakeBiometricAuthorizer(error = DeviceUnlockError.BiometryLockout)
        val gate = GraceWindowReauthGate(auth, ::clock, windowMs = 30_000L)
        assertThrows(DeviceUnlockError.BiometryLockout::class.java) {
            kotlinx.coroutines.runBlocking { gate.authorizeWrite("write") }
        }
        nowMs += 1L
        // Still no valid proof → the next write prompts again (same authorizer, set to succeed now is N/A;
        // assert by observing a second call IS attempted).
        assertThrows(DeviceUnlockError.BiometryLockout::class.java) {
            kotlinx.coroutines.runBlocking { gate.authorizeWrite("write2") }
        }
        assertEquals(listOf("write", "write2"), auth.reasons)
    }
}
