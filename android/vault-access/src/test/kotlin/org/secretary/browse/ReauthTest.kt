package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ReauthTest {
    private val window = ReauthWindow.V1_DEFAULT_MS

    @Test
    fun `null lastAuth always needs reauth`() {
        assertTrue(needsReauth(lastAuthAtMs = null, nowMs = 0L, windowMs = window))
    }

    @Test
    fun `within the window does not need reauth`() {
        assertFalse(needsReauth(lastAuthAtMs = 1_000L, nowMs = 1_000L + 29_999L, windowMs = window))
    }

    @Test
    fun `exactly at the window boundary needs reauth (inclusive)`() {
        assertTrue(needsReauth(lastAuthAtMs = 1_000L, nowMs = 1_000L + window, windowMs = window))
    }

    @Test
    fun `past the window needs reauth`() {
        assertTrue(needsReauth(lastAuthAtMs = 1_000L, nowMs = 1_000L + window + 1L, windowMs = window))
    }

    @Test
    fun `a zero window always needs reauth (prompt before every write)`() {
        assertTrue(needsReauth(lastAuthAtMs = 5_000L, nowMs = 5_000L, windowMs = 0L))
    }

    @Test
    fun `the v1 default window is 30 seconds`() {
        assertEquals(30_000L, ReauthWindow.V1_DEFAULT_MS)
    }

    @Test
    fun `reauthFailedMessage maps lockout to a try-again clause`() {
        assertEquals(
            "too many attempts — try again later",
            reauthFailedMessage(DeviceUnlockError.BiometryLockout),
        )
    }

    @Test
    fun `reauthFailedMessage maps unavailable and not-enrolled to the same clause`() {
        val unavailable = reauthFailedMessage(DeviceUnlockError.BiometryUnavailable)
        val notEnrolled = reauthFailedMessage(DeviceUnlockError.BiometryNotEnrolled)
        assertEquals("biometric authentication is unavailable on this device", unavailable)
        assertEquals(unavailable, notEnrolled)
    }

    @Test
    fun `reauthFailedMessage folds the integrity and generic arms to one message (no oracle)`() {
        val generic = "biometric authentication failed"
        assertEquals(generic, reauthFailedMessage(DeviceUnlockError.AuthenticationFailed))
        assertEquals(generic, reauthFailedMessage(DeviceUnlockError.WrappedSecretCorrupt))
        assertEquals(generic, reauthFailedMessage(DeviceUnlockError.Enclave("boom")))
    }

    @Test
    fun `reauthFailedMessage never leaks a raw exception string`() {
        // Detail must be a curated clause, never the class name / toString of the error.
        val msg = reauthFailedMessage(DeviceUnlockError.Enclave("se-internal-detail"))
        assertFalse(msg.contains("Enclave"))
        assertFalse(msg.contains("se-internal-detail"))
    }
}
