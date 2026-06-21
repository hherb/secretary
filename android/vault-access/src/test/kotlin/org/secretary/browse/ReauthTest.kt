package org.secretary.browse

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
        org.junit.jupiter.api.Assertions.assertEquals(30_000L, ReauthWindow.V1_DEFAULT_MS)
    }
}
