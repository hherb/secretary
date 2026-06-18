package org.secretary.app

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.secretary.browse.UnlockCredential

class PostOpenSyncTest {
    @Test
    fun `a password credential fires onPassword with the secret and never onRecovery`() {
        var pwSeen: ByteArray? = null
        var recoveryFired = false
        dispatchPostOpenSync(
            UnlockCredential.Password(byteArrayOf(1, 2, 3)),
            onPassword = { pwSeen = it },
            onRecovery = { recoveryFired = true },
        )
        assertArrayEquals(byteArrayOf(1, 2, 3), pwSeen)
        assertFalse(recoveryFired, "recovery action must not fire for a password credential")
    }

    @Test
    fun `a recovery credential fires onRecovery only`() {
        var pwFired = false
        var recoveryFired = false
        dispatchPostOpenSync(
            UnlockCredential.Recovery(byteArrayOf(9)),
            onPassword = { pwFired = true },
            onRecovery = { recoveryFired = true },
        )
        assertTrue(recoveryFired)
        assertFalse(pwFired, "password action must not fire for a recovery credential")
    }
}
