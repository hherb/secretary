package org.secretary.mirror

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class BackoffDelayTest {
    private val policy = RetryPolicy.CLOUD_DEFAULT // base=250, max=2000, attempts=5

    @Test
    fun `backoff is exponential then capped at maxDelay`() {
        assertEquals(250L, backoffDelayMs(1, policy))   // 250 * 2^0
        assertEquals(500L, backoffDelayMs(2, policy))   // 250 * 2^1
        assertEquals(1000L, backoffDelayMs(3, policy))  // 250 * 2^2
        assertEquals(2000L, backoffDelayMs(4, policy))  // 250 * 2^3 = 2000, == cap
        assertEquals(2000L, backoffDelayMs(5, policy))  // 250 * 2^4 = 4000, capped to 2000
        assertEquals(2000L, backoffDelayMs(99, policy))  // large attempt stays capped, no overflow
    }

    @Test
    fun `CLOUD_DEFAULT has the documented values`() {
        assertEquals(5, RetryPolicy.CLOUD_DEFAULT.maxAttempts)
        assertEquals(250L, RetryPolicy.CLOUD_DEFAULT.baseDelayMs)
        assertEquals(2000L, RetryPolicy.CLOUD_DEFAULT.maxDelayMs)
    }
}
