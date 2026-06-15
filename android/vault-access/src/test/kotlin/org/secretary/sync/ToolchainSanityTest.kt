package org.secretary.sync

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class ToolchainSanityTest {
    @Test
    fun junitRuns() {
        assertEquals(2, 1 + 1)
    }

    @Test
    fun coroutinesTestRuns() = runTest {
        assertEquals(4, suspendingDouble(2))
    }

    private suspend fun suspendingDouble(n: Int): Int = n * 2
}
