package org.secretary.sync

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import kotlin.time.Duration.Companion.milliseconds

class ChangeDetectionTuningTest {
    @Test
    fun constantsHaveExpectedValues() {
        assertEquals(2_000.milliseconds, ChangeDetectionTuning.defaultDebounceWindow)
        assertEquals(10_000.milliseconds, ChangeDetectionTuning.defaultSelfWriteMuteWindow)
    }
}
