package org.secretary.sync

import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * Named timing constants for folder-change detection (no magic numbers). Trailing
 * debounce raises the signal once the folder has been quiet for [defaultDebounceWindow]
 * after the last pulse; [defaultSelfWriteMuteWindow] sizes the self-write suppression
 * window a future writer (slice 4) can apply around its own record writes.
 */
object ChangeDetectionTuning {
    val defaultDebounceWindow: Duration = 2.seconds
    val defaultSelfWriteMuteWindow: Duration = 10.seconds
}
