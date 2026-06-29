package org.secretary.mirror

/**
 * Backoff schedule + attempt budget for [RetryingCloudFolderPort]. No magic numbers: every value
 * is a named field; [CLOUD_DEFAULT] is the production policy tuned for Google Drive's
 * eventually-consistent SAF DocumentsProvider (#330).
 */
data class RetryPolicy(val maxAttempts: Int, val baseDelayMs: Long, val maxDelayMs: Long) {
    init {
        require(maxAttempts >= 1) { "maxAttempts must be >= 1" }
        require(baseDelayMs >= 0) { "baseDelayMs must be >= 0" }
        require(maxDelayMs >= baseDelayMs) { "maxDelayMs must be >= baseDelayMs" }
    }

    companion object {
        /** 250 / 500 / 1000 / 2000 / (2000) ms across 5 attempts — worst case ~5.75 s of waiting. */
        val CLOUD_DEFAULT = RetryPolicy(maxAttempts = 5, baseDelayMs = 250, maxDelayMs = 2000)
    }
}

/** Cap the left-shift exponent so a large [attempt] cannot overflow the Long shift; any value at or
 *  past this point already exceeds [RetryPolicy.maxDelayMs] and is clamped to it. */
private const val MAX_BACKOFF_SHIFT = 32

/**
 * Pure: the delay in ms to wait AFTER a 1-based [attempt] fails, before the next attempt. Exponential
 * `baseDelayMs * 2^(attempt-1)`, clamped to [RetryPolicy.maxDelayMs].
 */
fun backoffDelayMs(attempt: Int, policy: RetryPolicy): Long {
    require(attempt >= 1) { "attempt is 1-based, got $attempt" }
    val shift = (attempt - 1).coerceAtMost(MAX_BACKOFF_SHIFT)
    val raw = policy.baseDelayMs shl shift
    return raw.coerceAtMost(policy.maxDelayMs)
}
