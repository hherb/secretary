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

/**
 * A [CloudFolderPort] decorator that absorbs eventually-consistent SAF providers (e.g. Google Drive,
 * #330) with bounded retry-with-backoff on [CloudFolderException] and, for [write], a post-write
 * read-back byte-equality verify. Host-testable: the class body holds no Android types; [sleep] and
 * [onRetry] are seams (default `Thread::sleep` / no-op, so there is no `android.util.Log` dependency).
 *
 * Only [CloudFolderException] is retried — the typed boundary the inner SAF port folds every provider
 * error into. A permanent failure (revoked permission) also folds to it; retrying simply burns the
 * bounded budget and rethrows, which is acceptable given the provider is eventually-consistent.
 */
class RetryingCloudFolderPort(
    private val inner: CloudFolderPort,
    private val policy: RetryPolicy = RetryPolicy.CLOUD_DEFAULT,
    private val sleep: (Long) -> Unit = Thread::sleep,
    private val onRetry: (String) -> Unit = {},
) : CloudFolderPort {

    override fun list(): List<String> = retrying("list") { inner.list() }

    override fun read(relativePath: String): ByteArray =
        retrying("read $relativePath") { inner.read(relativePath) }

    // No read-back verify: delete is idempotent, and a stale-still-present file is re-deleted on the
    // next flush pass — it never corrupts the vault — whereas a lost write loses data. Verifying
    // absence would mean treating a "no such file" read as the success signal, uglier than the
    // negligible risk it removes.
    override fun delete(relativePath: String) =
        retrying("delete $relativePath") { inner.delete(relativePath) }

    /**
     * Write then read-back-verify. One attempt = `inner.write` + `inner.read` + byte-equality. A
     * throw, an invisible read-back, or a mismatch retries the whole attempt (re-write is an
     * idempotent overwrite). Plain `contentEquals` — these are ciphertext blocks, not secrets that
     * need a constant-time compare.
     */
    override fun write(relativePath: String, bytes: ByteArray) {
        retrying("write $relativePath") {
            inner.write(relativePath, bytes)
            val readBack = inner.read(relativePath)
            if (!readBack.contentEquals(bytes)) {
                throw CloudFolderException("read-back mismatch: $relativePath")
            }
        }
    }

    private inline fun <T> retrying(op: String, block: () -> T): T {
        var attempt = 1
        while (true) {
            try {
                return block()
            } catch (e: CloudFolderException) {
                if (attempt >= policy.maxAttempts) {
                    throw CloudFolderException("$op failed after ${policy.maxAttempts} attempts: ${e.message}")
                }
                onRetry("$op attempt $attempt/${policy.maxAttempts} failed: ${e.message}")
                sleep(backoffDelayMs(attempt, policy))
                attempt++
            }
        }
    }
}
