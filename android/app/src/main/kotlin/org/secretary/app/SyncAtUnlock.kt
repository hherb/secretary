package org.secretary.app

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

/**
 * Launches [syncAtUnlock] on [scope] with a PRIVATE COPY of [password], zeroizing the copy when
 * the pass settles (success or throw).
 *
 * The copy is taken synchronously — before this function returns — so the caller may zeroize its
 * own [password] buffer immediately after this call without racing the background read. The copy
 * never outlives the launched pass.
 *
 * Secret hygiene: this is the sole owner of the COPY's lifetime; the caller remains the owner of
 * [password] and is responsible for zeroizing it. Mirrors the iOS `Task { await syncAtUnlock() }`
 * fire-and-forget at unlock, with the copy/zeroize made explicit because Android's caller zeroizes
 * the original in its own `finally`.
 *
 * @return the [Job] running the pass (await it in tests; production fires and forgets).
 */
fun launchSyncAtUnlock(
    scope: CoroutineScope,
    password: ByteArray,
    syncAtUnlock: suspend (ByteArray) -> Unit,
): Job {
    val copy = password.copyOf() // synchronous: safe against the caller zeroizing `password`
    return scope.launch {
        try {
            syncAtUnlock(copy)
        } finally {
            copy.fill(0)
        }
    }
}
