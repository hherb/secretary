package org.secretary.app

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test

@OptIn(ExperimentalCoroutinesApi::class)
class SyncAtUnlockTest {

    @Test
    fun passesADistinctCopy_carriesOriginalContents_originalUntouchedByHelper() = runTest {
        val original = byteArrayOf(1, 2, 3, 4)
        val seen = CompletableDeferred<ByteArray>()
        val contentsDuringPass = CompletableDeferred<ByteArray>()
        val job = launchSyncAtUnlock(this, original) { copy ->
            contentsDuringPass.complete(copy.copyOf()) // snapshot before finally zeroizes the copy
            seen.complete(copy)
        }
        job.join()
        // A DISTINCT array (so the caller may zeroize `original` independently)...
        assertFalse(seen.await() === original, "must be a distinct array")
        // ...that carried the ORIGINAL contents during the pass (guards against a zero-filled copy).
        assertArrayEquals(byteArrayOf(1, 2, 3, 4), contentsDuringPass.await())
        // The helper itself never mutates the original.
        assertArrayEquals(byteArrayOf(1, 2, 3, 4), original)
    }

    @Test
    fun copySurvivesCallerZeroizingOriginal_thenCopyZeroizedAfterPass() = runTest {
        val original = byteArrayOf(5, 6, 7, 8)
        val gate = CompletableDeferred<Unit>()
        val contentsDuringPass = CompletableDeferred<ByteArray>()
        lateinit var copyRef: ByteArray
        val job = launchSyncAtUnlock(this, original) { copy ->
            copyRef = copy
            gate.await()                       // hold the pass open
            contentsDuringPass.complete(copy.copyOf())
        }
        original.fill(0)                       // caller zeroizes its buffer while the pass is parked
        gate.complete(Unit)
        job.join()
        // The copy still held the ORIGINAL contents during the pass, despite the caller zeroizing.
        assertArrayEquals(byteArrayOf(5, 6, 7, 8), contentsDuringPass.await())
        // After the pass settles, the copy is zeroized.
        assertArrayEquals(byteArrayOf(0, 0, 0, 0), copyRef, "copy zeroized after the pass")
    }

    @Test
    fun copyZeroizedEvenWhenPassThrows() = runTest {
        val original = byteArrayOf(9, 9)
        lateinit var copyRef: ByteArray
        // Isolate the throwing fire-and-forget child from the TestScope: a SupervisorJob plus a
        // CoroutineExceptionHandler absorbs the uncaught exception so it does not fail the test.
        // (Production syncAtUnlock routes errors to lastError and does not throw; this is the
        // defensive zeroize-on-throw guarantee.) The scope shares runTest's scheduler so join()
        // advances it. UnconfinedTestDispatcher runs the child eagerly through to its finally.
        val handler = CoroutineExceptionHandler { _, _ -> /* expected: pass threw */ }
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler) + SupervisorJob() + handler)
        val job = launchSyncAtUnlock(scope, original) { copy ->
            copyRef = copy
            throw RuntimeException("pass failed")
        }
        job.join()
        assertArrayEquals(byteArrayOf(0, 0), copyRef, "copy zeroized on the throwing path too")
        scope.cancel()
    }
}
