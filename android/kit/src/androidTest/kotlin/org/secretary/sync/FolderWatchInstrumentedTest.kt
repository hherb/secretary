package org.secretary.sync

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.time.Duration.Companion.milliseconds

/**
 * Proves the real folder-watch wiring on a device: a real android.os.FileObserver on a
 * temp dir + a real main-Looper HandlerFlushScheduler, composed through a
 * ChangeDetectionMonitor. An external file write must pulse → debounce → raise onChange.
 * Host tests (with fakes) cannot touch FileObserver / Looper at all, so this is net-new
 * coverage. No golden vault / FFI / native .so needed — pure filesystem.
 *
 * The monitor is main-thread-confined, so start/stop run via runOnMainSync; the file
 * write happens on the test thread (simulating an external/remote writer). A short
 * debounce window keeps the test fast; a CountDownLatch + generous timeout absorbs
 * scheduler latency without flaking.
 */
@RunWith(AndroidJUnit4::class)
class FolderWatchInstrumentedTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private lateinit var dir: File
    private var monitor: ChangeDetectionMonitor? = null

    @After
    fun tearDown() {
        monitor?.let { m -> instrumentation.runOnMainSync { m.stop() } }
        if (::dir.isInitialized) dir.deleteRecursively()
    }

    @Test
    fun externalWriteRaisesDebouncedPendingChanges() {
        dir = File(
            instrumentation.targetContext.cacheDir,
            "folderwatch-${System.nanoTime()}",
        ).apply { mkdirs() }

        val changed = CountDownLatch(1)
        // Build + start the monitor on the main thread (its confinement contract).
        instrumentation.runOnMainSync {
            val m = makeChangeMonitor(
                folder = dir,
                debounceWindow = 150.milliseconds,
                onChange = { changed.countDown() },
            )
            m.start()
            monitor = m
        }

        // External write on the test thread → FileObserver fires → posts to main → pulse.
        File(dir, "manifest.cbor.enc").writeBytes(byteArrayOf(1, 2, 3))

        assertTrue(
            "onChange should fire within timeout after an external write",
            changed.await(10, TimeUnit.SECONDS),
        )
        instrumentation.runOnMainSync { assertTrue(monitor!!.pendingChanges) }
    }
}
