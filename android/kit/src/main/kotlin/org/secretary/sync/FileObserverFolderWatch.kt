package org.secretary.sync

import android.os.Build
import android.os.FileObserver
import android.os.Handler
import android.os.Looper
import java.io.File

/**
 * [FolderWatchPort] over a single non-recursive [android.os.FileObserver] on the vault
 * ROOT. FileObserver is non-recursive on all API levels, so this watches only the root's
 * immediate contents — which is sufficient: the top-level manifest.cbor.enc is re-signed
 * and rewritten (atomic rename) on every committed state advance (vault-format §4.4), so a
 * remote change always surfaces as a root-level event. A deep-only change with no manifest
 * rewrite is not a committed (sync-relevant) state.
 *
 * FileObserver delivers events on its own thread; each pulse is stamped with [now] and
 * marshalled onto [mainHandler] before [onPulse], so the monitor is only ever touched on
 * the main thread (mirror of iOS delivering on @MainActor).
 *
 * [mainHandler] and [now] are injectable for instrumented testing.
 */
class FileObserverFolderWatch(
    private val folder: File,
    private val mainHandler: Handler = Handler(Looper.getMainLooper()),
    private val now: () -> MonotonicInstant = ::monotonicNow,
) : FolderWatchPort {
    private companion object {
        // Create / write / move-in / move-out / delete events on the root's children.
        const val MASK = FileObserver.CREATE or FileObserver.MODIFY or
            FileObserver.MOVED_TO or FileObserver.MOVED_FROM or
            FileObserver.DELETE or FileObserver.CLOSE_WRITE
    }

    private var observer: FileObserver? = null

    override fun start(onPulse: (MonotonicInstant) -> Unit) {
        val obs = newObserver {
            val instant = now()
            mainHandler.post { onPulse(instant) }
        }
        observer = obs
        obs.startWatching()
    }

    override fun stop() {
        observer?.stopWatching()
        observer = null
    }

    private fun newObserver(onPulse: () -> Unit): FileObserver =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            object : FileObserver(folder, MASK) { // non-deprecated File ctor (API 29+), still non-recursive
                override fun onEvent(event: Int, path: String?) = onPulse()
            }
        } else {
            @Suppress("DEPRECATION") // String ctor: deprecated on 29+, identical non-recursive behavior
            object : FileObserver(folder.path, MASK) {
                override fun onEvent(event: Int, path: String?) = onPulse()
            }
        }
}
