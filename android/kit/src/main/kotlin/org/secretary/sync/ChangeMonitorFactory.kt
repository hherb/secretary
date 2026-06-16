package org.secretary.sync

import android.os.Looper
import java.io.File
import kotlin.time.Duration

/**
 * Composes the real adapters with a fresh [FolderChangeDetector] into a ready-to-start
 * [ChangeDetectionMonitor] for [folder]. Mirror of the iOS makeChangeMonitor factory.
 * Must be called on the main thread (the returned monitor is main-thread-confined); this
 * is enforced with a fast-fail check so a background-thread misuse crashes in development
 * rather than producing a silently misconfigured monitor.
 */
fun makeChangeMonitor(
    folder: File,
    debounceWindow: Duration = ChangeDetectionTuning.defaultDebounceWindow,
    onChange: () -> Unit,
): ChangeDetectionMonitor {
    check(Looper.myLooper() == Looper.getMainLooper()) {
        "makeChangeMonitor must be called on the main thread"
    }
    return ChangeDetectionMonitor(
        detector = FolderChangeDetector(debounceWindow),
        watch = FileObserverFolderWatch(folder),
        scheduler = HandlerFlushScheduler(),
        onChange = onChange,
    )
}
