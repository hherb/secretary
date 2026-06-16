package org.secretary.sync

import java.io.File
import kotlin.time.Duration

/**
 * Composes the real adapters with a fresh [FolderChangeDetector] into a ready-to-start
 * [ChangeDetectionMonitor] for [folder]. Mirror of the iOS makeChangeMonitor factory.
 * Must be called on the main thread (the returned monitor is main-thread-confined).
 */
fun makeChangeMonitor(
    folder: File,
    debounceWindow: Duration = ChangeDetectionTuning.defaultDebounceWindow,
    onChange: () -> Unit,
): ChangeDetectionMonitor = ChangeDetectionMonitor(
    detector = FolderChangeDetector(debounceWindow),
    watch = FileObserverFolderWatch(folder),
    scheduler = HandlerFlushScheduler(),
    onChange = onChange,
)
