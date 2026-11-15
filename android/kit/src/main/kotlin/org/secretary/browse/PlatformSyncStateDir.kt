package org.secretary.browse

import uniffi.secretary.setPlatformStateDir as ffiSetPlatformStateDir
import java.io.File

/**
 * Makes [dir] the directory every vault open reads this device's sync baseline from, for the
 * open-time rollback check (§10, #746). Without it the bridge reads a desktop data dir Android
 * never writes, and the check is silently inactive. Call once per process, before the first open,
 * with the SAME dir the app's sync passes persist to. Repeating the same path is a no-op; a
 * different path throws [VaultBrowseError.Failed].
 */
fun setPlatformSyncStateDir(dir: File): Unit = mapErrors { ffiSetPlatformStateDir(dir.path) }
