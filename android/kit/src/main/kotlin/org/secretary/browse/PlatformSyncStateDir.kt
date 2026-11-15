package org.secretary.browse

import uniffi.secretary.setPlatformStateDir as ffiSetPlatformStateDir
import java.io.File

/**
 * Makes [dir] the directory every vault open, repair and repair preview reads this device's sync
 * baseline from, for the §10 rollback checks (#746). Without it the bridge reads a desktop data dir
 * Android never writes, and those checks are silently inactive. Call once per process, before the
 * first open, with the SAME dir the app's sync passes persist to. Repeating the same path is a
 * no-op; a different path, a relative one, or any set after the bridge has already read its
 * default throws [VaultBrowseError.Failed].
 */
fun setPlatformSyncStateDir(dir: File): Unit = mapErrors { ffiSetPlatformStateDir(dir.path) }
