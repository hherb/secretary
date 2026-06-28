package org.secretary.mirror

import java.io.File

/**
 * A [PendingFlushMarker] backed by a sentinel file. The file MUST live outside the vault working
 * copy (e.g. the app-private sync-state dir) — [VaultMirror] mirrors every file under the working
 * dir, so a marker placed there would be pushed to the cloud and then deleted on materialize.
 *
 * Best-effort and idempotent: [set] creates the file if absent; [clear] deletes it tolerating
 * already-absent; I/O failures are swallowed (a marker we failed to write degrades to "no pending
 * flush", which a later successful flush makes moot — crashing the background flush would be worse).
 */
class FilePendingFlushMarker(private val markerFile: File) : PendingFlushMarker {
    override fun isSet(): Boolean = markerFile.exists()

    override fun set() {
        try {
            if (!markerFile.exists()) {
                markerFile.parentFile?.mkdirs()
                markerFile.createNewFile()
            }
        } catch (_: Exception) { /* see kdoc: best-effort */ }
    }

    override fun clear() {
        try { markerFile.delete() } catch (_: Exception) { /* idempotent best-effort */ }
    }
}
