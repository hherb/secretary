package org.secretary.app

import java.io.File

/** User-safe copy for the not-yet-wired cloud-open path (Slice 5 replaces the seam with materialize). */
const val CLOUD_OPEN_DEFERRED_REASON = "Syncing from your cloud folder arrives in the next update."

/**
 * Why the shared SAF folder picker was launched — a single [pickFolderLauncher] serves both the
 * Selection screen (pick an existing vault folder) and the create wizard (pick the parent folder),
 * so the result callback branches on this to route the picked tree URI to the right consumer.
 */
enum class FolderPickTarget { None, SelectExisting, WizardParent }

/**
 * The empty working directory the core creates a new vault into (`createInFolder`'s contract is an
 * existing empty dir). A fresh child of `filesDir/working/` keyed by the validated [vaultName]
 * (no path separators — validated upstream). Any stale directory from a prior interrupted create is
 * reset so the create never sees a non-empty target. The cloud flush of this dir is Slice 5.
 */
internal fun workingVaultDir(filesDir: File, vaultName: String): File {
    val dir = File(filesDir, "working/$vaultName")
    dir.deleteRecursively()
    dir.mkdirs()
    check(dir.isDirectory) { "failed to create working vault dir: ${dir.path}" }
    return dir
}
