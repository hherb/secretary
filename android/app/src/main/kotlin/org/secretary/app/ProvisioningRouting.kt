package org.secretary.app

import java.io.File

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

/**
 * The EXISTING working dir a just-created vault was written into, keyed by [vaultName] — the SAME
 * path [workingVaultDir] used at create time, but WITHOUT the `deleteRecursively()` reset (that would
 * wipe the freshly-created vault). Used by the create-then-open flow to flush working→cloud then open.
 */
internal fun createdWorkingVaultDir(filesDir: File, vaultName: String): File {
    val dir = File(filesDir, "working/$vaultName")
    dir.mkdirs()
    check(dir.isDirectory) { "missing created working vault dir: ${dir.path}" }
    return dir
}

/**
 * The working copy for a remembered cloud vault, keyed by its [vaultUuidHex] (stable across opens,
 * unlike the create-time name). Materialize populates it; it is NOT reset on open (it carries
 * un-pushed edits across an offline session). Falls back to a name-safe slug if uuid is empty.
 *
 * Unlike [workingVaultDir] this does NOT `deleteRecursively()` — an existing working dir may hold
 * un-pushed local edits; the coordinator's materialize reconciles it with the cloud.
 */
internal fun workingVaultDirForUuid(filesDir: File, vaultUuidHex: String): File {
    val key = vaultUuidHex.ifEmpty { "unknown" }
    val dir = File(filesDir, "working/$key")
    dir.mkdirs()
    check(dir.isDirectory) { "failed to create working vault dir: ${dir.path}" }
    return dir
}
