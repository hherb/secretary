package org.secretary.app

import java.io.File
import java.security.MessageDigest

/**
 * Why the shared SAF folder picker was launched — a single [pickFolderLauncher] serves both the
 * Selection screen (pick an existing vault folder) and the create wizard (pick the parent folder),
 * so the result callback branches on this to route the picked tree URI to the right consumer.
 */
enum class FolderPickTarget { None, SelectExisting, WizardParent }

/**
 * A STABLE, filesystem-safe key for one cloud vault, derived from its SAF [treeUri] — the lowercase
 * hex SHA-256 of the tree URI string. Pure: same URI → same key; different URIs → (overwhelmingly)
 * different keys; never empty; safe as a directory / file name (only `[0-9a-f]`).
 *
 * The tree URI uniquely identifies the cloud folder and is ALWAYS available (even before the vault's
 * UUID is learned on first open), so keying the working copy + the pending-flush marker by it — NOT
 * by the vault UUID — guarantees the same imported/created vault always maps to the same working dir
 * and marker across opens. A UUID-derived key would change from "unknown" to the real UUID after the
 * first open, orphaning any un-pushed edits left in the "unknown" dir (silent data loss); two distinct
 * not-yet-known vaults would also collide on a shared "unknown" dir. The treeUri key has neither flaw.
 *
 * NOTE: this is ONLY the LOCAL working-dir / marker key. The Rust sync layer's per-device SyncState
 * stays keyed by the real vault UUID (via `syncStateDir` + the manifest's `vault_uuid` passed to
 * `makeVaultSync`) — that keying is unchanged.
 */
internal fun cloudVaultKey(treeUri: String): String {
    val digest = MessageDigest.getInstance("SHA-256").digest(treeUri.toByteArray(Charsets.UTF_8))
    val sb = StringBuilder(digest.size * 2)
    for (b in digest) {
        val v = b.toInt() and 0xff
        sb.append("0123456789abcdef"[v ushr 4]).append("0123456789abcdef"[v and 0x0f])
    }
    return sb.toString()
}

/**
 * The working directory for a cloud vault identified by its [treeUri], under `filesDir/working/`
 * keyed by [cloudVaultKey]. Stable across opens REGARDLESS of whether the vault UUID is known yet, so
 * un-pushed edits in this dir survive a reopen (the coordinator's materialize reconciles them with
 * the cloud).
 *
 * [reset] true ONLY for vault CREATION: `createInFolder`'s contract is an existing EMPTY dir, so any
 * stale dir from a prior interrupted create is wiped first. For open / create-then-open it is false —
 * an existing working dir may hold un-pushed local edits that must NOT be wiped.
 */
internal fun cloudWorkingVaultDir(filesDir: File, treeUri: String, reset: Boolean): File {
    val dir = File(filesDir, "working/${cloudVaultKey(treeUri)}")
    if (reset) dir.deleteRecursively()
    dir.mkdirs()
    check(dir.isDirectory) { "failed to resolve cloud working vault dir: ${dir.path}" }
    return dir
}
