package org.secretary.browse

import android.content.Context
import android.content.Intent
import android.net.Uri

/**
 * The real [VaultLocationStore] over SharedPreferences + the SAF persistable-URI
 * permission grant. Kotlin mirror of iOS `BookmarkVaultLocationStore`.
 *
 * The class body holds NO Android types: it is constructed from five String-based
 * function seams so the persist/load/clear/availability logic (encode/decode, the
 * take-permission-before-write ordering, and the release-superseded-grant cleanup) is
 * host-testable with fakes, exactly like Slice 1's `createFn` seam. The live SAF +
 * SharedPreferences wiring lives only in the [safVaultLocationStore] factory, exercised
 * on-device.
 *
 * Persistable-URI grants count against an Android per-package cap, and clearing the pref
 * alone does NOT relinquish the SAF grant, so this store releases a grant the moment it
 * is superseded ([persist] with a different tree URI) or forgotten ([clear]) — otherwise
 * the design's "stale permission → re-pick" loop would leak a grant on every re-pick.
 * (iOS needs no analogue: a `UserDefaults` bookmark consumes no system-wide slot.)
 *
 * @param readPref returns the persisted blob, or null if none.
 * @param writePref persists the blob, or clears it when given null.
 * @param takePermission acquires a durable (persistable) read+write grant for the tree URI string.
 * @param releasePermission relinquishes a previously-taken durable grant for the tree URI string.
 * @param hasPermission reports whether a durable grant for the tree URI string is still held.
 */
class SafVaultLocationStore(
    private val readPref: () -> String?,
    private val writePref: (String?) -> Unit,
    private val takePermission: (String) -> Unit,
    private val releasePermission: (String) -> Unit,
    private val hasPermission: (String) -> Boolean,
) : VaultLocationStore {
    override fun load(): VaultLocation? = readPref()?.let { decodeVaultLocation(it) }

    override fun persist(location: VaultLocation) {
        val prior = load()
        // Acquire the durable grant BEFORE recording the location: never persist a tree
        // URI we have not secured persistable access to.
        takePermission(location.treeUri)
        writePref(encodeVaultLocation(location))
        // Release the superseded grant AFTER the new one is secured + recorded, so a
        // mid-persist failure can never leave us holding neither. Skip when the URI is
        // unchanged — we just re-took it, and releasing would drop the grant we depend on.
        if (prior != null && prior.treeUri != location.treeUri) {
            releasePermission(prior.treeUri)
        }
    }

    override fun clear() {
        // Release the grant before forgetting the location: clearing the pref alone does
        // not relinquish the SAF grant, so the persisted-URI permission would leak.
        load()?.let { releasePermission(it.treeUri) }
        writePref(null)
    }

    override fun isAvailable(location: VaultLocation): Boolean = hasPermission(location.treeUri)
}

/**
 * Production factory wiring the real SAF + SharedPreferences seams from [context]. The
 * only Android-bound code in this file; not host-tested (covered on-device / by Slice
 * 6's instrumented E2E).
 */
fun safVaultLocationStore(context: Context): VaultLocationStore {
    val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    val resolver = context.contentResolver
    val grantFlags = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
    return SafVaultLocationStore(
        readPref = { prefs.getString(KEY_LOCATION, null) },
        writePref = { blob ->
            val editor = prefs.edit()
            if (blob == null) editor.remove(KEY_LOCATION) else editor.putString(KEY_LOCATION, blob)
            editor.apply()
        },
        takePermission = { uri -> resolver.takePersistableUriPermission(Uri.parse(uri), grantFlags) },
        releasePermission = { uri -> resolver.releasePersistableUriPermission(Uri.parse(uri), grantFlags) },
        hasPermission = { uri ->
            val target = Uri.parse(uri)
            resolver.persistedUriPermissions.any {
                it.uri == target && it.isReadPermission && it.isWritePermission
            }
        },
    )
}

private const val PREFS_NAME = "secretary.vault.location"
private const val KEY_LOCATION = "location"
