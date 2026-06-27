package org.secretary.browse

import android.content.Context
import android.content.Intent
import android.net.Uri

/**
 * The real [VaultLocationStore] over SharedPreferences + the SAF persistable-URI
 * permission grant. Kotlin mirror of iOS `BookmarkVaultLocationStore`.
 *
 * The class body holds NO Android types: it is constructed from four String-based
 * function seams so the persist/load/clear/availability logic (encode/decode plus the
 * take-permission-before-write ordering) is host-testable with fakes, exactly like
 * Slice 1's `createFn` seam. The live SAF + SharedPreferences wiring lives only in the
 * [safVaultLocationStore] factory, exercised on-device.
 *
 * @param readPref returns the persisted blob, or null if none.
 * @param writePref persists the blob, or clears it when given null.
 * @param takePermission acquires a durable (persistable) read+write grant for the tree URI string.
 * @param hasPermission reports whether a durable grant for the tree URI string is still held.
 */
class SafVaultLocationStore(
    private val readPref: () -> String?,
    private val writePref: (String?) -> Unit,
    private val takePermission: (String) -> Unit,
    private val hasPermission: (String) -> Boolean,
) : VaultLocationStore {
    override fun load(): VaultLocation? = readPref()?.let { decodeVaultLocation(it) }

    override fun persist(location: VaultLocation) {
        // Acquire the durable grant BEFORE recording the location: never persist a tree
        // URI we have not secured persistable access to.
        takePermission(location.treeUri)
        writePref(encodeVaultLocation(location))
    }

    override fun clear() = writePref(null)

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
