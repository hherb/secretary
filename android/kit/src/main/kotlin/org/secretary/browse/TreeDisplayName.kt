package org.secretary.browse

import android.content.Context
import android.net.Uri
import androidx.documentfile.provider.DocumentFile

/** User-safe label when a SAF provider exposes no display name for a picked tree. */
internal const val TREE_DISPLAY_NAME_FALLBACK = "Cloud folder"

/** Pure: pick the provider's [name] if it is present and non-blank, else a safe fallback. Host-tested. */
internal fun treeDisplayNameOrFallback(name: String?): String =
    name?.takeIf { it.isNotBlank() } ?: TREE_DISPLAY_NAME_FALLBACK

/**
 * Resolve a human-readable label for a picked SAF tree [treeUri]. Android-bound (DocumentFile);
 * verified on-device, not host-tested (the pure fallback in [treeDisplayNameOrFallback] is). Used by
 * `AppRoot` to label a freshly picked folder. Mirrors the `SafCloudFolderPort` factory split (the
 * Android-bound piece lives behind a thin function; the decision logic is the host-tested pure part).
 */
fun displayNameForTree(context: Context, treeUri: Uri): String =
    treeDisplayNameOrFallback(DocumentFile.fromTreeUri(context, treeUri)?.name)
