package org.secretary.mirror

import java.io.File

/**
 * Document-ID ↔ relative-path mapping for [TestCloudDocumentsProvider].
 *
 * The root document id is the sentinel [ROOT] (`"root"`), NOT the empty string: a tree URI is
 * `content://<authority>/tree/<root-doc-id>`, and an empty root id yields the invalid URI
 * `content://.../tree/` that `DocumentFile.fromTreeUri` rejects. Every other document id is the
 * file's path RELATIVE to the temp root, using `/` separators (e.g. `"blocks/a.cbor.enc"`) — so
 * non-root ids match exactly the vault-relative POSIX paths `CloudFolderPort` callers use (and the
 * fault-injection path sets).
 *
 * Kept in its own file so [TestCloudDocumentsProvider] stays focused on the provider contract.
 */
internal object TestCloudDocId {
    const val ROOT: String = "root"

    /** Backing [File] for [docId] under [root]. The [ROOT] sentinel maps to [root] itself. */
    fun fileFor(root: File, docId: String): File =
        if (docId == ROOT) root else File(root, docId)

    /** Document id for a child named [name] under the directory at [parentId]. */
    fun childId(parentId: String, name: String): String =
        if (parentId == ROOT) name else "$parentId/$name"
}
