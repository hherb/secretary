package org.secretary.mirror

import android.database.Cursor
import android.database.MatrixCursor
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract.Document
import android.provider.DocumentsContract.Root
import android.provider.DocumentsProvider
import java.io.File
import java.io.FileNotFoundException

/**
 * A test-only [DocumentsProvider] (registered ONLY in the `:kit` androidTest APK) that backs a SAF
 * `content://` tree with a real temp directory. It lets instrumented tests drive the REAL SAF stack
 * (`DocumentFile.fromTreeUri`, `ContentResolver.openInputStream`/`openOutputStream`,
 * `DocumentsContract`) against a deterministic tree with no interactive system document picker.
 *
 * Authority: `org.secretary.kit.test.documents` (see androidTest `AndroidManifest.xml`).
 *
 * Document-id scheme: a file's path relative to the temp root (see [TestCloudDocId]); root id `""`.
 *
 * Configuration + fault injection are static [companion] fields, set by [TestCloudTree.install]
 * (which resets them on every install). Faults match a document id against a relative-path set;
 * a `"*"` entry faults all paths.
 */
class TestCloudDocumentsProvider : DocumentsProvider() {

    companion object {
        /** The current temp root the provider serves. Set by [TestCloudTree.install]. */
        @Volatile
        @JvmStatic
        var root: File? = null

        /** `openDocument` in a write mode throws [FileNotFoundException] for these relative paths. */
        @Volatile
        @JvmStatic
        var failWritePaths: Set<String> = emptySet()

        /** `createDocument` throws for these (parent-relative) target paths. */
        @Volatile
        @JvmStatic
        var failCreatePaths: Set<String> = emptySet()

        /** `deleteDocument` signals failure (→ `DocumentFile.delete()` == false) for these paths. */
        @Volatile
        @JvmStatic
        var deleteReturnsFalsePaths: Set<String> = emptySet()

        const val AUTHORITY: String = "org.secretary.kit.test.documents"
        const val ROOT_ID: String = "root"

        private val DEFAULT_ROOT_PROJECTION = arrayOf(
            Root.COLUMN_ROOT_ID,
            Root.COLUMN_DOCUMENT_ID,
            Root.COLUMN_TITLE,
            Root.COLUMN_FLAGS,
            Root.COLUMN_ICON,
        )

        private val DEFAULT_DOCUMENT_PROJECTION = arrayOf(
            Document.COLUMN_DOCUMENT_ID,
            Document.COLUMN_DISPLAY_NAME,
            Document.COLUMN_MIME_TYPE,
            Document.COLUMN_FLAGS,
            Document.COLUMN_SIZE,
            Document.COLUMN_LAST_MODIFIED,
        )

        /** True if [relPath] is faulted by [set] (membership or the `"*"` wildcard). */
        private fun faulted(set: Set<String>, relPath: String): Boolean =
            set.contains("*") || set.contains(relPath)
    }

    private fun requireRoot(): File =
        root ?: throw IllegalStateException("TestCloudDocumentsProvider.root not installed")

    override fun onCreate(): Boolean = true

    /**
     * REQUIRED for tree-URI access (API 26+): the framework's `enforceTree` rejects any document
     * reached through a `tree/<root>` URI unless this returns true for (rootDocId, docId). With our
     * relative-path doc-id scheme, [documentId] descends from [parentDocumentId] when the parent is
     * the [TestCloudDocId.ROOT] sentinel, or the child id is path-prefixed by the parent id. Without
     * this override every non-root query throws "… is not a descendant of root".
     */
    override fun isChildDocument(parentDocumentId: String, documentId: String): Boolean {
        if (parentDocumentId == TestCloudDocId.ROOT) return documentId != TestCloudDocId.ROOT
        return documentId.startsWith("$parentDocumentId/")
    }

    override fun queryRoots(projection: Array<out String>?): Cursor {
        val cursor = MatrixCursor(projection ?: DEFAULT_ROOT_PROJECTION)
        cursor.newRow().apply {
            add(Root.COLUMN_ROOT_ID, ROOT_ID)
            add(Root.COLUMN_DOCUMENT_ID, TestCloudDocId.ROOT)
            add(Root.COLUMN_TITLE, "Test Cloud Tree")
            add(Root.COLUMN_FLAGS, Root.FLAG_SUPPORTS_CREATE)
            add(Root.COLUMN_ICON, android.R.drawable.ic_menu_save)
        }
        return cursor
    }

    override fun queryDocument(documentId: String, projection: Array<out String>?): Cursor {
        val cursor = MatrixCursor(projection ?: DEFAULT_DOCUMENT_PROJECTION)
        val file = TestCloudDocId.fileFor(requireRoot(), documentId)
        if (!file.exists()) throw FileNotFoundException("no such document: $documentId")
        includeFile(cursor, documentId, file)
        return cursor
    }

    override fun queryChildDocuments(
        parentDocumentId: String,
        projection: Array<out String>?,
        sortOrder: String?,
    ): Cursor {
        val cursor = MatrixCursor(projection ?: DEFAULT_DOCUMENT_PROJECTION)
        val parent = TestCloudDocId.fileFor(requireRoot(), parentDocumentId)
        val children = parent.listFiles() ?: emptyArray()
        for (child in children) {
            includeFile(cursor, TestCloudDocId.childId(parentDocumentId, child.name), child)
        }
        return cursor
    }

    override fun openDocument(
        documentId: String,
        mode: String,
        signal: CancellationSignal?,
    ): ParcelFileDescriptor {
        val file = TestCloudDocId.fileFor(requireRoot(), documentId)
        val isWrite = mode.contains('w')
        if (isWrite && faulted(failWritePaths, documentId)) {
            throw FileNotFoundException("injected write fault for $documentId")
        }
        // "wt" = write + truncate; ParcelFileDescriptor maps SAF modes to POSIX open flags.
        val pfdMode = ParcelFileDescriptor.parseMode(mode)
        if (isWrite && mode.contains('t')) {
            // Truncate: ensure a clean overwrite even if the backing file already exists.
            if (file.exists()) file.delete()
        }
        return ParcelFileDescriptor.open(file, pfdMode)
    }

    override fun createDocument(
        parentDocumentId: String,
        mimeType: String,
        displayName: String,
    ): String {
        val parent = TestCloudDocId.fileFor(requireRoot(), parentDocumentId)
        val childId = TestCloudDocId.childId(parentDocumentId, displayName)
        if (faulted(failCreatePaths, childId)) {
            throw FileNotFoundException("injected create fault for $childId")
        }
        val target = File(parent, displayName)
        if (mimeType == Document.MIME_TYPE_DIR) {
            if (!target.mkdirs() && !target.isDirectory) {
                throw FileNotFoundException("cannot create directory $childId")
            }
        } else {
            parent.mkdirs()
            if (!target.createNewFile() && !target.isFile) {
                throw FileNotFoundException("cannot create file $childId")
            }
        }
        return childId
    }

    override fun deleteDocument(documentId: String) {
        val file = TestCloudDocId.fileFor(requireRoot(), documentId)
        if (faulted(deleteReturnsFalsePaths, documentId)) {
            // Model a failed SAF delete: do NOT remove the backing file and signal failure.
            // DocumentsContract surfaces a thrown exception here as DocumentFile.delete() == false.
            throw FileNotFoundException("injected delete-returns-false fault for $documentId")
        }
        if (!file.deleteRecursively()) {
            throw FileNotFoundException("cannot delete $documentId")
        }
    }

    override fun getDocumentType(documentId: String): String {
        val file = TestCloudDocId.fileFor(requireRoot(), documentId)
        return if (file.isDirectory) Document.MIME_TYPE_DIR else "application/octet-stream"
    }

    private fun includeFile(cursor: MatrixCursor, documentId: String, file: File) {
        var flags = Document.FLAG_SUPPORTS_DELETE
        val mime = if (file.isDirectory) {
            flags = flags or Document.FLAG_DIR_SUPPORTS_CREATE
            Document.MIME_TYPE_DIR
        } else {
            flags = flags or Document.FLAG_SUPPORTS_WRITE
            "application/octet-stream"
        }
        // Only emit columns the cursor was built with: MatrixCursor.RowBuilder.add(name, value)
        // throws if the column is not in the projection, and DocumentFile queries narrow
        // projections (often just COLUMN_DOCUMENT_ID), so a fixed 6-column add would throw and
        // surface as a null/empty child to the SAF stack.
        val values: Map<String, Any?> = mapOf(
            Document.COLUMN_DOCUMENT_ID to documentId,
            Document.COLUMN_DISPLAY_NAME to if (documentId == TestCloudDocId.ROOT) "root" else file.name,
            Document.COLUMN_MIME_TYPE to mime,
            Document.COLUMN_FLAGS to flags,
            Document.COLUMN_SIZE to file.length(),
            Document.COLUMN_LAST_MODIFIED to file.lastModified(),
        )
        val row = cursor.newRow()
        for (column in cursor.columnNames) {
            row.add(column, values[column])
        }
    }
}
