package org.secretary.mirror

import android.content.Context
import android.content.Intent
import android.provider.DocumentsContract
import java.io.File

/**
 * Installs and points [TestCloudDocumentsProvider] at a fresh temp root, returning a [TreeHandle]
 * whose [TreeHandle.treeUri] is the `content://` string a real `safCloudFolderPort` (and the rest
 * of the SAF stack) can traverse — with no interactive system document picker.
 *
 * Fault injection: the three fault sets are static on the provider (so the in-process provider sees
 * them), but reachable through the returned [TreeHandle] (`handle.failWritePaths = ...`, etc.) so a
 * test never names the provider class directly.
 */
object TestCloudTree {

    /**
     * A handle to an installed test tree. [treeUri] feeds `safCloudFolderPort(context, treeUri)`;
     * [rootDir] is the backing temp directory for direct assertions. The fault-set properties
     * delegate to [TestCloudDocumentsProvider]'s static fields (the provider runs in-process).
     */
    class TreeHandle(val treeUri: String, val rootDir: File) {
        var failWritePaths: Set<String>
            get() = TestCloudDocumentsProvider.failWritePaths
            set(value) { TestCloudDocumentsProvider.failWritePaths = value }

        var failCreatePaths: Set<String>
            get() = TestCloudDocumentsProvider.failCreatePaths
            set(value) { TestCloudDocumentsProvider.failCreatePaths = value }

        var deleteReturnsFalsePaths: Set<String>
            get() = TestCloudDocumentsProvider.deleteReturnsFalsePaths
            set(value) { TestCloudDocumentsProvider.deleteReturnsFalsePaths = value }
    }

    /**
     * Point the provider at a brand-new temp root, reset all fault sets, build the tree URI and
     * grant this package read/write access to it (the provider runs in the instrumentation/app
     * process — same UID — so a self-grant is sufficient).
     */
    fun install(context: Context): TreeHandle {
        val root = File(context.cacheDir, "saftree-" + System.nanoTime())
        root.mkdirs()

        TestCloudDocumentsProvider.root = root
        TestCloudDocumentsProvider.failWritePaths = emptySet()
        TestCloudDocumentsProvider.failCreatePaths = emptySet()
        TestCloudDocumentsProvider.deleteReturnsFalsePaths = emptySet()

        val treeUri = DocumentsContract.buildTreeDocumentUri(
            TestCloudDocumentsProvider.AUTHORITY,
            TestCloudDocId.ROOT,
        )
        context.grantUriPermission(
            context.packageName,
            treeUri,
            Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
        )

        return TreeHandle(treeUri.toString(), root)
    }
}
