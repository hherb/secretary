package org.secretary.mirror

import android.content.Context
import android.net.Uri
import androidx.documentfile.provider.DocumentFile

/**
 * The real [CloudFolderPort] over a SAF `content://` tree (a cloud-drive folder). Kotlin sibling
 * of `org.secretary.browse.SafVaultLocationStore`: the class body holds NO Android types — it is
 * constructed from four function seams, so the delegation + error-folding to [CloudFolderException]
 * is host-tested with fakes. All DocumentFile / ContentResolver traversal lives only in the
 * [safCloudFolderPort] factory (exercised on-device / by Slice 6's instrumented E2E).
 *
 * Any seam exception that is not already a [CloudFolderException] is folded into one, so a caller
 * (`VaultMirror`) sees a single typed boundary regardless of which provider error occurred.
 */
class SafCloudFolderPort(
    private val listFiles: () -> List<String>,
    private val readFile: (String) -> ByteArray,
    private val writeFile: (String, ByteArray) -> Unit,
    private val deleteFile: (String) -> Unit,
) : CloudFolderPort {
    override fun list(): List<String> = fold("list") { listFiles() }
    override fun read(relativePath: String): ByteArray = fold("read $relativePath") { readFile(relativePath) }
    override fun write(relativePath: String, bytes: ByteArray) = fold("write $relativePath") { writeFile(relativePath, bytes) }
    override fun delete(relativePath: String) = fold("delete $relativePath") { deleteFile(relativePath) }

    private inline fun <T> fold(op: String, block: () -> T): T = try {
        block()
    } catch (e: CloudFolderException) {
        throw e
    } catch (e: Exception) {
        throw CloudFolderException("SAF $op failed: ${e.message}")
    }
}

/**
 * Production factory wiring the real SAF DocumentFile traversal from [context] + [treeUri]. The
 * only Android-bound code in this file; not host-tested (covered on-device / by Slice 6). Paths
 * are vault-relative POSIX (`"blocks/<uuid>.cbor.enc"`); the factory splits on `/` to resolve or
 * create each path segment under the picked tree.
 */
fun safCloudFolderPort(context: Context, treeUri: String): CloudFolderPort {
    val resolver = context.contentResolver

    fun root(): DocumentFile =
        DocumentFile.fromTreeUri(context, Uri.parse(treeUri))
            ?: throw CloudFolderException("cannot resolve SAF tree: $treeUri")

    fun resolve(relativePath: String): DocumentFile? {
        var node: DocumentFile? = root()
        for (segment in relativePath.split('/')) {
            node = node?.findFile(segment) ?: return null
        }
        return node
    }

    fun walk(dir: DocumentFile, prefix: String, out: MutableList<String>) {
        for (child in dir.listFiles()) {
            val name = child.name ?: continue
            val path = if (prefix.isEmpty()) name else "$prefix/$name"
            if (child.isDirectory) walk(child, path, out) else out.add(path)
        }
    }

    fun findOrCreate(relativePath: String): DocumentFile {
        val segments = relativePath.split('/')
        var node = root()
        for (dirName in segments.dropLast(1)) {
            node = node.findFile(dirName)?.takeIf { it.isDirectory }
                ?: node.createDirectory(dirName)
                ?: throw CloudFolderException("cannot create directory $dirName in $relativePath")
        }
        val fileName = segments.last()
        // Overwrite means delete-then-create: SAF has no truncate-open primitive. A delete() that
        // returns false on a file that DOES exist must not be swallowed — SAF display names are not
        // unique, so a failed delete + createFile would silently fork a duplicate ("name (1)") and a
        // later findFile/resolve would match the STALE original, diverging the cloud from the working
        // copy. Surface it exactly like the deleteFile seam below.
        val existing = node.findFile(fileName)
        if (existing != null && !existing.delete()) {
            throw CloudFolderException("cannot overwrite existing file $relativePath")
        }
        return node.createFile("application/octet-stream", fileName)
            ?: throw CloudFolderException("cannot create file $relativePath")
    }

    return SafCloudFolderPort(
        listFiles = { mutableListOf<String>().also { walk(root(), "", it) } },
        readFile = { path ->
            val doc = resolve(path) ?: throw CloudFolderException("no such file: $path")
            resolver.openInputStream(doc.uri)?.use { it.readBytes() }
                ?: throw CloudFolderException("cannot open $path for read")
        },
        writeFile = { path, bytes ->
            val doc = findOrCreate(path)
            // "wt" = write + truncate, a documented ContentResolver open mode; the truncate guarantees a
            // clean overwrite even though findOrCreate already replaced any prior file at this path.
            resolver.openOutputStream(doc.uri, "wt")?.use { it.write(bytes) }
                ?: throw CloudFolderException("cannot open $path for write")
        },
        deleteFile = { path ->
            // Idempotent on an absent file (the CloudFolderPort.delete contract). But a delete that
            // fails on a file that DOES exist must not be swallowed — surface it like readFile does,
            // so the cloud folder can never silently diverge from the working copy.
            val doc = resolve(path)
            if (doc != null && !doc.delete()) throw CloudFolderException("cannot delete $path")
        },
    )
}
