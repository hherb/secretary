package org.secretary.mirror

/**
 * Read/write access to a vault folder that has no real filesystem path — on Android the SAF
 * `content://` tree behind a cloud-drive folder (Drive/Dropbox/OneDrive). Files are addressed
 * by vault-relative POSIX path (`"manifest.cbor.enc"`, `"blocks/<uuid>.cbor.enc"`); the impl
 * maps these onto its storage (a SAF DocumentFile subtree). Pure seam — the real impl is
 * `:kit`'s `SafCloudFolderPort`; host tests use the in-memory `FakeCloudFolderPort`.
 */
interface CloudFolderPort {
    /**
     * Every file under the folder, recursively, as vault-relative POSIX paths. Directories
     * themselves are not returned. Order is unspecified ([VaultMirror] sorts via the planner).
     */
    fun list(): List<String>

    /** Full contents of the file at [relativePath]. */
    fun read(relativePath: String): ByteArray

    /** Create or overwrite the file at [relativePath] with [bytes], creating parent
     *  directories as needed. */
    fun write(relativePath: String, bytes: ByteArray)

    /** Remove the file at [relativePath]; a no-op if it is already absent. */
    fun delete(relativePath: String)
}

/**
 * Thrown by [CloudFolderPort] implementations when a backing-store operation fails — a revoked
 * SAF permission, a provider I/O error, or a missing file on read. The one checked boundary
 * [VaultMirror] folds into `VaultMirrorException`, so callers never see a raw provider
 * exception. Mirrors `org.secretary.browse.DeviceUuidException`.
 */
class CloudFolderException(message: String) : Exception(message)
