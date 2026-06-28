package org.secretary.mirror

/**
 * The vault manifest filename. Written LAST on every mirror pass so a destination never holds
 * a manifest referencing a block that has not yet been copied (vault-format §9 write ordering).
 */
const val MANIFEST_FILENAME = "manifest.cbor.enc"

/**
 * Content fingerprint of one file: byte [size] plus lowercase-hex SHA-256 [sha256]. Two files
 * are identical iff their fingerprints are equal. (Size alone is insufficient — re-encryption
 * keeps the length but changes the bytes — so the hash is the load-bearing field.)
 */
data class FileFingerprint(val size: Long, val sha256: String)

/** One step of a mirror plan, addressed by vault-relative POSIX [relativePath]. */
sealed interface MirrorOp {
    val relativePath: String

    /** Copy the file from the source side to the destination side (create or overwrite). */
    data class Copy(override val relativePath: String) : MirrorOp

    /** Delete the file from the destination side (it is absent from the source). */
    data class Delete(override val relativePath: String) : MirrorOp
}

/**
 * Pure diff of two vault file-sets, producing an ordered plan that brings [dest] into
 * byte-identical agreement with [source]. The same function serves both directions: flush
 * passes `source = working, dest = cloud`; materialize passes `source = cloud, dest = working`.
 *
 * A file is **copied** when it is present in [source] and either absent from [dest] or carries
 * a different fingerprint. A file present in [dest] but absent from [source] is **deleted**.
 *
 * Ordering enforces the block-first invariant (vault-format §9): every non-manifest copy is
 * emitted before the [MANIFEST_FILENAME] copy, and every delete is emitted after all copies.
 * So a destination is never left with a manifest pointing at a not-yet-written block, nor with
 * a still-referenced block deleted before the superseding manifest lands — both broken windows;
 * the only intermediate states this ordering allows are the recoverable ones (the core's
 * fingerprint recheck tolerates a new block under a stale manifest). Within each group, order
 * is by path so plans are deterministic and reproducible.
 */
fun planMirror(
    source: Map<String, FileFingerprint>,
    dest: Map<String, FileFingerprint>,
): List<MirrorOp> {
    val copies = source.keys.filter { path -> source[path] != dest[path] }.sorted()
    val (manifestCopies, blockCopies) = copies.partition { it == MANIFEST_FILENAME }
    val deletes = dest.keys.filter { it !in source }.sorted()
    return buildList {
        blockCopies.forEach { add(MirrorOp.Copy(it)) }
        manifestCopies.forEach { add(MirrorOp.Copy(it)) }
        deletes.forEach { add(MirrorOp.Delete(it)) }
    }
}
