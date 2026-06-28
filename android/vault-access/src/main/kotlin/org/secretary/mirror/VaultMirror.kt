package org.secretary.mirror

import java.io.File
import java.io.IOException
import java.nio.file.Files

/**
 * What a mirror pass did: the vault-relative paths it [copied] and [deleted] on the
 * destination side. `copied` is empty and `deleted` is empty exactly when both sides already
 * agreed. A later slice's UI uses this for the "saved / synced" indicator.
 */
data class MirrorReport(val copied: List<String>, val deleted: List<String>)

/**
 * Thrown when a mirror pass cannot complete — a working-copy I/O failure or an underlying
 * [CloudFolderException]. One typed boundary so the Slice-5 lifecycle caller folds a single
 * error. Mirrors `org.secretary.browse.DeviceUuidException`.
 */
class VaultMirrorException(message: String) : Exception(message)

/**
 * Mirrors a vault folder between a real-filesystem working copy and a path-less [cloud] folder
 * (the SAF working-copy shim). Stateless: each pass content-hashes both sides, diffs via
 * [planMirror], and executes the plan block-first. The local-sidecar flush optimization is a
 * Slice-5 concern; here correctness comes first, so flush re-reads the cloud to fingerprint it.
 *
 * The only platform dependency is [CloudFolderPort] (faked in host tests) plus `java.io.File`
 * for the working copy (a real temp dir in host tests) — the `DeviceUuid` precedent. Both
 * passes buffer each side's file contents in memory once and reuse them for execution (one read
 * per file); streaming for very large vaults is a future optimization, not needed for a
 * personal secrets vault.
 */
class VaultMirror(private val cloud: CloudFolderPort) {

    /** Pull cloud → working: bring [workingDir] into byte-identical agreement with [cloud]. */
    fun materialize(workingDir: File): MirrorReport = runPass("materialize") {
        val cloudFiles = readCloud()
        val workingFiles = readWorking(workingDir)
        val plan = planMirror(fingerprints(cloudFiles), fingerprints(workingFiles))
        execute(
            plan,
            source = cloudFiles,
            applyCopy = { path, bytes -> writeWorking(workingDir, path, bytes) },
            applyDelete = { path -> deleteWorking(workingDir, path) },
        )
    }

    /** Push working → cloud: bring [cloud] into agreement with [workingDir], block-first. */
    fun flush(workingDir: File): MirrorReport = runPass("flush") {
        val workingFiles = readWorking(workingDir)
        val cloudFiles = readCloud()
        val plan = planMirror(fingerprints(workingFiles), fingerprints(cloudFiles))
        execute(
            plan,
            source = workingFiles,
            applyCopy = { path, bytes -> cloud.write(path, bytes) },
            applyDelete = { path -> cloud.delete(path) },
        )
    }

    private inline fun runPass(label: String, block: () -> MirrorReport): MirrorReport = try {
        block()
    } catch (e: CloudFolderException) {
        throw VaultMirrorException("$label failed: ${e.message}")
    } catch (e: IOException) {
        throw VaultMirrorException("$label failed: ${e.message}")
    }

    private fun execute(
        plan: List<MirrorOp>,
        source: Map<String, ByteArray>,
        applyCopy: (String, ByteArray) -> Unit,
        applyDelete: (String) -> Unit,
    ): MirrorReport {
        val copied = mutableListOf<String>()
        val deleted = mutableListOf<String>()
        for (op in plan) when (op) {
            is MirrorOp.Copy -> {
                applyCopy(op.relativePath, source.getValue(op.relativePath))
                copied.add(op.relativePath)
            }
            is MirrorOp.Delete -> {
                applyDelete(op.relativePath)
                deleted.add(op.relativePath)
            }
        }
        return MirrorReport(copied, deleted)
    }

    private fun readCloud(): Map<String, ByteArray> = cloud.list().associateWith { cloud.read(it) }

    private fun fingerprints(files: Map<String, ByteArray>): Map<String, FileFingerprint> =
        files.mapValues { (_, bytes) -> FileFingerprint(bytes.size.toLong(), sha256Hex(bytes)) }

    private fun readWorking(workingDir: File): Map<String, ByteArray> {
        if (!workingDir.isDirectory) return emptyMap()
        val base = workingDir.toPath()
        return workingDir.walkTopDown()
            .filter { it.isFile }
            .associate { file ->
                base.relativize(file.toPath()).toString().replace(File.separatorChar, '/') to file.readBytes()
            }
    }

    private fun writeWorking(workingDir: File, relativePath: String, bytes: ByteArray) {
        val target = File(workingDir, relativePath)
        target.parentFile?.mkdirs()
        target.writeBytes(bytes)
    }

    private fun deleteWorking(workingDir: File, relativePath: String) {
        // deleteIfExists is a no-op when the file is already gone (matching the CloudFolderPort
        // delete contract) but throws IOException on a real failure (permissions, busy) so the
        // working copy can never silently diverge from the cloud — runPass folds it to
        // VaultMirrorException.
        Files.deleteIfExists(File(workingDir, relativePath).toPath())
    }
}
