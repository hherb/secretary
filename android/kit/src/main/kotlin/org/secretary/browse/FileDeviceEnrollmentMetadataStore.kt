package org.secretary.browse

import java.io.File
import java.nio.ByteBuffer

/**
 * Real [DeviceEnrollmentMetadataStore]: persists the NON-secret enrollment ([vaultId] token + 16-byte
 * [DeviceEnrollment.deviceUuid]) to a single file under [dir]. Format: 4-byte big-endian vaultId
 * length, the vaultId UTF-8 bytes, then exactly 16 uuid bytes. [load] returns null for any
 * absent / short / malformed / wrong-uuid-length file (a conservative under-report, mirroring iOS's
 * `try? metadata.load()`). [save] writes atomically (temp + rename). Non-secret → not zeroized
 * (vault-format §3a: the uuid is a loggable filename stem). Keystore-free, so host-testable.
 */
class FileDeviceEnrollmentMetadataStore(private val dir: File) : DeviceEnrollmentMetadataStore {
    private val file: File get() = File(dir, FILE_NAME)

    override fun load(): DeviceEnrollment? {
        val f = file
        if (!f.exists()) return null
        val bytes = runCatching { f.readBytes() }.getOrNull() ?: return null
        if (bytes.size < HEADER_LEN + UUID_LEN) return null
        val vaultIdLen = ByteBuffer.wrap(bytes, 0, HEADER_LEN).int
        if (vaultIdLen < 0 || bytes.size != HEADER_LEN + vaultIdLen + UUID_LEN) return null
        val vaultId = String(bytes, HEADER_LEN, vaultIdLen, Charsets.UTF_8)
        val uuid = bytes.copyOfRange(HEADER_LEN + vaultIdLen, HEADER_LEN + vaultIdLen + UUID_LEN)
        return DeviceEnrollment(vaultId, uuid)
    }

    override fun save(enrollment: DeviceEnrollment) {
        require(enrollment.deviceUuid.size == UUID_LEN) { "deviceUuid must be $UUID_LEN bytes" }
        dir.mkdirs()
        val vaultIdBytes = enrollment.vaultId.toByteArray(Charsets.UTF_8)
        val out = ByteBuffer.allocate(HEADER_LEN + vaultIdBytes.size + UUID_LEN)
            .putInt(vaultIdBytes.size)
            .put(vaultIdBytes)
            .put(enrollment.deviceUuid)
            .array()
        val tmp = File(dir, "$FILE_NAME.tmp")
        try {
            tmp.writeBytes(out)
            check(tmp.renameTo(file)) { "atomic rename of enrollment metadata failed" }
        } catch (t: Throwable) {
            tmp.delete()
            throw t
        }
    }

    override fun clear() {
        file.delete()
    }

    private companion object {
        const val FILE_NAME = "enrollment"
        const val HEADER_LEN = 4
        const val UUID_LEN = 16
    }
}
