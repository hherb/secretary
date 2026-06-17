package org.secretary.browse

import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import java.security.SecureRandom

/** 16 bytes — a UUID. Named so the length is never a magic literal at call sites. */
const val DEVICE_UUID_BYTE_LEN = 16

/** Thrown when the device-uuid store cannot resolve a UUID: a persisted file is the wrong length,
 *  or any backing-store I/O fails (disk full, permission denied, unreadable). It is the *only*
 *  checked exception [FileDeviceUuidStore.deviceUuid] lets escape, so callers (e.g.
 *  `UniffiVaultSession`) can fold it to one typed error rather than leaking a raw [IOException]. */
class DeviceUuidException(message: String) : Exception(message)

/**
 * Resolves the 16-byte CRDT modifier UUID for a vault on this device. The edit FFI stamps it onto
 * every field a write touches. Non-secret (a public per-device fingerprint), so NOT key material.
 * Pure seam — mirrors iOS `DeviceUuidProviding`; the real impl is [FileDeviceUuidStore].
 */
interface DeviceUuidProvider {
    /** [vaultHex]: lowercase, dash-less vault-UUID hex. Returns exactly [DEVICE_UUID_BYTE_LEN] bytes. */
    fun deviceUuid(vaultHex: String): ByteArray
}

/**
 * File-backed [DeviceUuidProvider] mirroring iOS `DeviceUuidStore` / desktop
 * `settings/io.rs::load_or_create_device_uuid_in`: random 16 bytes per (install, vault) via
 * [SecureRandom], persisted as `<vaultHex>.dev`, read back on later calls so one device == one CRDT
 * fingerprint. A `CREATE_NEW` write that loses a same-launch race reads the winner back (converge).
 * The [directory] is supplied by `:app` from `Context.noBackupFilesDir` so a restored backup does not
 * clone the fingerprint.
 */
class FileDeviceUuidStore(private val directory: File) : DeviceUuidProvider {
    override fun deviceUuid(vaultHex: String): ByteArray {
        val file = File(directory, "$vaultHex.dev")
        try {
            // Common path: already persisted (a prior call this launch, or a prior launch).
            // Return it without drawing fresh entropy — no crypto work on the cache hit.
            if (file.exists()) return readUuid(file)
            directory.mkdirs()
            // Not present — mint a fresh fingerprint and atomically create the file. If we lost a
            // same-launch race the CREATE_NEW fails and we converge on the winner's persisted value.
            val uuid = ByteArray(DEVICE_UUID_BYTE_LEN).also { SecureRandom().nextBytes(it) }
            return try {
                Files.write(file.toPath(), uuid, StandardOpenOption.CREATE_NEW)
                uuid
            } catch (e: java.nio.file.FileAlreadyExistsException) {
                readUuid(file)   // raced (or appeared between the exists() check and the write) — converge
            }
        } catch (e: DeviceUuidException) {
            throw e   // wrong-length is already the typed boundary — keep it
        } catch (e: IOException) {
            // Disk full, permission denied, a non-directory parent, an unreadable file: fold to the
            // typed boundary. UniffiVaultSession maps only DeviceUuidException → VaultBrowseError, so
            // an escaping raw IOException here would crash the write coroutine.
            throw DeviceUuidException("device-uuid store I/O failed for ${file.name}: ${e.message}")
        }
    }

    private fun readUuid(file: File): ByteArray {
        val bytes = file.readBytes()
        if (bytes.size != DEVICE_UUID_BYTE_LEN) {
            throw DeviceUuidException("device-uuid file ${file.name} is ${bytes.size} bytes, expected $DEVICE_UUID_BYTE_LEN")
        }
        return bytes
    }
}
