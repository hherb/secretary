package org.secretary.browse

import java.io.File
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import java.security.SecureRandom

/** 16 bytes — a UUID. Named so the length is never a magic literal at call sites. */
const val DEVICE_UUID_BYTE_LEN = 16

/** Thrown when a persisted device-uuid file is unreadable or the wrong length. */
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
        directory.mkdirs()
        val file = File(directory, "$vaultHex.dev")
        val uuid = ByteArray(DEVICE_UUID_BYTE_LEN).also { SecureRandom().nextBytes(it) }
        return try {
            Files.write(file.toPath(), uuid, StandardOpenOption.CREATE_NEW)
            uuid
        } catch (e: java.nio.file.FileAlreadyExistsException) {
            readUuid(file)   // already present (this launch or a prior one) — converge on the persisted value
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
