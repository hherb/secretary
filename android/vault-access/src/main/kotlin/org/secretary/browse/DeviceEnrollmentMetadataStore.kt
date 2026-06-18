package org.secretary.browse

/**
 * Persists the NON-secret device-enrollment metadata (which vault, which slot UUID) so [unlock] can
 * detect a stale enrollment before touching the enclave. In slice 1 faked in-memory; in slice 2 a
 * small Keystore-free store (e.g. encrypted prefs). Mirror of iOS `DeviceEnrollmentMetadataStore`.
 */
interface DeviceEnrollmentMetadataStore {
    fun load(): DeviceEnrollment?
    fun save(enrollment: DeviceEnrollment)
    fun clear()
}

/** Non-secret enrollment metadata: the opaque [vaultId] token and the 16-byte slot [deviceUuid]. */
class DeviceEnrollment(val vaultId: String, val deviceUuid: ByteArray)
