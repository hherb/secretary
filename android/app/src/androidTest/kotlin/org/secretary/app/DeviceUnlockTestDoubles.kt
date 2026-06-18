package org.secretary.app

import org.secretary.browse.DeviceEnrollment
import org.secretary.browse.DeviceEnrollmentMetadataStore
import org.secretary.browse.DeviceSecretEnclave
import org.secretary.browse.DeviceUnlockError

/**
 * In-memory [DeviceSecretEnclave] for instrumented tests. The `:vault-access` module's
 * [FakeDeviceSecretEnclave] lives under `src/test` (host-only scope) and is invisible to
 * `src/androidTest` across module boundaries — hence this local copy. Behaviour is identical:
 * holds a COPY of the stored secret; no error injection (not needed here).
 */
class InMemoryDeviceSecretEnclave : DeviceSecretEnclave {
    private var stored: ByteArray? = null
    override val isEnrolled: Boolean get() = stored != null

    override suspend fun store(secret: ByteArray) {
        stored = secret.copyOf()
    }

    override suspend fun release(reason: String): ByteArray =
        stored?.copyOf() ?: throw DeviceUnlockError.NotEnrolled

    override suspend fun clear() {
        stored?.fill(0)
        stored = null
    }
}

/**
 * In-memory [DeviceEnrollmentMetadataStore] for instrumented tests. Same rationale as
 * [InMemoryDeviceSecretEnclave]: local copy because the `:vault-access` fake is host-only.
 */
class InMemoryEnrollmentMetadataStore : DeviceEnrollmentMetadataStore {
    private var enrollment: DeviceEnrollment? = null
    override fun load(): DeviceEnrollment? = enrollment
    override fun save(enrollment: DeviceEnrollment) {
        this.enrollment = DeviceEnrollment(enrollment.vaultId, enrollment.deviceUuid.copyOf())
    }
    override fun clear() { enrollment = null }
}
