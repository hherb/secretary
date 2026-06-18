package org.secretary.browse

/**
 * In-memory [VaultDeviceSlotPort] for host tests. Records every add/remove; returns a fresh COPY of
 * [issuedSecret] from each [addDeviceSlot] (so a coordinator that zeroizes its slot copy cannot
 * corrupt the fake's source); supports per-method error injection.
 */
class FakeVaultDeviceSlotPort(
    private val deviceUuid: ByteArray = ByteArray(16) { 1 },
    private val issuedSecret: ByteArray = ByteArray(32) { 2 },
    private val addError: Throwable? = null,
    private val removeError: Throwable? = null,
) : VaultDeviceSlotPort {
    val addCalls: MutableList<String> = mutableListOf()
    val removeCalls: MutableList<ByteArray> = mutableListOf()
    /** The exact array handed to the most recent caller (so a test can assert it was zeroized). */
    var lastIssuedSecret: ByteArray? = null
        private set

    override suspend fun addDeviceSlot(vaultFolder: String, password: ByteArray): EnrolledSlot {
        addCalls += vaultFolder
        addError?.let { throw it }
        val secret = issuedSecret.copyOf()
        lastIssuedSecret = secret
        return EnrolledSlot(deviceUuid.copyOf(), secret)
    }

    override suspend fun removeDeviceSlot(vaultFolder: String, deviceUuid: ByteArray) {
        removeCalls += deviceUuid.copyOf()
        removeError?.let { throw it }
    }
}

/** In-memory [DeviceSecretEnclave]: holds a COPY of the stored secret; supports error injection. */
class FakeDeviceSecretEnclave(
    private val storeError: Throwable? = null,
    private val releaseError: Throwable? = null,
) : DeviceSecretEnclave {
    private var stored: ByteArray? = null
    override val isEnrolled: Boolean get() = stored != null

    override suspend fun store(secret: ByteArray) {
        storeError?.let { throw it }
        stored = secret.copyOf()
    }

    override suspend fun release(reason: String): ByteArray {
        releaseError?.let { throw it }
        return stored?.copyOf() ?: throw DeviceUnlockError.NotEnrolled
    }

    override suspend fun clear() {
        stored?.fill(0)
        stored = null
    }
}

/** In-memory [DeviceEnrollmentMetadataStore]; supports save-error injection for rollback tests. */
class FakeEnrollmentMetadataStore(
    private val saveError: Throwable? = null,
) : DeviceEnrollmentMetadataStore {
    private var enrollment: DeviceEnrollment? = null
    override fun load(): DeviceEnrollment? = enrollment
    override fun save(enrollment: DeviceEnrollment) {
        saveError?.let { throw it }
        this.enrollment = DeviceEnrollment(enrollment.vaultId, enrollment.deviceUuid.copyOf())
    }
    override fun clear() { enrollment = null }
}
