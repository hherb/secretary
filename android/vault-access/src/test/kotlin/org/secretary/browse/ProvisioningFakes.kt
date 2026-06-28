package org.secretary.browse

/** In-memory [VaultCreatePort] for host tests. Records each call and hands the VM the EXACT phrase
 *  buffer it returns (via [lastReturnedPhrase]) so a zeroize-on-ack assertion can inspect it. */
class FakeVaultCreatePort(
    private val phrase: ByteArray = "alpha bravo charlie".toByteArray(Charsets.UTF_8),
    private val vaultUuid: ByteArray = ByteArray(16),
    private val error: VaultProvisioningError? = null,
) : VaultCreatePort {
    data class Call(val folderPath: String, val displayName: String, val passwordSize: Int)
    val calls = mutableListOf<Call>()
    var lastReturnedPhrase: ByteArray? = null
        private set

    override suspend fun createInFolder(
        folderPath: String,
        password: ByteArray,
        displayName: String,
    ): CreatedVault {
        calls.add(Call(folderPath, displayName, password.size))
        error?.let { throw it }
        val buf = phrase.copyOf()
        lastReturnedPhrase = buf
        return CreatedVault(phrase = buf, vaultUuid = vaultUuid.copyOf())
    }
}

/** In-memory [VaultLocationStore] for host tests. Records persists + clear so the view-model
 *  tests can assert forwarding and ordering. */
class FakeVaultLocationStore(
    private var stored: VaultLocation? = null,
    var available: Boolean = true,
) : VaultLocationStore {
    val persisted = mutableListOf<VaultLocation>()
    var cleared = false
        private set

    override fun load(): VaultLocation? = stored
    override fun persist(location: VaultLocation) {
        stored = location
        persisted.add(location)
    }
    override fun clear() {
        stored = null
        cleared = true
    }
    override fun isAvailable(location: VaultLocation): Boolean = available
}
