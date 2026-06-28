package org.secretary.browse

/** In-memory [VaultLocationStore] for host tests. Records persists + clear so the view-model
 *  tests can assert forwarding and ordering. */
class FakeVaultLocationStore(
    private var stored: VaultLocation? = null,
    private val available: Boolean = true,
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
