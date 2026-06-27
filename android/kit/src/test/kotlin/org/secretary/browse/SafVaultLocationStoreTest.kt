package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SafVaultLocationStoreTest {
    private val location = VaultLocation("My Vault", "content://x/tree/y")

    /** In-memory seams recording interactions for ordering/forwarding assertions. */
    private class Fakes(initialPref: String? = null) {
        var pref: String? = initialPref
        val events = mutableListOf<String>()
        val permitted = mutableSetOf<String>()

        fun store(): SafVaultLocationStore = SafVaultLocationStore(
            readPref = { pref },
            writePref = { blob -> events.add("write:$blob"); pref = blob },
            takePermission = { uri -> events.add("take:$uri"); permitted.add(uri) },
            releasePermission = { uri -> events.add("release:$uri"); permitted.remove(uri) },
            hasPermission = { uri -> uri in permitted },
        )
    }

    @Test
    fun `persist takes the permission before writing the pref`() {
        val f = Fakes()
        f.store().persist(location)
        assertEquals(
            listOf("take:content://x/tree/y", "write:${encodeVaultLocation(location)}"),
            f.events,
        )
    }

    @Test
    fun `load decodes the persisted blob`() {
        val f = Fakes(initialPref = encodeVaultLocation(location))
        assertEquals(location, f.store().load())
    }

    @Test
    fun `load returns null when nothing is persisted`() {
        assertNull(Fakes().store().load())
    }

    @Test
    fun `load returns null for a malformed blob`() {
        assertNull(Fakes(initialPref = "garbage").store().load())
    }

    @Test
    fun `clear writes null and load then returns null`() {
        val f = Fakes(initialPref = encodeVaultLocation(location))
        val store = f.store()
        store.clear()
        assertNull(f.pref)
        assertNull(store.load())
    }

    @Test
    fun `persist replaces a prior location`() {
        val store = Fakes().store()
        store.persist(VaultLocation("old", "content://x/tree/old"))
        store.persist(location)
        assertEquals(location, store.load())
    }

    @Test
    fun `isAvailable forwards to the permission probe`() {
        val store = Fakes().store()
        assertFalse(store.isAvailable(location))
        store.persist(location)
        assertTrue(store.isAvailable(location))
    }

    @Test
    fun `clear releases the grant before forgetting the location`() {
        val f = Fakes()
        val store = f.store()
        store.persist(location)
        store.clear()
        // The grant is relinquished, not just the pref — else it leaks toward Android's cap.
        assertFalse(store.isAvailable(location))
        assertNull(f.pref)
    }

    @Test
    fun `persist replacing a different URI releases the prior grant after securing the new one`() {
        val f = Fakes()
        val store = f.store()
        val old = VaultLocation("old", "content://x/tree/old")
        store.persist(old)
        f.events.clear()
        store.persist(location)
        assertEquals(
            listOf(
                "take:content://x/tree/y",
                "write:${encodeVaultLocation(location)}",
                "release:content://x/tree/old",
            ),
            f.events,
        )
        assertFalse(store.isAvailable(old))
        assertTrue(store.isAvailable(location))
    }

    @Test
    fun `persist replacing the same URI keeps the grant and releases nothing`() {
        val f = Fakes()
        val store = f.store()
        store.persist(location)
        store.persist(location.copy(displayName = "renamed"))
        assertTrue(store.isAvailable(location))
        assertFalse(f.events.any { it.startsWith("release:") })
    }
}
