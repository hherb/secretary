package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class VaultSelectionViewModelTest {
    private val location = VaultLocation("My Vault", "content://x/tree/y")

    @Test
    fun `empty when nothing persisted`() {
        val vm = VaultSelectionViewModel(FakeVaultLocationStore())
        vm.loadPersisted()
        assertEquals(VaultSelectionState.Empty, vm.state)
    }

    @Test
    fun `located when an available location is persisted`() {
        val vm = VaultSelectionViewModel(FakeVaultLocationStore(stored = location, available = true))
        vm.loadPersisted()
        assertEquals(VaultSelectionState.Located("My Vault"), vm.state)
    }

    @Test
    fun `unavailable when the persisted location's permission is gone`() {
        val vm = VaultSelectionViewModel(FakeVaultLocationStore(stored = location, available = false))
        vm.loadPersisted()
        assertTrue(vm.state is VaultSelectionState.Unavailable)
    }

    @Test
    fun `unavailable is preserved across a re-load`() {
        val store = FakeVaultLocationStore(stored = location, available = false)
        val vm = VaultSelectionViewModel(store)
        vm.loadPersisted()
        // Even if the store would now report it available, a surfaced Unavailable survives.
        store.available = true
        vm.loadPersisted()
        assertTrue(vm.state is VaultSelectionState.Unavailable)
    }

    @Test
    fun `recordSelection persists and locates`() {
        val store = FakeVaultLocationStore()
        val vm = VaultSelectionViewModel(store)
        vm.recordSelection(location)
        assertEquals(listOf(location), store.persisted)
        assertEquals(VaultSelectionState.Located("My Vault"), vm.state)
    }

    @Test
    fun `chooseDifferent clears the store and goes empty`() {
        val store = FakeVaultLocationStore(stored = location)
        val vm = VaultSelectionViewModel(store)
        vm.chooseDifferent()
        assertTrue(store.cleared)
        assertEquals(VaultSelectionState.Empty, vm.state)
    }

    @Test
    fun `markUnavailable surfaces the reason and retains the location`() {
        val store = FakeVaultLocationStore(stored = location)
        val vm = VaultSelectionViewModel(store)
        vm.markUnavailable("offline")
        assertEquals(VaultSelectionState.Unavailable("offline"), vm.state)
        assertTrue(!store.cleared) // retained, not cleared
    }
}
