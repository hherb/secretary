package org.secretary.browse

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class VaultProvisioningViewModelTest {
    private val tree = "content://x/tree/y"
    private fun pw(s: String) = s.toByteArray(Charsets.UTF_8)

    private fun vm(
        createPort: VaultCreatePort = FakeVaultCreatePort(),
        store: VaultLocationStore = FakeVaultLocationStore(),
    ) = VaultProvisioningViewModel(createPort, store)

    @Test
    fun `chooseFolder rejects an invalid name and stays on folder`() {
        val m = vm()
        m.chooseFolder(tree, "a/b")
        assertTrue(m.nameError is VaultNameError.IllegalCharacters)
        assertEquals(VaultProvisioningStep.Folder, m.step)
    }

    @Test
    fun `chooseFolder accepts a valid name and advances to credentials`() {
        val m = vm()
        m.chooseFolder(tree, "  My Vault ")
        assertNull(m.nameError)
        assertEquals(VaultProvisioningStep.Credentials(tree, "My Vault"), m.step)
    }

    @Test
    fun `create with mismatched passwords surfaces PasswordMismatch and stays on credentials`() = runTest {
        val m = vm()
        m.chooseFolder(tree, "My Vault")
        m.create("/tmp/work", pw("a"), pw("b"))
        assertEquals(VaultProvisioningError.PasswordMismatch, m.error)
        assertTrue(m.step is VaultProvisioningStep.Credentials)
    }

    @Test
    fun `create persists the location and reveals the mnemonic`() = runTest {
        val store = FakeVaultLocationStore()
        val port = FakeVaultCreatePort(phrase = "one two three".toByteArray())
        val m = VaultProvisioningViewModel(port, store)
        m.chooseFolder(tree, "My Vault")
        m.create("/tmp/work", pw("pw"), pw("pw"))
        // Persist happened with the Credentials treeUri + vaultName, BEFORE the mnemonic reveal.
        assertEquals(listOf(VaultLocation("My Vault", tree)), store.persisted)
        assertEquals(VaultProvisioningStep.Mnemonic, m.step)
        assertEquals(3, m.mnemonicRows?.size)
        // The port was called with the resolved folder path + the vault name as displayName.
        assertEquals(FakeVaultCreatePort.Call("/tmp/work", "My Vault", 2), port.calls.single())
    }

    @Test
    fun `create is re-entrancy-guarded`() = runTest {
        val store = FakeVaultLocationStore()
        val port = FakeVaultCreatePort()
        val m = VaultProvisioningViewModel(port, store)
        m.chooseFolder(tree, "My Vault")
        m.create("/tmp/work", pw("pw"), pw("pw")) // first → Mnemonic
        m.create("/tmp/work", pw("pw"), pw("pw")) // second → ignored (not in Credentials anymore)
        assertEquals(1, port.calls.size)
    }

    @Test
    fun `create maps FolderNotEmpty to error`() = runTest {
        val port = FakeVaultCreatePort(error = VaultProvisioningError.FolderNotEmpty)
        val m = VaultProvisioningViewModel(port, FakeVaultLocationStore())
        m.chooseFolder(tree, "My Vault")
        m.create("/tmp/work", pw("pw"), pw("pw"))
        assertEquals(VaultProvisioningError.FolderNotEmpty, m.error)
        assertTrue(m.step is VaultProvisioningStep.Credentials)
        assertFalse(m.isCreating)
    }

    @Test
    fun `acknowledge zeroizes the phrase and completes with the location`() = runTest {
        val store = FakeVaultLocationStore()
        val port = FakeVaultCreatePort(phrase = "alpha bravo".toByteArray())
        val m = VaultProvisioningViewModel(port, store)
        m.chooseFolder(tree, "My Vault")
        m.create("/tmp/work", pw("pw"), pw("pw"))
        m.acknowledgeMnemonic()
        assertNull(m.mnemonicRows)
        assertEquals(VaultProvisioningStep.Done(VaultLocation("My Vault", tree)), m.step)
        // The exact buffer the VM retained is wiped.
        assertTrue(port.lastReturnedPhrase!!.all { it == 0.toByte() })
    }

    @Test
    fun `acknowledge with a missing stored location surfaces a store fault`() = runTest {
        // Store accepts persist but reports nothing on load (simulated by a store that drops it).
        val droppingStore = object : VaultLocationStore {
            override fun load(): VaultLocation? = null
            override fun persist(location: VaultLocation) {}
            override fun clear() {}
            override fun isAvailable(location: VaultLocation) = true
        }
        val m = VaultProvisioningViewModel(FakeVaultCreatePort(), droppingStore)
        m.chooseFolder(tree, "My Vault")
        m.create("/tmp/work", pw("pw"), pw("pw"))
        m.acknowledgeMnemonic()
        assertTrue(m.error is VaultProvisioningError.CreateFailed)
        assertTrue(m.step is VaultProvisioningStep.Mnemonic) // did not advance to Done
    }

    @Test
    fun `cancel resets the wizard and zeroizes the phrase`() = runTest {
        val port = FakeVaultCreatePort(phrase = "alpha bravo".toByteArray())
        val m = VaultProvisioningViewModel(port, FakeVaultLocationStore())
        m.chooseFolder(tree, "My Vault")
        m.create("/tmp/work", pw("pw"), pw("pw"))
        m.cancel()
        assertNull(m.mnemonicRows)
        assertTrue(port.lastReturnedPhrase!!.all { it == 0.toByte() })
        assertEquals(VaultProvisioningStep.Folder, m.step)
        assertNull(m.error)
        assertNull(m.nameError)
    }
}
