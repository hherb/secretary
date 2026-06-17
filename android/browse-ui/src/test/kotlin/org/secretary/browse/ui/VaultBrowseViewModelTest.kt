package org.secretary.browse.ui

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.secretary.browse.BlockSummaryView
import org.secretary.browse.FakeVaultSession
import org.secretary.browse.RecordSummaryView
import org.secretary.browse.VaultBrowseModel
import org.secretary.browse.textField

@OptIn(ExperimentalCoroutinesApi::class)
class VaultBrowseViewModelTest {
    private val dispatcher = StandardTestDispatcher()
    private val block = BlockSummaryView(ByteArray(16) { 0x4c }, "Logins", 1u, 2u)
    private val recs = listOf(
        RecordSummaryView("aa", "login", listOf("p"), 1u, 2u, false, listOf(textField("username", "u"))),
    )

    @BeforeEach fun setUp() = Dispatchers.setMain(dispatcher)
    @AfterEach fun tearDown() = Dispatchers.resetMain()

    private fun model() = VaultBrowseModel(FakeVaultSession("abcd", listOf(block), mapOf(block.uuidHex to recs)))

    @Test
    fun `loadBlocks forwards to the model`() = runTest {
        val vm = VaultBrowseViewModel(model())
        vm.loadBlocks()
        assertEquals(listOf(block), vm.blocks.value)
    }

    @Test
    fun `selectBlock launches the suspend read and publishes records`() = runTest {
        val vm = VaultBrowseViewModel(model())
        vm.loadBlocks()
        vm.selectBlock(block)
        dispatcher.scheduler.advanceUntilIdle()
        assertEquals(recs, vm.selectedRecords.value)
        assertEquals(block, vm.selectedBlock.value)
    }

    @Test
    fun `back clears the selection`() = runTest {
        val vm = VaultBrowseViewModel(model())
        vm.loadBlocks(); vm.selectBlock(block); dispatcher.scheduler.advanceUntilIdle()
        vm.back()
        assertNull(vm.selectedBlock.value)
        assertNull(vm.selectedRecords.value)
    }
}
