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
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.secretary.browse.BlockSummaryView
import org.secretary.browse.FakeVaultSession
import org.secretary.browse.RecordSummaryView
import org.secretary.browse.RevealedValue
import org.secretary.browse.VaultBrowseModel
import org.secretary.browse.hexOfBytes
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

    @Test
    fun `reveal forwards to the model and publishes the revealed value`() = runTest {
        val pw = textField("password", "hunter2")
        val rec = RecordSummaryView("ab", "login", emptyList(), 1u, 2u, false, listOf(pw))
        val m = VaultBrowseModel(FakeVaultSession("abcd", listOf(block), mapOf(block.uuidHex to listOf(rec))))
        val vm = VaultBrowseViewModel(m)
        vm.reveal(rec, pw)
        assertEquals(RevealedValue.Text("hunter2"), vm.revealed.value["ab/password"])
    }

    @Test
    fun `hide and hideAll forward to the model`() = runTest {
        val pw = textField("password", "hunter2")
        val rec = RecordSummaryView("ab", "login", emptyList(), 1u, 2u, false, listOf(pw))
        val m = VaultBrowseModel(FakeVaultSession("abcd", listOf(block), mapOf(block.uuidHex to listOf(rec))))
        val vm = VaultBrowseViewModel(m)
        vm.reveal(rec, pw)
        vm.hide("ab", "password")
        assertTrue(vm.revealed.value.isEmpty())
        vm.reveal(rec, pw)
        vm.hideAll()
        assertTrue(vm.revealed.value.isEmpty())
    }

    @Test
    fun `confirmBlockName create reaches the model`() = runTest {
        val block = BlockSummaryView(ByteArray(16) { 0x4c }, "Logins", 1u, 2u)
        val fake = FakeVaultSession("abcd", listOf(block))
        val vm = VaultBrowseViewModel(VaultBrowseModel(fake))
        vm.startCreateBlock()
        vm.confirmBlockName("Work")
        dispatcher.scheduler.advanceUntilIdle()
        assertEquals(listOf("Work"), fake.created)
    }

    @Test
    fun `confirmMove reaches the model`() = runTest {
        val src = BlockSummaryView(ByteArray(16) { 0x11 }, "Src", 1u, 2u)
        val tgt = BlockSummaryView(ByteArray(16) { 0x22 }, "Tgt", 1u, 2u)
        val rec = RecordSummaryView(hexOfBytes(ByteArray(16) { 0x33 }), "login", emptyList(), 1u, 2u, false,
            listOf(textField("u", "v")))
        val fake = FakeVaultSession("abcd", listOf(src, tgt), mapOf(src.uuidHex to listOf(rec)))
        val vm = VaultBrowseViewModel(VaultBrowseModel(fake))
        vm.selectBlock(src); dispatcher.scheduler.advanceUntilIdle()
        vm.startMoveRecord(rec)
        vm.confirmMove(tgt); dispatcher.scheduler.advanceUntilIdle()
        assertEquals(1, fake.moved.size)
    }
}
