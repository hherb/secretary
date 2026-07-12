package org.secretary.browse.ui

import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import org.junit.Rule
import org.junit.Test
import org.secretary.browse.EmptyTrashReportInfo
import org.secretary.browse.ExpiredEntryInfo
import org.secretary.browse.PurgeResultInfo
import org.secretary.browse.RetentionReportInfo
import org.secretary.browse.TrashBrowseModel
import org.secretary.browse.TrashPort
import org.secretary.browse.TrashedBlockInfo

/**
 * Instrumented render guard for the Trash purge-notice banner (#417): proves `testTag("trash-notice")`
 * renders the view-model's `notice` — both the success text and the `filesFailed > 0` warning variant.
 * The banner FORMATTER is host-tested (`TrashFormattingTest`); this asserts the render BINDING.
 */
class TrashNoticeRenderTest {
    @get:Rule val composeRule = createComposeRule()

    /** Minimal androidTest TrashPort: only `emptyTrash()` is exercised; other ops must not be called. */
    private class FakeTrashPort(private val purged: Int, private val failed: Int) : TrashPort {
        override fun listTrashedBlocks(): List<TrashedBlockInfo> = emptyList()
        override fun expiredTrashEntries(windowMs: Long): List<ExpiredEntryInfo> = emptyList()
        override fun defaultRetentionWindowMs(): Long = 0L
        override suspend fun restoreBlock(uuid: ByteArray) = error("unused in render test")
        override suspend fun purgeBlock(uuid: ByteArray): PurgeResultInfo = error("unused in render test")
        override suspend fun emptyTrash(): EmptyTrashReportInfo =
            EmptyTrashReportInfo(purged, 0, purged, 0, 0, failed)
        override suspend fun autoPurgeExpired(windowMs: Long): RetentionReportInfo = error("unused in render test")
    }

    private fun render(purged: Int, failed: Int) {
        val vm = TrashBrowseViewModel(TrashBrowseModel(FakeTrashPort(purged, failed)))
        composeRule.setContent { TrashScreen(viewModel = vm, onBack = {}) }
        composeRule.runOnIdle { vm.emptyTrash() }
        composeRule.waitForIdle()
    }

    @Test
    fun emptyTrashSuccess_rendersPurgedCount() {
        render(purged = 2, failed = 0)
        composeRule.onNodeWithTag("trash-notice").assertTextEquals("Purged 2 items")
    }

    @Test
    fun emptyTrashPartialFailure_rendersWarningVariant() {
        render(purged = 2, failed = 1)
        composeRule.onNodeWithTag("trash-notice")
            .assertTextEquals("Purged 2 items · 1 file could not be removed")
    }
}
