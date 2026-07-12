package org.secretary.browse

import kotlin.test.Test
import kotlin.test.assertEquals

class PurgeNoticeTest {
    @Test fun singlePurge() =
        assertEquals(PurgeNotice("Deleted forever", PurgeSeverity.SUCCESS),
            formatPurgeNotice(PurgeOutcome.SinglePurge))

    @Test fun emptyTrashSingular() =
        assertEquals(PurgeNotice("Purged 1 item", PurgeSeverity.SUCCESS),
            formatPurgeNotice(PurgeOutcome.EmptyTrash(purgedCount = 1, filesFailed = 0)))

    @Test fun emptyTrashPlural() =
        assertEquals(PurgeNotice("Purged 4 items", PurgeSeverity.SUCCESS),
            formatPurgeNotice(PurgeOutcome.EmptyTrash(purgedCount = 4, filesFailed = 0)))

    @Test fun oneFailedFileWarnsSingular() =
        assertEquals(PurgeNotice("Purged 4 items · 1 file could not be removed", PurgeSeverity.WARNING),
            formatPurgeNotice(PurgeOutcome.EmptyTrash(purgedCount = 4, filesFailed = 1)))

    @Test fun failedFilesWarnPlural() =
        assertEquals(PurgeNotice("Purged 4 items · 2 files could not be removed", PurgeSeverity.WARNING),
            formatPurgeNotice(PurgeOutcome.Retention(purgedCount = 4, filesFailed = 2)))

    @Test fun retentionNoop() =
        assertEquals(PurgeNotice("No items were past the retention window", PurgeSeverity.SUCCESS),
            formatPurgeNotice(PurgeOutcome.Retention(purgedCount = 0, filesFailed = 0)))

    @Test fun emptyTrashNoop() =
        assertEquals(PurgeNotice("Trash was already empty", PurgeSeverity.SUCCESS),
            formatPurgeNotice(PurgeOutcome.EmptyTrash(purgedCount = 0, filesFailed = 0)))
}
