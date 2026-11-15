package org.secretary.sync

import android.os.Bundle
import androidx.test.runner.AndroidJUnitRunner
import org.secretary.browse.setPlatformSyncStateDir
import java.io.File

/** The one dir this test process's opens read their baseline from (#746; the override is once per process). */
internal const val TEST_STATE_DIRNAME = "rollback-test-sync-state"

/**
 * Sets the bridge's sync-state dir before any test runs, as `MainActivity.onCreate` does in the app
 * (#746). The bridge fixes the dir on its first read, so a test that set it after an earlier test had
 * already opened a vault would be refused.
 */
class StateDirTestRunner : AndroidJUnitRunner() {
    override fun onCreate(arguments: Bundle?) {
        setPlatformSyncStateDir(File(targetContext.filesDir, TEST_STATE_DIRNAME).apply { mkdirs() })
        super.onCreate(arguments)
    }
}
