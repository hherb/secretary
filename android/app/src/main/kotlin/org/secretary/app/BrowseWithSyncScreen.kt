package org.secretary.app

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.TextButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import org.secretary.browse.ui.BrowseScreen
import org.secretary.browse.ui.VaultBrowseViewModel
import org.secretary.sync.ui.SyncScreen
import org.secretary.sync.ui.VaultSyncViewModel

/**
 * The unified browse+sync screen: the sync badge (and its password/conflict sheets, owned by the
 * reused [SyncScreen]) sit above the [BrowseScreen] content, with a "Device settings" entry that
 * invokes [onOpenSettings] (AppRoot routes to the Settings sub-view). Holds NO state.
 */
@Composable
fun BrowseWithSyncScreen(
    browse: VaultBrowseViewModel,
    sync: VaultSyncViewModel,
    onOpenSettings: () -> Unit = {},
) {
    Column(modifier = Modifier.fillMaxSize()) {
        SyncScreen(viewModel = sync)
        TextButton(
            onClick = onOpenSettings,
            modifier = Modifier.align(Alignment.End).testTag("open-settings"),
        ) { Text("Device settings") }
        HorizontalDivider()
        BrowseScreen(viewModel = browse)
    }
}
