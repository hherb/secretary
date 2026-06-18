package org.secretary.app

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.HorizontalDivider
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import org.secretary.browse.ui.BrowseScreen
import org.secretary.browse.ui.VaultBrowseViewModel
import org.secretary.sync.ui.SyncScreen
import org.secretary.sync.ui.VaultSyncViewModel

/**
 * The unified browse+sync screen: the sync badge (and its password/conflict sheets, all owned by
 * the reused [SyncScreen]) sit above the [BrowseScreen] content. Because the badge row is outside
 * BrowseScreen's swappable block-list/record-list content, it stays visible on both views.
 *
 * This composable holds NO state — it is pure composition of two independently-tested library
 * surfaces ([SyncScreen] from `:sync-ui`, [BrowseScreen] from `:browse-ui`). Mirrors iOS's unified
 * `VaultBrowseScreen`, which likewise composes both view-models at the app layer.
 */
@Composable
fun BrowseWithSyncScreen(browse: VaultBrowseViewModel, sync: VaultSyncViewModel) {
    Column(modifier = Modifier.fillMaxSize()) {
        SyncScreen(viewModel = sync)
        HorizontalDivider()
        BrowseScreen(viewModel = browse)
    }
}
