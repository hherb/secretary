package org.secretary.app

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import org.secretary.browse.VaultSelectionState

/**
 * Entry screen: choose what vault to open. Renders [VaultSelectionState]; all logic lives in
 * `VaultSelectionViewModel`. The cloud-open path ([onOpen]) is wired in `AppRoot` to the Slice-5
 * materialize-then-unlock seam; this slice's working open paths are Create and the demo vault.
 * Mirror of iOS `VaultSelectionScreen`.
 */
@Composable
fun VaultSelectionScreen(
    state: VaultSelectionState,
    onCreate: () -> Unit,
    onOpen: () -> Unit,
    onChooseDifferent: () -> Unit,
    onPickFolder: () -> Unit,
    onDemo: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("Secretary")
        when (state) {
            is VaultSelectionState.Empty -> {
                Text("No vault selected yet.")
                Button(onClick = onCreate, modifier = Modifier.fillMaxWidth().testTag("create-vault")) {
                    Text("Create new vault")
                }
                OutlinedButton(onClick = onPickFolder, modifier = Modifier.fillMaxWidth().testTag("pick-folder")) {
                    Text("Open an existing vault folder")
                }
                OutlinedButton(onClick = onDemo, modifier = Modifier.fillMaxWidth().testTag("open-demo")) {
                    Text("Open the demo vault")
                }
            }
            is VaultSelectionState.Located -> {
                Text(state.displayName)
                Button(onClick = onOpen, modifier = Modifier.fillMaxWidth().testTag("open-vault")) {
                    Text("Open")
                }
                OutlinedButton(onClick = onChooseDifferent, modifier = Modifier.fillMaxWidth().testTag("choose-different")) {
                    Text("Choose a different vault")
                }
            }
            is VaultSelectionState.Unavailable -> {
                Text(state.reason, modifier = Modifier.testTag("selection-reason"))
                Button(onClick = onPickFolder, modifier = Modifier.fillMaxWidth().testTag("pick-folder")) {
                    Text("Re-pick folder")
                }
                OutlinedButton(onClick = onDemo, modifier = Modifier.fillMaxWidth().testTag("open-demo")) {
                    Text("Open the demo vault")
                }
            }
        }
    }
}
