package org.secretary.app

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
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
    SecretaryScreen {
        SecretaryBrandHeader(
            title = "Your private vault",
            subtitle = "Passwords and private records, encrypted on every device.",
        )
        SecretaryPanel {
            when (state) {
                is VaultSelectionState.Empty -> {
                    Text("Get started", style = MaterialTheme.typography.titleLarge)
                    Text(
                        "Create a new vault or reconnect one from your cloud folder.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Button(onClick = onCreate, modifier = Modifier.fillMaxWidth().testTag("create-vault")) {
                        Text("Create new vault")
                    }
                    OutlinedButton(onClick = onPickFolder, modifier = Modifier.fillMaxWidth().testTag("pick-folder")) {
                        Text("Open an existing vault folder")
                    }
                    OutlinedButton(onClick = onDemo, modifier = Modifier.fillMaxWidth().testTag("open-demo")) {
                        Text("Explore the demo vault")
                    }
                }
                is VaultSelectionState.Located -> {
                    Text("Welcome back", style = MaterialTheme.typography.titleLarge)
                    Text(
                        state.displayName,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        style = MaterialTheme.typography.bodyLarge,
                    )
                    Button(onClick = onOpen, modifier = Modifier.fillMaxWidth().testTag("open-vault")) {
                        Text("Open vault")
                    }
                    OutlinedButton(onClick = onChooseDifferent, modifier = Modifier.fillMaxWidth().testTag("choose-different")) {
                        Text("Choose a different vault")
                    }
                }
                is VaultSelectionState.Unavailable -> {
                    Text("Vault unavailable", style = MaterialTheme.typography.titleLarge)
                    Text(
                        state.reason,
                        color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.testTag("selection-reason"),
                    )
                    Button(onClick = onPickFolder, modifier = Modifier.fillMaxWidth().testTag("pick-folder")) {
                        Text("Reconnect folder")
                    }
                    OutlinedButton(onClick = onDemo, modifier = Modifier.fillMaxWidth().testTag("open-demo")) {
                        Text("Explore the demo vault")
                    }
                }
            }
        }
    }
}
