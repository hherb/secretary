package org.secretary.app

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import org.secretary.browse.MnemonicWord
import org.secretary.browse.VaultNameError
import org.secretary.browse.VaultProvisioningError
import org.secretary.browse.VaultProvisioningStep

/**
 * Create-vault wizard. Renders [VaultProvisioningStep]; all logic lives in
 * `VaultProvisioningViewModel`. `AppRoot` resolves the empty working dir and bridges the VM's fields
 * in. Password fields are String-backed (the typed String lingers until GC — same accepted tradeoff
 * as `UnlockScreen`); the credential byte buffers are owned + zeroized by `AppRoot`. Mirror of iOS
 * `CreateVaultWizardView`.
 */
@Composable
fun CreateVaultWizardScreen(
    step: VaultProvisioningStep,
    nameError: VaultNameError?,
    error: VaultProvisioningError?,
    isCreating: Boolean,
    mnemonicRows: List<MnemonicWord>?,
    onPickParent: () -> Unit,
    pickedFolderLabel: String?,
    onChooseFolder: (vaultName: String) -> Unit,
    onCreate: (password: String, confirm: String) -> Unit,
    onAcknowledge: () -> Unit,
    onCancel: () -> Unit,
) {
    val stepNumber = when (step) {
        is VaultProvisioningStep.Folder -> 1
        is VaultProvisioningStep.Credentials -> 2
        is VaultProvisioningStep.Mnemonic -> 3
        is VaultProvisioningStep.Done -> 3
    }
    SecretaryScreen {
        SecretaryBrandHeader(
            title = "Create a new vault",
            subtitle = "Step $stepNumber of 3 · encrypted from the very first save.",
        )
        LinearProgressIndicator(
            progress = { stepNumber / 3f },
            modifier = Modifier.fillMaxWidth(),
            color = MaterialTheme.colorScheme.secondary,
            trackColor = MaterialTheme.colorScheme.secondaryContainer,
        )
        SecretaryPanel {
            when (step) {
                is VaultProvisioningStep.Folder -> {
                    var name by remember { mutableStateOf("") }
                    Text("Choose a location", style = MaterialTheme.typography.titleLarge)
                    Text(
                        "Secretary creates an encrypted vault inside the cloud folder you choose.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    OutlinedButton(onClick = onPickParent, modifier = Modifier.fillMaxWidth().testTag("wizard-pick-parent")) {
                        Text(pickedFolderLabel?.let { "Folder: $it" } ?: "Choose a cloud folder")
                    }
                    OutlinedTextField(
                        value = name, onValueChange = { name = it },
                        label = { Text("Vault name") },
                        modifier = Modifier.fillMaxWidth().testTag("wizard-name"),
                    )
                    nameError?.let {
                        Text(
                            it.message ?: "Invalid name",
                            color = MaterialTheme.colorScheme.error,
                            modifier = Modifier.testTag("wizard-name-error"),
                        )
                    }
                    Button(onClick = { onChooseFolder(name) }, modifier = Modifier.fillMaxWidth().testTag("wizard-next")) {
                        Text("Continue")
                    }
                }
                is VaultProvisioningStep.Credentials -> {
                    var password by remember { mutableStateOf("") }
                    var confirm by remember { mutableStateOf("") }
                    Text("Protect your vault", style = MaterialTheme.typography.titleLarge)
                    Text(
                        "Use a strong password you can remember. Secretary cannot recover it for you.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    OutlinedTextField(
                        value = password, onValueChange = { password = it },
                        label = { Text("Master password") }, visualTransformation = PasswordVisualTransformation(),
                        modifier = Modifier.fillMaxWidth().testTag("wizard-password"),
                    )
                    OutlinedTextField(
                        value = confirm, onValueChange = { confirm = it },
                        label = { Text("Confirm password") }, visualTransformation = PasswordVisualTransformation(),
                        modifier = Modifier.fillMaxWidth().testTag("wizard-confirm"),
                    )
                    error?.let {
                        Text(
                            it.message ?: "Create failed",
                            color = MaterialTheme.colorScheme.error,
                            modifier = Modifier.testTag("wizard-error"),
                        )
                    }
                    Button(
                        onClick = { onCreate(password, confirm) },
                        enabled = !isCreating,
                        modifier = Modifier.fillMaxWidth().testTag("wizard-create"),
                    ) { Text(if (isCreating) "Creating…" else "Create vault") }
                }
                is VaultProvisioningStep.Mnemonic -> {
                    Text("Save your recovery phrase", style = MaterialTheme.typography.titleLarge)
                    Text(
                        "Write down these 24 words. They are the only way to recover this vault.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Column(modifier = Modifier.testTag("mnemonic-grid")) {
                        mnemonicRows.orEmpty().forEach {
                            Text(
                                "${it.index}. ${it.word}",
                                modifier = Modifier.padding(vertical = 3.dp),
                                style = MaterialTheme.typography.bodyLarge,
                            )
                        }
                    }
                    error?.let {
                        Text(
                            it.message ?: "Error",
                            color = MaterialTheme.colorScheme.error,
                            modifier = Modifier.testTag("wizard-error"),
                        )
                    }
                    Button(onClick = onAcknowledge, modifier = Modifier.fillMaxWidth().testTag("wizard-ack")) {
                        Text("I've written it down")
                    }
                }
                is VaultProvisioningStep.Done -> {
                    Text("Vault ready", style = MaterialTheme.typography.titleLarge)
                }
            }
        }
        OutlinedButton(onClick = onCancel, modifier = Modifier.fillMaxWidth().testTag("wizard-cancel")) {
            Text("Cancel")
        }
    }
}
