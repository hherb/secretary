package org.secretary.app

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
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
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("Create a new vault")
        when (step) {
            is VaultProvisioningStep.Folder -> {
                var name by remember { mutableStateOf("") }
                OutlinedButton(onClick = onPickParent, modifier = Modifier.fillMaxWidth().testTag("wizard-pick-parent")) {
                    Text(pickedFolderLabel?.let { "Folder: $it" } ?: "Choose a cloud folder")
                }
                OutlinedTextField(
                    value = name, onValueChange = { name = it },
                    label = { Text("Vault name") },
                    modifier = Modifier.fillMaxWidth().testTag("wizard-name"),
                )
                nameError?.let { Text(it.message ?: "Invalid name", modifier = Modifier.testTag("wizard-name-error")) }
                Button(onClick = { onChooseFolder(name) }, modifier = Modifier.fillMaxWidth().testTag("wizard-next")) {
                    Text("Next")
                }
            }
            is VaultProvisioningStep.Credentials -> {
                var password by remember { mutableStateOf("") }
                var confirm by remember { mutableStateOf("") }
                OutlinedTextField(
                    value = password, onValueChange = { password = it },
                    label = { Text("Password") }, visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth().testTag("wizard-password"),
                )
                OutlinedTextField(
                    value = confirm, onValueChange = { confirm = it },
                    label = { Text("Confirm password") }, visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth().testTag("wizard-confirm"),
                )
                error?.let { Text(it.message ?: "Create failed", modifier = Modifier.testTag("wizard-error")) }
                Button(
                    onClick = { onCreate(password, confirm) },
                    enabled = !isCreating,
                    modifier = Modifier.fillMaxWidth().testTag("wizard-create"),
                ) { Text(if (isCreating) "Creating…" else "Create vault") }
            }
            is VaultProvisioningStep.Mnemonic -> {
                Text("Write down these 24 words. They are the only way to recover this vault.")
                Column(modifier = Modifier.testTag("mnemonic-grid"), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    mnemonicRows.orEmpty().forEach { Text("${it.index}. ${it.word}") }
                }
                error?.let { Text(it.message ?: "Error", modifier = Modifier.testTag("wizard-error")) }
                Button(onClick = onAcknowledge, modifier = Modifier.fillMaxWidth().testTag("wizard-ack")) {
                    Text("I've written it down")
                }
            }
            is VaultProvisioningStep.Done -> {
                Text("Vault ready.")
            }
        }
        OutlinedButton(onClick = onCancel, modifier = Modifier.fillMaxWidth().testTag("wizard-cancel")) {
            Text("Cancel")
        }
    }
}
