package org.secretary.app

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import org.secretary.browse.DeviceSettingsState

/**
 * Device-management Settings surface. A pure function of [state] + callbacks (no view-model
 * reference), so it is driven directly in instrumented tests. [onEnroll] receives the password bytes
 * collected by the enroll dialog — AppRoot forwards them to the VM and zeroizes them after.
 *
 * Password hygiene: the dialog's `String`-backed field lingers until GC (same demo-skeleton tradeoff
 * as `UnlockScreen`); the derived `ByteArray` is owned (and zeroized) by AppRoot's [onEnroll] lambda.
 */
@Composable
fun DeviceSettingsScreen(
    state: DeviceSettingsState,
    onEnroll: (password: ByteArray) -> Unit,
    onDisenroll: () -> Unit,
    onBack: () -> Unit,
) {
    var showEnrollDialog by remember { mutableStateOf(false) }
    var showDisenrollDialog by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("Device settings")
        Text(
            text = if (state.enrolled) {
                "This device is enrolled for biometric unlock."
            } else {
                "This device is not enrolled for biometric unlock."
            },
            modifier = Modifier.testTag("device-status"),
        )

        val error = state.error
        if (error != null) {
            Text(text = error, modifier = Modifier.testTag("device-error"))
        }

        if (state.enrolled) {
            Button(
                onClick = { showDisenrollDialog = true },
                enabled = !state.working,
                modifier = Modifier.fillMaxWidth().testTag("disenroll-button"),
            ) { Text("Disable biometric unlock") }
        } else {
            Button(
                onClick = { showEnrollDialog = true },
                enabled = !state.working,
                modifier = Modifier.fillMaxWidth().testTag("enroll-button"),
            ) { Text("Enable biometric unlock") }
        }

        OutlinedButton(
            onClick = onBack,
            modifier = Modifier.fillMaxWidth().testTag("settings-back"),
        ) { Text("Back") }
    }

    if (showEnrollDialog) {
        EnrollPasswordDialog(
            onConfirm = { password ->
                showEnrollDialog = false
                onEnroll(password.toByteArray(Charsets.UTF_8))
            },
            onDismiss = { showEnrollDialog = false },
        )
    }

    if (showDisenrollDialog) {
        AlertDialog(
            onDismissRequest = { showDisenrollDialog = false },
            title = { Text("Disable biometric unlock?") },
            text = { Text("You will need your password to open this vault next time.") },
            confirmButton = {
                TextButton(
                    onClick = { showDisenrollDialog = false; onDisenroll() },
                    modifier = Modifier.testTag("disenroll-confirm"),
                ) { Text("Disable") }
            },
            dismissButton = { TextButton(onClick = { showDisenrollDialog = false }) { Text("Cancel") } },
        )
    }
}

/** Password re-prompt for enroll-from-settings; confirm is disabled until a password is entered. */
@Composable
private fun EnrollPasswordDialog(onConfirm: (String) -> Unit, onDismiss: () -> Unit) {
    var password by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Enable biometric unlock") },
        text = {
            OutlinedTextField(
                value = password,
                onValueChange = { password = it },
                label = { Text("Vault password") },
                visualTransformation = PasswordVisualTransformation(),
                singleLine = true,
                modifier = Modifier.fillMaxWidth().testTag("enroll-password-field"),
            )
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(password) },
                enabled = password.isNotEmpty(),
                modifier = Modifier.testTag("enroll-confirm"),
            ) { Text("Enable") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
