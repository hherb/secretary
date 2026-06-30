package org.secretary.app

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import org.secretary.browse.RecoveryPhrase
import org.secretary.browse.UnlockCredential

/** The two unlock credentials the screen can produce. */
private enum class UnlockMode { Password, Recovery }

/**
 * Unlock surface for the walking skeleton: a Password/Recovery segmented toggle. Password mode is a
 * masked single-line field; recovery mode is a multi-line, unmasked 24-word phrase field (a dotted
 * 24-word phrase is unreadable, and the unlock moment is already trusted under FLAG_SECURE). On
 * submit it hands an [UnlockCredential] to [onUnlock] — password bytes, or the phrase normalized via
 * [RecoveryPhrase.normalize] then UTF-8 encoded. Mirror of iOS `UnlockViewModel.Mode` + segmented
 * control.
 *
 * Biometric affordances (C.3 slice 2):
 * - When [isEnrolled] is true, a "Unlock with biometrics" button (testTag `biometric-unlock`) is
 *   shown above the mode toggle; tapping it invokes [onBiometricUnlock] so AppRoot can drive the
 *   BiometricPrompt flow.
 * - When [isEnrolled] is false and the user is in Password mode, a "Remember this device with
 *   biometrics" checkbox (testTag `remember-device`) is shown below the password field. It is a
 *   controlled checkbox: [rememberDevice] drives its checked state and every toggle is reported via
 *   [onEnrollChoice], so AppRoot owns the single source of truth and can enroll the device after a
 *   successful password unlock.
 *
 * Password hygiene: Compose `TextField` is String-backed, so the typed String lingers until GC —
 * acceptable for this demo skeleton (same tradeoff as the password field). The credential's byte
 * buffer IS zeroized by [AppRoot] after the open pass.
 *
 * @param title Screen heading text; distinguishes demo vault from a named cloud target.
 * @param isUnlocking When true, disables every control and swaps the unlock button label for a
 *   [CircularProgressIndicator] during the multi-second vault open.
 * @param unsyncedCreateWarning When true, shows a persistent "created but not yet synced" banner
 *   above the title (#329).
 */
@Composable
fun UnlockScreen(
    title: String,
    isEnrolled: Boolean,
    rememberDevice: Boolean,
    isUnlocking: Boolean,
    onUnlock: (UnlockCredential) -> Unit,
    onEnrollChoice: (Boolean) -> Unit,
    onBiometricUnlock: () -> Unit,
    unsyncedCreateWarning: Boolean = false,
) {
    var mode by remember { mutableStateOf(UnlockMode.Password) }
    var password by remember { mutableStateOf("") }
    var phrase by remember { mutableStateOf("") }

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        if (unsyncedCreateWarning) {
            Text(
                "Vault created but not yet synced — keep this device online and reopen to " +
                    "finish the upload. The vault currently exists only on this device.",
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.fillMaxWidth().testTag("unsynced-create-warning"),
            )
        }

        Text(title)

        if (isEnrolled) {
            Button(
                onClick = onBiometricUnlock,
                enabled = !isUnlocking,
                modifier = Modifier.fillMaxWidth().testTag("biometric-unlock"),
            ) { Text("Unlock with biometrics") }
        }

        SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
            SegmentedButton(
                selected = mode == UnlockMode.Password,
                onClick = { mode = UnlockMode.Password },
                enabled = !isUnlocking,
                shape = SegmentedButtonDefaults.itemShape(index = 0, count = 2),
                modifier = Modifier.testTag("mode-password"),
            ) { Text("Password") }
            SegmentedButton(
                selected = mode == UnlockMode.Recovery,
                onClick = { mode = UnlockMode.Recovery },
                enabled = !isUnlocking,
                shape = SegmentedButtonDefaults.itemShape(index = 1, count = 2),
                modifier = Modifier.testTag("mode-recovery"),
            ) { Text("Recovery phrase") }
        }

        when (mode) {
            UnlockMode.Password -> Column {
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text("Vault password") },
                    visualTransformation = PasswordVisualTransformation(),
                    singleLine = true,
                    enabled = !isUnlocking,
                    modifier = Modifier.fillMaxWidth().testTag("password-field"),
                )
                if (!isEnrolled) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(
                            checked = rememberDevice,
                            onCheckedChange = onEnrollChoice,
                            enabled = !isUnlocking,
                            modifier = Modifier.testTag("remember-device"),
                        )
                        Text("Remember this device with biometrics")
                    }
                }
            }
            UnlockMode.Recovery -> OutlinedTextField(
                value = phrase,
                onValueChange = { phrase = it },
                label = { Text("24-word recovery phrase") },
                singleLine = false,
                minLines = 3,
                enabled = !isUnlocking,
                modifier = Modifier.fillMaxWidth().testTag("recovery-field"),
            )
        }

        Button(
            onClick = {
                val credential = when (mode) {
                    UnlockMode.Password ->
                        UnlockCredential.Password(password.toByteArray(Charsets.UTF_8))
                    UnlockMode.Recovery ->
                        UnlockCredential.Recovery(
                            RecoveryPhrase.normalize(phrase).toByteArray(Charsets.UTF_8))
                }
                onUnlock(credential)
            },
            enabled = !isUnlocking && when (mode) {
                UnlockMode.Password -> password.isNotEmpty()
                UnlockMode.Recovery -> phrase.isNotBlank()
            },
            modifier = Modifier.fillMaxWidth().testTag("unlock-button"),
        ) {
            if (isUnlocking) {
                CircularProgressIndicator(modifier = Modifier.testTag("unlock-progress"))
            } else {
                Text(if (mode == UnlockMode.Password) "Unlock & Sync" else "Unlock")
            }
        }
    }
}
