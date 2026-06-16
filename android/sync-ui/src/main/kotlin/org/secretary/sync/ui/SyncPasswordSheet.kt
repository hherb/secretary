package org.secretary.sync.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ModalBottomSheet
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
import org.secretary.sync.VaultSyncError

/** Test tag for the password [OutlinedTextField] inside [PasswordSheetContent]. */
const val PASSWORD_FIELD_TAG = "password-field"

/** Test tag for the inline error [Text] inside [PasswordSheetContent]. */
const val PASSWORD_ERROR_TAG = "password-error"

private val SHEET_PADDING = 16.dp
private val SHEET_GAP = 12.dp

/**
 * Bottom-sheet wrapper. Shown only when [visible]; dismissal routes through [onDismiss]. The
 * testable body lives in [PasswordSheetContent] so unit-rendering tests skip the sheet window.
 *
 * @param visible Whether the sheet is currently open. When `false` the composable emits nothing.
 * @param error   Non-null error to display inline after a failed sync attempt (e.g.
 *                [VaultSyncError.WrongPasswordOrCorrupt]). The sheet stays open on failure;
 *                it is the caller's responsibility to keep [visible] = `true` until success.
 * @param onSubmit  Called with the UTF-8 bytes of the entered password when the user taps Sync.
 *                  The field is cleared immediately before this callback fires so the [String]
 *                  lifetime is minimised (though [String] is immutable — see [PasswordSheetContent]).
 * @param onDismiss Called when the user dismisses the sheet (swipe-down or Cancel).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SyncPasswordSheet(
    visible: Boolean,
    error: VaultSyncError?,
    onSubmit: (ByteArray) -> Unit,
    onDismiss: () -> Unit,
) {
    if (!visible) return
    ModalBottomSheet(onDismissRequest = onDismiss) {
        PasswordSheetContent(error = error, onSubmit = onSubmit, onDismiss = onDismiss)
    }
}

/**
 * The password-entry body, decoupled from [SyncPasswordSheet] so that instrumented tests can
 * set it as the top-level composition content and skip the bottom-sheet window and animation.
 *
 * **Security notes:**
 * - The password lives only in transient `remember` state (NOT `rememberSaveable`), so it is
 *   never persisted or included in saved-state bundles.
 * - The [String] backing the [OutlinedTextField] is immutable on the JVM; we cannot zeroize it.
 *   Minimising lifetime is the practical mitigation: the field is cleared (`password = ""`) on
 *   every terminal path (Submit and Cancel) before the callback fires, so the old string becomes
 *   unreachable as quickly as composition allows.
 * - The [ByteArray] forwarded to [onSubmit] is the caller's responsibility to zeroize after use.
 *
 * @param error     Non-null error to display inline; `null` = no error row rendered.
 * @param onSubmit  Receives the UTF-8 byte encoding of the entered password.
 * @param onDismiss Invoked when the user taps Cancel.
 */
@Composable
fun PasswordSheetContent(
    error: VaultSyncError?,
    onSubmit: (ByteArray) -> Unit,
    onDismiss: () -> Unit,
) {
    var password by remember { mutableStateOf("") }
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(SHEET_PADDING),
        verticalArrangement = Arrangement.spacedBy(SHEET_GAP),
    ) {
        Text(text = "Enter your vault password to sync")
        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text("Password") },
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            modifier = Modifier
                .fillMaxWidth()
                .testTag(PASSWORD_FIELD_TAG),
        )
        if (error != null) {
            Text(
                text = syncErrorLabel(error),
                modifier = Modifier.testTag(PASSWORD_ERROR_TAG),
            )
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.End,
        ) {
            TextButton(onClick = {
                password = ""
                onDismiss()
            }) {
                Text("Cancel")
            }
            Button(onClick = {
                val bytes = password.toByteArray()
                password = "" // clear ASAP; String is immutable so this is minimal-lifetime, not true zeroize
                onSubmit(bytes)
            }) {
                Text("Sync")
            }
        }
    }
}
