package org.secretary.app

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp

/**
 * Minimal unlock surface for the walking skeleton: a masked password field + an "Unlock & Sync"
 * button. On submit it hands the password (UTF-8 bytes) to [onUnlock], which runs the real
 * makeVaultSync + silent sync (see [AppRoot]).
 *
 * Password hygiene: Compose `TextField` is String-backed (like iOS `SecureField`), so the typed
 * String lingers until GC — acceptable for this demo skeleton. The byte buffer derived on submit
 * IS zeroized by [AppRoot] after the pass. No vault plaintext is ever shown (sync-only; no browse).
 */
@Composable
fun UnlockScreen(onUnlock: (ByteArray) -> Unit) {
    var password by remember { mutableStateOf("") }

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("Secretary — demo vault")
        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text("Vault password") },
            visualTransformation = PasswordVisualTransformation(),
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Button(
            onClick = { onUnlock(password.toByteArray(Charsets.UTF_8)) },
            enabled = password.isNotEmpty(),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Unlock & Sync")
        }
    }
}
