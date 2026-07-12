package org.secretary.browse.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.secretary.browse.VaultBrowseError

/**
 * The Android per-vault Settings screen — mirror of iOS `SettingsScreen`. Two controls: trash
 * retention (days) and re-auth grace (minutes), both validated against the projected FFI bounds.
 * Save routes through the model's write-reauth gate (a settings change is a vault write) and, on a
 * grace change, retargets the live gate. Distinct from the device-enrollment "Device settings"
 * screen (`open-settings`); this one is reached via `open-vault-settings`.
 *
 * Render stays host-untested (existing gap #417); the `testTag`s hook a future Compose assertion.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(viewModel: SettingsBrowseViewModel, onBack: () -> Unit) {
    val retentionDays by viewModel.retentionDays.collectAsStateWithLifecycle()
    val graceMinutes by viewModel.graceMinutes.collectAsStateWithLifecycle()
    val writing by viewModel.writing.collectAsStateWithLifecycle()
    val error by viewModel.error.collectAsStateWithLifecycle()
    val notice by viewModel.notice.collectAsStateWithLifecycle()

    LaunchedEffect(Unit) { viewModel.load() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Vault settings") },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("vault-settings-back")) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            error?.let { SettingsErrorBanner(it) }
            notice?.let {
                Text(
                    it.text,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.testTag("settings-notice"),
                )
            }
            NumberSettingField(
                label = "Trash retention (days)",
                value = retentionDays,
                range = viewModel.retentionDaysRange,
                enabled = !writing,
                onValueChange = viewModel::setRetentionDays,
                fieldTag = "settings-retention-days",
            )
            NumberSettingField(
                label = "Re-auth grace (minutes)",
                value = graceMinutes,
                range = viewModel.graceMinutesRange,
                enabled = !writing,
                onValueChange = viewModel::setGraceMinutes,
                fieldTag = "settings-grace-minutes",
            )
            Button(
                onClick = { viewModel.save() },
                enabled = !writing,
                modifier = Modifier.fillMaxWidth().testTag("settings-save"),
            ) { Text("Save") }
        }
    }
}

/**
 * A numeric settings input bound to a clamped [Int] control. Typing routes through [onValueChange],
 * which clamps to [range] in the model, so the displayed value can never leave the valid range;
 * a blank/non-numeric entry is ignored (leaves the current value). The [range] is shown as a hint.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun NumberSettingField(
    label: String,
    value: Int,
    range: IntRange,
    enabled: Boolean,
    onValueChange: (Int) -> Unit,
    fieldTag: String,
) {
    OutlinedTextField(
        value = value.toString(),
        onValueChange = { text -> text.toIntOrNull()?.let(onValueChange) },
        label = { Text(label) },
        supportingText = { Text("${range.first}–${range.last}") },
        singleLine = true,
        enabled = enabled,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        modifier = Modifier.fillMaxWidth().testTag(fieldTag),
    )
}

@Composable
private fun SettingsErrorBanner(error: VaultBrowseError) {
    val text = when (error) {
        is VaultBrowseError.ReauthFailed -> "Couldn't authorize the change: ${error.detail}"
        else -> "Couldn't save settings: ${error::class.simpleName}"
    }
    Text(
        text = text,
        color = MaterialTheme.colorScheme.error,
        style = MaterialTheme.typography.bodyMedium,
        modifier = Modifier.fillMaxWidth().testTag("settings-error"),
    )
}
