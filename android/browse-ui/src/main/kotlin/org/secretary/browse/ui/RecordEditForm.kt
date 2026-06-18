package org.secretary.browse.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.secretary.browse.EditableField
import org.secretary.browse.FieldKind
import org.secretary.browse.RecordEditModel

/**
 * The add/edit record form — the third [BrowseScreen] state. Binds directly to the pure
 * [RecordEditModel]'s StateFlows and calls its mutators on each edit; [onCommit] / [onCancel] are the
 * suspend-bridged actions owned by the view model. Mirror of iOS `RecordEditScreen`.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RecordEditForm(
    model: RecordEditModel,
    onCommit: () -> Unit,
    onCancel: () -> Unit,
) {
    val recordType by model.recordType.collectAsStateWithLifecycle()
    val tags by model.tags.collectAsStateWithLifecycle()
    val fields by model.fields.collectAsStateWithLifecycle()
    val error by model.error.collectAsStateWithLifecycle()
    val loadFailed by model.loadFailed.collectAsStateWithLifecycle()
    val inFlight by model.inFlight.collectAsStateWithLifecycle()

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            TextButton(onClick = onCancel, modifier = Modifier.testTag("cancel-record")) { Text("Cancel") }
            TextButton(
                onClick = onCommit,
                enabled = !loadFailed && !inFlight,
                modifier = Modifier.testTag("save-record"),
            ) { Text("Save") }
        }
        error?.let {
            // Prefer the typed arm's detail (e.g. "field 'x' is not valid hex", "duplicate field
            // name: y") over the bare class name; fall back to the class name for message-less arms.
            val detail = it.message?.takeIf(String::isNotBlank) ?: it::class.simpleName
            Text(
                text = "Couldn't save: $detail",
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium,
            )
        }
        OutlinedTextField(
            value = recordType,
            onValueChange = model::setRecordType,
            label = { Text("Type") },
            modifier = Modifier.fillMaxWidth().testTag("record-type-input"),
        )
        LazyColumn(modifier = Modifier.fillMaxSize()) {
            items(tags.indices.toList()) { i ->
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    OutlinedTextField(
                        value = tags[i],
                        onValueChange = { model.setTag(i, it) },
                        label = { Text("Tag") },
                        modifier = Modifier.weight(1f).testTag("tag-$i"),
                    )
                    TextButton(onClick = { model.removeTag(i) }) { Text("Remove") }
                }
            }
            item {
                TextButton(onClick = model::addTag, modifier = Modifier.testTag("add-tag")) { Text("Add tag") }
                HorizontalDivider()
            }
            items(fields, key = { it.id }) { field ->
                FieldEditor(field, model)
                HorizontalDivider()
            }
            item {
                TextButton(onClick = model::addField, modifier = Modifier.testTag("add-field")) { Text("Add field") }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun FieldEditor(field: EditableField, model: RecordEditModel) {
    Column(modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            OutlinedTextField(
                value = field.name,
                onValueChange = { model.setFieldName(field.id, it) },
                label = { Text("Name") },
                modifier = Modifier.weight(1f).testTag("field-name-${field.id}"),
            )
            TextButton(onClick = { model.removeField(field.id) }) { Text("Remove") }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(
                selected = field.kind == FieldKind.Text,
                onClick = { model.setFieldKind(field.id, FieldKind.Text) },
                label = { Text("Text") },
                modifier = Modifier.testTag("field-kind-text-${field.id}"),
            )
            FilterChip(
                selected = field.kind == FieldKind.Bytes,
                onClick = { model.setFieldKind(field.id, FieldKind.Bytes) },
                label = { Text("Bytes (hex)") },
                modifier = Modifier.testTag("field-kind-bytes-${field.id}"),
            )
        }
        OutlinedTextField(
            value = field.rawText,
            onValueChange = { model.setFieldRawText(field.id, it) },
            label = { Text(if (field.kind == FieldKind.Bytes) "hex bytes" else "value") },
            modifier = Modifier.fillMaxWidth().testTag("field-value-${field.id}"),
        )
    }
}
