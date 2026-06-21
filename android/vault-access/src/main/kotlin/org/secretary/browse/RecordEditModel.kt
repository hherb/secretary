package org.secretary.browse

import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * One editable field row. [rawText] holds plaintext for [FieldKind.Text] fields and a hex string for
 * [FieldKind.Bytes] fields (the only byte-entry affordance this slice). [id] is a stable synthetic
 * key for Compose list stability — a monotonic counter, NOT crypto, never reaching the vault. Mirror
 * of iOS `EditableField`.
 */
data class EditableField(
    val id: Long,
    val name: String = "",
    val kind: FieldKind = FieldKind.Text,
    val rawText: String = "",
)

/**
 * Drives the add/edit record form. Host-testable with [FakeVaultSession]. Pure mirror of iOS
 * `RecordEditViewModel` (which is a Combine ObservableObject); here the form state is exposed as
 * [StateFlow]s with explicit mutators, consistent with [VaultBrowseModel]. On a successful [commit]
 * it sets [committed] (the screen dismisses + the browse model re-reads); on failure it sets a typed
 * [error] and writes nothing.
 *
 * Secret hygiene: [fields]'s [EditableField.rawText] holds revealed plaintext for the edit duration
 * (accepted, scoped — matches iOS). The owning [VaultBrowseModel] drops this model on
 * cancel / commit / lock.
 */
class RecordEditModel(
    private val session: VaultSession,
    private val blockUuid: ByteArray,
    val mode: Mode,
    private val gate: WriteReauthGate = NoopReauthGate,
) {
    /** Add a brand-new record, or replace an existing one identified by its 16-byte UUID. */
    sealed interface Mode {
        data object Add : Mode
        data class Edit(val recordUuid: ByteArray) : Mode
    }

    private val _recordType = MutableStateFlow("")
    val recordType: StateFlow<String> = _recordType.asStateFlow()

    private val _tags = MutableStateFlow<List<String>>(emptyList())
    val tags: StateFlow<List<String>> = _tags.asStateFlow()

    private val _fields = MutableStateFlow<List<EditableField>>(emptyList())
    val fields: StateFlow<List<EditableField>> = _fields.asStateFlow()

    private val _error = MutableStateFlow<VaultBrowseError?>(null)
    val error: StateFlow<VaultBrowseError?> = _error.asStateFlow()

    private val _committed = MutableStateFlow(false)
    val committed: StateFlow<Boolean> = _committed.asStateFlow()

    private val _inFlight = MutableStateFlow(false)
    /** True while a [commit] write is in flight. Blocks a concurrent second commit; the UI also
     *  disables Save while set. Reset in [commit]'s finally on success, typed error, and raw throwable. */
    val inFlight: StateFlow<Boolean> = _inFlight.asStateFlow()

    private val _loadFailed = MutableStateFlow(false)
    /** Set by [load] on a reveal failure; while true, [commit] refuses to write (never clobber a
     *  record we could not fully read). A fresh model (always built per-edit) starts clean. */
    val loadFailed: StateFlow<Boolean> = _loadFailed.asStateFlow()

    private var nextFieldId: Long = 0

    fun setRecordType(value: String) { _recordType.value = value }

    /** Append a blank field row with a fresh deterministic [EditableField.id]. */
    fun addField() {
        _fields.value = _fields.value + EditableField(id = nextFieldId++)
    }

    fun removeField(id: Long) { _fields.value = _fields.value.filterNot { it.id == id } }

    fun setFieldName(id: Long, name: String) = mutateField(id) { it.copy(name = name) }
    fun setFieldKind(id: Long, kind: FieldKind) = mutateField(id) { it.copy(kind = kind) }
    fun setFieldRawText(id: Long, rawText: String) = mutateField(id) { it.copy(rawText = rawText) }

    private inline fun mutateField(id: Long, transform: (EditableField) -> EditableField) {
        _fields.value = _fields.value.map { if (it.id == id) transform(it) else it }
    }

    fun addTag() { _tags.value = _tags.value + "" }
    fun setTag(index: Int, value: String) {
        _tags.value = _tags.value.toMutableList().also { if (index in it.indices) it[index] = value }
    }
    fun removeTag(index: Int) {
        _tags.value = _tags.value.toMutableList().also { if (index in it.indices) it.removeAt(index) }
    }

    /**
     * Prefill from an existing record for editing, revealing each field into a row (text → plaintext,
     * bytes → lowercase hex). A reveal that throws is captured into [error] + [loadFailed] instead of
     * propagating. Mirror of iOS `RecordEditViewModel.load`.
     */
    fun load(record: RecordSummaryView) {
        try {
            _recordType.value = record.type
            _tags.value = record.tags
            _fields.value = record.fields.map { field ->
                when (val revealed = field.reveal()) {
                    is RevealedValue.Text -> EditableField(nextFieldId++, field.name, FieldKind.Text, revealed.value)
                    is RevealedValue.Bytes -> EditableField(nextFieldId++, field.name, FieldKind.Bytes, hexOfBytes(revealed.value))
                }
            }
            _loadFailed.value = false
        } catch (e: VaultBrowseError) {
            _error.value = e
            _loadFailed.value = true
        } catch (e: Exception) {
            _error.value = VaultBrowseError.Failed(e.toString())
            _loadFailed.value = true
        }
    }

    /**
     * Build → validate → write. Sets [committed] on success; sets [error] and writes nothing on any
     * validation or FFI failure. Refuses to run while [loadFailed]. Mirror of iOS
     * `RecordEditViewModel.commit`.
     */
    suspend fun commit() {
        if (_inFlight.value || _committed.value || _loadFailed.value) return
        _inFlight.value = true
        try {
            val content = buildContent() ?: return // sets _error on hex failure
            content.validate()?.let {
                _error.value = mapValidation(it)
                return
            }
            try {
                gate.authorizeWrite("Confirm saving this entry")
            } catch (e: DeviceUnlockError.UserCancelled) {
                return // silent: no write, no error; the edit form stays open
            } catch (e: DeviceUnlockError) {
                _error.value = VaultBrowseError.ReauthFailed(e.toString())
                return
            }
            try {
                when (val m = mode) {
                    Mode.Add -> session.appendRecord(blockUuid, content)
                    is Mode.Edit -> session.editRecord(blockUuid, m.recordUuid, content)
                }
                _error.value = null
                _committed.value = true
            } catch (e: VaultBrowseError) {
                _error.value = e
            } catch (e: CancellationException) {
                throw e // never swallow coroutine cancellation (commit is suspend)
            } catch (e: Exception) {
                // Mirror load()/reveal(): an unexpected throwable from the FFI write (e.g. a uniffi
                // InternalException from a Rust panic — NOT a VaultException, so mapErrors lets it
                // through) must not escape commit() and crash the launching coroutine. Fold to Failed.
                _error.value = VaultBrowseError.Failed(e.toString())
            }
        } finally {
            _inFlight.value = false
        }
    }

    /** Map the form rows to input fields, parsing hex for byte fields. Returns null + sets [error]
     *  on the first invalid-hex field; drops blank tags. */
    private fun buildContent(): RecordContentInput? {
        val built = ArrayList<FieldContentInput>(_fields.value.size)
        for (f in _fields.value) {
            val value = when (f.kind) {
                FieldKind.Text -> FieldContentValue.Text(f.rawText)
                FieldKind.Bytes -> {
                    val bytes = parseHexLenient(f.rawText)
                        ?: run {
                            _error.value = VaultBrowseError.InvalidArgument("field '${f.name}' is not valid hex")
                            return null
                        }
                    FieldContentValue.Bytes(bytes)
                }
            }
            built += FieldContentInput(f.name, value)
        }
        val cleanTags = _tags.value.map { it.trim() }.filter { it.isNotEmpty() }
        return RecordContentInput(_recordType.value, cleanTags, built)
    }

    private fun mapValidation(v: RecordContentInputError): VaultBrowseError = when (v) {
        RecordContentInputError.EmptyFieldName -> VaultBrowseError.InvalidArgument("a field name is empty")
        is RecordContentInputError.DuplicateFieldName -> VaultBrowseError.InvalidArgument("duplicate field name: ${v.name}")
    }
}
