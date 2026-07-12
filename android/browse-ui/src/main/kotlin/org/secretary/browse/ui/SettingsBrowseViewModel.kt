package org.secretary.browse.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import org.secretary.browse.SettingsBanner
import org.secretary.browse.SettingsModel
import org.secretary.browse.VaultBrowseError

/**
 * Thin Compose bridge over the host-tested [SettingsModel]. Holds NO settings logic — it re-exposes
 * the model's StateFlows for `collectAsStateWithLifecycle` and launches the model's suspend save on
 * [viewModelScope]. Mirror of [TrashBrowseViewModel]; the injected [model] wraps `:kit`'s real
 * session (a `SettingsPort`) in production and a fake in tests; this class never touches the FFI.
 */
class SettingsBrowseViewModel(private val model: SettingsModel) : ViewModel() {
    val retentionDays: StateFlow<Int> = model.retentionDays
    val graceMinutes: StateFlow<Int> = model.graceMinutes
    val writing: StateFlow<Boolean> = model.writing
    val error: StateFlow<VaultBrowseError?> = model.error
    val notice: StateFlow<SettingsBanner?> = model.notice

    val retentionDaysRange: IntRange get() = model.retentionDaysRange
    val graceMinutesRange: IntRange get() = model.graceMinutesRange

    /** Load the persisted settings into the two controls (synchronous read). */
    fun load() = model.load()

    fun setRetentionDays(days: Int) = model.setRetentionDays(days)
    fun setGraceMinutes(minutes: Int) = model.setGraceMinutes(minutes)

    /** Gated save (re-auth → write → retarget-after-save); runs the model's suspend save. */
    fun save() { viewModelScope.launch { model.save() } }
}
