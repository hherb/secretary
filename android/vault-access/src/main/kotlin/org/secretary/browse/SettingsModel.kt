package org.secretary.browse

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Host-tested per-vault Settings model — Kotlin mirror of the shipped iOS `SettingsViewModel`.
 * Exposes two editable controls (retention window in days, re-auth grace in minutes), validated
 * client-side against the projected FFI [SettingsBounds]. A save routes through the shared re-auth
 * [gate] (a settings change is a vault write, so it obeys the same gate-integrity invariants as the
 * Trash destructive ops — [TrashBrowseModel.guardedWrite]), preserves the two round-tripped fields
 * the UI never edits (auto-lock, require-password), and — **strictly after a successful save** —
 * retargets the live gate to a changed grace window.
 *
 * Security ordering (load-bearing): the save is gated against the CURRENT (pre-save) grace window;
 * the retarget runs only on success (and only when the grace window changed). A user at an
 * unlocked-but-unattended session outside the current grace window therefore cannot widen their own
 * grace window to self-authorize the widening — the widening still demands a biometric proof. See
 * [RetargetableReauthGate.retargetWindow].
 *
 * Main-thread-confined like [TrashBrowseModel] (the injected gate is not thread-safe). [save] is
 * `suspend` because the real [SettingsPort] offloads the FFI write to IO.
 *
 * @param makeGraceGate builds the delegate for a NEW grace window (production:
 *   `{ w -> GraceWindowReauthGate(authorizer, clock, w) }`); invoked only on a grace-changing save.
 * @param nowMs monotonic clock (production: `SystemClock.elapsedRealtime`) — the instant the
 *   retargeted window opens from (a successful gated save just proved presence).
 */
class SettingsModel(
    private val port: SettingsPort,
    private val gate: RetargetableReauthGate,
    private val makeGraceGate: (windowMs: Long) -> WriteReauthGate,
    private val nowMs: () -> Long,
) {
    private val bounds: SettingsBounds = port.settingsBounds()

    private val _retentionDays = MutableStateFlow(retentionDaysFromMs(bounds.retentionDefaultMs))
    val retentionDays: StateFlow<Int> = _retentionDays.asStateFlow()

    private val _graceMinutes = MutableStateFlow(graceMinutesFromMs(bounds.reauthGraceDefaultMs))
    val graceMinutes: StateFlow<Int> = _graceMinutes.asStateFlow()

    private val _writing = MutableStateFlow(false)
    /** True while a save is in flight — disables the Save button + inputs. */
    val writing: StateFlow<Boolean> = _writing.asStateFlow()

    private val _error = MutableStateFlow<VaultBrowseError?>(null)
    val error: StateFlow<VaultBrowseError?> = _error.asStateFlow()

    private val _notice = MutableStateFlow<SettingsBanner?>(null)
    /** Set on a successful save; cleared at the start of any new save. */
    val notice: StateFlow<SettingsBanner?> = _notice.asStateFlow()

    /** The valid retention-days range (from the projected bounds) — one source with the client clamp. */
    val retentionDaysRange: IntRange =
        retentionDaysFromMs(bounds.retentionMinMs)..retentionDaysFromMs(bounds.retentionMaxMs)

    /** The valid grace-minutes range (from the projected bounds). */
    val graceMinutesRange: IntRange =
        graceMinutesFromMs(bounds.reauthGraceMinMs)..graceMinutesFromMs(bounds.reauthGraceMaxMs)

    /**
     * Load the persisted settings into the two controls. On a hard read error (corrupt vault —
     * unreachable for a normally-opened vault) the controls fall back to the bounds defaults and
     * [error] is surfaced. The two UI-less fields are NOT cached here — [save] re-reads them fresh,
     * so a save can never write back a stale placeholder.
     */
    fun load() {
        _error.value = null
        try {
            val s = port.readSettings()
            _retentionDays.value = clampRetentionDays(retentionDaysFromMs(s.retentionWindowMs), bounds)
            _graceMinutes.value = clampGraceMinutes(graceMinutesFromMs(s.reauthGraceWindowMs), bounds)
        } catch (e: VaultBrowseError) {
            _error.value = e
            _retentionDays.value = retentionDaysFromMs(bounds.retentionDefaultMs)
            _graceMinutes.value = graceMinutesFromMs(bounds.reauthGraceDefaultMs)
        }
    }

    /** Set the retention-days control, clamped to the projected bounds. */
    fun setRetentionDays(days: Int) { _retentionDays.value = clampRetentionDays(days, bounds) }

    /** Set the grace-minutes control, clamped to the projected bounds. */
    fun setGraceMinutes(minutes: Int) { _graceMinutes.value = clampGraceMinutes(minutes, bounds) }

    /**
     * Gated save: re-auth against the current window → re-read the persisted settings and merge only
     * the two edited fields (retention + grace) onto the two unedited ones → persist all four → on
     * success retarget the gate to the new grace window (only when it changed) + show the banner.
     *
     * The re-read (not a cached load value) supplies the two UI-less fields, so a save can never write
     * a stale placeholder (a save before [load], or after a load that threw) and it closes the
     * load→save TOCTOU against another client. [_writing] is set before the gate await so a second
     * save during the biometric prompt is rejected. Mirror of [TrashBrowseModel.guardedWrite] +
     * shipped iOS `SettingsViewModel.save`.
     */
    suspend fun save() {
        if (_writing.value) return
        _writing.value = true
        _notice.value = null
        _error.value = null
        try {
            // Gate the save against the CURRENT (pre-save) grace window. CancellationException is NOT
            // caught here (it propagates past these DeviceUnlockError catches) — do NOT widen.
            try {
                gate.authorizeWrite("Confirm changing vault settings")
            } catch (e: DeviceUnlockError.UserCancelled) {
                return // silent: no write, no retarget, no notice
            } catch (e: DeviceUnlockError) {
                _error.value = VaultBrowseError.ReauthFailed(reauthFailedMessage(e))
                return
            }

            // Re-read the persisted settings for the two unedited fields; abort on a read error
            // (no write on failure, so nothing is clobbered).
            val current = try {
                port.readSettings()
            } catch (e: VaultBrowseError) {
                _error.value = e
                return
            }

            val newSettings = current.copy(
                reauthGraceWindowMs = msFromGraceMinutes(_graceMinutes.value),
                retentionWindowMs = msFromRetentionDays(_retentionDays.value),
            )

            try {
                port.writeSettings(newSettings)
            } catch (e: VaultBrowseError) {
                _error.value = e
                return
            }

            // SUCCESS — retarget strictly AFTER the write (so the save was evaluated against the
            // pre-save window), and ONLY when the grace window changed. `retargetWindow` reseeds
            // presence to `now`; sliding the window on a retention-only edit would extend the
            // unattended-write window past the anchor of the user's last real authentication.
            if (newSettings.reauthGraceWindowMs != current.reauthGraceWindowMs) {
                gate.retargetWindow(makeGraceGate(newSettings.reauthGraceWindowMs), nowMs())
            }
            _notice.value = settingsSavedBanner()
        } finally {
            _writing.value = false
        }
    }
}
