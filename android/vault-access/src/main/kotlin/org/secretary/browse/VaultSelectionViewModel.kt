package org.secretary.browse

/** User-safe reason shown when a remembered vault's SAF grant is no longer held. */
const val PERMISSION_REVOKED_REASON =
    "This vault's folder is no longer accessible — re-pick it to continue."

/**
 * Drives the vault-selection screen over a [VaultLocationStore]. Plain class with a mutable [state]
 * field (mirrors `DeviceSettingsViewModel`); `AppRoot` bridges it into Compose. Fully host-testable —
 * holds only the injected store. Mirror of iOS `VaultSelectionViewModel`, minus iOS `beginAccess` /
 * shape-probe: resolving a SAF tree to an operable path is the working-copy materialize step (Slice 5).
 */
class VaultSelectionViewModel(private val store: VaultLocationStore) {
    var state: VaultSelectionState = VaultSelectionState.Empty
        private set

    /**
     * Recompute state from the persisted store. A surfaced [VaultSelectionState.Unavailable] is
     * preserved, NOT silently downgraded — a failed open's reason must survive a re-appear, or the
     * user gets an Open button that just fails again. The user clears it via [chooseDifferent] or a
     * fresh [recordSelection].
     */
    fun loadPersisted() {
        if (state is VaultSelectionState.Unavailable) return
        val loc = store.load()
        state = when {
            loc == null -> VaultSelectionState.Empty
            !store.isAvailable(loc) -> VaultSelectionState.Unavailable(PERMISSION_REVOKED_REASON)
            else -> VaultSelectionState.Located(loc.displayName)
        }
    }

    /** Remember a freshly picked vault and locate it. */
    fun recordSelection(location: VaultLocation) {
        store.persist(location)
        state = VaultSelectionState.Located(location.displayName)
    }

    /**
     * Surface [reason] as [VaultSelectionState.Unavailable] (e.g. a Slice-5 materialize/permission
     * failure). The remembered location is RETAINED — losing the user's selection silently would be
     * wrong; they re-pick or choose-different explicitly.
     */
    fun markUnavailable(reason: String) {
        state = VaultSelectionState.Unavailable(reason)
    }

    /** Forget the remembered vault and return to empty. */
    fun chooseDifferent() {
        store.clear()
        state = VaultSelectionState.Empty
    }
}
