package org.secretary.browse

/**
 * What the vault-selection screen shows. [Empty] — nothing remembered. [Located] — a remembered,
 * accessible vault (offer Open). [Unavailable] — a remembered vault whose SAF permission is gone
 * or whose open failed (offer re-pick); the reason survives a screen re-appear so the screen never
 * lies about being openable. Kotlin mirror of iOS `VaultSelectionState`.
 */
sealed interface VaultSelectionState {
    data object Empty : VaultSelectionState
    data class Located(val displayName: String) : VaultSelectionState
    data class Unavailable(val reason: String) : VaultSelectionState
}
