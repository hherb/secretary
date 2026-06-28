package org.secretary.browse

/**
 * Typed failures from the create-vault surface. Throwable (mirrors [VaultBrowseError] /
 * [org.secretary.sync.VaultSyncError]) so the provisioning coordinator can `catch (e: VaultProvisioningError)`.
 * Kotlin mirror of iOS `VaultProvisioningError`.
 */
sealed class VaultProvisioningError(message: String? = null) : Exception(message) {
    /** The target folder already exists and is non-empty (FFI `VaultFolderNotEmpty`). */
    data object FolderNotEmpty : VaultProvisioningError()

    /** The typed password and its confirmation did not match (UI pre-check, never from the FFI). */
    data object PasswordMismatch : VaultProvisioningError()

    /** Any other create failure, with a diagnostic detail (the mapper's else-fold). */
    data class CreateFailed(val detail: String) : VaultProvisioningError(detail)
}
