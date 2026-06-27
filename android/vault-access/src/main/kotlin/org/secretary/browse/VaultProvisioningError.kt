package org.secretary.browse

/**
 * Typed failures from the create-vault surface. Throwable (mirrors [VaultBrowseError] /
 * [org.secretary.sync.VaultSyncError]) so the provisioning coordinator can `catch (e: VaultProvisioningError)`.
 * Kotlin mirror of iOS `VaultProvisioningError`. Only the arms slice 1 can produce are defined here;
 * later slices (SAF mkdir, password pre-check) add `FolderInvalid` / `PasswordMismatch`.
 */
sealed class VaultProvisioningError(message: String? = null) : Exception(message) {
    /** The target folder already exists and is non-empty (FFI `VaultFolderNotEmpty`). */
    data object FolderNotEmpty : VaultProvisioningError()

    /** Any other create failure, with a diagnostic detail (the mapper's else-fold). */
    data class CreateFailed(val detail: String) : VaultProvisioningError(detail)
}
