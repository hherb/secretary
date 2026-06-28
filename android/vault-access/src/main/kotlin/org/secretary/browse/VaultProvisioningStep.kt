package org.secretary.browse

/**
 * The create-vault wizard's position. [Folder] — pick a parent SAF tree + type a name. [Credentials]
 * — carries the picked [treeUri] + validated [vaultName] while the user enters a password. [Mnemonic]
 * — the created vault's recovery phrase is being shown. [Done] — finished; carries the persisted
 * [location] so `AppRoot` can route to open. Kotlin mirror of iOS `VaultProvisioningStep`.
 */
sealed interface VaultProvisioningStep {
    data object Folder : VaultProvisioningStep
    data class Credentials(val treeUri: String, val vaultName: String) : VaultProvisioningStep
    data object Mnemonic : VaultProvisioningStep
    data class Done(val location: VaultLocation) : VaultProvisioningStep
}
