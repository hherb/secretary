package org.secretary.browse

/** Plain value compare of the typed password and its confirmation. Not constant-time, and it need
 *  not be: both are caller-owned local buffers (user-typed), neither is compared against a stored
 *  secret. */
internal fun passwordsMatch(a: ByteArray, b: ByteArray): Boolean = a.contentEquals(b)

/**
 * Drives the create-vault wizard over a [VaultCreatePort] + [VaultLocationStore]. Plain class with
 * mutable published fields (mirrors `DeviceSettingsViewModel`); `AppRoot` bridges them into Compose.
 * Fully host-testable — holds only injected ports. The CPU-heavy Argon2id create is offloaded off
 * the main thread inside the port impl (`:kit` `UniffiVaultCreatePort`), so [create] only suspends.
 * Mirror of iOS `VaultProvisioningViewModel`, adapted to the Android `createInFolder(folderPath, …)`
 * port (the caller resolves + creates the empty working dir; this VM does not touch the filesystem).
 */
class VaultProvisioningViewModel(
    private val createPort: VaultCreatePort,
    private val store: VaultLocationStore,
) {
    var step: VaultProvisioningStep = VaultProvisioningStep.Folder
        private set
    var nameError: VaultNameError? = null
        private set
    var error: VaultProvisioningError? = null
        private set
    var isCreating: Boolean = false
        private set
    var mnemonicRows: List<MnemonicWord>? = null
        private set

    /** The one-shot recovery phrase, retained only between [create] and [acknowledgeMnemonic]/[cancel]. */
    private var phrase: ByteArray? = null

    /** The vault UUID from the FFI create result, retained alongside [phrase] to thread into the
     *  persisted location on [acknowledgeMnemonic]. Not secret — no zeroize needed. */
    private var createdVaultUuid: ByteArray? = null

    /** Validate the typed name; advance to [VaultProvisioningStep.Credentials] or publish [nameError]. */
    fun chooseFolder(treeUri: String, vaultName: String) {
        error = null
        when (val v = validateVaultName(vaultName)) {
            is VaultNameValidation.Invalid -> nameError = v.error
            is VaultNameValidation.Valid -> {
                nameError = null
                step = VaultProvisioningStep.Credentials(treeUri, v.name)
            }
        }
    }

    /**
     * Create the vault: re-entrancy-guarded; confirm-match the password; call the port; persist the
     * location BEFORE revealing the phrase (a crash mid-flow then leaves an openable + remembered
     * vault); advance to [VaultProvisioningStep.Mnemonic]. [folderPath] is a fresh EMPTY directory
     * the caller has created (port contract). The caller owns zeroizing its own [password]/[confirm].
     */
    suspend fun create(folderPath: String, password: ByteArray, confirm: ByteArray) {
        if (isCreating) return
        val creds = step as? VaultProvisioningStep.Credentials ?: return
        error = null
        if (!passwordsMatch(password, confirm)) {
            error = VaultProvisioningError.PasswordMismatch
            return
        }
        isCreating = true
        try {
            val created = createPort.createInFolder(folderPath, password, creds.vaultName)
            val uuidHex = hexOfBytes(created.vaultUuid)
            store.persist(VaultLocation(creds.vaultName, creds.treeUri, uuidHex)) // persist BEFORE mnemonic
            createdVaultUuid = created.vaultUuid
            phrase = created.phrase
            mnemonicRows = groupMnemonic(created.phrase)
            step = VaultProvisioningStep.Mnemonic
        } catch (e: VaultProvisioningError) {
            error = e
        } catch (e: Exception) {
            error = VaultProvisioningError.CreateFailed(e.message ?: e.toString())
        } finally {
            isCreating = false
        }
    }

    /** User confirmed they wrote down the phrase: wipe it + the rows, complete with the location. A
     *  null load now is a real store fault (the location was persisted during [create]) — surface it
     *  rather than stranding the user (no silent failure). */
    fun acknowledgeMnemonic() {
        if (step !is VaultProvisioningStep.Mnemonic) return
        wipePhrase()
        val loc = store.load()
        if (loc == null) {
            error = VaultProvisioningError.CreateFailed("vault location unavailable after create")
            return
        }
        step = VaultProvisioningStep.Done(loc)
    }

    /** Abandon the wizard: scrub the retained phrase + rows and return to the initial
     *  [VaultProvisioningStep.Folder] state. The VM is a remembered instance reused across the
     *  wizard's lifetime, so leaving a stale [step]/[error]/[nameError] would render a broken
     *  screen on re-entry. Safe from any step. */
    fun cancel() {
        wipePhrase()
        step = VaultProvisioningStep.Folder
        nameError = null
        error = null
    }

    private fun wipePhrase() {
        phrase?.fill(0)
        phrase = null
        mnemonicRows = null
        createdVaultUuid = null
    }
}
