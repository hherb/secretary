package org.secretary.browse

/**
 * The product of a successful create: the one-shot 24-word recovery phrase as UTF-8 bytes.
 * The caller owns zeroizing [phrase] once it has been shown to and acknowledged by the user
 * (mirrors iOS `CreatedVault`). Plain class (not `data class`) so the secret bytes are never
 * structurally compared, copied, or logged via a generated `toString`/`equals`.
 */
class CreatedVault(val phrase: ByteArray)

/**
 * Creates a brand-new v1 vault in an existing, empty real-filesystem folder, returning the
 * recovery phrase. The pure seam mirrors iOS `VaultCreatePort`; the real impl (`:kit`
 * `UniffiVaultCreatePort`) runs Argon2id off the main thread. [password] is forwarded per call
 * and never retained.
 *
 * [folderPath] is a real POSIX path (UTF-8) to an existing empty directory — the caller is
 * responsible for creating it. A non-empty folder surfaces [VaultProvisioningError.FolderNotEmpty].
 */
interface VaultCreatePort {
    suspend fun createInFolder(folderPath: String, password: ByteArray, displayName: String): CreatedVault
}
