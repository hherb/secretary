package org.secretary.browse

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uniffi.secretary.VaultException
import uniffi.secretary.createVaultInFolder

/**
 * The real [VaultCreatePort] over the generated `uniffi.secretary.createVaultInFolder` call. Kotlin
 * mirror of iOS `UniffiVaultCreatePort`.
 *
 * [createInFolder] re-derives the vault key with Argon2id, so it runs on [ioDispatcher]
 * (default [Dispatchers.IO]) to keep the caller responsive. The path is UTF-8 encoded and the
 * password [ByteArray] is forwarded per call; neither is retained. The returned phrase is
 * caller-owned (caller zeroizes after the user acknowledges it).
 *
 * [createFn] is the injectable FFI seam: it returns the one-shot recovery-phrase bytes (or null).
 * Its default invokes the real binding inside `.use { … }` so the native [uniffi.secretary.MnemonicOutput]
 * handle is always released. [clockMs] supplies `created_at_ms` (injected for deterministic tests).
 */
class UniffiVaultCreatePort(
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val clockMs: () -> Long = System::currentTimeMillis,
    private val createFn: (ByteArray, ByteArray, String, ULong) -> ByteArray? =
        { folderPath, password, displayName, createdAtMs ->
            createVaultInFolder(folderPath, password, displayName, createdAtMs).use { it.takePhrase() }
        },
) : VaultCreatePort {
    override suspend fun createInFolder(
        folderPath: String,
        password: ByteArray,
        displayName: String,
    ): CreatedVault =
        withContext(ioDispatcher) {
            val phrase = mapProvisioningErrors {
                createFn(folderPath.toByteArray(Charsets.UTF_8), password, displayName, clockMs().toULong())
            } ?: throw VaultProvisioningError.CreateFailed("recovery phrase unavailable")
            CreatedVault(phrase)
        }
}

/** Run an FFI call, translating any [VaultException] into the domain [VaultProvisioningError]. */
internal inline fun <T> mapProvisioningErrors(block: () -> T): T =
    try {
        block()
    } catch (e: VaultException) {
        throw mapVaultProvisioningError(e)
    }

/** Map a create-surface [VaultException] to the typed [VaultProvisioningError]. */
internal fun mapVaultProvisioningError(e: VaultException): VaultProvisioningError =
    when (e) {
        is VaultException.VaultFolderNotEmpty -> VaultProvisioningError.FolderNotEmpty
        else -> VaultProvisioningError.CreateFailed(e.message ?: (e::class.simpleName ?: "create failed"))
    }

/** Production factory for the real create port (live binding + IO dispatcher). */
fun uniffiVaultCreatePort(): VaultCreatePort = UniffiVaultCreatePort()
