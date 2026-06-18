package org.secretary.app

import android.content.Context
import org.json.JSONObject
import java.io.File
import java.io.IOException

/**
 * Stages a WRITABLE copy of the bundled read-only golden_vault_001 into the app's private
 * storage on first launch (the asset is read-only; a sync pass rewrites manifest/blocks).
 * Never mutates the bundled asset, so the frozen KAT is never touched. Idempotent. Mirror of
 * iOS `AppVaultProvisioning.swift`.
 *
 * The vault + its inputs JSON are bundled by the `stageGoldenVaultForApp` Gradle task from the
 * canonical `core/tests/data` location (see build.gradle.kts).
 */
object AppVaultProvisioning {
    private const val VAULT_ASSET = "golden_vault_001"
    private const val INPUTS_ASSET = "golden_vault_001_inputs.json"

    /** Returns the writable staged vault dir, copying it from assets on first call. */
    fun stageGoldenVault(context: Context): File {
        // A present vault asset dir has children; empty children here means it was never
        // bundled (the stage task didn't run), not a leaf file at the top level.
        check(!context.assets.list(VAULT_ASSET).isNullOrEmpty()) {
            "$VAULT_ASSET not bundled in the APK — the stageGoldenVaultForApp Gradle task did not run"
        }
        val dest = File(context.filesDir, VAULT_ASSET)
        if (dest.exists()) return dest
        // Crash-safe staging: copy into a temp sibling, then rename into place. The recursive copy
        // is not atomic, so a crash mid-copy could otherwise leave a half-written vault that the
        // `dest.exists()` short-circuit above would later return as if complete. rename(2) within
        // filesDir IS atomic, so `dest` only ever appears fully populated. Any leftover staging dir
        // from a previously-interrupted attempt is cleared first.
        val staging = File(context.filesDir, "$VAULT_ASSET.staging")
        staging.deleteRecursively()
        copyAsset(context, VAULT_ASSET, staging)
        if (!staging.renameTo(dest)) {
            staging.deleteRecursively()
            throw IOException("failed to stage $VAULT_ASSET into ${dest.path}")
        }
        return dest
    }

    /** The pinned 16-byte vault UUID, parsed from the bundled inputs JSON (single source of truth). */
    fun goldenVaultUuid(context: Context): ByteArray {
        val json = try {
            context.assets.open(INPUTS_ASSET).bufferedReader().use { it.readText() }
        } catch (e: IOException) {
            throw IllegalStateException(
                "$INPUTS_ASSET not bundled in the APK — the stageGoldenVaultForApp Gradle task did not run",
                e,
            )
        }
        return parseVaultUuidHex(JSONObject(json).getString("vault_uuid"))
    }

    /** The golden vault's 24-word BIP-39 recovery phrase, read from the bundled inputs JSON
     *  (single source of truth — a published KAT, not a real secret). */
    fun goldenRecoveryPhrase(context: Context): String {
        val json = try {
            context.assets.open(INPUTS_ASSET).bufferedReader().use { it.readText() }
        } catch (e: IOException) {
            throw IllegalStateException(
                "$INPUTS_ASSET not bundled in the APK — the stageGoldenVaultForApp Gradle task did not run",
                e,
            )
        }
        return JSONObject(json).getString("recovery_mnemonic_phrase")
    }

    // AssetManager.list() returns the children of a directory, or an empty array for a leaf
    // file. The golden vault has no empty directories, so empty-children == file. A genuinely
    // empty asset directory would be mis-staged as a leaf file, but this pinned fixture has none.
    private fun copyAsset(context: Context, assetPath: String, dest: File) {
        val children = context.assets.list(assetPath) ?: emptyArray()
        if (children.isEmpty()) {
            dest.parentFile?.mkdirs()
            context.assets.open(assetPath).use { input ->
                dest.outputStream().use { input.copyTo(it) }
            }
        } else {
            dest.mkdirs()
            for (child in children) copyAsset(context, "$assetPath/$child", File(dest, child))
        }
    }
}
