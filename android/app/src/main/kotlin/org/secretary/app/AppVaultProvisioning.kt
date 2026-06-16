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
        copyAsset(context, VAULT_ASSET, dest)
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
