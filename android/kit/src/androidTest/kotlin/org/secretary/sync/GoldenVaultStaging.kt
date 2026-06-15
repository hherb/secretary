package org.secretary.sync

import android.content.Context
import org.json.JSONObject
import java.io.File

/**
 * AndroidTest helper: stages a WRITABLE copy of golden_vault_001 from the test APK
 * assets onto the device, and reads the pinned vault UUID. The tracked fixture is never
 * opened directly — only the per-test cacheDir copy is, so a frozen KAT is never mutated.
 */
object GoldenVaultStaging {
    private const val VAULT_ASSET = "golden_vault_001"
    private const val INPUTS_ASSET = "golden_vault_001_inputs.json"
    private const val UUID_BYTES = 16

    /** Recursively copy the bundled golden vault into a fresh unique dir under cacheDir. */
    fun stageWritableVault(context: Context): File {
        // A present vault asset dir has children; empty children here means it was never
        // bundled (the stage task didn't run), not a leaf file at the top level.
        check(!context.assets.list(VAULT_ASSET).isNullOrEmpty()) {
            "golden_vault_001 not bundled in the test APK — the stageGoldenVaultForAndroidTest Gradle task did not run"
        }
        val dest = File(context.cacheDir, "gv-${System.nanoTime()}/$VAULT_ASSET")
        copyAsset(context, VAULT_ASSET, dest)
        return dest
    }

    /** A fresh empty sync-state dir under cacheDir. */
    fun freshStateDir(context: Context): File =
        File(context.cacheDir, "state-${System.nanoTime()}").apply { mkdirs() }

    /** The pinned 16-byte vault UUID, parsed from the bundled inputs JSON (single source of truth). */
    fun goldenVaultUuid(context: Context): ByteArray {
        val json = try {
            context.assets.open(INPUTS_ASSET).bufferedReader().use { it.readText() }
        } catch (e: java.io.IOException) {
            throw IllegalStateException(
                "$INPUTS_ASSET not bundled in the test APK — the stageGoldenVaultForAndroidTest Gradle task did not run",
                e,
            )
        }
        val hex = JSONObject(json).getString("vault_uuid").replace("-", "")
        return ByteArray(UUID_BYTES) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }

    // AssetManager.list() returns the children of a directory, or an empty array for a
    // leaf file. The golden vault has no empty directories, so empty-children == file.
    // Limitation: a genuinely empty asset directory would be mis-staged as a leaf file,
    // but this pinned fixture has none, so the heuristic is exact here.
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
