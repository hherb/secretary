package org.secretary.mirror

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.secretary.browse.DeviceEnrollment
import org.secretary.browse.FileDeviceEnrollmentMetadataStore
import org.secretary.browse.KeystoreDeviceSecretEnclave
import org.secretary.browse.KeystoreKeyConfig
import org.secretary.browse.DeviceUnlockCoordinator
import org.secretary.browse.UniffiVaultDeviceSlotPort
import org.secretary.sync.GoldenVaultStaging
import java.io.File
import javax.crypto.Cipher

/**
 * Instrumented E2E: a real device-enrollment slot survives a working→cloud→working SAF round-trip.
 *
 * Test C: stages a golden working copy, installs the SAF test tree, flushes working→cloud so the
 * cloud holds a valid vault, mints a device slot via [DeviceUnlockCoordinator.enroll], flushes
 * working→cloud again, wipes the working dir, materializes back from the cloud, and asserts the
 * `devices/<uuid>.wrap` file is present in the rematerialized working copy.
 *
 * This proves the slot survives the SAF round-trip — something host tests with a fake
 * [CloudFolderPort] cannot prove (they never touch the real ContentResolver / DocumentsProvider).
 */
@RunWith(AndroidJUnit4::class)
class CloudEnrollSafRoundTripInstrumentedTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    private val toClean = mutableListOf<File>()

    @After
    fun cleanup() = toClean.forEach { it.deleteRecursively() }

    private fun freshDir(prefix: String): File =
        File(context.cacheDir, "$prefix-${System.nanoTime()}").apply { mkdirs() }.also { toClean += it }

    /** Recursively copy [src] tree into [dst] (dst created if absent). */
    private fun copyTree(src: File, dst: File) {
        src.walkTopDown().filter { it.isFile }.forEach { file ->
            val rel = src.toPath().relativize(file.toPath()).toString()
            File(dst, rel).apply { parentFile?.mkdirs() }.writeBytes(file.readBytes())
        }
    }

    /**
     * Test C — enroll slot round-trips through real SAF.
     *
     * 1. Stage the golden vault into a working dir, flush working→cloud via [VaultMirror].
     * 2. Enroll this device: [DeviceUnlockCoordinator.enroll] mints `devices/<uuid>.wrap` in the
     *    working copy; flush working→cloud again so the slot reaches the cloud.
     * 3. Wipe the working dir completely; [VaultMirror.materialize] pulls the cloud back.
     * 4. Assert a file matching `devices/<uuid>.wrap` is present in the rematerialized working copy,
     *    using the enrolled [DeviceEnrollment.deviceUuid] to name the expected path.
     *
     * The golden-vault KAT password is "correct horse battery staple" (published in the KAT inputs
     * JSON and used by all other instrumented tests in this module).
     */
    @Test
    fun cloudEnroll_roundTrips_wrapThroughSaf() = runBlocking {
        val tree = TestCloudTree.install(context)
        val workingDir = freshDir("wc-enroll")
        val enclaveDir = freshDir("enclave-enroll")

        // 1. Stage the golden vault working copy and flush it to the cloud.
        val golden = GoldenVaultStaging.stageWritableVault(context).also { toClean += it.parentFile!! }
        copyTree(golden, workingDir)

        val mirror = VaultMirror(safCloudFolderPort(context, tree.treeUri))
        val workingCopyMirror = VaultMirrorWorkingCopy(mirror, workingDir)

        // Push the golden working copy to the cloud so the cloud holds a valid vault.
        workingCopyMirror.flush()
        assertTrue(
            "cloud must hold the manifest after first flush",
            safCloudFolderPort(context, tree.treeUri).list().contains(MANIFEST_FILENAME),
        )

        // 2. Enroll this device: mint a real slot into the working copy.
        val passthrough: (Cipher, String) -> Cipher = { c, _ -> c }
        val enclave = KeystoreDeviceSecretEnclave(
            dir = enclaveDir,
            gate = passthrough,
            keyAlias = "secretary.devicesecret.cloud.SAFRoundTrip.${System.nanoTime()}",
            keyConfig = KeystoreKeyConfig.TEST_NO_AUTH,
        )
        val metadata = FileDeviceEnrollmentMetadataStore(enclaveDir)

        // goldenPassword from the published KAT inputs (not a real secret).
        val goldenPassword = "correct horse battery staple".toByteArray()
        val coordinator = DeviceUnlockCoordinator(UniffiVaultDeviceSlotPort(), enclave, metadata)
        val vaultId = bytesToHex(GoldenVaultStaging.goldenVaultUuid(context))

        try {
            coordinator.enroll(workingDir.path, vaultId, goldenPassword)
        } finally {
            goldenPassword.fill(0)
        }

        // The enrollment must have saved metadata and the wrap file must be in the working copy.
        val enrollment = checkNotNull(metadata.load()) {
            "enrollment metadata must be present after coordinator.enroll"
        }
        val expectedWrap = "devices/${formatUuidHyphenated(enrollment.deviceUuid)}.wrap"
        assertTrue(
            "working copy must hold the wrap file after enroll: $expectedWrap",
            File(workingDir, expectedWrap).exists(),
        )

        // Flush working→cloud so the wrap slot reaches the cloud.
        workingCopyMirror.flush()

        val cloudFiles = safCloudFolderPort(context, tree.treeUri).list()
        assertTrue(
            "cloud must hold the wrap file after second flush: $expectedWrap",
            cloudFiles.contains(expectedWrap),
        )

        // 3. Wipe the working dir; materialize from the cloud.
        workingDir.deleteRecursively()
        workingDir.mkdirs()

        workingCopyMirror.materialize()

        // 4. Assert the wrap file is present in the rematerialized working copy.
        assertTrue(
            "rematerialized working copy must hold the wrap file: $expectedWrap",
            File(workingDir, expectedWrap).exists(),
        )

        // Cleanup: clear the enclave key (best-effort; @After handles dirs).
        runCatching { enclave.clear() }
        metadata.clear()
    }
}
