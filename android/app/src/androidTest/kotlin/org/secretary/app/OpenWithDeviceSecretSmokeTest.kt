package org.secretary.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.secretary.browse.DeviceUnlockCoordinator
import org.secretary.browse.DeviceUnlockError
import org.secretary.browse.FileDeviceUuidStore
import org.secretary.browse.UnlockCredential
import org.secretary.browse.VaultBrowseError
import org.secretary.browse.hexOfBytes
import org.secretary.browse.openWithCredential
import org.secretary.browse.uniffiVaultOpenPort
import org.secretary.browse.UniffiVaultDeviceSlotPort
import java.io.File

/**
 * On-device round-trip proof of the device-secret open path over the REAL
 * libsecretary_ffi_uniffi.so:
 *   1. Enrol — password-open mints a fresh device slot into the staged golden vault.
 *   2. Unlock — coordinator releases the credential and opens via the device-secret path.
 *   3. Disenroll — slot revoked; enclave + metadata cleared.
 *   4. Post-disenroll reopens fail with the expected typed errors.
 *
 * The in-memory [InMemoryDeviceSecretEnclave] + [InMemoryEnrollmentMetadataStore] stand in for
 * the Android-Keystore/Secure-Storage halves (slice 2). The test never touches the tracked
 * golden-vault fixture — [AppVaultProvisioning.stageGoldenVault] copies to filesDir first.
 */
@RunWith(AndroidJUnit4::class)
class OpenWithDeviceSecretSmokeTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val toClean = mutableListOf<File>()

    @After fun cleanup() {
        toClean.forEach { it.deleteRecursively() }
        File(context.filesDir, "golden_vault_001").deleteRecursively()
    }

    @Test
    fun enrolUnlockDisenrol_roundTripOverRealSo() = runBlocking {
        // ── Stage a writable copy of the golden vault ──────────────────────────────────────────
        val folder = AppVaultProvisioning.stageGoldenVault(context)
        val deviceUuidsDir = File(context.noBackupFilesDir, "devices-${System.nanoTime()}")
        val deviceUuids = FileDeviceUuidStore(deviceUuidsDir)
        toClean += deviceUuidsDir

        // Derive the string vault-id used by the coordinator (lowercase hex, no dashes).
        val vaultUuidBytes = AppVaultProvisioning.goldenVaultUuid(context)
        val vaultId = hexOfBytes(vaultUuidBytes)
        val expectedVaultUuidHex = "00112233445566778899aabbccddeeff"
        assertEquals("vaultId matches golden uuid hex", expectedVaultUuidHex, vaultId)

        // ── Coordinator wired with in-memory test doubles + the real device-slot FFI port ─────
        val slotPort = UniffiVaultDeviceSlotPort()
        val enclave = InMemoryDeviceSecretEnclave()
        val metadataStore = InMemoryEnrollmentMetadataStore()
        val coordinator = DeviceUnlockCoordinator(slotPort, enclave, metadataStore)

        val openPort = uniffiVaultOpenPort(deviceUuids)

        // ── Step 1: Enrol ───────────────────────────────────────────────────────────────────────
        val passwordBytes = AppVaultProvisioning.goldenPassword(context).toByteArray(Charsets.UTF_8)
        withContext(Dispatchers.IO) {
            coordinator.enroll(folder.path, vaultId, passwordBytes)
        }
        passwordBytes.fill(0)

        assertTrue("isEnrolled true after enrol", coordinator.isEnrolled)

        // Capture the enrolled device uuid before disenrol clears metadata.
        val capturedDeviceUuid = checkNotNull(metadataStore.load()?.deviceUuid?.copyOf()) {
            "enrollment metadata must be present after enrol"
        }

        // ── Step 2: Unlock → openWithCredential → assert vaultUuidHex ─────────────────────────
        val credential = withContext(Dispatchers.IO) {
            coordinator.unlock(vaultId, "smoke test unlock")
        }
        val session = withContext(Dispatchers.IO) {
            openWithCredential(openPort, folder.path, credential)
        }
        credential.secret.fill(0)

        try {
            assertEquals(
                "session.vaultUuidHex() matches golden vault uuid",
                expectedVaultUuidHex,
                session.vaultUuidHex(),
            )
        } finally {
            session.wipe()
        }

        // ── Step 3: Disenrol ───────────────────────────────────────────────────────────────────
        withContext(Dispatchers.IO) {
            coordinator.disenroll(folder.path)
        }

        assertFalse("isEnrolled false after disenrol", coordinator.isEnrolled)

        // ── Step 4a: Reopen via captured uuid → DeviceSlotNotFound ────────────────────────────
        try {
            withContext(Dispatchers.IO) {
                openWithCredential(
                    openPort,
                    folder.path,
                    UnlockCredential.DeviceSecret(capturedDeviceUuid, ByteArray(32)),
                )
            }
            fail("expected VaultBrowseError.DeviceSlotNotFound but open succeeded")
        } catch (e: VaultBrowseError.DeviceSlotNotFound) {
            // expected
        }

        // ── Step 4b: coordinator.unlock after disenrol → DeviceUnlockError.NotEnrolled ────────
        try {
            withContext(Dispatchers.IO) {
                coordinator.unlock(vaultId, "should not reach enclave")
            }
            fail("expected DeviceUnlockError.NotEnrolled but unlock succeeded")
        } catch (e: DeviceUnlockError.NotEnrolled) {
            // expected
        }
    }
}
