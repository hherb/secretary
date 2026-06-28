package org.secretary.mirror

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.secretary.browse.uniffiVaultCreatePort
import java.io.File
import java.nio.file.Files

/**
 * Headline Slice-6 instrumented E2E: exercises [VaultWorkingCopyCoordinator] over the REAL
 * [VaultMirror] + REAL SAF stack ([safCloudFolderPort] / [TestCloudTree]) + the REAL Rust `.so`
 * (the uniffi create port), on a real device. Two lifecycle proofs:
 *
 * 1. create → flush (createThenOpen pushes working→cloud) → a FRESH empty working dir
 *    `openExisting()` materializes the whole vault back from the cloud.
 * 2. The #327 offline-create-no-clobber fix: a faulted create push AND an un-persistable marker
 *    escalate to [PendingFlushNotPersisted]; the offline-created vault still lives in the working
 *    dir, and a later reopen over the still-manifest-less cloud does NOT clobber it (the materialize
 *    guard in [VaultMirror.materialize]).
 *
 * `openAndSync` is a thin stand-in (asserts the working dir holds [MANIFEST_FILENAME]) — the full
 * uniffi open+sync FFI path is already covered by `SyncRoundTripInstrumentedTest`; this test
 * isolates the lifecycle ORDERING over real SAF.
 */
@RunWith(AndroidJUnit4::class)
class CloudWorkingCopyLifecycleInstrumentedTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private fun freshDir(p: String) = Files.createTempDirectory(p).toFile()

    private fun coordinator(tree: TestCloudTree.TreeHandle, workingDir: File, markerFile: File) =
        VaultWorkingCopyCoordinator(
            VaultMirrorWorkingCopy(VaultMirror(safCloudFolderPort(context, tree.treeUri)), workingDir),
            FilePendingFlushMarker(markerFile),
        ) {
            // openAndSync stand-in: assert the working copy is materialized
            assertTrue("materialized working copy must hold a manifest", File(workingDir, MANIFEST_FILENAME).exists())
            "S"
        }

    @Test fun create_flush_then_reopen_materializes_from_cloud() = runBlocking {
        val tree = TestCloudTree.install(context)
        val workingDir = freshDir("wc-create-")
        val created = uniffiVaultCreatePort().createInFolder(workingDir.path, "pw".toByteArray(), "Lifecycle")
        // createThenOpen pushes working→cloud, then opens
        coordinator(tree, workingDir, File(freshDir("mk-"), "m"))
            .createThenOpen(bytesToHex(created.vaultUuid)) { /* persist no-op */ }
        assertTrue("cloud must now hold the manifest", safCloudFolderPort(context, tree.treeUri).list().contains(MANIFEST_FILENAME))

        // A fresh device: empty working dir, reopen pulls the whole vault
        val freshWorking = freshDir("wc-reopen-")
        coordinator(tree, freshWorking, File(freshDir("mk2-"), "m")).openExisting()
        assertTrue(File(freshWorking, MANIFEST_FILENAME).exists())
    }

    @Test fun offline_create_then_reopen_does_not_clobber_when_marker_lost() = runBlocking {
        val tree = TestCloudTree.install(context)
        val workingDir = freshDir("wc-offline-")
        val created = uniffiVaultCreatePort().createInFolder(workingDir.path, "pw".toByteArray(), "Offline")
        // Force the create push to fail: fault ALL writes to the cloud.
        tree.failWritePaths = setOf("*")
        // Point the marker at an UNWRITABLE path (parent is a regular file) so set() cannot persist.
        val markerParent = File(freshDir("mk-bad-"), "afile").apply { writeBytes(byteArrayOf(0)) }
        val badMarker = File(markerParent, "m") // parent is a file → mkdirs/createNewFile fail
        val coord = coordinator(tree, workingDir, badMarker)
        assertThrows(PendingFlushNotPersisted::class.java) {
            runBlocking { coord.createThenOpen(bytesToHex(created.vaultUuid)) { } }
        }
        // The offline-created vault still lives in the working copy …
        assertTrue(File(workingDir, MANIFEST_FILENAME).exists())
        // … and a reopen over the (still manifest-less) cloud must NOT clobber it.
        tree.failWritePaths = emptySet()
        // Precondition: the cloud is still manifest-less (the failed push left it empty).
        // materialize() must detect this and skip pull rather than overwriting the working copy.
        assertFalse(
            "cloud must still be manifest-less before the guarded reopen",
            safCloudFolderPort(context, tree.treeUri).list().contains(MANIFEST_FILENAME),
        )
        coordinator(tree, workingDir, File(freshDir("mk-ok-"), "m")).openExisting()
        assertTrue("materialize guard preserves the un-pushed vault", File(workingDir, MANIFEST_FILENAME).exists())
    }
}
