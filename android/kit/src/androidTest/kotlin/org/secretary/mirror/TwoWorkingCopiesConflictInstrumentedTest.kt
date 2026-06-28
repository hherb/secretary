package org.secretary.mirror

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.secretary.sync.GoldenVaultStaging
import org.secretary.sync.SyncOutcome
import org.secretary.sync.UniffiVaultSyncPort
import uniffi.secretary.BlockInput
import uniffi.secretary.FieldInput
import uniffi.secretary.FieldInputValue
import uniffi.secretary.RecordInput
import uniffi.secretary.openVaultWithPassword
import uniffi.secretary.readBlock
import uniffi.secretary.saveBlock
import java.io.File

/**
 * The headline Slice-6 conflict E2E: two devices make divergent edits, the edits are transported
 * through the REAL SAF stack ([safCloudFolderPort] / [TestCloudTree] / [VaultMirror]), the REAL
 * Rust core merges them via the native sync FFI ([UniffiVaultSyncPort.sync]), and BOTH sides
 * converge to IDENTICAL merged record content on a real device.
 *
 * Construction (Scenario A — disjoint appended records, no tombstone → no veto, so a plain `sync`
 * auto-commits the merge; verified against `core/src/sync/ingest.rs` + the bridge's
 * `sync_vault_in_clean_concurrent_merge_commits_and_advances`):
 *
 * - Device A opens its working copy and appends a NEW record `[0xAA;16]` (`who=alice`) into the
 *   golden block under `deviceUuidA`, producing a validly signed+encrypted manifest_A + block_A
 *   with vector clock `{golden, A:1}`.
 * - Device B branches from the SAME golden base and appends a NEW record `[0xBB;16]` (`who=bob`)
 *   under `deviceUuidB`, producing manifest_B + block_B with clock `{golden, B:1}`. `{golden,A:1}`
 *   and `{golden,B:1}` are CONCURRENT (distinct device UUIDs).
 * - The cloud provider's fork is simulated by writing into `tree.rootDir`: A's manifest+block become
 *   the canonical files, and B's manifest+block are placed as `.sync-conflict-from-device-b`
 *   siblings of BOTH the manifest AND the block. Placing only the manifest sibling would silently
 *   drop B's record edits (the block carries the actual records) — both are required.
 *
 * To make `sync` see a CONCURRENT canonical-vs-state relation (the only relation that triggers
 * conflict-copy ingestion + merge), device B is synced first into a shared state dir while its
 * working copy still holds canonical B — advancing the persisted clock to `{golden, B:1}`. The
 * fork is then materialized into A's merge working copy (canonical A + both siblings, pulled via
 * real SAF), and `sync` is run against the SAME state dir: `clock_relation({golden,B:1},
 * {golden,A:1})` is Concurrent → the sibling block is ingested and merged → `MergedClean`, written
 * back to A's working copy. The merged result is then flushed to the cloud and materialized into a
 * fresh device-B working copy, proving B converges to the same set.
 *
 * Non-vacuous convergence assertion: the `{recordUuid → who}` map read back from side A equals the
 * one read back from side B, and both contain alice AND bob. B's `[0xBB]` being visible on side A
 * is the load-bearing proof that the BLOCK sibling (not just the manifest) was ingested.
 *
 * Real native FFI + real SAF + real merge — none of which host tests with fakes can exercise.
 */
@RunWith(AndroidJUnit4::class)
class TwoWorkingCopiesConflictInstrumentedTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    // Published golden-vault KAT password — not a real secret, so not zeroized.
    private val goldenPassword = "correct horse battery staple".toByteArray()

    // The single pre-built block in golden_vault_001 (11223344-5566-7788-99aa-bbccddeeff00). Both
    // devices append into it. Pinned here because the smoke-test `VAULT_001_BLOCK_UUID` constant
    // lives outside the :kit androidTest classpath (ffi/secretary-ffi-uniffi/tests/kotlin).
    private val blockUuid = byteArrayOf(
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88.toByte(),
        0x99.toByte(), 0xaa.toByte(), 0xbb.toByte(), 0xcc.toByte(),
        0xdd.toByte(), 0xee.toByte(), 0xff.toByte(), 0x00,
    )

    // Distinct 16-byte device UUIDs so the two devices' vector clocks are Concurrent, not ordered.
    private val deviceUuidA = ByteArray(16) { 0x0A.toByte() }
    private val deviceUuidB = ByteArray(16) { 0x0B.toByte() }

    // The two new records each device appends. Distinct UUIDs → union merge (no field collision).
    private val recordUuidA = ByteArray(16) { 0xAA.toByte() }
    private val recordUuidB = ByteArray(16) { 0xBB.toByte() }

    // Merge timestamp; pinned to the golden vault's clock domain for determinism.
    private val nowMs = 2_000_000_000_000uL

    private val siblingSuffix = ".sync-conflict-from-device-b"

    private val toClean = mutableListOf<File>()

    @After fun cleanup() = toClean.forEach { it.deleteRecursively() }

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
     * Open [workingDir], read the golden block's existing records, append [newRecord]
     * ([who]) under [deviceUuid], and saveBlock — persisting a validly signed+encrypted
     * manifest + block. Re-reads existing records so the saved block is a superset, not a
     * replacement (save_block replaces the whole block entry by uuid).
     */
    private fun appendRecord(workingDir: File, newRecordUuid: ByteArray, who: String, deviceUuid: ByteArray) {
        val folderPathBytes = workingDir.path.toByteArray()
        val out = openVaultWithPassword(folderPathBytes, goldenPassword)
        out.identity.use { id ->
            out.manifest.use { mf ->
                val existing = mutableListOf<RecordInput>()
                readBlock(id, mf, blockUuid, false).use { block ->
                    val count = block.recordCount()
                    var i = 0uL
                    while (i < count) {
                        val rec = block.recordAt(i)!!
                        val fields = rec.fieldNames().map { name ->
                            val fh = rec.fieldByName(name)!!
                            // Existing golden field is text; preserve it verbatim.
                            FieldInput(name, FieldInputValue.Text(fh.exposeText()!!))
                        }
                        existing += RecordInput(rec.recordUuid(), rec.recordType(), rec.tags(), fields)
                        i++
                    }
                }
                val appended = RecordInput(
                    recordUuid = newRecordUuid,
                    recordType = "note",
                    tags = emptyList(),
                    fields = listOf(FieldInput("who", FieldInputValue.Text(who))),
                )
                saveBlock(
                    id,
                    mf,
                    BlockInput(blockUuid, "Notes", existing + appended),
                    deviceUuid,
                    nowMs,
                )
            }
        }
    }

    /** Read the block in [workingDir] as a `{recordUuidHex → who-field}` map (live records only). */
    private fun readWhoMap(workingDir: File): Map<String, String?> {
        val folderPathBytes = workingDir.path.toByteArray()
        val out = openVaultWithPassword(folderPathBytes, goldenPassword)
        val result = linkedMapOf<String, String?>()
        out.identity.use { id ->
            out.manifest.use { mf ->
                readBlock(id, mf, blockUuid, false).use { block ->
                    val count = block.recordCount()
                    var i = 0uL
                    while (i < count) {
                        val rec = block.recordAt(i)!!
                        result[bytesToHex(rec.recordUuid())] = rec.fieldByName("who")?.exposeText()
                        i++
                    }
                }
            }
        }
        return result
    }

    @Test
    fun twoWorkingCopiesOverOneSafTreeConvergeToIdenticalMergedContent() = runBlocking {
        val tree = TestCloudTree.install(context)

        // 1. Seed the cloud with the golden vault (write directly into the SAF-backed root).
        val golden = GoldenVaultStaging.stageWritableVault(context).also { toClean += it.parentFile!! }
        copyTree(golden, tree.rootDir)
        assertTrue(
            "cloud must hold the golden manifest after seeding",
            safCloudFolderPort(context, tree.treeUri).list().contains(MANIFEST_FILENAME),
        )

        // 2. Device A: materialize cloud → workingA, append [0xAA] who=alice under deviceUuidA.
        val workingA = freshDir("wc-a")
        VaultMirror(safCloudFolderPort(context, tree.treeUri)).materialize(workingA)
        appendRecord(workingA, recordUuidA, "alice", deviceUuidA)

        // 3. Device B: branch the SAME base (cloud is still the golden base) → workingB,
        //    append [0xBB] who=bob under deviceUuidB.
        val workingB = freshDir("wc-b")
        VaultMirror(safCloudFolderPort(context, tree.treeUri)).materialize(workingB)
        appendRecord(workingB, recordUuidB, "bob", deviceUuidB)

        // 4. Seed the shared sync state to device B's clock {golden, B:1} so the later sync on the
        //    A-canonical fork sees a CONCURRENT relation (the merge trigger). Syncing B's working
        //    copy (canonical = B) against a fresh state dir advances the persisted clock to B's.
        val stateDir = freshDir("state")
        val syncPort = UniffiVaultSyncPort()
        val seedOutcome = syncPort.sync(stateDir.path, workingB.path, goldenPassword, nowMs)
        assertEquals(
            "seeding B into a fresh state dir must fast-forward to B's clock",
            SyncOutcome.AppliedAutomatically,
            seedOutcome,
        )

        // 5. Simulate the cloud provider's fork in the SAF-backed root:
        //    canonical = A's manifest+block; B's manifest+block as .sync-conflict-from-device-b
        //    siblings of BOTH. The block sibling carries B's actual record edits.
        val blockRel = "blocks/${formatUuidHyphenated(blockUuid)}.cbor.enc"
        File(tree.rootDir, MANIFEST_FILENAME).writeBytes(File(workingA, MANIFEST_FILENAME).readBytes())
        File(tree.rootDir, blockRel).writeBytes(File(workingA, blockRel).readBytes())
        File(tree.rootDir, MANIFEST_FILENAME + siblingSuffix)
            .writeBytes(File(workingB, MANIFEST_FILENAME).readBytes())
        File(tree.rootDir, blockRel + siblingSuffix)
            .writeBytes(File(workingB, blockRel).readBytes())

        // Confirm the fork landed in the SAF tree (canonical + both siblings visible through SAF).
        val cloudList = safCloudFolderPort(context, tree.treeUri).list()
        assertTrue("canonical manifest present", cloudList.contains(MANIFEST_FILENAME))
        assertTrue("manifest sibling present", cloudList.contains(MANIFEST_FILENAME + siblingSuffix))
        assertTrue("block sibling present", cloudList.contains(blockRel + siblingSuffix))

        // 6. Converge side A: materialize cloud → fresh working copy (pulls canonical A + both
        //    siblings through real SAF), then sync against the B-seeded state → CONCURRENT → merge.
        val workingMergeA = freshDir("wc-merge-a")
        VaultMirror(safCloudFolderPort(context, tree.treeUri)).materialize(workingMergeA)
        // The materialized working copy must carry the block sibling for ingest to find it.
        assertTrue(
            "materialized working copy must hold the block sibling pulled via SAF",
            File(workingMergeA, blockRel + siblingSuffix).exists(),
        )
        val mergeOutcome = syncPort.sync(stateDir.path, workingMergeA.path, goldenPassword, nowMs)
        assertEquals(
            "concurrent disjoint-append merge commits cleanly (no veto)",
            SyncOutcome.MergedClean,
            mergeOutcome,
        )

        // Side-A read-back: BOTH devices' records must be present.
        val sideA = readWhoMap(workingMergeA)
        assertEquals("side A holds alice", "alice", sideA[bytesToHex(recordUuidA)])
        assertEquals(
            "side A holds bob — proves the BLOCK sibling was ingested, not just the manifest",
            "bob",
            sideA[bytesToHex(recordUuidB)],
        )

        // 7. Converge side B: push A's merged result to the cloud, materialize a fresh device-B
        //    working copy, and read it back. A `sync` on the merged clock is a fast-forward; the
        //    load-bearing proof is the read-back content equality below.
        VaultMirror(safCloudFolderPort(context, tree.treeUri)).flush(workingMergeA)
        val workingFinalB = freshDir("wc-final-b")
        VaultMirror(safCloudFolderPort(context, tree.treeUri)).materialize(workingFinalB)
        val sideB = readWhoMap(workingFinalB)

        // 8. FULL-CONTENT CONVERGENCE: identical {recordUuid → who} set on both sides, both with
        //    alice AND bob.
        assertEquals("both sides converge to the identical merged record set", sideA, sideB)
        assertTrue("converged set contains alice", sideA.containsValue("alice"))
        assertTrue("converged set contains bob", sideA.containsValue("bob"))
        Unit
    }
}
