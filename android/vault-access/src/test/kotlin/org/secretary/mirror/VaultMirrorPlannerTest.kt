package org.secretary.mirror

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class VaultMirrorPlannerTest {
    private fun fp(seed: Int) = FileFingerprint(seed.toLong(), "hash$seed")
    private val manifestA = mapOf(MANIFEST_FILENAME to fp(1))

    @Test
    fun `copies a file present in source but absent from dest`() {
        val plan = planMirror(source = mapOf("blocks/a.cbor.enc" to fp(1)), dest = emptyMap())
        assertEquals(listOf(MirrorOp.Copy("blocks/a.cbor.enc")), plan)
    }

    @Test
    fun `copies a file whose fingerprint differs (same size, different hash)`() {
        val plan = planMirror(
            source = mapOf("blocks/a.cbor.enc" to FileFingerprint(10, "new")),
            dest = mapOf("blocks/a.cbor.enc" to FileFingerprint(10, "old")),
        )
        assertEquals(listOf(MirrorOp.Copy("blocks/a.cbor.enc")), plan)
    }

    @Test
    fun `skips a file with an identical fingerprint`() {
        val same = mapOf("blocks/a.cbor.enc" to fp(7))
        assertEquals(emptyList<MirrorOp>(), planMirror(source = same, dest = same))
    }

    @Test
    fun `deletes a file present in dest but absent from source`() {
        val plan = planMirror(source = emptyMap(), dest = mapOf("blocks/gone.cbor.enc" to fp(1)))
        assertEquals(listOf(MirrorOp.Delete("blocks/gone.cbor.enc")), plan)
    }

    @Test
    fun `copies the manifest last among copies (block-first invariant)`() {
        val plan = planMirror(
            source = mapOf(
                MANIFEST_FILENAME to fp(1),
                "blocks/a.cbor.enc" to fp(2),
                "blocks/b.cbor.enc" to fp(3),
            ),
            dest = emptyMap(),
        )
        assertEquals(
            listOf(
                MirrorOp.Copy("blocks/a.cbor.enc"),
                MirrorOp.Copy("blocks/b.cbor.enc"),
                MirrorOp.Copy(MANIFEST_FILENAME),
            ),
            plan,
        )
    }

    @Test
    fun `emits all deletes after all copies`() {
        val plan = planMirror(
            source = mapOf(MANIFEST_FILENAME to fp(1), "blocks/keep.cbor.enc" to fp(2)),
            dest = mapOf("blocks/old.cbor.enc" to fp(9)),
        )
        val lastCopyIndex = plan.indexOfLast { it is MirrorOp.Copy }
        val firstDeleteIndex = plan.indexOfFirst { it is MirrorOp.Delete }
        assertTrue(lastCopyIndex < firstDeleteIndex, "all copies must precede any delete: $plan")
        assertEquals(MirrorOp.Copy(MANIFEST_FILENAME), plan[lastCopyIndex])
    }

    @Test
    fun `preserves vault-relative subdirectory paths`() {
        val plan = planMirror(source = mapOf("contacts/x.cbor.enc" to fp(1)), dest = emptyMap())
        assertEquals(listOf(MirrorOp.Copy("contacts/x.cbor.enc")), plan)
    }

    @Test
    fun `an empty source plans deletes for every dest file`() {
        val plan = planMirror(source = emptyMap(), dest = mapOf("a" to fp(1), "b" to fp(2)))
        assertEquals(listOf(MirrorOp.Delete("a"), MirrorOp.Delete("b")), plan)
    }

    @Test
    fun `two empty sides plan nothing`() {
        assertEquals(emptyList<MirrorOp>(), planMirror(emptyMap(), emptyMap()))
    }

    @Test
    fun `orders copies and deletes deterministically by path`() {
        val plan = planMirror(
            source = mapOf("blocks/c.cbor.enc" to fp(1), "blocks/a.cbor.enc" to fp(2)),
            dest = mapOf("blocks/z.cbor.enc" to fp(3), "blocks/m.cbor.enc" to fp(4)),
        )
        assertEquals(
            listOf(
                MirrorOp.Copy("blocks/a.cbor.enc"),
                MirrorOp.Copy("blocks/c.cbor.enc"),
                MirrorOp.Delete("blocks/m.cbor.enc"),
                MirrorOp.Delete("blocks/z.cbor.enc"),
            ),
            plan,
        )
    }

    @Test
    fun `manifest-only change plans just the manifest copy`() {
        val plan = planMirror(
            source = mapOf(MANIFEST_FILENAME to fp(2), "blocks/a.cbor.enc" to fp(5)),
            dest = manifestA + ("blocks/a.cbor.enc" to fp(5)),
        )
        assertEquals(listOf(MirrorOp.Copy(MANIFEST_FILENAME)), plan)
    }
}
