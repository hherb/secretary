package org.secretary.browse

/** Instrumented-source VaultSession double (androidTest can't see the unit-test fake). */
class FakeVaultSession(
    private val vaultUuidHex: String,
    private val blocks: List<BlockSummaryView>,
    private val recordsByBlockHex: Map<String, List<RecordSummaryView>> = emptyMap(),
) : VaultSession {
    var wiped: Boolean = false
        private set

    override fun vaultUuidHex(): String = vaultUuidHex
    override fun blockSummaries(): List<BlockSummaryView> = blocks
    override suspend fun readBlock(blockUuid: ByteArray, includeDeleted: Boolean): List<RecordSummaryView> =
        recordsByBlockHex[hexOfBytes(blockUuid)] ?: emptyList()
    override fun wipe() { wiped = true }
}

fun textField(name: String, value: String): RevealableField =
    RevealableField(name, FieldKind.Text) { RevealedValue.Text(value) }
