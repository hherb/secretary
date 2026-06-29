package org.secretary.mirror

/**
 * In-memory [CloudFolderPort] for host tests: a path→bytes map with call recording and fault
 * injection. [writeOrder] records mutating calls (`write:`/`delete:`) for block-first ordering
 * assertions; [callLog] records EVERY op (incl. reads/lists) for retry/verify assertions.
 *
 * Fault injection: [failWith] makes every op throw (revoked-permission path); [failNextN] makes the
 * next N ops throw then succeed (transient eventual-consistency failure); [readMissNextN] makes the
 * next N reads report a present file as missing (write-succeeded-but-not-yet-visible).
 */
class FakeCloudFolderPort(initial: Map<String, ByteArray> = emptyMap()) : CloudFolderPort {
    private val files = LinkedHashMap<String, ByteArray>().apply { putAll(initial) }
    val writeOrder = mutableListOf<String>()
    val callLog = mutableListOf<String>()
    var failWith: String? = null
    var failNextN: Int = 0
    var readMissNextN: Int = 0

    fun snapshot(): Map<String, ByteArray> = files.toMap()

    override fun list(): List<String> = guard("list") { files.keys.toList() }

    override fun read(relativePath: String): ByteArray = guard("read:$relativePath") {
        if (readMissNextN > 0) {
            readMissNextN--
            throw CloudFolderException("no such file: $relativePath")
        }
        files[relativePath]?.copyOf() ?: throw CloudFolderException("no such file: $relativePath")
    }

    override fun write(relativePath: String, bytes: ByteArray) = guard("write:$relativePath") {
        writeOrder.add("write:$relativePath")
        files[relativePath] = bytes.copyOf()
    }

    override fun delete(relativePath: String) = guard("delete:$relativePath") {
        writeOrder.add("delete:$relativePath")
        files.remove(relativePath)
        Unit
    }

    private fun <T> guard(opLabel: String, block: () -> T): T {
        callLog.add(opLabel)
        failWith?.let { throw CloudFolderException(it) }
        if (failNextN > 0) {
            failNextN--
            throw CloudFolderException("injected transient failure ($opLabel)")
        }
        return block()
    }
}
