package org.secretary.mirror

/**
 * In-memory [CloudFolderPort] for host tests: a path→bytes map with call-order recording and
 * optional fault injection. [writeOrder] records every mutating call (`write:`/`delete:`) so a
 * test can assert the block-first execution order; [failWith], when set, makes every operation
 * throw [CloudFolderException] (the revoked-permission / provider-error path).
 */
class FakeCloudFolderPort(initial: Map<String, ByteArray> = emptyMap()) : CloudFolderPort {
    private val files = LinkedHashMap<String, ByteArray>().apply { putAll(initial) }
    val writeOrder = mutableListOf<String>()
    var failWith: String? = null

    fun snapshot(): Map<String, ByteArray> = files.toMap()

    override fun list(): List<String> = guard { files.keys.toList() }

    override fun read(relativePath: String): ByteArray = guard {
        files[relativePath]?.copyOf() ?: throw CloudFolderException("no such file: $relativePath")
    }

    override fun write(relativePath: String, bytes: ByteArray) = guard {
        writeOrder.add("write:$relativePath")
        files[relativePath] = bytes.copyOf()
    }

    override fun delete(relativePath: String) = guard {
        writeOrder.add("delete:$relativePath")
        files.remove(relativePath)
        Unit
    }

    private fun <T> guard(block: () -> T): T {
        failWith?.let { throw CloudFolderException(it) }
        return block()
    }
}
