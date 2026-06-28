package org.secretary.mirror

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SafCloudFolderPortInstrumentedTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun write_creates_nested_dirs_then_list_walks_them() {
        val tree = TestCloudTree.install(context)
        val port = safCloudFolderPort(context, tree.treeUri)
        port.write("blocks/deep/b.cbor.enc", byteArrayOf(5))
        port.write(MANIFEST_FILENAME, byteArrayOf(6))
        val listed = port.list().toSet()
        assertTrue(listed.contains("blocks/deep/b.cbor.enc"))
        assertTrue(listed.contains(MANIFEST_FILENAME))
    }

    @Test fun write_overwrites_via_delete_then_create_with_truncation() {
        val tree = TestCloudTree.install(context)
        val port = safCloudFolderPort(context, tree.treeUri)
        port.write("m", byteArrayOf(1, 2, 3, 4))
        port.write("m", byteArrayOf(9)) // shorter — proves "wt" truncation, no stale tail
        assertArrayEquals(byteArrayOf(9), port.read("m"))
    }

    @Test fun delete_of_absent_is_a_noop() {
        val tree = TestCloudTree.install(context)
        val port = safCloudFolderPort(context, tree.treeUri)
        port.delete("nope") // must not throw (CloudFolderPort.delete contract)
    }

    @Test fun delete_that_returns_false_on_existing_file_is_surfaced() {
        val tree = TestCloudTree.install(context)
        val port = safCloudFolderPort(context, tree.treeUri)
        port.write("stuck", byteArrayOf(1))
        tree.deleteReturnsFalsePaths = setOf("stuck")
        val e = assertThrows(CloudFolderException::class.java) { port.delete("stuck") }
        assertTrue(e.message!!.contains("cannot delete"))
    }

    @Test fun overwrite_when_delete_returns_false_is_surfaced_not_silently_forked() {
        val tree = TestCloudTree.install(context)
        val port = safCloudFolderPort(context, tree.treeUri)
        port.write("dup", byteArrayOf(1))
        tree.deleteReturnsFalsePaths = setOf("dup")
        val e = assertThrows(CloudFolderException::class.java) { port.write("dup", byteArrayOf(2)) }
        assertTrue(e.message!!.contains("cannot overwrite"))
    }
}
