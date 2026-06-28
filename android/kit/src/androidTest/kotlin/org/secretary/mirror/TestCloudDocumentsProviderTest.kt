package org.secretary.mirror

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class TestCloudDocumentsProviderTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun port_over_test_provider_round_trips_via_real_saf() {
        val tree = TestCloudTree.install(context)
        val port = safCloudFolderPort(context, tree.treeUri) // REAL DocumentFile + ContentResolver
        port.write("blocks/a.cbor.enc", byteArrayOf(1, 2, 3))
        assertTrue(port.list().contains("blocks/a.cbor.enc"))
        assertArrayEquals(byteArrayOf(1, 2, 3), port.read("blocks/a.cbor.enc"))
        port.delete("blocks/a.cbor.enc")
        assertTrue(!port.list().contains("blocks/a.cbor.enc"))
    }
}
