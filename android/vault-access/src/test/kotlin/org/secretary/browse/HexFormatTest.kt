package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class HexFormatTest {
    @Test
    fun `round-trips lowercase hex`() {
        val bytes = byteArrayOf(0x00, 0x0f, 0x10.toByte(), 0xff.toByte())
        assertArrayEquals(bytes, parseHexLenient(hexOfBytes(bytes)))
    }

    @Test
    fun `accepts uppercase and whitespace`() {
        assertArrayEquals(byteArrayOf(0xAB.toByte(), 0xCD.toByte()), parseHexLenient("AB CD"))
    }

    @Test
    fun `empty string parses to empty bytes`() {
        assertArrayEquals(ByteArray(0), parseHexLenient(""))
    }

    @Test
    fun `odd length is rejected`() {
        assertNull(parseHexLenient("abc"))
    }

    @Test
    fun `non-hex char is rejected`() {
        assertNull(parseHexLenient("zz"))
    }
}
