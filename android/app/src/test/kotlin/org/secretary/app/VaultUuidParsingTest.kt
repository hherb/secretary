package org.secretary.app

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class VaultUuidParsingTest {

    @Test
    fun parsesDashedHexInto16Bytes() {
        val uuid = parseVaultUuidHex("00112233-4455-6677-8899-aabbccddeeff")
        val expected = byteArrayOf(
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77.toByte(),
            0x88.toByte(), 0x99.toByte(), 0xaa.toByte(), 0xbb.toByte(),
            0xcc.toByte(), 0xdd.toByte(), 0xee.toByte(), 0xff.toByte(),
        )
        assertArrayEquals(expected, uuid)
    }

    @Test
    fun rejectsWrongLength() {
        assertThrows(IllegalArgumentException::class.java) {
            parseVaultUuidHex("00112233")
        }
    }

    @Test
    fun rejectsNonHex() {
        assertThrows(IllegalArgumentException::class.java) {
            parseVaultUuidHex("zz112233-4455-6677-8899-aabbccddeeff")
        }
    }
}
