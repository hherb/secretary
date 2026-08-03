package org.secretary.browse

import org.secretary.diagnostics.SecretFreeThrowable
import org.secretary.diagnostics.diagnosticDetail
import org.secretary.sync.VaultSyncError
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** Stands in for a decrypted record field name or a Rust-authored detail string. */
private const val SECRET = "s3cr3t-field-name"

class SecretFreeConformanceTest {
    @Test
    fun `all five error families are declared secret-free`() {
        assertTrue(VaultBrowseError.VaultMismatch is SecretFreeThrowable)
        assertTrue(VaultSyncError.InProgress is SecretFreeThrowable)
        assertTrue(DeviceUnlockError.NotEnrolled is SecretFreeThrowable)
        assertTrue(VaultProvisioningError.FolderNotEmpty is SecretFreeThrowable)
        assertTrue(VaultNameError.Blank is SecretFreeThrowable)
    }

    @Test
    fun `CorruptVault is redacted - it carries a Rust-authored string`() {
        val rendered = diagnosticDetail(VaultBrowseError.CorruptVault("duplicate map key: $SECRET"))
        assertFalse(rendered.contains(SECRET), rendered)
        assertEquals("CorruptVault(<redacted>)", rendered)
    }

    @Test
    fun `SaveCryptoFailure is redacted - same Rust fold as CorruptVault`() {
        val rendered = diagnosticDetail(
            VaultBrowseError.SaveCryptoFailure("record CBOR error: duplicate map key: $SECRET"),
        )
        assertFalse(rendered.contains(SECRET), rendered)
        assertEquals("SaveCryptoFailure(<redacted>)", rendered)
    }

    @Test
    fun `InvalidArgument is redacted - RecordEditModel puts a field name in it`() {
        val rendered = diagnosticDetail(VaultBrowseError.InvalidArgument("duplicate field name: $SECRET"))
        assertFalse(rendered.contains(SECRET), rendered)
        assertEquals("InvalidArgument(<redacted>)", rendered)
    }

    @Test
    fun `redaction does not touch message, so on-screen copy is unaffected`() {
        val error = VaultBrowseError.InvalidArgument("field '$SECRET' is not valid hex")
        assertTrue(error.message!!.contains(SECRET), "UI must still name the bad field")
    }

    @Test
    fun `an audited-safe arm still renders in full`() {
        // FolderInvalid carries "{context}: {source}" — a path plus an errno.
        val rendered = diagnosticDetail(VaultBrowseError.FolderInvalid("failed to read vault.toml"))
        assertTrue(rendered.contains("failed to read vault.toml"), rendered)
    }

    @Test
    fun `an arm with no payload renders its name`() {
        assertEquals("WrongPasswordOrCorrupt", diagnosticDetail(VaultBrowseError.WrongPasswordOrCorrupt))
    }
}
