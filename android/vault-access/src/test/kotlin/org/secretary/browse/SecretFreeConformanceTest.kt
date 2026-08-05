package org.secretary.browse

import org.secretary.diagnostics.SecretFreeThrowable
import org.secretary.diagnostics.diagnosticDetail
import org.secretary.mirror.CloudFolderException
import org.secretary.mirror.VaultMirrorException
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
    fun `#475 regression - the wrapper exception types are declared secret-free too`() {
        // These three carry ONLY Kotlin-authored text (a fixed literal plus a path, a filename,
        // an op label, or an already-gated diagnosticDetail render), so default-denying them
        // bought no safety and cost every nested wrap its reason — the whole cloud-sync failure
        // path collapsed to "<undisclosed …>". See each declaration's payload-origin audit and
        // CloudFolderExceptionDiagnosticTest for the behaviour.
        assertTrue(CloudFolderException("x") is SecretFreeThrowable)
        assertTrue(VaultMirrorException("x") is SecretFreeThrowable)
        assertTrue(DeviceUuidException("x") is SecretFreeThrowable)
    }

    @Test
    fun `#475 regression - a DeviceUuidException renders its reason, not a marker`() {
        // UniffiVaultSession folds this into VaultBrowseError.Failed via
        // "device-uuid resolve failed: ${diagnosticDetail(e)}" — an unconformed type made that
        // prefix the only surviving information.
        val rendered = diagnosticDetail(DeviceUuidException("device-uuid file d.uuid is 3 bytes, expected 16"))
        assertFalse(rendered.contains("<undisclosed"), rendered)
        assertTrue(rendered.contains("is 3 bytes, expected 16"), rendered)
    }

    /** #474: `core` error payloads are data-free by construction, so the detail must survive. */
    @Test
    fun `CorruptVault detail survives rendering`() {
        val rendered = diagnosticDetail(VaultBrowseError.CorruptVault("manifest fingerprint mismatch"))
        assertTrue(rendered.contains("manifest fingerprint mismatch"), rendered)
    }

    /** #474: same guarantee, the SaveCryptoFailure arm — kept as a SEPARATE assertion from
     *  CorruptVault's (not combined) so a regression in only one arm cannot hide behind the
     *  other still passing (the #475 vacuity trap). */
    @Test
    fun `SaveCryptoFailure detail survives rendering`() {
        val rendered = diagnosticDetail(VaultBrowseError.SaveCryptoFailure("AEAD tag mismatch on block write"))
        assertTrue(rendered.contains("AEAD tag mismatch on block write"), rendered)
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
