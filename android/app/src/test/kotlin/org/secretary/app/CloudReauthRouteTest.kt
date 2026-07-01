package org.secretary.app

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Test
import java.io.File

class CloudReauthRouteTest {
    @Test fun unenrolled_uses_noop() {
        assertEquals(GateChoice.NOOP, cloudReauthRoute(enclaveEnrolled = false, openVaultId = "abcd", metadataVaultId = "abcd"))
    }

    @Test fun enrolled_matching_vault_uses_grace_window() {
        assertEquals(GateChoice.GRACE_WINDOW, cloudReauthRoute(enclaveEnrolled = true, openVaultId = "abcd", metadataVaultId = "abcd"))
    }

    @Test fun enrolled_mismatched_vault_uses_noop() {
        // stale enrollment for a treeUri whose underlying vault changed → don't block writes
        assertEquals(GateChoice.NOOP, cloudReauthRoute(enclaveEnrolled = true, openVaultId = "abcd", metadataVaultId = "ef01"))
    }

    @Test fun enrolled_null_metadata_uses_noop() {
        assertEquals(GateChoice.NOOP, cloudReauthRoute(enclaveEnrolled = true, openVaultId = "abcd", metadataVaultId = null))
    }

    @Test fun empty_openVaultId_uses_noop_even_when_enrolled() {
        // #340: a remembered SAF cloud vault's UUID is "" until it is resolved during open. Chosen
        // from "", the gate falls to NOOP even for an enrolled vault — which is why openCloudBrowse
        // must re-target the gate from the resolved UUID (see cloudGateForResolvedVault). Once
        // resolved, enrolled_matching_vault_uses_grace_window above shows the same vault picks GRACE.
        assertEquals(GateChoice.NOOP, cloudReauthRoute(enclaveEnrolled = true, openVaultId = "", metadataVaultId = "abcd"))
    }

    @Test fun device_secret_dir_is_namespaced_by_key() {
        val base = File("/data/nobackup")
        assertEquals(File("/data/nobackup/devicesecret/cloud/KEY123"), cloudDeviceSecretDir(base, "KEY123"))
    }

    @Test fun device_dir_differs_per_key() {
        val base = File("/data/nobackup")
        assertNotEquals(cloudDeviceSecretDir(base, "A"), cloudDeviceSecretDir(base, "B"))
    }

    @Test fun key_alias_is_prefixed_and_per_key() {
        assertEquals("secretary.devicesecret.cloud.KEY123", cloudDeviceKeyAlias("KEY123"))
        assertNotEquals(cloudDeviceKeyAlias("A"), cloudDeviceKeyAlias("B"))
    }
}
