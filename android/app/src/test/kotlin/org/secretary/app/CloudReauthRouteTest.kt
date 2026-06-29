package org.secretary.app

import org.junit.jupiter.api.Assertions.assertEquals
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

    @Test fun device_secret_dir_is_namespaced_by_key() {
        val base = File("/data/nobackup")
        assertEquals(File("/data/nobackup/devicesecret/cloud/KEY123"), cloudDeviceSecretDir(base, "KEY123"))
    }

    @Test fun device_dir_differs_per_key() {
        val base = File("/data/nobackup")
        assert(cloudDeviceSecretDir(base, "A") != cloudDeviceSecretDir(base, "B"))
    }

    @Test fun key_alias_is_prefixed_and_per_key() {
        assertEquals("secretary.devicesecret.cloud.KEY123", cloudDeviceKeyAlias("KEY123"))
        assert(cloudDeviceKeyAlias("A") != cloudDeviceKeyAlias("B"))
    }
}
