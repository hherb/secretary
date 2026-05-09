//! Vault-manifest opaque handle and value types: `OpenVaultManifest`,
//! `OpenVaultOutput`, `BlockSummary`.

use super::identity::UnlockedIdentity;

/// uniffi wrapper around `secretary_ffi_bridge::OpenVaultManifest`. Newtype;
/// methods are thin forwarders.
pub struct OpenVaultManifest(pub(crate) secretary_ffi_bridge::OpenVaultManifest);

impl OpenVaultManifest {
    pub fn vault_uuid(&self) -> Vec<u8> {
        self.0.vault_uuid()
    }

    pub fn owner_user_uuid(&self) -> Vec<u8> {
        self.0.owner_user_uuid()
    }

    pub fn block_count(&self) -> u64 {
        self.0.block_count()
    }

    pub fn block_summaries(&self) -> Vec<BlockSummary> {
        self.0
            .block_summaries()
            .into_iter()
            .map(BlockSummary::from)
            .collect()
    }

    pub fn find_block(&self, block_uuid: Vec<u8>) -> Option<BlockSummary> {
        self.0.find_block(&block_uuid).map(BlockSummary::from)
    }

    pub fn wipe(&self) {
        self.0.wipe();
    }
}

/// uniffi dictionary projection of `secretary_ffi_bridge::BlockSummary`.
/// All fields are plaintext metadata — no secret material.
pub struct BlockSummary {
    pub block_uuid: Vec<u8>,
    pub block_name: String,
    pub created_at_ms: u64,
    pub last_modified_ms: u64,
    pub recipient_uuids: Vec<Vec<u8>>,
}

impl From<secretary_ffi_bridge::BlockSummary> for BlockSummary {
    fn from(b: secretary_ffi_bridge::BlockSummary) -> Self {
        Self {
            block_uuid: b.block_uuid.to_vec(),
            block_name: b.block_name,
            created_at_ms: b.created_at_ms,
            last_modified_ms: b.last_modified_ms,
            recipient_uuids: b.recipient_uuids.into_iter().map(|u| u.to_vec()).collect(),
        }
    }
}

/// uniffi dictionary projection. Holds two opaque-handle Arc references.
/// Same shape as B.3b's `CreateVaultOutput` dictionary.
pub struct OpenVaultOutput {
    pub identity: std::sync::Arc<UnlockedIdentity>,
    pub manifest: std::sync::Arc<OpenVaultManifest>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_summary_projection_round_trip_preserves_all_fields() {
        let bridge = secretary_ffi_bridge::BlockSummary {
            block_uuid: [1u8; 16],
            block_name: "test".to_string(),
            created_at_ms: 100,
            last_modified_ms: 200,
            recipient_uuids: vec![[2u8; 16], [3u8; 16]],
        };
        let proj = BlockSummary::from(bridge);
        assert_eq!(proj.block_uuid, vec![1u8; 16]);
        assert_eq!(proj.block_name, "test");
        assert_eq!(proj.created_at_ms, 100);
        assert_eq!(proj.last_modified_ms, 200);
        assert_eq!(proj.recipient_uuids, vec![vec![2u8; 16], vec![3u8; 16]]);
    }
}
