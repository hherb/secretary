//! Create-vault DTOs crossing the IPC boundary.
//!
//! `CreateVaultDto.mnemonic` is the single secret-bearing field in the create
//! slice (spec §5): the 24-word recovery phrase, produced once on an explicit
//! create and displayed once. `CreateTargetProbeDto` is non-secret.

/// Result of a successful `create_vault`. The `mnemonic` is the user's only
/// recovery path — displayed once, never persisted by the app.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateVaultDto {
    pub mnemonic: String,
}

/// Result of `probe_create_target` — drives the wizard's empty-check +
/// subfolder offer. Non-secret.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTargetProbeDto {
    pub exists: bool,
    pub is_empty: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn to_value<T: serde::Serialize>(v: &T) -> Value {
        serde_json::from_str(&serde_json::to_string(v).expect("serialize")).expect("parse")
    }

    #[test]
    fn create_vault_dto_serializes_mnemonic() {
        let v = to_value(&CreateVaultDto {
            mnemonic: "abandon ability able about above absent ...".to_string(),
        });
        assert_eq!(v["mnemonic"], "abandon ability able about above absent ...");
        assert_eq!(v.as_object().expect("object").len(), 1);
    }

    #[test]
    fn probe_dto_uses_camel_case_is_empty() {
        let v = to_value(&CreateTargetProbeDto {
            exists: true,
            is_empty: false,
        });
        assert_eq!(v["exists"], true);
        // camelCase: `is_empty` -> `isEmpty` on the wire.
        assert_eq!(v["isEmpty"], false);
        assert!(v.get("is_empty").is_none(), "snake_case must not leak");
    }
}
