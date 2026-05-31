//! D.1.6 contacts DTOs. `ContactSummaryDto` carries the decrypted contact
//! display name (a secret-boundary value); its `Debug` redacts it. Card bytes
//! and public keys never appear in any DTO (spec §3).

use secretary_ffi_bridge::ContactSummary;

/// One contact surfaced to the picker. Card bytes/public keys are NOT here.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactSummaryDto {
    pub contact_uuid_hex: String,
    pub display_name: String,
}

impl std::fmt::Debug for ContactSummaryDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContactSummaryDto")
            .field("contact_uuid_hex", &self.contact_uuid_hex)
            .field("display_name", &"<redacted>")
            .finish()
    }
}

impl From<&ContactSummary> for ContactSummaryDto {
    fn from(s: &ContactSummary) -> Self {
        ContactSummaryDto {
            contact_uuid_hex: hex::encode(s.contact_uuid),
            display_name: s.display_name.clone(),
        }
    }
}

/// Result of `list_contacts`: the picker rows + a count of unreadable/
/// unverifiable `.card` files (surfaced, never hidden — spec §3).
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListContactsDto {
    pub contacts: Vec<ContactSummaryDto>,
    pub unreadable_count: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    fn to_json<T: serde::Serialize>(v: &T) -> Value {
        serde_json::from_str(&serde_json::to_string(v).expect("ser")).expect("parse")
    }

    #[test]
    fn contact_summary_dto_camel_case() {
        let dto = ContactSummaryDto {
            contact_uuid_hex: "00112233445566778899aabbccddeeff".into(),
            display_name: "Alice".into(),
        };
        let v = to_json(&dto);
        assert_eq!(v["contactUuidHex"], "00112233445566778899aabbccddeeff");
        assert_eq!(v["displayName"], "Alice");
        assert!(v.get("contact_uuid_hex").is_none());
    }

    #[test]
    fn contact_summary_debug_redacts_name() {
        let dto = ContactSummaryDto {
            contact_uuid_hex: "ab".into(),
            display_name: "SecretName".into(),
        };
        let dbg = format!("{dto:?}");
        assert!(!dbg.contains("SecretName"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn list_contacts_dto_shape() {
        let dto = ListContactsDto {
            contacts: vec![],
            unreadable_count: 3,
        };
        let v = to_json(&dto);
        assert_eq!(v["unreadableCount"], 3);
        assert!(v["contacts"].is_array());
    }
}
