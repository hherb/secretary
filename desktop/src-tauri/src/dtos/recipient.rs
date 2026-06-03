//! D.1.8 per-block recipient DTO. `RecipientDto` carries a recipient's public
//! uuid + classification + (for a resolved contact) its display name — a
//! secret-boundary value, so `Debug` redacts it. Card bytes / public keys
//! never appear (spec §3; D.1.8 §4.4).

use secretary_ffi_bridge::{RecipientKind, RecipientSummary};

/// One recipient of a block surfaced to the "Shared with" banner.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecipientDto {
    pub uuid_hex: String,
    pub kind: RecipientKindDto,
    /// `Some(name)` only for a resolved `Contact`; `None` for owner / unknown.
    pub display_name: Option<String>,
}

/// Wire tag for the recipient classification. Serialized lower-case so the
/// frontend switches on `"owner" | "contact" | "unknown"`.
#[derive(Debug, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecipientKindDto {
    Owner,
    Contact,
    Unknown,
}

impl std::fmt::Debug for RecipientDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecipientDto")
            .field("uuid_hex", &self.uuid_hex)
            .field("kind", &self.kind)
            .field("display_name", &self.display_name.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl From<&RecipientSummary> for RecipientDto {
    fn from(s: &RecipientSummary) -> Self {
        let (kind, display_name) = match &s.kind {
            RecipientKind::Owner => (RecipientKindDto::Owner, None),
            RecipientKind::Contact { display_name } => {
                (RecipientKindDto::Contact, Some(display_name.clone()))
            }
            RecipientKind::Unknown => (RecipientKindDto::Unknown, None),
        };
        RecipientDto {
            uuid_hex: hex::encode(s.recipient_uuid),
            kind,
            display_name,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn to_json<T: serde::Serialize>(v: &T) -> Value {
        serde_json::from_str(&serde_json::to_string(v).expect("ser")).expect("parse")
    }

    #[test]
    fn recipient_dto_camel_case_and_kind_tag() {
        let dto = RecipientDto {
            uuid_hex: "00112233445566778899aabbccddeeff".into(),
            kind: RecipientKindDto::Contact,
            display_name: Some("Alice".into()),
        };
        let v = to_json(&dto);
        assert_eq!(v["uuidHex"], "00112233445566778899aabbccddeeff");
        assert_eq!(v["kind"], "contact");
        assert_eq!(v["displayName"], "Alice");
        assert!(v.get("uuid_hex").is_none());
    }

    #[test]
    fn owner_serializes_as_owner_with_null_name() {
        let dto = RecipientDto {
            uuid_hex: "ab".into(),
            kind: RecipientKindDto::Owner,
            display_name: None,
        };
        let v = to_json(&dto);
        assert_eq!(v["kind"], "owner");
        assert!(v["displayName"].is_null());
    }

    #[test]
    fn unknown_serializes_as_unknown() {
        let v = to_json(&RecipientDto {
            uuid_hex: "ab".into(),
            kind: RecipientKindDto::Unknown,
            display_name: None,
        });
        assert_eq!(v["kind"], "unknown");
    }

    #[test]
    fn debug_redacts_display_name() {
        let dto = RecipientDto {
            uuid_hex: "ab".into(),
            kind: RecipientKindDto::Contact,
            display_name: Some("SecretName".into()),
        };
        let dbg = format!("{dto:?}");
        assert!(!dbg.contains("SecretName"));
        assert!(dbg.contains("redacted"));
    }
}
