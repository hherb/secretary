//! uniffi dictionary projections for the #374 crash-repair informed-consent
//! surface: `ApprovedWidening` (foreign → Rust input, unvalidated) and
//! `AddedRecipient` / `WideningReport` / `RepairPreview` (Rust → foreign
//! output, projected from the bridge's `preview_repair_with_*` trio).
//! Mirrors the `ContactSummary` wiring pattern in `wrappers/contacts.rs`.
//!
//! `ApprovedWidening`'s four byte fields are NOT validated by this type —
//! per the established rule (FFI input validation lives at the binding
//! wrapper, not the dictionary), the namespace-fn wrappers in
//! `namespace/repair.rs` length-check every field (16/32/32/16-each bytes)
//! before converting to `secretary_ffi_bridge::FfiApprovedWidening`.

/// One user-approved crash-repair recipient widening. uniffi dictionary
/// counterpart of [`secretary_ffi_bridge::FfiApprovedWidening`]. Carries
/// unvalidated foreign input — see module docs.
#[derive(Debug, Clone)]
pub struct ApprovedWidening {
    /// Should be exactly 16 bytes; validated at the namespace-fn wrapper.
    pub block_uuid: Vec<u8>,
    /// Should be exactly 32 bytes; validated at the namespace-fn wrapper.
    pub file_fingerprint: Vec<u8>,
    /// Should be exactly 32 bytes; validated at the namespace-fn wrapper.
    /// The committed manifest entry fingerprint from
    /// [`WideningReport::committed_fingerprint_hex`] — the #391 third
    /// consent bind.
    pub committed_fingerprint: Vec<u8>,
    /// Each entry should be exactly 16 bytes; validated at the
    /// namespace-fn wrapper.
    pub added_recipients: Vec<Vec<u8>>,
}

/// One recipient a consent-eligible widening would add. uniffi dictionary
/// projection of [`secretary_ffi_bridge::FfiAddedRecipient`]. All fields
/// are non-secret display strings, already hex/UUID-formatted by the
/// bridge.
#[derive(Debug, Clone)]
pub struct AddedRecipient {
    pub uuid_hex: String,
    pub display_name: String,
    pub card_fingerprint_hex: String,
}

impl From<secretary_ffi_bridge::FfiAddedRecipient> for AddedRecipient {
    fn from(a: secretary_ffi_bridge::FfiAddedRecipient) -> Self {
        Self {
            uuid_hex: a.uuid_hex,
            display_name: a.display_name,
            card_fingerprint_hex: a.card_fingerprint_hex,
        }
    }
}

/// One block whose crash residue is a consent-eligible recipient
/// widening. uniffi dictionary projection of
/// [`secretary_ffi_bridge::FfiWideningReport`].
#[derive(Debug, Clone)]
pub struct WideningReport {
    pub block_uuid_hex: String,
    pub block_name: String,
    pub file_fingerprint_hex: String,
    /// The committed manifest entry fingerprint this widening was diffed
    /// against — copy verbatim into
    /// [`ApprovedWidening::committed_fingerprint`] (decoded to raw
    /// bytes); the #391 third consent bind.
    pub committed_fingerprint_hex: String,
    pub added: Vec<AddedRecipient>,
}

impl From<secretary_ffi_bridge::FfiWideningReport> for WideningReport {
    fn from(w: secretary_ffi_bridge::FfiWideningReport) -> Self {
        Self {
            block_uuid_hex: w.block_uuid_hex,
            block_name: w.block_name,
            file_fingerprint_hex: w.file_fingerprint_hex,
            committed_fingerprint_hex: w.committed_fingerprint_hex,
            added: w.added.into_iter().map(AddedRecipient::from).collect(),
        }
    }
}

/// The read-only result of a `preview_repair_with_*` call. uniffi
/// dictionary projection of [`secretary_ffi_bridge::FfiRepairPreview`].
#[derive(Debug, Clone)]
pub struct RepairPreview {
    pub widenings: Vec<WideningReport>,
}

impl From<secretary_ffi_bridge::FfiRepairPreview> for RepairPreview {
    fn from(p: secretary_ffi_bridge::FfiRepairPreview) -> Self {
        Self {
            widenings: p.widenings.into_iter().map(WideningReport::from).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn added_recipient_projection_round_trip() {
        let bridge = secretary_ffi_bridge::FfiAddedRecipient {
            uuid_hex: "0102-uuid".to_string(),
            display_name: "Carol".to_string(),
            card_fingerprint_hex: "abcd".to_string(),
        };
        let p = AddedRecipient::from(bridge);
        assert_eq!(p.uuid_hex, "0102-uuid");
        assert_eq!(p.display_name, "Carol");
        assert_eq!(p.card_fingerprint_hex, "abcd");
    }

    #[test]
    fn widening_report_projection_round_trip() {
        let bridge = secretary_ffi_bridge::FfiWideningReport {
            block_uuid_hex: "block-uuid".to_string(),
            block_name: "Passwords".to_string(),
            file_fingerprint_hex: "ff00".to_string(),
            committed_fingerprint_hex: "cc11".to_string(),
            added: vec![secretary_ffi_bridge::FfiAddedRecipient {
                uuid_hex: "0102-uuid".to_string(),
                display_name: "Carol".to_string(),
                card_fingerprint_hex: "abcd".to_string(),
            }],
        };
        let p = WideningReport::from(bridge);
        assert_eq!(p.block_uuid_hex, "block-uuid");
        assert_eq!(p.block_name, "Passwords");
        assert_eq!(p.file_fingerprint_hex, "ff00");
        assert_eq!(p.committed_fingerprint_hex, "cc11");
        assert_eq!(p.added.len(), 1);
        assert_eq!(p.added[0].display_name, "Carol");
    }

    #[test]
    fn repair_preview_projection_round_trip_empty() {
        let bridge = secretary_ffi_bridge::FfiRepairPreview { widenings: vec![] };
        let p = RepairPreview::from(bridge);
        assert!(p.widenings.is_empty());
    }

    #[test]
    fn repair_preview_projection_round_trip_nonempty() {
        let bridge = secretary_ffi_bridge::FfiRepairPreview {
            widenings: vec![secretary_ffi_bridge::FfiWideningReport {
                block_uuid_hex: "block-uuid".to_string(),
                block_name: "Passwords".to_string(),
                file_fingerprint_hex: "ff00".to_string(),
                committed_fingerprint_hex: "cc11".to_string(),
                added: vec![],
            }],
        };
        let p = RepairPreview::from(bridge);
        assert_eq!(p.widenings.len(), 1);
        assert_eq!(p.widenings[0].block_name, "Passwords");
    }
}
