//! D.1.6 contacts wrappers (#206): the `ContactSummary` dictionary
//! projection of `secretary_ffi_bridge::ContactSummary`.

/// uniffi dictionary projection of `secretary_ffi_bridge::ContactSummary`.
/// All fields are non-secret public metadata.
#[derive(Debug)]
pub struct ContactSummary {
    pub contact_uuid: Vec<u8>,
    pub display_name: String,
    pub shared_block_count: u32,
}

impl From<secretary_ffi_bridge::ContactSummary> for ContactSummary {
    fn from(s: secretary_ffi_bridge::ContactSummary) -> Self {
        Self {
            contact_uuid: s.contact_uuid.to_vec(),
            display_name: s.display_name,
            shared_block_count: s.shared_block_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contact_summary_projection_round_trip() {
        let bridge = secretary_ffi_bridge::ContactSummary {
            contact_uuid: [9u8; 16],
            display_name: "Carol".to_string(),
            shared_block_count: 3,
        };
        let p = ContactSummary::from(bridge);
        assert_eq!(p.contact_uuid, vec![9u8; 16]);
        assert_eq!(p.display_name, "Carol");
        assert_eq!(p.shared_block_count, 3);
    }
}
