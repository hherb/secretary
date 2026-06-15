use std::path::Path;

use crate::convergence_helpers::{decrypt_block_records, Baseline};

/// Secret-free, order-stable projection of a `Record` used for
/// cross-ordering convergence comparison. Field VALUES are not compared
/// directly (they are `SecretString`); instead the value is hashed into
/// a stable digest so equality is meaningful without exposing secrets.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LogicalRecord {
    pub record_uuid: [u8; 16],
    pub tombstone: bool,
    pub last_mod_ms: u64,
    pub field_names: Vec<String>,
    /// (field_name, blake3-of-plaintext-value) pairs, sorted by name.
    pub field_value_digests: Vec<(String, [u8; 32])>,
}

/// Decrypt the named block in `folder` and project to a sorted
/// `Vec<LogicalRecord>` (sorted by record_uuid for stable comparison).
pub fn decrypt_state(
    baseline: &Baseline,
    folder: &Path,
    block_uuid: [u8; 16],
) -> Vec<LogicalRecord> {
    let records = decrypt_block_records(folder, baseline.password(), block_uuid);
    let mut out: Vec<LogicalRecord> = records
        .iter()
        .map(|r| {
            let mut field_names: Vec<String> = r.fields.keys().cloned().collect();
            field_names.sort();
            let mut field_value_digests: Vec<(String, [u8; 32])> = r
                .fields
                .iter()
                .map(|(k, v)| (k.clone(), digest_field_value(&v.value)))
                .collect();
            field_value_digests.sort_by(|a, b| a.0.cmp(&b.0));
            LogicalRecord {
                record_uuid: r.record_uuid,
                tombstone: r.tombstone,
                last_mod_ms: r.last_mod_ms,
                field_names,
                field_value_digests,
            }
        })
        .collect();
    out.sort();
    out
}

fn digest_field_value(value: &secretary_core::vault::RecordFieldValue) -> [u8; 32] {
    use secretary_core::crypto::hash::hash;
    use secretary_core::vault::RecordFieldValue;
    let bytes: &[u8] = match value {
        RecordFieldValue::Text(s) => s.expose().as_bytes(),
        RecordFieldValue::Bytes(b) => b.expose(),
    };
    *hash(bytes).as_bytes()
}

/// The convergence contract's logical-equality assertion: two orderings
/// of the same scenario must decrypt to identical logical state.
pub fn assert_converged(order_ab: &[LogicalRecord], order_ba: &[LogicalRecord]) {
    assert_eq!(
        order_ab, order_ba,
        "order-independence violated: A-canonical and B-canonical orderings diverged",
    );
}
