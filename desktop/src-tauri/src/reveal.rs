//! Pure projection + encoding helpers for the D.1.2 read path. No I/O, no
//! session state — these take bridge handles (already produced by
//! `read_block`) or raw bytes and return DTOs / encoded strings. Keeping
//! them pure lets the command layer in `commands/browse.rs` stay a thin
//! shell and lets these be unit-tested without a Tauri runtime.

use base64::Engine as _;
use zeroize::Zeroize;

use secretary_ffi_bridge::{BlockReadOutput, FieldHandle, Record};

use crate::dtos::{BlockDetailDto, FieldMetaDto, RecordDto};

/// Project a decrypted [`BlockReadOutput`] into a [`BlockDetailDto`],
/// **skipping tombstoned records** (trash/restore is D.1.5). Carries only
/// plaintext metadata — never calls `expose_text`/`expose_bytes`.
pub fn project_block_detail(block_uuid_hex: String, output: &BlockReadOutput) -> BlockDetailDto {
    let mut records = Vec::with_capacity(output.record_count());
    for i in 0..output.record_count() {
        let Some(record) = output.record_at(i) else {
            continue;
        };
        if record.tombstone() {
            continue;
        }
        records.push(project_record(&record));
    }
    BlockDetailDto {
        block_uuid_hex,
        block_name: output.block_name(),
        records,
    }
}

fn project_record(record: &Record) -> RecordDto {
    let field_count = record.field_count();
    let mut fields = Vec::with_capacity(field_count);
    for i in 0..field_count {
        if let Some(handle) = record.field_at(i) {
            fields.push(project_field_meta(&handle));
        }
    }
    RecordDto {
        record_uuid_hex: hex::encode(record.record_uuid()),
        record_type: record.record_type(),
        tags: record.tags(),
        created_at_ms: record.created_at_ms(),
        last_mod_ms: record.last_mod_ms(),
        // Derive field_count from the projected fields, not the separate
        // record.field_count() accessor, so the wire value stays consistent
        // with the fields array under a concurrent wipe().
        field_count: fields.len() as u64,
        fields,
    }
}

fn project_field_meta(handle: &FieldHandle) -> FieldMetaDto {
    FieldMetaDto {
        name: handle.name(),
        last_mod_ms: handle.last_mod_ms(),
        is_text: handle.is_text(),
        is_bytes: handle.is_bytes(),
    }
}

/// Locate a record in the output by its hex UUID. Returns `None` if no
/// record matches. Linear scan — record counts per block are small and the
/// reveal path is human-paced.
pub fn locate_record(output: &BlockReadOutput, record_uuid_hex: &str) -> Option<Record> {
    for i in 0..output.record_count() {
        if let Some(record) = output.record_at(i) {
            // Mirror project_block_detail: reveal must not resolve tombstoned records.
            if record.tombstone() {
                continue;
            }
            if hex::encode(record.record_uuid()) == record_uuid_hex {
                return Some(record);
            }
        }
    }
    None
}

/// Base64-encode revealed `bytes`-field plaintext, then zeroize the input
/// buffer. The returned `String` is the (unavoidable) widening point; the
/// raw `Vec<u8>` is overwritten before it drops.
pub fn encode_revealed_bytes(mut bytes: Vec<u8>) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
    bytes.zeroize();
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_revealed_bytes_matches_standard_base64() {
        let out = encode_revealed_bytes(b"hunter2".to_vec());
        assert_eq!(out, "aHVudGVyMg==");
    }

    #[test]
    fn encode_revealed_bytes_empty_is_empty_string() {
        assert_eq!(encode_revealed_bytes(vec![]), "");
    }

    #[test]
    fn encode_revealed_bytes_binary_roundtrips() {
        let raw = vec![0xde, 0xad, 0xbe, 0xef];
        let out = encode_revealed_bytes(raw.clone());
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(out.as_bytes())
            .expect("valid base64");
        assert_eq!(decoded, raw);
    }
}
