//! Test fixtures shared between `interactive.rs` and `noninteractive.rs`
//! unit tests. Compiled only under `#[cfg(test)]`.

use secretary_core::sync::{BlockId, RecordId, RecordTombstoneVeto};
use secretary_core::vault::record::Record;
use std::collections::BTreeMap;

/// Build a minimal [`RecordTombstoneVeto`] whose `record_id` is the
/// 16-byte repetition of `record_id_byte`. The single-byte pattern
/// makes per-veto bijection assertions easy to read.
pub fn dummy_veto(record_id_byte: u8) -> RecordTombstoneVeto {
    let record_id: RecordId = [record_id_byte; 16];
    let block_id: BlockId = [0; 16];
    RecordTombstoneVeto {
        record_id,
        block_id,
        local_state: Record {
            record_uuid: record_id,
            record_type: "kv".into(),
            fields: BTreeMap::new(),
            tags: Vec::new(),
            created_at_ms: 0,
            last_mod_ms: 0,
            tombstone: false,
            tombstoned_at_ms: 0,
            unknown: BTreeMap::new(),
        },
        disk_tombstone_at_ms: 1_000,
        disk_tombstoner_device: [0; 16],
    }
}
