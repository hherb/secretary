//! [`Record`] — per-record handle. `Arc<Mutex<Option<Inner>>>` so
//! accessors can return cheap clones; every clone shares the same wiped
//! state via `Option::take` on the shared inner.

use std::sync::{Arc, Mutex};

use super::FieldHandle;
use crate::sync_helpers::lock_or_recover;

/// Per-record handle. Shared via `Arc` so accessors can return cheap
/// clones the foreign caller can store independently.
#[derive(Clone)]
pub struct Record {
    inner: Arc<Mutex<Option<RecordInner>>>,
}

struct RecordInner {
    record_uuid: [u8; 16],
    record_type: String,
    tags: Vec<String>,
    created_at_ms: u64,
    last_mod_ms: u64,
    tombstone: bool,
    /// Field handles in the BTreeMap iteration order (matches the
    /// canonical-CBOR order modulo the `len-then-bytes` reorder, which
    /// is irrelevant once the data is in memory). The corresponding
    /// `field_names` Vec is computed from this list at accessor time.
    fields: Vec<FieldHandle>,
}

impl std::fmt::Debug for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let is_closed = lock_or_recover(&self.inner).is_none();
        f.debug_struct("Record")
            .field("closed", &is_closed)
            .finish()
    }
}

impl Record {
    /// Build a `Record` from its component fields. Crate-private:
    /// only [`super::read_block`] constructs this from the decrypted
    /// `core::vault::record::Record`. Takes individual args so the
    /// inner struct stays fully private to this file.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        record_uuid: [u8; 16],
        record_type: String,
        tags: Vec<String>,
        created_at_ms: u64,
        last_mod_ms: u64,
        tombstone: bool,
        fields: Vec<FieldHandle>,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Some(RecordInner {
                record_uuid,
                record_type,
                tags,
                created_at_ms,
                last_mod_ms,
                tombstone,
                fields,
            }))),
        }
    }

    /// 16-byte record UUID. Returns 16 zero bytes if wiped.
    pub fn record_uuid(&self) -> [u8; 16] {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.record_uuid)
            .unwrap_or([0u8; 16])
    }

    /// Open-ended record-type discriminator (e.g. `"login"`). Returns
    /// `""` if wiped.
    pub fn record_type(&self) -> String {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.record_type.clone())
            .unwrap_or_default()
    }

    /// Cross-cutting tags. Returns an empty `Vec` if wiped.
    pub fn tags(&self) -> Vec<String> {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.tags.clone())
            .unwrap_or_default()
    }

    /// Record creation timestamp, Unix milliseconds. Returns 0 if wiped.
    pub fn created_at_ms(&self) -> u64 {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.created_at_ms)
            .unwrap_or(0)
    }

    /// Record-level last-modification timestamp, Unix milliseconds.
    /// Returns 0 if wiped.
    pub fn last_mod_ms(&self) -> u64 {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.last_mod_ms)
            .unwrap_or(0)
    }

    /// `false` = live, `true` = deleted. Returns `false` if wiped.
    /// Note: `tombstoned_at_ms` (CRDT death-clock) is NOT projected —
    /// sync-orchestration internal.
    pub fn tombstone(&self) -> bool {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.tombstone)
            .unwrap_or(false)
    }

    /// Number of fields in the record. Returns 0 if wiped.
    pub fn field_count(&self) -> usize {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.fields.len())
            .unwrap_or(0)
    }

    /// Field names in BTreeMap iteration order. Returns an empty `Vec`
    /// if wiped.
    pub fn field_names(&self) -> Vec<String> {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.fields.iter().map(|f| f.name()).collect())
            .unwrap_or_default()
    }

    /// Returns a clone of the [`FieldHandle`] by name, or `None` if no
    /// field has this name or the record has been wiped. The clone
    /// shares the same Arc as the original — wiping either invalidates
    /// both.
    pub fn field_by_name(&self, name: &str) -> Option<FieldHandle> {
        lock_or_recover(&self.inner)
            .as_ref()
            .and_then(|i| i.fields.iter().find(|f| f.name() == name).cloned())
    }

    /// Returns a clone of the [`FieldHandle`] at `idx`, or `None` if
    /// out of range or wiped.
    pub fn field_at(&self, idx: usize) -> Option<FieldHandle> {
        lock_or_recover(&self.inner)
            .as_ref()
            .and_then(|i| i.fields.get(idx).cloned())
    }

    /// Drop the wrapped record now, cascading wipe to every contained
    /// [`FieldHandle`]. **Idempotent** — multiple calls do not panic.
    pub fn wipe(&self) {
        if let Some(inner) = lock_or_recover(&self.inner).take() {
            for f in &inner.fields {
                f.wipe();
            }
        }
    }
}
