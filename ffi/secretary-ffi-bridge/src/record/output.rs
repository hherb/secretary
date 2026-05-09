//! [`BlockReadOutput`] — container handle for one block's decrypted records.
//!
//! Holds owned [`Record`](super::Record)s; [`BlockReadOutput::wipe`]
//! cascades wipe to every contained record + field. Uses the simpler
//! `Mutex<Option<Inner>>` (not `Arc<Mutex<Option<...>>>`) because there
//! is no shared-clone access pattern at this level — the foreign
//! caller holds exactly one `BlockReadOutput`.

use std::sync::Mutex;

use super::Record;
use crate::sync_helpers::lock_or_recover;

/// Container handle for one block's decrypted records. Holds owned
/// [`Record`]s; [`BlockReadOutput::wipe`] cascades to every contained
/// record + field. Idempotent.
pub struct BlockReadOutput {
    inner: Mutex<Option<BlockReadOutputInner>>,
}

/// File-private inner. Constructor takes individual args so the type
/// stays fully encapsulated.
struct BlockReadOutputInner {
    block_uuid: [u8; 16],
    block_name: String,
    records: Vec<Record>,
}

/// Redacted Debug — never leak any secret material in `{:?}` output.
impl std::fmt::Debug for BlockReadOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let is_closed = lock_or_recover(&self.inner).is_none();
        f.debug_struct("BlockReadOutput")
            .field("closed", &is_closed)
            .finish()
    }
}

impl BlockReadOutput {
    /// Build a `BlockReadOutput` from its component fields. Crate-private:
    /// only [`super::read_block`] constructs this. Takes individual args
    /// so the inner struct stays fully private to this file.
    pub(crate) fn new(block_uuid: [u8; 16], block_name: String, records: Vec<Record>) -> Self {
        Self {
            inner: Mutex::new(Some(BlockReadOutputInner {
                block_uuid,
                block_name,
                records,
            })),
        }
    }

    /// 16-byte block UUID. Returns 16 zero bytes if wiped.
    pub fn block_uuid(&self) -> [u8; 16] {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.block_uuid)
            .unwrap_or([0u8; 16])
    }

    /// User-visible block name. Returns `""` if wiped.
    pub fn block_name(&self) -> String {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.block_name.clone())
            .unwrap_or_default()
    }

    /// Number of records in the block. Returns 0 if wiped.
    pub fn record_count(&self) -> usize {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.records.len())
            .unwrap_or(0)
    }

    /// Returns a clone of the [`Record`] handle at `idx`, or `None` if
    /// `idx` is out of range or the output has been wiped. The clone
    /// shares the same `Arc<Mutex<Option<RecordInner>>>` as the
    /// original — wiping either invalidates both.
    pub fn record_at(&self, idx: usize) -> Option<Record> {
        lock_or_recover(&self.inner)
            .as_ref()
            .and_then(|i| i.records.get(idx).cloned())
    }

    /// Drop the wrapped records now, cascading wipe to every inner
    /// [`Record`] and [`FieldHandle`](super::FieldHandle). **Idempotent**
    /// — multiple calls do not panic.
    pub fn wipe(&self) {
        if let Some(inner) = lock_or_recover(&self.inner).take() {
            // Walk the records and wipe each before they go out of scope.
            // The Drop cascade would also wipe via Record's own Drop, but
            // explicit wipe lets the spec claim "wipe is the single
            // cleanup point" without depending on drop ordering.
            for r in &inner.records {
                r.wipe();
            }
            // inner drops here → records Vec drops → each Record's Drop
            // runs, but its inner Option is already None so it's a no-op.
        }
    }
}
