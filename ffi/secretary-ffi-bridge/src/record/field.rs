//! [`FieldHandle`] — per-field handle. Holds the `RecordFieldValue`
//! (`SecretString` or `SecretBytes`); [`FieldHandle::expose_text`] /
//! [`FieldHandle::expose_bytes`] is the explicit secret-pull boundary.
//!
//! `Arc<Mutex<Option<Inner>>>` so accessors can return cheap clones
//! that share the same wiped state.

use std::sync::{Arc, Mutex};

use secretary_core::vault::record::RecordFieldValue;

use crate::sync_helpers::lock_or_recover;

/// Per-field handle. Shared via `Arc` so accessors can return cheap
/// clones the foreign caller can store independently. Wiping any clone
/// wipes them all (uses `Option::take` on the shared inner).
#[derive(Clone)]
pub struct FieldHandle {
    inner: Arc<Mutex<Option<FieldHandleInner>>>,
}

struct FieldHandleInner {
    name: String,
    value: RecordFieldValue,
    last_mod_ms: u64,
    device_uuid: [u8; 16],
}

impl std::fmt::Debug for FieldHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let is_closed = lock_or_recover(&self.inner).is_none();
        f.debug_struct("FieldHandle")
            .field("closed", &is_closed)
            .finish()
    }
}

impl FieldHandle {
    /// Build a `FieldHandle` from its component fields. Crate-private:
    /// only [`super::read_block`] constructs this.
    pub(crate) fn new(
        name: String,
        value: RecordFieldValue,
        last_mod_ms: u64,
        device_uuid: [u8; 16],
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Some(FieldHandleInner {
                name,
                value,
                last_mod_ms,
                device_uuid,
            }))),
        }
    }

    /// Field name (e.g. `"password"`, `"username"`). Returns `""` if
    /// wiped.
    pub fn name(&self) -> String {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.name.clone())
            .unwrap_or_default()
    }

    /// Per-field last-modification timestamp, Unix milliseconds.
    /// Returns 0 if wiped.
    pub fn last_mod_ms(&self) -> u64 {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.last_mod_ms)
            .unwrap_or(0)
    }

    /// 16-byte UUID of the device that last modified this field.
    /// Returns 16 zero bytes if wiped.
    pub fn device_uuid(&self) -> [u8; 16] {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.device_uuid)
            .unwrap_or([0u8; 16])
    }

    /// `true` if the field's payload is text. Returns `false` if wiped.
    pub fn is_text(&self) -> bool {
        lock_or_recover(&self.inner)
            .as_ref()
            .is_some_and(|i| matches!(i.value, RecordFieldValue::Text(_)))
    }

    /// `true` if the field's payload is bytes. Returns `false` if wiped.
    pub fn is_bytes(&self) -> bool {
        lock_or_recover(&self.inner)
            .as_ref()
            .is_some_and(|i| matches!(i.value, RecordFieldValue::Bytes(_)))
    }

    /// Pull the secret payload as UTF-8 [`String`]. Returns `None` if
    /// the field is bytes (caller should use [`Self::expose_bytes`]) or
    /// has been wiped.
    ///
    /// Returns a fresh `String` allocation; **caller is responsible for
    /// clearing it** (e.g. Python `del`, Swift `String` going out of
    /// scope, Kotlin GC). The underlying `SecretString` in the
    /// `FieldHandle` is NOT wiped by this call — call [`Self::wipe`]
    /// explicitly when done with the handle.
    ///
    /// Invalid-UTF-8 cannot reach this accessor by construction: CBOR
    /// `tstr` (major type 3) requires valid UTF-8 per RFC 8949 §3.1,
    /// and `core::vault::record::parse_record_field` only constructs
    /// `RecordFieldValue::Text(SecretString::new(s))` from an already-
    /// validated `Value::Text(s)`. The fuzz harness has a defense-in-
    /// depth assertion (B.4b Task 5) that would catch any future
    /// regression.
    pub fn expose_text(&self) -> Option<String> {
        lock_or_recover(&self.inner)
            .as_ref()
            .and_then(|i| match &i.value {
                RecordFieldValue::Text(s) => Some(s.expose().to_owned()),
                RecordFieldValue::Bytes(_) => None,
            })
    }

    /// Pull the secret payload as raw bytes. Returns `None` if the
    /// field is text (caller should use [`Self::expose_text`]) or has
    /// been wiped.
    ///
    /// Returns a fresh `Vec<u8>`; caller is responsible for clearing
    /// it. The underlying `SecretBytes` in the `FieldHandle` is NOT
    /// wiped by this call.
    pub fn expose_bytes(&self) -> Option<Vec<u8>> {
        lock_or_recover(&self.inner)
            .as_ref()
            .and_then(|i| match &i.value {
                RecordFieldValue::Bytes(b) => Some(b.expose().to_vec()),
                RecordFieldValue::Text(_) => None,
            })
    }

    /// Drop the wrapped field now. **Idempotent** — multiple calls do
    /// not panic. After this returns, every accessor returns the empty
    /// default and `expose_text` / `expose_bytes` return `None`.
    /// Cascades through every cloned `FieldHandle` because they share
    /// the underlying `Arc<Mutex<Option<...>>>`.
    pub fn wipe(&self) {
        let _drop = lock_or_recover(&self.inner).take();
        // _drop goes out of scope → FieldHandleInner drops → its `value`
        // (RecordFieldValue) drops → SecretString / SecretBytes
        // ZeroizeOnDrop runs.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secretary_core::crypto::secret::{SecretBytes, SecretString};

    fn dummy_text(name: &str, value: &str) -> FieldHandle {
        FieldHandle::new(
            name.to_string(),
            RecordFieldValue::Text(SecretString::new(value.to_string())),
            42,
            [0xab; 16],
        )
    }

    fn dummy_bytes(name: &str, value: &[u8]) -> FieldHandle {
        FieldHandle::new(
            name.to_string(),
            RecordFieldValue::Bytes(SecretBytes::new(value.to_vec())),
            42,
            [0xab; 16],
        )
    }

    #[test]
    fn text_field_is_text_not_bytes() {
        let f = dummy_text("password", "hunter2");
        assert!(f.is_text());
        assert!(!f.is_bytes());
        assert_eq!(f.expose_text(), Some("hunter2".to_string()));
        assert_eq!(f.expose_bytes(), None);
    }

    #[test]
    fn bytes_field_is_bytes_not_text() {
        let f = dummy_bytes("totp", &[0xde, 0xad, 0xbe, 0xef]);
        assert!(f.is_bytes());
        assert!(!f.is_text());
        assert_eq!(f.expose_bytes(), Some(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(f.expose_text(), None);
    }

    #[test]
    fn wipe_drops_secret_and_returns_empty_defaults() {
        let f = dummy_text("password", "hunter2");
        f.wipe();
        assert_eq!(f.expose_text(), None);
        assert_eq!(f.name(), "");
        assert_eq!(f.last_mod_ms(), 0);
        assert_eq!(f.device_uuid(), [0u8; 16]);
        // Idempotent.
        f.wipe();
        f.wipe();
    }

    #[test]
    fn arc_clone_shares_wiped_state() {
        let f1 = dummy_text("password", "hunter2");
        let f2 = f1.clone();
        assert_eq!(f1.expose_text(), Some("hunter2".to_string()));
        assert_eq!(f2.expose_text(), Some("hunter2".to_string()));
        f1.wipe();
        assert_eq!(f1.expose_text(), None);
        assert_eq!(f2.expose_text(), None);
    }

    #[test]
    fn metadata_accessors_return_constructor_args() {
        let f = dummy_text("password", "hunter2");
        assert_eq!(f.name(), "password");
        assert_eq!(f.last_mod_ms(), 42);
        assert_eq!(f.device_uuid(), [0xab; 16]);
    }
}
