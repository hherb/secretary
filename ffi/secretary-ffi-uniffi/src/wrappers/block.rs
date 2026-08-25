//! Per-block decrypted-record opaque handles: `BlockReadOutput`, `Record`,
//! `FieldHandle`. The cascade is BlockReadOutput → Record → FieldHandle;
//! wiping any level cascades down to the children.

/// uniffi wrapper around `secretary_ffi_bridge::BlockReadOutput`. Newtype;
/// methods are thin forwarders. Drops on foreign refcount → 0 (RAII safety
/// net via uniffi-generated `AutoCloseable.close()` on Kotlin / `deinit` on
/// Swift) or via explicit `wipe()`.
pub struct BlockReadOutput(pub(crate) secretary_ffi_bridge::BlockReadOutput);

impl BlockReadOutput {
    pub fn block_uuid(&self) -> Vec<u8> {
        self.0.block_uuid().to_vec()
    }
    pub fn block_name(&self) -> String {
        self.0.block_name()
    }
    pub fn record_count(&self) -> u64 {
        self.0.record_count() as u64
    }
    pub fn record_at(&self, idx: u64) -> Option<std::sync::Arc<Record>> {
        // u64 → usize CAN truncate on 32-bit targets; `idx as usize` would
        // wrap a too-large `idx` to a smaller in-range value and return
        // `Some(record)` instead of `None`. `try_from` short-circuits to
        // `None` for any `idx` that doesn't fit, preserving "out-of-range
        // index returns None" on every platform.
        let idx = usize::try_from(idx).ok()?;
        self.0
            .record_at(idx)
            .map(|r| std::sync::Arc::new(Record(r)))
    }
    pub fn wipe(&self) {
        self.0.wipe();
    }
}

/// uniffi wrapper around `secretary_ffi_bridge::Record`.
pub struct Record(pub(crate) secretary_ffi_bridge::Record);

impl Record {
    pub fn record_uuid(&self) -> Vec<u8> {
        self.0.record_uuid().to_vec()
    }
    pub fn record_type(&self) -> String {
        self.0.record_type()
    }
    pub fn tags(&self) -> Vec<String> {
        self.0.tags()
    }
    pub fn created_at_ms(&self) -> u64 {
        self.0.created_at_ms()
    }
    pub fn last_mod_ms(&self) -> u64 {
        self.0.last_mod_ms()
    }
    pub fn tombstone(&self) -> bool {
        self.0.tombstone()
    }
    pub fn field_count(&self) -> u64 {
        self.0.field_count() as u64
    }
    pub fn field_names(&self) -> Vec<String> {
        self.0.field_names()
    }
    pub fn field_by_name(&self, name: String) -> Option<std::sync::Arc<FieldHandle>> {
        self.0
            .field_by_name(&name)
            .map(|f| std::sync::Arc::new(FieldHandle(f)))
    }
    pub fn field_at(&self, idx: u64) -> Option<std::sync::Arc<FieldHandle>> {
        // See `BlockReadOutput::record_at` for the truncation rationale —
        // `try_from` keeps "out-of-range index returns None" platform-
        // independent on 32-bit targets where `idx as usize` could wrap.
        let idx = usize::try_from(idx).ok()?;
        self.0
            .field_at(idx)
            .map(|f| std::sync::Arc::new(FieldHandle(f)))
    }
    pub fn wipe(&self) {
        self.0.wipe();
    }
}

/// uniffi wrapper around `secretary_ffi_bridge::FieldHandle`.
pub struct FieldHandle(pub(crate) secretary_ffi_bridge::FieldHandle);

impl FieldHandle {
    pub fn name(&self) -> String {
        self.0.name()
    }
    pub fn last_mod_ms(&self) -> u64 {
        self.0.last_mod_ms()
    }
    pub fn device_uuid(&self) -> Vec<u8> {
        self.0.device_uuid().to_vec()
    }
    pub fn is_text(&self) -> bool {
        self.0.is_text()
    }
    pub fn is_bytes(&self) -> bool {
        self.0.is_bytes()
    }
    /// Decrypted field plaintext, or `None` for a wiped/non-text field.
    /// String is caller-owned; caller MUST zeroize after use.
    ///
    /// #519: there is no Rust-side wipe here. The reason is NOT that there
    /// is no local to wrapper-type — the bridge's `expose().to_vec()`
    /// result IS a local this crate owns. There are three copies per call,
    /// and the second is the one that cannot be reached:
    ///
    /// 1. the bridge's `to_vec()` — ours, unwiped;
    /// 2. the `RustBuffer` — `lower_into_rust_buffer`
    ///    (`uniffi_core-0.32.0/src/ffi_converter_traits.rs:265`) builds a
    ///    `Vec<u8>` and hands it to the foreign side, which frees it
    ///    through uniffi's own generated `rustbuffer_free` ->
    ///    `RustBuffer::destroy`. **We never see that free.**
    /// 3. the Swift `Data` / Kotlin `ByteArray` — the caller's documented
    ///    contract.
    ///
    /// `uniffi::custom_type!` does not help: `uniffi_macros-0.32.0/
    /// src/custom.rs:236-247` generates `<Vec<u8> as Lower>::write(
    /// lower_expr, buf)`, so a custom type must still materialise a real
    /// `Vec<u8>` first. Only a hand-authored `unsafe impl Lower` avoids
    /// copy 1 — an `unsafe trait` in a crate that sets
    /// `unsafe_code = "deny"`, requiring a hand-written duplicate of
    /// uniffi's wire format that must stay byte-exact across every uniffi
    /// upgrade. That closes 1 of 3 copies. Copy 2 needs upstream support.
    pub fn expose_text(&self) -> Option<String> {
        self.0.expose_text()
    }
    /// Decrypted field plaintext, or `None` for a wiped/non-bytes field.
    /// Bytes are caller-owned heap; caller MUST zeroize after use.
    /// Same #519 three-copy analysis as [`Self::expose_text`].
    pub fn expose_bytes(&self) -> Option<Vec<u8>> {
        self.0.expose_bytes()
    }
    pub fn wipe(&self) {
        self.0.wipe();
    }
}
