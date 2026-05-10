# Sub-project B.4c — `save_block` (encrypt + persist record mutations)

**Date:** 2026-05-09
**Status:** Design approved (brainstormed 2026-05-09; this doc is the input to writing-plans).
**Predecessor:** [B.4b — read_block](2026-05-09-ffi-b4b-read-block-design.md).
**Successor (planned):** B.4d — `share_block` (multi-recipient extension).

## 1. Purpose

Add a fallible "encrypt + atomic-persist one block" entry point to the bridge crate, surfaced through the PyO3 (`secretary-ffi-py`) and uniffi (`secretary-ffi-uniffi`) flavors. v1 single-author: the saving identity is the vault owner, and recipients are owner-only; multi-recipient flows are B.4d's `share_block`.

`core::vault::save_block` already exists at [orchestrators.rs:701](../../../core/src/vault/orchestrators.rs#L701); B.4c is a thin bridge layer that exposes it through the foreign FFI surfaces with type-safe input shapes and the same handle-lifecycle / error-mapping discipline B.4a/B.4b established.

## 2. Architectural decisions (settled in brainstorming)

| Decision | Choice | Rationale |
|---|---|---|
| Locking model on `OpenVaultManifest` | `&self` + interior mutability via existing `Mutex<Option<inner>>` | Matches B.4b read pattern; PyO3 `&self` ergonomic; uniffi auto-handles `Arc<Self>`; fewer wrapper layers |
| Foreign record-input shape | Single-call flat structs with tagged value enum | One FFI hop; uniffi maps cleanly to Kotlin sealed class / Swift enum / Python tagged dataclass; mirrors the read-side hybrid (Record + FieldHandle) projection |
| UUID / now_ms ownership | Caller provides everything (`block_uuid`, `record_uuid[]`, `now_ms`) | Deterministic tests; no hidden global state in bridge; supports update path (same uuid → replace) |
| Recipients in v1 | Owner-only; bridge internally builds `[owner_card]` | Smaller surface; matches incremental B.4 progression; multi-recipient path is B.4d |
| Zeroize discipline on input field values | Bridge wraps in `SecretString` / `SecretBytes` at FFI boundary | Bridge layer does NOT widen the existing `core::RecordFieldValue` v1 zeroize gap (CLAUDE.md-flagged); plaintext exposure limited to the brief `BlockInput → BlockPlaintext` conversion |
| Save-time crypto failure mapping | New `FfiVaultError::SaveCryptoFailure { detail }` variant | Save-time crypto failures on already-validated inputs are categorically different from on-disk corruption; the existing read path's `CorruptVault` mapping is correct *for reads* but wrong for save |

## 3. Module structure

```
ffi/secretary-ffi-bridge/src/
├── save/
│   ├── mod.rs           ~40 LOC, input-type re-exports + module docs
│   ├── input.rs         ~150 LOC, BlockInput / RecordInput / FieldInput / FieldInputValue / SecretString
│   └── orchestration.rs ~250 LOC, save_block free function
├── vault.rs             +1 method (snapshot_for_save_block, ~50 LOC)
├── identity.rs          +1 accessor (signer_secret_keys, ~50 LOC) + SignerSecretKeysError enum
├── error.rs             +1 variant (SaveCryptoFailure)
└── lib.rs               +1 line of pub use save::{save_block, BlockInput, ...}
```

`vault.rs` is at 762 lines (already over the 500-line policy threshold per CLAUDE.md). NEXT_SESSION defers the vault.rs split until *after* B.4c. For *new* code the proactive-split feedback rule applies — put the bulk in a new `save/` module mirroring the existing `record/` directory.

## 4. Public bridge API

```rust
// save/input.rs

/// Bridge-side wrapper for secret UTF-8 text. Wraps a Sensitive<Vec<u8>>;
/// constructor validates UTF-8. Empty strings allowed. Zeroize-on-drop.
/// New newtype, not yet present in the workspace.
pub struct SecretString(/* Sensitive<Vec<u8>> */);

impl SecretString {
    pub fn new(s: String) -> Self;
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, std::str::Utf8Error>;
    pub(crate) fn expose_str(&self) -> &str;  // crate-internal only
}

pub enum FieldInputValue {
    Text(SecretString),
    Bytes(SecretBytes),  // existing zeroize-typed wrapper
}

pub struct FieldInput {
    pub name: String,        // plaintext — already plaintext in core::RecordField.name
    pub value: FieldInputValue,
}

pub struct RecordInput {
    pub record_uuid: [u8; 16],
    pub fields: Vec<FieldInput>,
}

pub struct BlockInput {
    pub block_uuid: [u8; 16],
    pub block_name: String,  // plaintext within encrypted manifest
    pub records: Vec<RecordInput>,  // empty allowed
}

// save/orchestration.rs

/// Encrypt and atomically persist one block of records. Mirrors the
/// free-function shape of `crate::record::read_block`.
///
/// v1 single-author: recipients = [owner_card]. Multi-recipient is B.4d.
///
/// On Ok(()): block file written to `<vault>/blocks/<uuid>.cbor.enc` and
/// the manifest re-signed and atomically replaced. The bridge-held
/// `OpenVaultManifest` is updated in place to reflect the new manifest
/// body and envelope.
///
/// On Err: bridge in-memory state is byte-identical to pre-call. On-disk
/// state may have a partial write (block file persisted but manifest
/// re-sign failed); §9 atomicity is per-file, and a divergent
/// block-file-without-manifest-entry is harmless because `open_vault`
/// reads only entries listed in the manifest.
pub fn save_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    input: BlockInput,
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<(), FfiVaultError>;
```

## 5. Data flow

```
save_block(identity, manifest, input, device_uuid, now_ms)
  │
  1. Lock identity inner; lock manifest inner.
  │  Build a temporary core::vault::OpenVault by:
  │    - Sensitive::new on a fresh slot for identity_block_key (zeroize the stack copy)
  │    - clone identity (the IdentityBundle — Sensitive fields clone-and-zeroize correctly)
  │    - clone owner_card
  │    - clone manifest body  ◄── unmodified-on-failure invariant
  │    - clone manifest_file  ◄──
  │
  2. Convert BlockInput → core::vault::BlockPlaintext:
  │    - For each FieldInputValue::Text(SecretString), expose_str() to populate
  │      core::RecordFieldValue::Text(String). Plaintext exposure is a few
  │      microseconds; SecretString drops afterwards.
  │    - For each FieldInputValue::Bytes(SecretBytes), expose() to populate
  │      core::RecordFieldValue::Bytes(Vec<u8>). SecretBytes drops afterwards.
  │
  3. Call core::vault::save_block(folder, &mut open_vault, plaintext,
  │                               &[owner_card], device_uuid, now_ms, &mut OsRng)
  │  which: re-derives BCK, encrypts block, atomic-writes blocks/<uuid>.cbor.enc,
  │         re-signs manifest with hybrid Ed25519+ML-DSA-65, atomic-writes manifest.
  │
  4. Match result:
  │    Ok(()):  m_inner.manifest = open_vault.manifest
  │             m_inner.manifest_file = open_vault.manifest_file
  │             // The other clones (IBK, identity, owner_card) drop with their
  │             // ZeroizeOnDrop impls. BlockPlaintext drops too.
  │             return Ok(())
  │    Err(e):  // m_inner UNCHANGED. Clones drop and zeroize.
  │             return Err(map_core_vault_error(e))
  │
  5. Locks released.
```

**RNG:** `OsRng` directly inside the bridge — same pattern as `core::vault::create_vault` callers. Not parameterized through the FFI surface (the foreign side cannot pass `&mut impl RngCore` across the boundary).

**Recipients:** `std::slice::from_ref(&open_vault.owner_card)` — owner-only, no foreign-side `recipients` parameter.

## 6. Error mapping

`core::vault::VaultError` → `FfiVaultError`:

| Core failure | Variant | Detail |
|---|---|---|
| Tick clock overflow | `SaveCryptoFailure` | `"vector clock saturated for device"` |
| `MlKem768Public::from_bytes` (owner) | `SaveCryptoFailure` | `"in-memory ML-KEM-768 parse failed: {e}"` |
| `pk_bundle_bytes()` / canonical-CBOR encode | `SaveCryptoFailure` | `"failed to canonicalize {thing}: {e}"` |
| `encrypt_block` | `SaveCryptoFailure` | `"failed to encrypt block: {e}"` |
| `encode_block_file` | `SaveCryptoFailure` | `"failed to encode block file: {e}"` |
| `sign_manifest` | `SaveCryptoFailure` | `"failed to re-sign manifest: {e}"` |
| `encode_manifest_file` | `SaveCryptoFailure` | `"failed to encode manifest: {e}"` |
| `create_dir_all(blocks/)` | `FolderInvalid` | `"failed to create blocks/ subdirectory: {e}"` |
| `write_atomic(block_path)` | `FolderInvalid` | `"failed to write block file: {e}"` |
| `write_atomic(manifest_path)` | `FolderInvalid` | `"failed to write manifest: {e}"` |
| Identity handle wiped | `CorruptVault` | `"identity handle has been closed"` |
| Manifest handle wiped | `CorruptVault` | `"vault manifest handle has been closed"` |
| `signer_secret_keys()` `MlDsa65ParseFailed` | `SaveCryptoFailure` | `"in-memory ML-DSA-65 parse failed"` |

`BlockInput.block_uuid` length is structurally enforced (`[u8; 16]`); foreign-binding wrappers (PyO3 / uniffi) surface wrong-length input as `ValueError` / `IllegalArgumentException`. Empty `records` vec is **allowed** (spec permits empty blocks).

**Asymmetry between read and save:**
- B.4b read path: crypto failures on on-disk bytes → `CorruptVault` (correct: input *is* the on-disk file).
- B.4c save path: crypto failures on freshly-built struct → `SaveCryptoFailure` (correct: failure produces *new* bytes from valid in-memory inputs).

This asymmetry is intentional and documented in the spec.

**New variant (`FfiVaultError::SaveCryptoFailure { detail }`):**
- Same `{ detail }` shape as `CorruptVault` and `FolderInvalid`.
- `Debug` redacts `detail` to `"<redacted>"` (B.4a redaction discipline).
- Mirrored into the uniffi `FfiVaultError`; PyO3 maps to a new `SaveCryptoFailureError` exception class.

**New bridge-internal type (parallel to existing `ReaderSecretKeysError`):**

```rust
pub(crate) enum SignerSecretKeysError {
    HandleClosed,         // identity handle wiped
    MlDsa65ParseFailed,   // post-unlock memory corruption hypothesis
}
```

## 7. Failure invariant

`core::save_block` performs two sequential atomic writes (block file at step 7, manifest at step 13). If the first succeeds and the second fails:

- **On disk:** new block file present, old manifest in place. The block UUID is not in `manifest.blocks`, so the next `open_vault` will not see the block. Harmless — block file is orphaned but inert.
- **In memory:** bridge `inner.manifest` and `inner.manifest_file` UNCHANGED (because the data flow operates on clones and only writes back on `Ok(())`).

Pinned by test `save_block_failure_leaves_in_memory_manifest_unchanged` (cfg(unix), uses chmod-to-read-only on `blocks/`). On Windows, the analogue would be `SetFileAttributesW` with read-only bit; not in scope for B.4c — Unix coverage suffices for the bridge invariant test, since the property under test is bridge-side, not platform-IO-side.

## 8. Test plan

### Bridge crate (17 unit tests + 1 proptest entry = 18 new test result lines)

| Module | Test | Purpose |
|---|---|---|
| save/orchestration | `save_block_insert_round_trips_through_read_block` | Open → save (new uuid) → read returns same records |
| | `save_block_update_replaces_existing_entry_and_advances_clock` | Same uuid → entry replaced; created_at_ms preserved; clock incremented |
| | `save_block_with_empty_records_succeeds` | Spec allows empty blocks |
| | `save_block_with_mixed_text_and_bytes_fields_round_trips` | FieldInputValue arm coverage |
| | `save_block_persists_to_disk_visible_to_fresh_open` | Save → close → open new handle → read sees the block |
| | `save_block_on_wiped_manifest_returns_corrupt_vault_handle_closed` | Mirrors B.4b read_block pattern |
| | `save_block_on_wiped_identity_returns_corrupt_vault_handle_closed` | Same |
| | `save_block_failure_leaves_in_memory_manifest_unchanged` (cfg(unix)) | Failure invariant: chmod blocks/ → FolderInvalid → manifest.block_count() pre-call |
| save/input | `secret_string_zeroizes_on_drop` | New SecretString unit |
| | `secret_string_rejects_invalid_utf8_in_from_bytes` | UTF-8 invariant |
| | `field_input_value_text_converts_to_core_record_field_value_text` | Conversion path |
| | `field_input_value_bytes_converts_to_core_record_field_value_bytes` | Conversion path |
| | `block_input_to_block_plaintext_preserves_uuid_and_name` | Conversion path |
| identity | `signer_secret_keys_after_wipe_returns_handle_closed` | Mirrors reader_secret_keys test |
| | `signer_secret_keys_when_live_returns_ok_tuple` | Mirrors reader_secret_keys test |
| vault | `snapshot_for_save_block_returns_some_when_live_and_none_when_wiped` | Mirrors snapshot_for_read_block test |
| | `snapshot_for_save_block_atomic_under_concurrent_wipe` | TOCTOU coverage parallel to read_block |

### Property test (proptest)

```rust
#[proptest]
fn block_input_round_trips_through_save_and_read(
    block_uuid: [u8; 16],
    block_name: String,
    records: Vec<arbitrary_record_input>,
) { ... }
```

One property: any well-formed BlockInput round-trips byte-identically through save_block → read_block. 256 cases × 1 property; cheap because save+read is ~10ms.

### PyO3 (~10 new tests)

- `test_save_block_round_trip_insert`
- `test_save_block_update_advances_vector_clock`
- `test_save_block_text_field_round_trip`
- `test_save_block_bytes_field_round_trip`
- `test_save_block_empty_records_allowed`
- `test_save_block_on_wiped_manifest_raises_corrupt_vault_error`
- `test_save_block_on_wiped_identity_raises_corrupt_vault_error`
- `test_save_block_wrong_length_block_uuid_raises_value_error`
- `test_save_block_persists_visible_to_fresh_open`
- `test_save_crypto_failure_error_class_is_distinct`

### Uniffi smoke (Swift +4, Kotlin +4)

- `saveBlock_insertRoundTripsThroughReadBlock`
- `saveBlock_updateAdvancesVectorClock`
- `saveBlock_onWipedManifestSurfacesTypedError`
- `saveBlock_textAndBytesFieldsRoundTrip`

### Conformance / fuzz

`conformance.py`, the differential-replay harness, and the `block_file` fuzz target all exercise the same `core::block::encrypt_block` path that B.4c calls into. **No conformance or fuzz changes required.**

### Acceptance counts

| Surface | Before | After | Target (NEXT_SESSION) |
|---|---|---|---|
| `cargo test --release --workspace` | 552 + 9 ignored | 570 + 9 ignored | 568+ ✓ |
| `pytest` (PyO3) | 40 | 50 | 50+ ✓ |
| Swift smoke | 22 | 26 | 26+ ✓ |
| Kotlin smoke | 23 | 27 | 27+ ✓ |
| `cargo clippy + fmt` | clean / OK | clean / OK | clean / OK ✓ |
| `conformance.py` + freshness | PASS | PASS | PASS ✓ |

## 9. Scope boundaries

**In scope.** Everything in §3–§8.

**Out of scope (explicit):**
- Multi-recipient creation (deferred to B.4d's `share_block`).
- Trash / un-trash flows (separate manifest list, separate task).
- Concurrent reads-during-save throughput optimization (Mutex serializes; v1 single-threaded UIs accept this).
- Performance measurement of the ~5ms re-sign cost — capture as a follow-up GitHub issue if not measured during B.4c.
- v2 zeroize-typing of `core::RecordFieldValue` (CLAUDE.md-flagged gap; bridge wrapping does NOT close it, only stops widening it).
- vault.rs file-size split (NEXT_SESSION defers until after B.4c).
- Windows analogue of the cfg(unix) failure-invariant test.

## 10. Risks

| Risk | Mitigation |
|---|---|
| Manifest re-sign Ed25519 + ML-DSA-65 ~5ms per save | Acceptable for v1; capture follow-up issue for measurement; not a B.4c blocker |
| Concurrent save+read lock contention | Acceptable for v1 single-threaded UIs; same lock serializes both paths |
| Failure invariant ("on-disk partial write, in-memory unchanged") | Test `save_block_failure_leaves_in_memory_manifest_unchanged` pins it; cfg(unix); document the on-disk-divergence-is-harmless property in the spec (this doc, §7) |
| `core::IdentityBundle` clone cost | ~200 bytes copy per save; trivial. Required because core::save_block takes `&mut OpenVault` (owned identity field) |
| Foreign-side `SecretString` discipline gap | The `String` / `bytes` value owned by Python/Swift/Kotlin GC before crossing FFI is the user's responsibility. Bridge wraps at the boundary; cannot enforce upstream. Document clearly. |
| `SecretString` UTF-8 invariant | `from_bytes` validates; constructor from `String` accepts (already-validated). Empty string allowed. Test `secret_string_rejects_invalid_utf8_in_from_bytes`. |

## 11. Build sequence

Single feature branch `feat/ffi-b4c-save-block`, single PR, four task commits + one docs commit. User stays in the inner review loop per the feedback memory.

| Task | Scope | Tests added |
|---|---|---|
| 1: Bridge accessors + types + new error variant | `signer_secret_keys()` on UnlockedIdentity; `snapshot_for_save_block()` on OpenVaultManifest; `save/input.rs` types (SecretString, BlockInput, RecordInput, FieldInput, FieldInputValue); `FfiVaultError::SaveCryptoFailure` variant + Debug redaction. **No save_block yet.** | ~9 (helpers + accessors + variant pin) |
| 2: Bridge save_block free function | `save/orchestration.rs` with the §5 data flow; round-trip + update + empty + mixed + persists + wiped-manifest + wiped-identity + failure-invariant tests; proptest | 8 + 1 proptest |
| 3: uniffi surface | Mirror SaveCryptoFailure variant + From-impl; namespace fn `save_block`; UDL types for input structs; Swift + Kotlin smoke tests | 4 Swift, 4 Kotlin |
| 4: PyO3 surface | `#[pyfunction] save_block`; `#[pyclass]` for input structs; `SaveCryptoFailureError`; module `__all__`; pytest coverage | 10 |
| docs commit | README "Where we are" totals; ROADMAP.md B.4 entry; NEXT_SESSION.md (committed pre-push per the feedback memory); handoff `docs/handoffs/YYYY-MM-DD-b4c-save-block.md` | n/a |

After Task 4, full test surface should hit the §8 acceptance counts (568 cargo, 50 pytest, 26 Swift, 27 Kotlin).

## 12. References

- [B.4b spec](2026-05-09-ffi-b4b-read-block-design.md) — read_block, the structural mirror this design follows
- [B.4a spec](2026-05-06-ffi-b4a-open-vault-design.md) — OpenVaultManifest handle pattern, `Mutex<Option<inner>>`, redaction discipline
- [B.3b spec](2026-05-05-ffi-b3b-create-vault-design.md) — atomic-write contract via `tempfile::persist`
- [core/src/vault/orchestrators.rs:701](../../../core/src/vault/orchestrators.rs#L701) — the `save_block` core orchestrator this wraps
- [docs/manual/contributors/memory-hygiene-audit-internal.md](../../manual/contributors/memory-hygiene-audit-internal.md) — wrapper discipline + drop ordering invariants the new SecretString must follow
- [CLAUDE.md](../../../CLAUDE.md) — "Memory hygiene: zeroize discipline" section + the v2 RecordFieldValue gap note this spec preserves
