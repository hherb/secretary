# Sub-project B.4b — FFI `read_block` (decrypt records from an open vault)

**Date:** 2026-05-09
**Author:** Horst Herb (with Claude)
**Status:** Approved — ready for implementation plan
**Touches:** edits in `ffi/secretary-ffi-bridge/`, `ffi/secretary-ffi-py/`, `ffi/secretary-ffi-uniffi/`; no `core/` changes; no on-disk fixture changes.

## Background

Sub-project B.4a ([design](2026-05-06-ffi-b4a-open-vault-design.md), [PR #28](https://github.com/hherb/secretary/pull/28)) shipped the folder-based `open_vault` path through PyO3 and uniffi via the shared `secretary-ffi-bridge` crate. The FFI surface now contains 7 user-facing entry points, with two opaque handles returning from the open paths: `UnlockedIdentity` (B.2) and `OpenVaultManifest` (B.4a). The latter holds the Identity Block Key + manifest body + envelope + verified owner contact card internally, set up so subsequent B.4 sub-projects can extend the surface without re-opening.

B.4b adds the next entry point: **`read_block`**. Given an open vault (the two B.4a handles) and a block UUID, return the decrypted records inside that block. The plaintext records carry the user's actual passwords / API keys / secret notes through the FFI for the first time — so the projection of `core::vault::record::{Record, RecordField, RecordFieldValue}` to Python / Swift / Kotlin is the central type-design question, not the orchestration.

The "bytes-not-strings" discipline established in B.2 / B.3a / B.3b for password input doesn't fit cleanly here: a `RecordFieldValue::Text` payload (from `SecretString`) is genuinely human-readable text (usernames, URLs, secret notes) the caller wants as `str`, not `bytes`. The hybrid handle/value-type design described below resolves this by making secret exposure an explicit, opt-in step on a per-field basis while keeping non-secret metadata ergonomic.

This sub-project does **not** yet expose record encryption (`save_block`, B.4c) or recipient management (`share_block`, B.4d). It also does not surface trash entries (deferred to Sub-project C / sync orchestration) or the multi-author block flow (deferred to B.4d / contact discovery).

## Goals

1. One new top-level `pub fn` on the bridge: `read_block(&UnlockedIdentity, &OpenVaultManifest, &[u8; 16])` returning `Result<BlockReadOutput, FfiVaultError>`. Free-function shape (not a method on either handle) per the project preference for pure functions in reusable modules.
2. Three new opaque handle types on the bridge:
   - `BlockReadOutput` — container for one block's records; `wipe()` cascades to every contained `Record` + `FieldHandle`'s secret.
   - `Record` — per-record handle; holds `FieldHandle`s + non-secret metadata accessors.
   - `FieldHandle` — per-field handle; holds the `RecordFieldValue` (`SecretString` or `SecretBytes`); `expose_text()` / `expose_bytes()` is the explicit secret-pull boundary.
3. `FfiVaultError` grows from 6 → 7 variants: add `BlockNotFound { uuid_hex: String }`. Same flat-enum shape; same `thiserror` derivation.
4. `OpenVaultManifestInner` is extended (bridge-internal change, no public B.4a surface change) with a `vault_folder: PathBuf` field so `read_block` can resolve `blocks/<uuid>.cbor.enc` without re-asking the caller for the folder.
5. `Record` projection is a **hybrid**: foreign-language Records carry plain non-secret metadata (record_uuid, record_type, tags, timestamps, tombstone) plus an ordered list of `FieldHandle`s. Each `FieldHandle` carries name + last_mod + device_uuid as plain accessors, and `expose_text()` / `expose_bytes()` for the secret payload.
6. The bridge crate stays the single source of FFI code truth; PyO3 and uniffi project the new surface from it.
7. Extend `core/fuzz/fuzz_targets/record.rs` with a defense-in-depth UTF-8-validity assertion on every successfully-decoded `RecordFieldValue::Text` (tripwire for any future weakening of the decode path; structurally guaranteed today by CBOR `tstr` validation). See "Open questions / risks" §1 for the full rationale and the rejected alternative (surfacing yet another `FfiVaultError` variant on `expose_text`).
8. All gates green at session close: cargo workspace +12-14 tests; pytest +10 tests; Swift smoke +4 asserts; Kotlin smoke +4 asserts. Conformance + freshness PASS unchanged. Fuzz target extension verified via a single `cargo fuzz run record -- -runs=10000` smoke run on the nightly toolchain (no new corpus required — the existing corpus exercises the Text-field path).

## Non-goals (YAGNI)

- **No `save_block` / record mutation.** B.4c will add the encrypted-write-and-update-manifest path, including the open question of whether `OpenVaultManifest` needs a `&mut self` writer-borrow model or stays at `&self` with the `Mutex<Option<...>>` pattern. B.4b's surface is read-only.
- **No `share_block` / recipient management.** B.4d.
- **No `Trash` / tombstoned block entries surfaced.** `Manifest.trash` stays internal. `block_summaries()` continues to filter out trashed blocks; `read_block(trashed_uuid)` returns `BlockNotFound`. Sub-project C (sync orchestration) will add the restore-from-trash flow with full vector-clock context — surfacing trash here without that context would be incomplete (resurrection conflict detection requires sync-orchestrator knowledge).
- **No multi-author block reading.** B.4b assumes the block author = vault owner (the v1 single-author case covered by `golden_vault_001`). The bridge takes `manifest.owner_card` as the sender card when calling `core::block::decrypt_block`. If the on-disk block's `author_fingerprint` doesn't match `fingerprint(owner_card_canonical_bytes)`, `decrypt_block` returns `BlockError::AuthorFingerprintMismatch` which folds into `FfiVaultError::CorruptVault`. B.4d's `share_block` flow will add a `contacts/<author_uuid>.card` discovery step + the `ContactCard` accessor surface needed to read multi-author blocks correctly.
- **No `vector_clock` projection.** `BlockPlaintext.vector_clock` is sync-orchestration internal; same rationale as B.4a deferring `BlockEntry.vector_clock_summary`.
- **No `block_version` / `schema_version` projection.** Both always 1 in v1; surfacing is unjustified until v2 introduces version-gated semantics.
- **No `Record.unknown` / `RecordField.unknown` forward-compat CBOR.** Mirrors B.4a's "no `BlockSummary.unknown`" decision — surfacing requires projecting `UnknownValue` (canonical CBOR), unjustified until v2 introduces concrete unknown semantics.
- **No `Record.tombstoned_at_ms` projection.** CRDT death-clock is sync-orchestration internal. (Note: `Record.tombstone: bool` IS surfaced — UI affordances for "show deleted records" are reasonable for a B.4b read-only viewer.)
- **No conformance.py extension.** Same rationale as B.3a / B.3b / B.4a — `core::block::decrypt_block` is fully covered by existing tests; the FFI surface is not part of the spec contract. Adding a folder-based read replay would not add spec-contract benefit.
- **No new on-disk fixture.** `golden_vault_001/blocks/11223344-5566-7788-99aa-bbccddeeff00.cbor.enc` already provides the read-block KAT (1 record, 2 fields, both Text — username + password). `golden_vault_002/` carries a parallel fixture used for cross-vault mismatch tests.
- **No CI integration.** Still no `.github/workflows/`.
- **No public-key accessors on `UnlockedIdentity`.** Still deferred from B.2 / B.3a / B.3b / B.4a. Will arrive whenever the first sharing operation needs them.

## Architecture

### Crate layout after B.4b

Strictly additive on B.4a. One new module on the bridge crate; no removed files.

```
ffi/
├── secretary-ffi-bridge/        ← single source of FFI code truth
│   └── src/
│       ├── lib.rs               ← edit: re-export read_block, BlockReadOutput, Record, FieldHandle;
│       │                                  update crate-doc to reflect 7 → 8 pub fns
│       ├── error.rs             ← edit: add 7th variant FfiVaultError::BlockNotFound { uuid_hex };
│       │                                  extend From<core::VaultError> mapping for block-class failures
│       ├── identity.rs          ← UNCHANGED (UnlockedIdentity re-used as-is)
│       ├── unlock.rs            ← UNCHANGED (B.2 / B.3a bytes-in surface)
│       ├── create.rs            ← UNCHANGED (B.3b)
│       ├── vault.rs             ← edit: extend OpenVaultManifestInner with vault_folder: PathBuf
│       │                                  (no public B.4a accessor surface change)
│       └── record.rs            ← NEW: read_block free fn + BlockReadOutput + Record + FieldHandle + tests
│
├── secretary-ffi-py/             ← +1 #[pyfunction], +3 #[pyclass], +1 create_exception!, +pytest
└── secretary-ffi-uniffi/         ← +1 namespace fn, +1 [Error] enum variant, +1 dictionary slot,
                                     +3 interfaces, +Swift smoke asserts, +Kotlin smoke asserts
```

The bridge crate stays pure-safe Rust under `#![forbid(unsafe_code)]`. The two binding-flavor crates retain their existing crate-local `unsafe_code = "deny"` carve-outs from B.1 / B.1.1.

### FFI surface after B.4b

8 user-facing entry points (was 7 after B.4a):

- **bytes-in:** `open_with_password`, `open_with_recovery`, `create_vault` (B.2 / B.3a / B.3b)
- **folder-in:** `open_vault_with_password`, `open_vault_with_recovery` (B.4a)
- **NEW:** `read_block` (B.4b)
- **smokes:** `add`, `version`

Two error types: `FfiUnlockError` (5-variant, bytes-in unchanged) and `FfiVaultError` (now 7-variant, +`BlockNotFound`).

Five opaque handles (was 2 after B.4a):

- `UnlockedIdentity` (B.2)
- `OpenVaultManifest` (B.4a)
- `BlockReadOutput` (B.4b — NEW)
- `Record` (B.4b — NEW)
- `FieldHandle` (B.4b — NEW)

All five share the `Mutex<Option<Inner>>` newtype + `lock_or_recover` poisoning-safety helper + idempotent `wipe()` semantics. `Record` and `FieldHandle` additionally wrap their inner in `Arc` so accessors can hand out cheap clones (the underlying secret lives once; all clones see the same `wipe()`).

### What lives where

| Concern | secretary-ffi-bridge | secretary-ffi-py | secretary-ffi-uniffi |
|---|---|---|---|
| `read_block(&identity, &manifest, &[u8; 16]) -> Result<BlockReadOutput, FfiVaultError>` | ✓ — locks both handles, looks up BlockEntry, reads + decodes + decrypts the block file, builds the output | thin `#[pyfunction]` forwarder; `Vec<u8> → [u8; 16]` raises `ValueError` on wrong length | thin namespace fn forwarder; `Vec<u8> → [u8; 16]` raises uniffi error on wrong length |
| `BlockReadOutput` (NEW opaque handle) | ✓ — `Mutex<Option<BlockReadOutputInner>>` newtype + `lock_or_recover` + idempotent `wipe()` | `#[pyclass]` newtype with `__enter__`/`__exit__` | uniffi `interface` (UDL); `AutoCloseable` via uniffi 0.31 codegen |
| `Record` (NEW opaque handle) | ✓ — `Arc<Mutex<Option<RecordInner>>>` (clone-cheap) | `#[pyclass]` newtype | uniffi `interface` (UDL) |
| `FieldHandle` (NEW opaque handle) | ✓ — `Arc<Mutex<Option<FieldHandleInner>>>` (clone-cheap) | `#[pyclass]` newtype | uniffi `interface` (UDL) |
| `FfiVaultError::BlockNotFound { uuid_hex }` | ✓ — added to flat enum; updated `From<core::VaultError>` mapping | `create_exception!(VaultBlockNotFound)`; mapping arm in `ffi_vault_error_to_pyerr` | added to `[Error] VaultError` UDL enum with `uuid_hex` field |

### `OpenVaultManifestInner` extension

```rust
// ffi/secretary-ffi-bridge/src/vault.rs (B.4b edit)
pub(crate) struct OpenVaultManifestInner {
    /// 32-byte Identity Block Key from core::OpenVault. Zeroized on drop.
    identity_block_key: Sensitive<[u8; 32]>,
    /// Decrypted manifest body — plaintext block list + vault-level
    /// vector clock + kdf_params attestation.
    manifest: Manifest,
    /// On-disk manifest envelope.
    manifest_file: ManifestFile,
    /// Owner's self-signed contact card, already self-verified at open_vault.
    owner_card: ContactCard,
    /// NEW in B.4b: the vault folder path the manifest was opened from.
    /// Used by read_block to resolve `blocks/<uuid>.cbor.enc`.
    /// B.4c (save_block) and B.4d (share_block) will reuse this for
    /// atomic writes through `tempfile::persist`.
    vault_folder: PathBuf,
}
```

`open_vault_with_password` and `open_vault_with_recovery` already receive the folder path; they pass it into `OpenVaultManifestInner` at construction. No B.4a public accessor on `OpenVaultManifest` exposes `vault_folder` — it stays internal. (If a future sub-project needs to surface it for UI, that's an additive accessor, not a breaking change.)

### `read_block` orchestration

```
Foreign caller                       Bridge crate                            secretary_core
─────────────                        ────────────                            ──────────────
read_block(identity,
           manifest,
           block_uuid: bytes)
     │
     ├─ PyO3/uniffi marshal ────────▶ bridge::read_block(
     │   (length-validate bytes)         &UnlockedIdentity,
     │                                    &OpenVaultManifest,
     │                                    &[u8; 16])
     │                                       │
     │                                       │ Step 1: lock both handles via lock_or_recover.
     │                                       │   - identity → IdentityBundle (x25519_sk + ml_kem_768_sk)
     │                                       │   - manifest → ManifestInner (manifest body, owner_card,
     │                                       │     vault_folder, manifest_file)
     │                                       │
     │                                       │ Step 2: locate the manifest BlockEntry.
     │                                       │   manifest.blocks.iter().find(|b| b.block_uuid == *uuid)
     │                                       │   - Not found → FfiVaultError::BlockNotFound { uuid_hex }
     │                                       │   - Trash entries are NOT considered (B.4b non-goal).
     │                                       │
     │                                       │ Step 3: resolve block file path.
     │                                       │   path = vault_folder / "blocks" / format!("{}.cbor.enc",
     │                                       │                                            uuid_hyphenated)
     │                                       │
     │                                       │ Step 4: read block file from disk.
     │                                       │   std::fs::read(&path)
     │                                       │   - ENOENT → CorruptVault { detail: "block file missing
     │                                       │     for {uuid_hex}" }
     │                                       │   - Other I/O → FolderInvalid { detail: "..." }
     │                                       │
     │                                       │ Step 5: decode the BlockFile envelope.
     │                                       │   block::decode_block_file(&bytes)
     │                                       │   - Errors → CorruptVault { detail: "malformed block file:
     │                                       │     <BlockError>" }
     │                                       │
     │                                       │ Step 6: prepare sender + reader handles.
     │                                       │   sender_card = &manifest.owner_card  (v1 single-author)
     │                                       │   sender_fp   = fingerprint(canonicalize(sender_card))
     │                                       │   reader_card = &manifest.owner_card  (owner reads own block)
     │                                       │   reader_fp   = same as sender_fp for owner
     │                                       │   sender_pk_bundle = canonicalize(owner_card)
     │                                       │   reader_pk_bundle = same
     │                                       │   sender_ed_pk = parse owner_card.ed25519_pk
     │                                       │   sender_pq_pk = parse owner_card.ml_dsa_65_pk
     │                                       │
     │                                       │ Step 7: drop the manifest lock; keep identity lock.
     │                                       │   (Decrypt is purely a function of the loaded bytes +
     │                                       │   the borrowed sender/reader keys; manifest doesn't
     │                                       │   need to stay held.)
     │                                       │
     │                                       │ Step 8: hybrid verify-then-decrypt.
     │                                       │   block::decrypt_block(
     │                                       │       &block_file,
     │                                       │       &sender_fp, &sender_pk_bundle,
     │                                       │       &sender_ed_pk, &sender_pq_pk,
     │                                       │       &reader_fp, &reader_pk_bundle,
     │                                       │       &identity.x25519_sk,
     │                                       │       &identity.ml_kem_768_sk,
     │                                       │   ) → Result<BlockPlaintext, BlockError>
     │                                       │   - All BlockError variants fold into CorruptVault
     │                                       │     { detail: "<BlockError display>" } per the
     │                                       │     anti-conflation discipline (NotARecipient, signature
     │                                       │     fail, AAD mismatch, AuthorFingerprintMismatch,
     │                                       │     BlockUuidMismatch all map to CorruptVault).
     │                                       │
     │                                       │ Step 9: drop identity lock.
     │                                       │
     │                                       │ Step 10: convert BlockPlaintext → BlockReadOutput.
     │                                       │   For each record in plaintext.records (preserve order):
     │                                       │     For each (name, RecordField) in record.fields
     │                                       │     (BTreeMap iteration order):
     │                                       │       Build FieldHandle wrapping the moved RecordFieldValue.
     │                                       │     Build Record wrapping the FieldHandles + metadata.
     │                                       │   Wrap Records into BlockReadOutput.
     │                                       │
     │                                       └─▶ Ok(BlockReadOutput)
     │
     ◀─ marshal back ─────────────────────── BlockReadOutput
```

### Key invariants on the orchestration

- **Verify-before-decrypt.** Same discipline as `core::open_vault`. `core::block::decrypt_block` does hybrid signature verification BEFORE hybrid-decap. A tampered/forged block never causes a private-key operation to run.
- **`lock_or_recover` poisoning safety.** If a previous `read_block` call panicked mid-decap, the next call recovers via `lock_or_recover` rather than re-poisoning the mutex.
- **Manifest lock released before decrypt.** Step 7 drops the manifest lock so concurrent `find_block` / `block_summaries` calls stay possible during the long-running decrypt. (Rust core itself isn't concurrent here, but the pattern matters once we add async wrappers.)
- **No move-out of identity secrets.** `decrypt_block` borrows `&kem::X25519Secret` / `&kem::MlKem768Secret`. The `IdentityBundle` stays intact; subsequent `read_block` calls re-borrow.
- **Records constructed outside both locks.** Once decrypt returns the `BlockPlaintext`, both locks are dropped before the record-conversion loop — no risk of deadlock if the construction does anything that re-enters the bridge.
- **`Arc<Mutex<Option<...>>>` semantics for clones.** `BlockReadOutput::record_at(idx)` returns a clone of the `Arc<Mutex<Option<RecordInner>>>`. `Record::field_by_name(name)` and `Record::field_at(idx)` likewise clone the `Arc`. Calling `wipe()` on any clone uses `Option::take()` on the shared inner, so every other clone immediately sees the wiped state and accessors return empty defaults (matching the B.4a "wipe-then-access returns empty defaults" pattern, not panics).
- **Wipe cascades.** `BlockReadOutput::wipe()` walks its `records: Vec<Record>` and calls `wipe()` on each, which cascades to the `FieldHandle`s. This is the single cleanup point; foreign callers that use the context manager / `defer` / `use` idiom get full cleanup automatically.

## Components

### Bridge crate types (`ffi/secretary-ffi-bridge/src/record.rs`)

```rust
//! Bridge surface for `read_block` (Sub-project B.4b).
//!
//! Exposes the free function `read_block(&identity, &manifest, &[u8; 16])`
//! and the three opaque handle types that carry the decrypted records out
//! to PyO3 / uniffi: [`BlockReadOutput`], [`Record`], [`FieldHandle`].

use std::sync::{Arc, Mutex};
use std::path::PathBuf;
use secretary_core::vault::record::RecordFieldValue;

use crate::error::FfiVaultError;
use crate::identity::UnlockedIdentity;
use crate::vault::OpenVaultManifest;

/// Free-function entry point. Borrows both handles; returns a fresh
/// container of decrypted records or a typed error.
pub fn read_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: &[u8; 16],
) -> Result<BlockReadOutput, FfiVaultError>;

// ----- BlockReadOutput -----

/// Container handle for one block's decrypted records. Holds owned
/// `Record`s; `wipe()` cascades to every contained record + field.
pub struct BlockReadOutput {
    inner: Mutex<Option<BlockReadOutputInner>>,
}

pub(crate) struct BlockReadOutputInner {
    block_uuid: [u8; 16],
    block_name: String,
    records: Vec<Record>,
}

impl BlockReadOutput {
    pub fn block_uuid(&self) -> [u8; 16];
    pub fn block_name(&self) -> String;
    pub fn record_count(&self) -> usize;
    /// Returns a clone of the Record handle at `idx`, or `None` if `idx`
    /// is out of range or the output has been wiped.
    pub fn record_at(&self, idx: usize) -> Option<Record>;
    /// Idempotent. After this returns, all accessors return empty defaults
    /// and `record_at` returns `None`.
    pub fn wipe(&self);
}

// ----- Record -----

/// Per-record handle. `Arc<Mutex<Option<...>>>` so accessors can hand
/// out cheap clones; every clone shares the same wiped state.
pub struct Record {
    inner: Arc<Mutex<Option<RecordInner>>>,
}

pub(crate) struct RecordInner {
    record_uuid: [u8; 16],
    record_type: String,
    tags: Vec<String>,
    created_at_ms: u64,
    last_mod_ms: u64,
    tombstone: bool,
    fields: Vec<FieldHandle>,
}

impl Record {
    pub fn record_uuid(&self) -> [u8; 16];
    pub fn record_type(&self) -> String;
    pub fn tags(&self) -> Vec<String>;
    pub fn created_at_ms(&self) -> u64;
    pub fn last_mod_ms(&self) -> u64;
    pub fn tombstone(&self) -> bool;
    pub fn field_count(&self) -> usize;
    /// Field names in BTreeMap iteration order (matches the order Records
    /// are encoded on the wire — see `core::vault::record::encode`).
    pub fn field_names(&self) -> Vec<String>;
    /// Returns a clone of the FieldHandle by name, or `None` if no field
    /// has this name or the record has been wiped.
    pub fn field_by_name(&self, name: &str) -> Option<FieldHandle>;
    /// Returns a clone of the FieldHandle at `idx`, or `None` if out of
    /// range or wiped.
    pub fn field_at(&self, idx: usize) -> Option<FieldHandle>;
    pub fn wipe(&self);
}

// ----- FieldHandle -----

/// Per-field handle. Holds the `RecordFieldValue` (which itself wraps
/// `SecretString` or `SecretBytes`). The `expose_text()` / `expose_bytes()`
/// boundary is the explicit secret-pull point.
pub struct FieldHandle {
    inner: Arc<Mutex<Option<FieldHandleInner>>>,
}

pub(crate) struct FieldHandleInner {
    name: String,
    value: RecordFieldValue,
    last_mod_ms: u64,
    device_uuid: [u8; 16],
}

impl FieldHandle {
    pub fn name(&self) -> String;
    pub fn last_mod_ms(&self) -> u64;
    pub fn device_uuid(&self) -> [u8; 16];
    pub fn is_text(&self) -> bool;
    pub fn is_bytes(&self) -> bool;
    /// Pull the secret out as UTF-8 string. Returns `None` if the field
    /// is bytes (caller should use `expose_bytes()`) or has been wiped.
    /// Returns a fresh `String` allocation; **caller is responsible for
    /// clearing it** (e.g. Python `del`, Swift `String` going out of scope,
    /// Kotlin GC). The underlying SecretString in the FieldHandle is NOT
    /// wiped by this call — call `wipe()` explicitly when done.
    pub fn expose_text(&self) -> Option<String>;
    /// Pull the secret out as raw bytes. Returns `None` if the field is
    /// text or has been wiped. Returns a fresh `Vec<u8>`; caller is
    /// responsible for clearing it.
    pub fn expose_bytes(&self) -> Option<Vec<u8>>;
    pub fn wipe(&self);
}
```

### `FfiVaultError` after B.4b

```rust
// ffi/secretary-ffi-bridge/src/error.rs
#[derive(Debug, Error)]
pub enum FfiVaultError {
    // — Existing 6 from B.4a (unchanged) —
    #[error("password is wrong, or the identity bundle is corrupted")]
    WrongPasswordOrCorrupt,

    #[error("recovery mnemonic is wrong, or the identity bundle is corrupted")]
    WrongMnemonicOrCorrupt,

    #[error("recovery mnemonic is not a valid 24-word BIP-39 phrase: {detail}")]
    InvalidMnemonic { detail: String },

    #[error("vault.toml and identity.bundle.enc reference different vaults")]
    VaultMismatch,

    #[error("vault data integrity failure: {detail}")]
    CorruptVault { detail: String },

    #[error("vault folder is invalid: {detail}")]
    FolderInvalid { detail: String },

    // — NEW in B.4b —
    /// The requested block UUID does not appear in the manifest's live
    /// blocks list. (Trashed blocks are filtered out — they also surface
    /// as `BlockNotFound` until Sub-project C adds the restore-from-trash
    /// flow.)
    ///
    /// `uuid_hex` is the 32-char lowercase hex of the requested UUID, e.g.
    /// `"112233445566778899aabbccddeeff00"`. Stored as a `String` for
    /// consistency with the other variants' `detail: String` payloads;
    /// the foreign caller can `bytes.fromhex(uuid_hex)` if needed.
    #[error("block not found in manifest: {uuid_hex}")]
    BlockNotFound { uuid_hex: String },
}
```

### Mapping table: failure mode → `FfiVaultError` variant

| Failure during `read_block` | `FfiVaultError` variant | `detail` source |
|---|---|---|
| `block_uuid` not in `manifest.blocks` | `BlockNotFound { uuid_hex }` | hex of requested uuid |
| Block file at `blocks/<uuid>.cbor.enc` missing on disk | `CorruptVault { detail }` | `"block file missing for {uuid_hex}"` |
| Block file unreadable (perms, EBUSY, etc.) | `FolderInvalid { detail }` | `"failed to read block file: {io_error}"` |
| `decode_block_file` fails (truncated header, bad magic, malformed CBOR) | `CorruptVault { detail }` | `"malformed block file: {BlockError display}"` |
| Hybrid signature verify fails | `CorruptVault { detail }` | `"block signature verification failed"` |
| `NotARecipient` (owner not in recipient table — corruption case in v1) | `CorruptVault { detail }` | `"reader is not a recipient of this block"` |
| `AuthorFingerprintMismatch` (block author ≠ vault owner — multi-author case deferred to B.4d) | `CorruptVault { detail }` | `"block author fingerprint mismatch"` |
| AAD mismatch / tag fail / decap fail | `CorruptVault { detail }` | `"block decryption failed: {BlockError display}"` |
| `BlockUuidMismatch` between header and plaintext | `CorruptVault { detail }` | `"block uuid mismatch: header {hex} ≠ plaintext {hex}"` |
| `block_uuid` argument has wrong length (≠ 16) at the FFI boundary | (PyO3) `ValueError` / (uniffi) `IllegalArgumentException` | `"block_uuid must be 16 bytes, got {n}"` |

### PyO3 wrapper (`ffi/secretary-ffi-py/src/lib.rs`)

```python
# Foreign-language API after B.4b
import secretary_ffi_py as sfp

# Open the vault (B.4a)
output = sfp.open_vault_with_password(folder, b"correct horse battery staple")
identity, manifest = output.identity, output.manifest

# Read one block (B.4b)
block_uuid = bytes.fromhex("112233445566778899aabbccddeeff00")
block = sfp.read_block(identity, manifest, block_uuid)
# block: BlockReadOutput

assert block.block_name() == "Personal logins"
assert block.record_count() == 1

record = block.record_at(0)
assert record.record_type() == "login"
assert record.tags() == ["work"]
assert record.field_names() == ["password", "username"]  # BTreeMap order

field = record.field_by_name("password")
assert field.is_text()
secret_str = field.expose_text()  # returns "hunter2"
# caller clears secret_str when done
del secret_str

# Wrong-length UUID raises ValueError (not VaultBlockNotFound):
try:
    sfp.read_block(identity, manifest, b"too short")
except ValueError as e:
    assert "block_uuid must be 16 bytes" in str(e)

# Unknown UUID raises VaultBlockNotFound (in the VaultError family):
try:
    sfp.read_block(identity, manifest, bytes.fromhex("00" * 16))
except sfp.VaultBlockNotFound as e:
    assert e.uuid_hex == "00" * 16

# Cleanup — single wipe drops every record + field's secret
block.wipe()

# Or via context manager:
with sfp.read_block(identity, manifest, block_uuid) as block:
    ...
# Auto-wipe on context exit.
```

PyO3 mapping additions:
- `#[pyfunction] read_block(identity: &UnlockedIdentity, manifest: &OpenVaultManifest, block_uuid: &[u8])`. Length check: `block_uuid.len() == 16` else raise `ValueError("block_uuid must be 16 bytes, got {n}")`.
- `#[pyclass] BlockReadOutput` with `__enter__`/`__exit__` (auto-wipe on exit).
- `#[pyclass] Record` with `__enter__`/`__exit__`.
- `#[pyclass] FieldHandle` with `__enter__`/`__exit__`.
- `create_exception!(VaultBlockNotFound)` with `uuid_hex` attribute.
- `ffi_vault_error_to_pyerr` extended with the 7th arm:
  ```rust
  FfiVaultError::BlockNotFound { uuid_hex } => {
      VaultBlockNotFound::new_err((uuid_hex,))  // (detail,) tuple convention
  }
  ```

### uniffi UDL (`ffi/secretary-ffi-uniffi/src/secretary.udl`)

```idl
namespace secretary {
    [Throws=VaultError]
    BlockReadOutput read_block(
        UnlockedIdentity identity,
        OpenVaultManifest manifest,
        bytes block_uuid
    );
};

[Error]
enum VaultError {
    "WrongPasswordOrCorrupt",
    "WrongMnemonicOrCorrupt",
    "InvalidMnemonic",
    "VaultMismatch",
    "CorruptVault",
    "FolderInvalid",
    "BlockNotFound",   // NEW; carries uuid_hex: string via field projection
};

interface BlockReadOutput {
    bytes block_uuid();
    string block_name();
    u64 record_count();
    Record? record_at(u64 idx);
    void wipe();
};

interface Record {
    bytes record_uuid();
    string record_type();
    sequence<string> tags();
    u64 created_at_ms();
    u64 last_mod_ms();
    boolean tombstone();
    u64 field_count();
    sequence<string> field_names();
    FieldHandle? field_by_name(string name);
    FieldHandle? field_at(u64 idx);
    void wipe();
};

interface FieldHandle {
    string name();
    u64 last_mod_ms();
    bytes device_uuid();
    boolean is_text();
    boolean is_bytes();
    string? expose_text();
    bytes? expose_bytes();
    void wipe();
};
```

uniffi 0.31 codegen-rename quirks (per project memory `project_secretary_uniffi_codegen_renames.md`): `wipe` → `close` in Kotlin (and `AutoCloseable` is auto-generated); `wipe` stays as `wipe()` plus an explicit Swift extension if the project chooses to add one. Bridge crate API stays unchanged.

The wrong-length-`bytes` path is handled at the uniffi codegen layer — Swift's `Data.count != 16` would surface as a uniffi marshalling error; Kotlin's `ByteArray.size != 16` likewise. The bridge's `read_block` itself only ever sees `&[u8; 16]` (compile-time enforced).

## Testing

### Bridge crate unit tests (`ffi/secretary-ffi-bridge/src/record.rs`)

Target **+12 to +14 tests** (B.4a added +20 in `vault.rs`; record.rs is smaller in scope).

Pinned KAT source: `core/tests/data/golden_vault_001_inputs.json` `block_plaintext.records[0]` — 1 record, 2 fields (`username`, `password`), both Text.

| Test | What it pins |
|---|---|
| `read_block_returns_one_record_two_fields_for_golden_vault_001` | End-to-end: open + read; assert `record_count() == 1`, `field_count() == 2`. |
| `read_block_record_metadata_matches_pinned_kat` | record_uuid (hex `33445566778899aabbccddeeff001122`), record_type (`"login"`), tags (`["work"]`), tombstone (`false`), created_at_ms / last_mod_ms (`2000000000000`). |
| `read_block_field_names_in_btreemap_order` | `field_names() == ["password", "username"]`. |
| `read_block_field_text_payload_matches_pinned_kat` | `expose_text("password") == Some("hunter2")`; `expose_text("username") == Some("owner@example.com")`. |
| `read_block_field_metadata_matches_pinned_kat` | last_mod_ms + device_uuid for both fields. |
| `read_block_field_is_text_not_bytes` | `is_text() == true`, `is_bytes() == false`, `expose_bytes() == None`. |
| `read_block_unknown_uuid_returns_block_not_found` | Random UUID → `Err(BlockNotFound { uuid_hex })`; uuid_hex matches input. |
| `read_block_corrupt_block_file_returns_corrupt_vault` | Tampered first byte of `blocks/<uuid>.cbor.enc` → `Err(CorruptVault)`. |
| `read_block_missing_block_file_returns_corrupt_vault` | Manifest entry exists; file deleted. → `Err(CorruptVault { detail: "block file missing for ..." })`. |
| `block_read_output_wipe_drops_records` | After `wipe()`, `record_count() == 0`, `record_at(0).is_none()`. |
| `record_wipe_drops_field_handles` | After `record.wipe()`, `field_count() == 0`, `field_by_name(...) == None`. Foreign caller still holding a clone of an earlier `FieldHandle` sees `expose_text() == None`. |
| `field_handle_arc_clones_share_wiped_state` | Two clones via `record_at(0).field_at(0)`; wipe one, assert the other reflects the wipe. |
| `read_block_after_open_vault_with_recovery_succeeds` | Same end-to-end with the recovery unlock path. |
| `block_not_found_display_string_pinned` | Tripwire: `FfiVaultError::BlockNotFound { uuid_hex: "abc...".into() }.to_string()` ends with `"abc..."`. |

### pytest (`ffi/secretary-ffi-py/tests/test_smoke.py`)

Target **+10 tests** (B.4a added +7).

Module-scoped `opened_vault` fixture from B.4a is reused (already amortizes Argon2id cost).

| Test | Notes |
|---|---|
| `test_read_block_shape` | record_count == 1, field_count == 2. |
| `test_read_block_record_metadata` | record_uuid, record_type, tags, tombstone match inputs.json. |
| `test_read_block_field_text_password` | `field_by_name("password").expose_text() == "hunter2"`. |
| `test_read_block_field_text_username` | `field_by_name("username").expose_text() == "owner@example.com"`. |
| `test_read_block_field_metadata` | last_mod_ms + device_uuid bytes. |
| `test_read_block_unknown_uuid_raises_block_not_found` | `with pytest.raises(VaultBlockNotFound) as exc`; `exc.value.uuid_hex == "00" * 16`. |
| `test_read_block_wrong_length_uuid_raises_value_error` | `bytes(15)` → `ValueError`. |
| `test_read_block_field_bytes_is_none_for_text_field` | `expose_bytes()` returns `None` for a text field. |
| `test_block_read_output_context_manager_wipes` | `with sfp.read_block(...) as block: ...`; after exit, `record_count()` returns 0. |
| `test_record_field_handles_share_state_after_wipe` | Two foreign-side references to the same field handle; wipe one, the other returns `None`. |

### Swift / Kotlin smokes

Target **+4 asserts each** (B.4a added +3).

```text
PASS: read_block success → record_count == 1 + field_count == 2
PASS: field_by_name("password").expose_text() == "hunter2"
PASS: read_block(unknown_uuid) → VaultError.BlockNotFound(uuid_hex matches)
PASS: wipe → record_count == 0
```

Smokes piggy-back on the existing `golden_vault_001` fixture; no new test data.

### Verification gate at session close

| Check | Target |
|---|---|
| `cargo test --release --workspace` | **535+ passed + 9 ignored** (was 522 + 9; +12-14 new) |
| `cargo clippy --release --workspace -- -D warnings` | clean |
| `cargo fmt --all -- --check` | OK |
| `uv run --directory ffi/secretary-ffi-py pytest` | **40 passed** (was 30; +10) |
| `uv run core/tests/python/conformance.py` | PASS unchanged |
| `uv run core/tests/python/spec_test_name_freshness.py` | PASS unchanged |
| Swift smoke | 22/22 (was 18; +4) |
| Kotlin smoke | 23 PASS lines (was 19; +4) |

## Decisions log (carried into implementation)

1. **Hybrid Record projection** (Q1). `Record` is value-typed in metadata, opaque in payload. `FieldHandle.expose_text()` / `expose_bytes()` is the explicit secret-pull boundary. Rejected: eager copy-out (no zeroize discipline) + opaque-Record-with-accessors-only (busiest API).
2. **Free function `read_block`** (Q2). Pure-function shape over method-on-handle. Matches the project preference for free functions in reusable modules. Identity + manifest both passed by reference; both internally lock through `lock_or_recover`.
3. **+1 variant `BlockNotFound`** (Q3). 7-variant `FfiVaultError`. File-missing folds into `CorruptVault`; decrypt failures fold into `CorruptVault`. Rejected: +2 variants (BlockFileMissing as separate would surface a sync-race transient that B.4b doesn't yet model) + Option<None> return (conflates "not present" with success).
4. **Trash deferred to Sub-project C** (Q4). `block_summaries()` filters trashed; `read_block(trashed_uuid)` returns `BlockNotFound`. Rejected: surfacing trash here without sync-orchestrator vector-clock context would be incomplete.
5. **Vault folder held in `OpenVaultManifestInner`** (Section 3 follow-up). Bridge-internal extension to B.4a's `OpenVaultManifest`; no public accessor change. B.4c (`save_block`) and B.4d (`share_block`) reuse for atomic-write paths.
6. **Wrong-length UUID = ValueError / IllegalArgumentException** (Section 5 follow-up). Distinguish programmer error from data error. Bridge function takes `&[u8; 16]` (compile-time enforced); FFI wrappers validate length and raise the foreign idiomatic exception. Rejected: folding into `BlockNotFound` would silently mask call-site bugs.
7. **No `Record.unknown` / `RecordField.unknown` projection.** Mirrors B.4a's `BlockSummary.unknown` non-goal — surfacing forward-compat CBOR through the FFI is unjustified until v2 introduces concrete unknown semantics.
8. **`Record.tombstone: bool` IS surfaced** (UI affordance for "show deleted"); **`Record.tombstoned_at_ms` is NOT** (sync-orchestration internal).
9. **Single-author block reading only.** `manifest.owner_card` is the assumed sender; multi-author + contact discovery deferred to B.4d. Mismatch surfaces as `CorruptVault`.

## Open questions / risks

### In scope for B.4b implementation

1. **`expose_text()` invalid UTF-8 — fuzz-target hardening.** `RecordFieldValue::Text` wraps `SecretString` whose contents must be valid UTF-8 by Rust type contract. The structural guarantee is already in place: CBOR's `tstr` (major type 3) requires valid UTF-8 per RFC 8949 §3.1; `ciborium`'s decoder enforces this on `Value::Text`; `parse_record_field` at [core/src/vault/record.rs](../../../core/src/vault/record.rs) line ~697 only constructs `RecordFieldValue::Text(SecretString::new(s))` from an already-validated `Value::Text(s)`. So invalid UTF-8 cannot reach `expose_text()` by construction. Extend the existing `core/fuzz/fuzz_targets/record.rs` target with a defense-in-depth assertion: after successful `record::decode`, walk every `RecordFieldValue::Text` and assert `s.expose()` is valid UTF-8 (it always is — the assertion serves as a tripwire if the decode path is ever weakened to allow direct `SecretString` construction from non-validated bytes). Promotion workflow follows the existing fuzz harness conventions in [core/fuzz/README.md](../../../core/fuzz/README.md). The rejected alternative — surfacing a 7th-or-8th `FfiVaultError` variant via changing `expose_text() -> Option<String>` to `Result<Option<String>, FfiVaultError>` — would propagate a corruption-time concern (the block file was tampered with on disk) to a foreign-language access-time path (the caller is just reading a field), forcing every caller to handle an error that is structurally impossible in the v1 type contract. Worse, it would split the corruption-class signal between `read_block`'s return (which already maps decode failures to `CorruptVault`) and the per-field accessor — fragmenting the anti-conflation discipline established for `FfiVaultError`.

### Deferred to B.4c+

- **`Mutex<Option<...>>` vs `&mut self` for `save_block`.** Still open from B.4a. B.4c will need to mutate the manifest body to add a new block entry, then atomic-write the new manifest envelope. The choice between extending the existing `&self` + interior-mutability pattern vs. introducing a writer-borrow model is B.4c's design call.
- **Multi-author block reading.** B.4d's `share_block` will need to add `contacts/<author_uuid>.card` discovery to read blocks from co-recipients. The `OpenVaultManifest` may grow a `contact_cards: BTreeMap<Uuid, ContactCard>` lazy-load cache; that decision belongs to B.4d.
- **Bytes-typing of secret payloads in `FieldHandle::expose_text()`.** The current design returns a fresh `String` allocation; the foreign caller is responsible for clearing it. A future hardening pass could explore returning a `SecretString`-like opaque handle that *itself* zeroizes-on-drop in the foreign language — but that requires per-language opaque-string types (Python `secretstring` library, Swift `Data` with deinit, Kotlin `CharArray` discipline). Deferred.
