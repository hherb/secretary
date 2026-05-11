# Sub-project B.5 — `trash_block` / `restore_block` (lifecycle pair)

**Date:** 2026-05-11
**Status:** Design approved (brainstormed 2026-05-11; this doc is the input to writing-plans).
**Predecessor:** [B.4d — share_block](2026-05-10-ffi-b4d-share-block-design.md).
**Successor (planned):** Sub-project C kickoff (file watching + cloud-folder integration + conflict detection).

## 1. Purpose

Add the **block-lifecycle pair** — moving a block to trash and restoring it — to the bridge crate, surfaced through PyO3 and uniffi. B.5 closes the gap between "I created a block" (B.4c `save_block`) and "I deleted a block, then changed my mind" (B.5 `trash_block` / `restore_block`).

Sub-project C will need this pair for sync-layer conflict resolution: a sync conflict where device A trashed a block and device B kept editing it is unrecoverable without a way to restore the trashed copy on A.

**Important framing correction (vs. NEXT_SESSION.md 2026-05-11):** the wire format is frozen — `manifest.trash` and `TrashEntry { block_uuid, tombstoned_at_ms, tombstoned_by }` are already in [core/src/vault/manifest.rs:351-360](../../../core/src/vault/manifest.rs#L351-L360). But **`core::vault::orchestrators` has no `trash_block` or `restore_block` function today**; only `save_block` and `share_block` exist. B.5 is real new core orchestrator code, not just FFI plumbing. Additionally, [docs/vault-format.md §7](../../vault-format.md) describes deletion (5 lines) but is silent on restore semantics — B.5 extends the spec accordingly.

## 2. Architectural decisions (settled in brainstorming)

| Decision | Choice | Rationale |
|---|---|---|
| Scope | `trash_block` + `restore_block` end-to-end (core + bridge + PyO3 + uniffi + smoke runners) | Completes the lifecycle round-trip; gives Sub-project C the primitives it needs. "Trash only with restore deferred" splits a tightly coupled pair across two sessions and leaves Sub-project C blocked. "Trash + permanent purge" skips the user-visible undelete that's the actual UX need. |
| Multi-copy restore policy | **Restore-and-purge:** most recent trashed copy (by filename timestamp) is restored; **all** older trashed copies for the same UUID are physically deleted in the same operation | Cleanest "undelete" UX — the user is undoing "the last trash," not "some trash." Avoids forcing callers to think about which version of a deleted thing they want back. The lost ability to recover even older versions through the retention window is acceptable for v1; it's a feature that can be re-added behind a separate API (`list_trashed_versions(uuid)`) later without breaking the v1 surface. |
| Live-UUID collision on restore | **Reject:** if `block_uuid` appears in both `manifest.trash` AND `manifest.blocks`, restore returns `BlockUuidAlreadyLive`. Caller must trash the live copy first | Keeps `save_block`'s contract untouched (no behavior change to a shipped, well-tested orchestrator). The state machine for any given UUID is "absent → live → trashed → live → trashed → …" without overlap. Never silently overwrites live data. |
| Restore verification | **Full decrypt + hybrid-verify** (`block::decrypt_block`) of the trashed file before any manifest write | Defense in depth: an attacker with write access to `trash/` could plant a corrupt or forged block file and force its restoration into `manifest.blocks`. Verification cost (~10ms) is negligible; failure is typed (`RestoreVerificationFailed`) so the UI can decide between purge-without-restore and forensic capture. Aligns with the project's "security paths can't rely on assumptions" discipline. |
| Recipient resolution on restore | **Scan `contacts/*.card`** to build a fingerprint → contact_uuid map, since the block file's §6.2 recipient table is keyed by fingerprint and `BlockEntry.recipients` requires `contact_uuid`s | The two identifiers are different by design (the recipient table is BLAKE3 of the canonical contact card; the manifest's recipient list is the contact's UUID). `restore_block` cannot avoid this resolution step — the block file alone doesn't carry contact_uuids. Reuses the existing `VaultError::MissingRecipientCard { fingerprint }` variant. Cost: one `read_dir` + N `ContactCard::from_canonical_cbor` decodes, where N = contacts count (single-digit for typical vaults). Done BEFORE the filesystem rename so the failure path leaves the trash file untouched. |
| Vector clock on restore | Re-derived **verbatim** from the trashed block file's §6.1 header `vector_clock` | Sync correctness: a restored block is the same conceptual block that was trashed, with the same causal history. Resetting the clock would cause sync peers to treat the restored block as a new block, breaking merge semantics. Only the **manifest-level** vector clock is ticked (the manifest's content changed). |
| `tombstoned_by` semantics | `device_uuid` (per [vault-format.md:192](../../vault-format.md)) — passed as an orchestrator parameter, **not** auto-derived from owner identity | Already fixed by the wire format. The orchestrator does not infer it. |
| Filesystem operation | `fs::rename(2)` — atomic on a single filesystem; `EXDEV` (cross-filesystem) surfaces as `VaultError::Io { context: "trash_block: cross-filesystem rename", source }` | Spec §7 says "Move" — `rename(2)` is the unambiguous atomic interpretation. The blocks/ and trash/ subdirectories live inside the same vault folder by construction; cross-filesystem is a configuration error. |
| Module shape | Two separate bridge modules (`bridge/trash/`, `bridge/restore/`) mirroring `bridge/share/`'s minimal shape (`mod.rs` + `orchestration.rs`, no `input.rs`) | Follows the established per-orchestrator pattern (B.4c save, B.4d share). Trash and restore share almost no implementation code (one moves a file out + drops a manifest entry; the other moves a file in + verifies it + re-derives a manifest entry). A unified `set_block_status(target)` enum API was rejected as overengineered for two operations with no shared body. |

## 3. Module structure

```
core/src/vault/orchestrators.rs
                          +2 pub fn (trash_block, restore_block); ~250 LOC added

core/src/vault/mod.rs     +3 VaultError variants (BlockUuidAlreadyLive,
                          BlockNotInTrash, RestoreVerificationFailed);
                          existing exhaustive matches in From<core::VaultError>
                          for FfiVaultError become compile errors until the
                          three new arms are added (issue #40 tripwire firing)

ffi/secretary-ffi-bridge/src/
├── trash/
│   ├── mod.rs              ~25 LOC, module docs + re-exports
│   └── orchestration.rs    ~120 LOC, trash_block free function +
│                            map_core_vault_error_trash
├── restore/
│   ├── mod.rs              ~25 LOC, module docs + re-exports
│   └── orchestration.rs    ~150 LOC, restore_block free function +
│                            map_core_vault_error_restore
├── error/vault.rs           +2 FfiVaultError variants (BlockUuidAlreadyLive,
│                            BlockNotInTrash); +3 arms in
│                            From<core::VaultError>; +5 drift-prevention
│                            pin tests
└── lib.rs                   +2 re-export lines

ffi/secretary-ffi-py/src/lib.rs
                          +2 #[pyfunction] (trash_block, restore_block)
                          +2 PyO3 exception class declarations
                          (VaultBlockUuidAlreadyLive, VaultBlockNotInTrash)

ffi/secretary-ffi-uniffi/secretary-ffi-uniffi.udl
                          +2 [Throws=VaultError] declarations
                          +2 VaultError enum variants

docs/vault-format.md      +1 paragraph in §7 tightening trash filename
                          grammar; +1 new §7.1 sub-section (restore semantics)
```

## 4. Core orchestrator surface

### 4.1 `core::vault::trash_block`

```rust
/// Move a live block into trash. §7 deletion sequence.
pub fn trash_block(
    folder: &Path,
    open: &mut OpenVault,
    block_uuid: [u8; 16],
    device_uuid: [u8; 16],
    now_ms: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(), VaultError>;
```

Step-by-step:

1. Find the block in `open.manifest.blocks`; return `VaultError::BlockNotFound { block_uuid }` if absent. (Reuses the existing variant introduced by `share_block`.)
2. Compose the trash filename: `trash/<uuid-hyphenated>.cbor.enc.<now_ms>`.
3. `std::fs::create_dir_all(folder.join("trash"))` (lazy mkdir, mirrors `save_block`'s `blocks/` create at [core/src/vault/orchestrators.rs:809-812](../../../core/src/vault/orchestrators.rs#L809-L812)).
4. `std::fs::rename(folder.join("blocks").join(...), folder.join("trash").join(...))`. Maps `EXDEV` / `ENOENT` to `VaultError::Io { context: "trash_block: rename blocks/ → trash/", source }`.
5. Remove the `BlockEntry` from `open.manifest.blocks` (the position from step 1).
6. Append `TrashEntry { block_uuid, tombstoned_at_ms: now_ms, tombstoned_by: device_uuid }` to `open.manifest.trash`.
7. Tick `open.manifest.vector_clock` for `device_uuid`. (Manifest content changed; per-block clock is NOT ticked — block content is unchanged.)
8. Re-sign the manifest with a fresh AEAD nonce; atomic-write per §9. Mirrors `save_block` steps 11–14.
9. Refresh `open.manifest_file` in place.

### 4.2 `core::vault::restore_block`

```rust
/// Restore the most recent trashed copy of a block; purge older copies.
pub fn restore_block(
    folder: &Path,
    open: &mut OpenVault,
    block_uuid: [u8; 16],
    device_uuid: [u8; 16],
    now_ms: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(), VaultError>;
```

Step-by-step:

1. If `block_uuid` appears in `open.manifest.blocks` → `VaultError::BlockUuidAlreadyLive { block_uuid }`.
2. Scan `folder.join("trash")` for entries whose filename matches `<uuid-hyphenated>.cbor.enc.*`. Parse the suffix after `.cbor.enc.` as `u64` unix millis. Ill-formed suffixes (non-numeric, overflow) are integrity failures surfaced as `VaultError::Io { context: "restore_block: ill-formed trash filename", source: std::io::Error::other(...) }`.
3. If the matching-file list is empty AND no `TrashEntry` exists for `block_uuid` → `VaultError::BlockNotInTrash { block_uuid }`. (Both conditions are required because the file/manifest pair is supposed to be coherent; one without the other is also a `BlockNotInTrash`.)
4. Pick the file with the **largest** suffix as the *restore target*; all other matching files are *purge targets*.
5. Read the restore target's bytes. Call `block::decode_block_file` → `block::decrypt_block` with the owner's pubkeys + `open.identity_block_key` + the owner's reader keys (`x25519_sk`, `ml_kem_768_sk`). On any decode/decrypt/verify failure → `VaultError::RestoreVerificationFailed { block_uuid, detail: format!("{e}") }`. **Manifest and `trash/` are NOT modified on this path** — the function returns the error before any state mutation.
6. Resolve recipient `contact_uuid`s from the decrypted block file's §6.2 recipient table:
    - The recipient table is keyed by `recipient_fingerprint` (16-byte BLAKE3 of the canonical contact-card bytes). `BlockEntry.recipients` is `Vec<contact_uuid>` (a different identifier). Restore must map fingerprint → contact_uuid.
    - The owner's fingerprint is already known: `fingerprint(&open.owner_card.to_canonical_cbor()?)`. Match it against the table first; for owner-only blocks this is the only mapping needed.
    - For non-owner recipients (blocks that have been `share_block`-ed at least once), scan `folder.join("contacts").read_dir()`, decode each `*.card` via `ContactCard::from_canonical_cbor`, compute its fingerprint, and build a `HashMap<Fingerprint, contact_uuid>`. Look up each table entry's fingerprint.
    - Any unresolved fingerprint surfaces as `VaultError::MissingRecipientCard { fingerprint }` — reusing the existing variant introduced by `share_block`. **Restore halts here, before any filesystem mutation** — the trash file is still in `trash/`, the manifest is still unmodified. Recovery: restore the missing card to `contacts/<uuid>.card` and retry.
7. `std::fs::rename(restore-target, folder.join("blocks").join(...))`. The `blocks/` directory exists by construction (we already had a block there at trash time, or save_block created it). Maps I/O errors as `VaultError::Io { context: "restore_block: rename trash/ → blocks/", source }`. **This is the point of no easy return** — preceding steps are pure reads; subsequent steps are manifest mutations.
8. For each purge target, `std::fs::remove_file(...)`. Best-effort: individual failures are logged via `tracing::warn!` but do NOT roll back the restore — the block is already live.
9. Build the new `BlockEntry` from the decrypted `BlockFile` (held in memory from step 5) and the resolved contact_uuids from step 6:
    - `block_uuid` = file header's `block_uuid` (cross-check against the requested uuid; mismatch → `RestoreVerificationFailed` — but this should have already fired in step 5's verify).
    - `block_name` = decoded plaintext's `block_name`.
    - `fingerprint` = BLAKE3-256 of the on-disk bytes read in step 5.
    - `recipients` = the resolved `contact_uuid`s from step 6, in the same order as the file's recipient table (the manifest encoder re-sorts to ascending lex by contact_uuid on emit; in-memory order does not matter).
    - `vector_clock_summary` = file header's `vector_clock` (preserved verbatim).
    - `suite_id` = file header's `suite_id`.
    - `created_at_ms` = file header's `created_at_ms`.
    - `last_mod_ms` = `now_ms` (the restoring write's wall-clock).
    - `unknown` = empty `BTreeMap` (consistent with `save_block`'s fresh inserts).
10. Append the new `BlockEntry` to `open.manifest.blocks`; remove the matching `TrashEntry` from `open.manifest.trash`.
11. Tick `open.manifest.vector_clock` for `device_uuid`.
12. Re-sign the manifest with a fresh AEAD nonce; atomic-write per §9.
13. Refresh `open.manifest_file` in place.

**Ordering rationale.** Steps 1–6 are pure reads (no filesystem mutation). Step 7 is the irreversible filesystem move. Steps 8–13 are best-effort cleanup + manifest update. Any failure in steps 1–6 leaves the vault in its pre-call state. A failure between step 7 and step 12 leaves an orphan block file in `blocks/` and a stale `TrashEntry` in the manifest — recoverable on next `open_vault` by retrying the restore (which finds the file in `blocks/` rather than `trash/`, surfaces `BlockUuidAlreadyLive` or `BlockNotInTrash`, and the caller can manually unwind).

## 5. Error surface

### 5.1 New `core::vault::VaultError` variants

Placed in [core/src/vault/mod.rs](../../../core/src/vault/mod.rs) near the existing `NotAuthor` / `RecipientAlreadyPresent` / `BlockNotFound` cluster:

```rust
/// trash_block / restore_block precondition: the requested block_uuid
/// exists in manifest.trash but also exists in manifest.blocks.
#[error("block {block_uuid:?} is currently live and trashed; trash the live copy before restoring")]
BlockUuidAlreadyLive { block_uuid: [u8; 16] },

/// restore_block precondition: no file matching trash/<uuid>.cbor.enc.*
/// was found AND no TrashEntry exists in manifest.trash for this uuid.
#[error("block {block_uuid:?} is not in trash")]
BlockNotInTrash { block_uuid: [u8; 16] },

/// restore_block step 5: the trashed block file failed §6.1 hybrid
/// signature verification or AEAD decrypt. An attacker with write access
/// to trash/ planted a corrupt or forged file. The manifest is NOT
/// modified; the trash file is NOT touched.
#[error("trashed block {block_uuid:?} failed verification: {detail}")]
RestoreVerificationFailed { block_uuid: [u8; 16], detail: String },
```

Adding these three variants makes the existing exhaustive matches in `From<core::VaultError> for FfiVaultError`, `map_core_vault_error` (save), and `map_core_vault_error_share` (share) **compile errors** until three new arms are added in each. This is the issue #40 tripwire firing as designed.

### 5.2 New `FfiVaultError` variants

In [ffi/secretary-ffi-bridge/src/error/vault.rs](../../../ffi/secretary-ffi-bridge/src/error/vault.rs):

```rust
/// `restore_block`: the UUID has both a TrashEntry and a live BlockEntry.
#[error("block is currently live and trashed: {detail}")]
BlockUuidAlreadyLive { detail: String },

/// `restore_block`: no matching file in trash/ and no TrashEntry.
#[error("block is not in trash: {detail}")]
BlockNotInTrash { detail: String },
```

`RestoreVerificationFailed` from core maps to the existing `FfiVaultError::CorruptVault { detail }` — "data on disk doesn't match what we signed" is exactly the CorruptVault contract.

### 5.3 Per-orchestrator bridge mappers

Both exhaustive (no `_ =>` catchall):

`map_core_vault_error_trash` routing:
- `Io { .. }` → `FolderInvalid`
- `BlockNotFound { .. }` → `BlockNotFound`
- everything else → `SaveCryptoFailure`

`map_core_vault_error_restore` routing:
- `Io { .. }` → `FolderInvalid`
- `BlockUuidAlreadyLive { .. }` → `BlockUuidAlreadyLive`
- `BlockNotInTrash { .. }` → `BlockNotInTrash`
- `RestoreVerificationFailed { .. }` → `CorruptVault`
- `MissingRecipientCard { fingerprint }` → `MissingRecipientCard { detail }` (existing variant — restore's recipient-resolution step can surface it when a previously-shared block's non-owner contact card is missing from `contacts/`)
- everything else → `SaveCryptoFailure`

### 5.4 Drift-prevention pin tests

Five new tests in [ffi/secretary-ffi-bridge/src/error/vault.rs](../../../ffi/secretary-ffi-bridge/src/error/vault.rs) (~75 LOC), mirroring the PR #46 / issue #40 pattern:

- `BlockUuidAlreadyLive` routes through `From` (folder-in API)
- `BlockNotInTrash` routes through `From`
- `RestoreVerificationFailed` folds to `CorruptVault` through `From`
- `BlockNotFound` from a trash-path origin routes through `map_core_vault_error_trash` (asserts mapper exhaustiveness)
- `RestoreVerificationFailed` routes through `map_core_vault_error_restore` (asserts mapper exhaustiveness)

## 6. Bridge orchestration

Identical shape for both orchestrators (mirrors [ffi/secretary-ffi-bridge/src/save/orchestration.rs:49-133](../../../ffi/secretary-ffi-bridge/src/save/orchestration.rs#L49-L133)):

```rust
pub fn trash_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: [u8; 16],
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<(), FfiVaultError>;

pub fn restore_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: [u8; 16],
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<(), FfiVaultError>;
```

Both follow the same six-step pattern:

1. Snapshot manifest under one lock: `manifest.snapshot_for_save_block()` → `(manifest_body, manifest_file, owner_card, ibk, vault_folder)`. The accessor's name was chosen for save_block but its shape is identical to what trash/restore need; no new accessor is added.
2. Snapshot identity: `identity.clone_inner_bundle()` (wiped-handle surfaces `CorruptVault`).
3. Build a temp `OpenVault` from clones (unmodified-on-failure invariant).
4. Call `core::vault::trash_block(...)` / `core::vault::restore_block(...)`.
5. On `Ok`: `manifest.replace_manifest_and_file(open_vault.manifest, open_vault.manifest_file)`. A concurrent wipe between steps 1–4 surfaces as `CorruptVault`.
6. On `Err`: map via the per-orchestrator mapper.

**Failure invariant (both):**

- On `Err`: bridge in-memory state is byte-identical to pre-call.
- On `Err` after the filesystem rename succeeded but the manifest re-sign failed: the file is in `trash/` (or `blocks/` for restore) but the manifest still shows the pre-rename view. Recoverable on next `open_vault` — the orphan file is detectable by `read_block` returning `BlockNotFound`, and the user can retry the operation.

## 7. FFI surface

### 7.1 PyO3 ([ffi/secretary-ffi-py](../../../ffi/secretary-ffi-py))

Two new pyfunctions in `src/lib.rs`. Value-typed inputs (`block_uuid: &[u8; 16]`, `device_uuid: &[u8; 16]`); both wrap the bridge call with `py.allow_threads(...)` (releases the GIL during I/O + crypto).

Two new Python exception types in `secretary_ffi_py.error`:

```python
class VaultBlockUuidAlreadyLive(VaultError): ...
class VaultBlockNotInTrash(VaultError): ...
```

Other routings (`VaultBlockNotFound`, `VaultCorruptVault`, `VaultFolderInvalid`, `VaultSaveCryptoFailure`) reuse existing exception types.

### 7.2 uniffi ([ffi/secretary-ffi-uniffi](../../../ffi/secretary-ffi-uniffi))

Two new declarations in `secretary-ffi-uniffi.udl`:

```idl
namespace secretary_ffi_uniffi {
    // ... existing ...

    [Throws=VaultError]
    void trash_block(
        UnlockedIdentity identity,
        OpenVaultManifest manifest,
        bytes block_uuid,
        bytes device_uuid,
        u64 now_ms
    );

    [Throws=VaultError]
    void restore_block(
        UnlockedIdentity identity,
        OpenVaultManifest manifest,
        bytes block_uuid,
        bytes device_uuid,
        u64 now_ms
    );
};
```

Two new variants on the existing `[Error] enum VaultError`:

```idl
[Error]
enum VaultError {
    // ... existing variants ...
    "BlockUuidAlreadyLive",
    "BlockNotInTrash",
};
```

uniffi codegen produces:
- **Swift**: `func trashBlock(...) throws`, `func restoreBlock(...) throws`; `VaultError.blockUuidAlreadyLive`, `.blockNotInTrash`
- **Kotlin**: `@Throws(VaultException::class) fun trashBlock(...)` etc.; `VaultException.BlockUuidAlreadyLive`, `BlockNotInTrash`

### 7.3 Smoke runner additions

**Swift** ([tests/swift/main.swift](../../../ffi/secretary-ffi-uniffi/tests/swift/main.swift)) — 4 new asserts (30 → 34):

- Round-trip: save → trash → expect `read_block` to surface `VaultError.blockNotFound`.
- Restore → expect `read_block` to succeed and return identical plaintext.
- Trash → save fresh block with same UUID → attempt restore → expect `VaultError.blockUuidAlreadyLive`.
- Attempt restore on a UUID never trashed → expect `VaultError.blockNotInTrash`.

**Kotlin** ([tests/kotlin/Main.kt](../../../ffi/secretary-ffi-uniffi/tests/kotlin/) generated by `run.sh`) — same 4 asserts (31 → 35).

## 8. Spec extension to `docs/vault-format.md`

### 8.1 Tighten §7 trash filename grammar

Add immediately after current line 408 (existing 5-line §7):

> The trash filename grammar is `<block-uuid-hyphenated>.cbor.enc.<unix-millis>` where `<unix-millis>` is the decimal ASCII representation of the deletion's `tombstoned_at_ms` (matches the manifest's `TrashEntry.tombstoned_at_ms`). Multiple files matching `<block-uuid-hyphenated>.cbor.enc.*` may co-exist when the same `block_uuid` is trashed → restored → re-trashed within the retention window. The filename is the canonical record of when a particular trashing happened; the manifest's `TrashEntry` carries the **most recent** `tombstoned_at_ms` only (older tombstone times are not tracked in the manifest).
>
> The "Move" in step 1 is `rename(2)` semantics — atomic on a single filesystem. An attempt to trash a block whose `blocks/` directory and `trash/` directory live on different filesystems (e.g., one is a cloud-folder mount-point and the other is local) is a configuration error and surfaces as an I/O failure (`EXDEV`). Recovery: re-locate the vault on a single filesystem.

### 8.2 New §7.1 — restoring a block

Inserted as a sub-section of §7. Current "Tombstones and deletion" becomes §7.0 "Deleting a block"; new content is §7.1 "Restoring a block". Verbatim text to insert into `docs/vault-format.md`:

> ### 7.1 Restoring a block
>
> Restoring a block reverses the §7.0 deletion sequence. The trash retention window (default 90 days) makes restore meaningful: until physical purge, the encrypted block file is still on disk in `trash/`.
>
> **Preconditions:**
>
> - The `block_uuid` MUST have a corresponding `TrashEntry` in `manifest.trash` AND at least one file in `trash/` matching `<block-uuid>.cbor.enc.*`. A disagreement between the two (file without manifest entry, or vice versa) is an integrity failure and surfaces as a typed error.
> - The `block_uuid` MUST NOT appear in `manifest.blocks`. A live-and-trashed UUID cannot be restored — the caller must first trash the live copy.
>
> **Sequence:**
>
> 1. Scan `trash/` for files matching `<block-uuid>.cbor.enc.*`. Parse each suffix as a u64 of decimal unix millis. Reject ill-formed suffixes (non-numeric, overflowing u64) as integrity failures.
> 2. Pick the file with the **largest** suffix as the *restore target*. All other matching files are *purge targets*.
> 3. Read the restore-target's bytes. Decode + AEAD-decrypt + §6.1 hybrid-verify (Ed25519 ∧ ML-DSA-65; **both** halves must verify) the file against the owner's contact-card pubkeys. Failure halts restore — the manifest is NOT modified and `trash/` is NOT modified.
> 4. Map each `recipient_fingerprint` in the decrypted block file's §6.2 recipient table to a `contact_uuid` by: (a) matching against the owner card's fingerprint (already in memory), and (b) for any unmatched fingerprint, scanning `contacts/*.card`, decoding each card, and computing its fingerprint until a match is found. Any unresolved fingerprint halts restore — the trash file and manifest are still untouched at this point.
> 5. `rename(2)` the restore target to `blocks/<block-uuid>.cbor.enc`. Atomic per §9.
> 6. Physically remove every purge target via `fs::remove_file`. Best-effort: individual failures here log but do not roll back the restore — the block is already live.
> 7. Build the `BlockEntry` from the decrypted block file:
>     - `block_uuid`, `block_name` (from plaintext), `suite_id`, `created_at_ms`, and `vector_clock_summary` from the file's §6.1 header. **Block-level vector clock is preserved verbatim** — restore does not tick the per-block clock because the block's *content* did not change.
>     - `fingerprint` = BLAKE3-256 of the restored file's bytes (matches the bytes that just passed verification).
>     - `recipients` = the resolved `contact_uuid`s from step 4.
>     - `last_mod_ms` = now (the restoring write's wall-clock).
> 8. Append the new `BlockEntry` to `manifest.blocks`; remove the matching `TrashEntry` from `manifest.trash`.
> 9. Tick the manifest-level vector clock for the restoring `device_uuid` (the manifest *did* change — its block set moved).
> 10. Re-sign the manifest with a fresh AEAD nonce; atomic-write per §9.
>
> Atomic-write ordering mirrors §9: file move first (step 5), manifest write second (step 10). A crash between leaves the block live-on-disk but absent from the manifest — recoverable on next open by re-attempting the restore.
>
> Restore preserves the block-level vector clock so that a sync of the restored block to another device is treated as a continuation, not a fork: the receiving device will see a block with the same `block_uuid` and a `vector_clock_summary` greater-or-equal to what it last observed, and will merge accordingly.

### 8.3 No change to `crypto-design.md`

Cryptographic primitives are unchanged. Trash and restore only rearrange already-encrypted artifacts and re-sign the manifest with the existing §8 hybrid signature flow.

### 8.4 Conformance script

No change required. The existing manifest round-trip in `core/tests/python/conformance.py` already exercises `TrashEntry` encode/decode. A future "golden vault with trashed block" KAT for cross-language behavior verification is a Sub-project C follow-up, not a B.5 blocker.

`spec_test_name_freshness.py` runs unmodified — the spec extension uses no concrete `fn test_...` identifiers.

## 9. Test plan

### 9.1 Core layer

**Inline unit tests in `core/src/vault/orchestrators.rs::tests` (~6 tests):**

- `trash_block_moves_file_and_updates_manifest` — happy path, single block.
- `trash_block_rejects_unknown_uuid` — surfaces `BlockNotFound`.
- `trash_block_ticks_manifest_clock_not_block_clock` — clock invariant.
- `restore_block_round_trip` — save → trash → restore returns identical plaintext.
- `restore_block_purges_older_copies` — trash → restore → trash → restore: only newest survives.
- `restore_block_preserves_block_vector_clock` — sync-correctness invariant.

**Integration tests in `core/tests/trash_restore.rs` (~8 tests):**

- `trash_then_restore_two_blocks_independent` — UUIDs isolated.
- `restore_rejects_live_uuid_collision` — surfaces `BlockUuidAlreadyLive`.
- `restore_rejects_when_not_in_trash` — surfaces `BlockNotInTrash`.
- `restore_rejects_tampered_file` — write garbage into trash/, expect `RestoreVerificationFailed`.
- `restore_rejects_signature_substitution` — swap two block files in trash/, expect verify failure.
- `restore_share_then_trash_round_trip` — `save_block` → `share_block` (adds a second recipient card to `contacts/`) → `trash_block` → `restore_block` returns a `BlockEntry` with both recipient `contact_uuid`s in the correct order.
- `restore_rejects_missing_recipient_card` — share a block, trash it, **delete the non-owner card from `contacts/`**, attempt restore → expect `MissingRecipientCard { fingerprint }`. Confirms the trash file is still in `trash/` and the manifest is unchanged after the failure (the failure-mode "no filesystem mutation" invariant).
- `trash_filename_grammar_parses_unix_millis` — round-trips ts values across day/hour boundaries.

### 9.2 Bridge layer

**Inline unit tests in `trash/orchestration.rs` + `restore/orchestration.rs` (~4 tests each):**

- happy-path round-trip
- wiped-handle surfaces `CorruptVault`
- mapper routing pin tests for the new variants

**Integration tests in `tests/trash_block.rs` + `tests/restore_block.rs` (~3 tests each):**

- end-to-end through bridge + on-disk vault assertion
- unmodified-on-failure invariant
- atomic-write ordering recovery (rename succeeded, manifest re-sign induced to fail, next open_vault recovers)

### 9.3 PyO3 layer

**~10 pytest tests in `test_trash_restore.py`:**

- happy-path round-trip (Python `bytes`-typed UUIDs)
- `VaultBlockNotFound` raised for unknown UUID
- `VaultBlockUuidAlreadyLive` raised for live-collision
- `VaultBlockNotInTrash` raised when nothing trashed
- `VaultCorruptVault` raised for tampered trash file
- recipient identity preserved across trash/restore
- vector-clock continuity assertion
- wiped-handle behavior
- `share_block` + `trash_block` + `restore_block` round-trip preserves the shared recipient set
- `VaultMissingRecipientCard` raised when the non-owner card is removed from `contacts/` between share and restore

### 9.4 uniffi smoke runners

Per §7.3: Swift +4 (→ 34), Kotlin +4 (→ 35).

### 9.5 Property tests

**One proptest in `core/tests/trash_restore_proptest.rs`:**

- `trash_restore_round_trip_preserves_plaintext` — for arbitrary `BlockPlaintext`, `save → trash → restore` returns byte-identical plaintext on `read_block`. Cases pinned at 16 (matches the existing `share_block_proptest` pattern, same Argon2id cost rationale; issue #38 applies).

### 9.6 Total test growth

- cargo workspace: **+27–32 tests** (603 → ~630–635)
- pytest: **+10** (57 → 67)
- Swift smoke: **+4** (30 → 34)
- Kotlin smoke: **+4** (31 → 35)

### 9.7 File-size impact

`error/vault.rs` is currently 524 LOC (already ~24 over the 500-line policy threshold, tracked as issue #44). The +3 arms + +5 pin tests add ~60 LOC → ~584 LOC. Per the project memory and the B.4d posture, the per-variant explicit matching is intrinsic to the type; splitting tests would over-deepen the directory. **Defer the split decision until B.5 lands** and re-evaluate as one cleanup pass — same posture as PR #46.

## 10. Build sequence

1. **Core orchestrator + spec change** (one commit, with the §7.1 spec extension landing in the same commit as the Rust orchestrator).
    - Add 3 `VaultError` variants. Fix the resulting compile errors at 3 mapper sites (save's `map_core_vault_error`, share's `map_core_vault_error_share`, the `From<core::VaultError>` impl in bridge `error/vault.rs`).
    - Implement `core::vault::trash_block` + `core::vault::restore_block`.
    - 6 inline unit tests + 6 integration tests + 1 proptest.
    - `docs/vault-format.md` §7 tightening + §7.1 restore section.
2. **Bridge orchestrators** (one commit per direction or one combined; reviewer's call).
    - `bridge/trash/` and `bridge/restore/` modules.
    - 2 new `FfiVaultError` variants + 3 new `From` arms + 2 new per-orchestrator mappers.
    - 5 drift-prevention pin tests + ~6–8 integration tests.
3. **PyO3 layer.**
    - 2 pyfunctions + 2 exception types.
    - 8 pytest tests.
4. **uniffi layer.**
    - 2 UDL declarations + 2 enum variants.
    - 4 Swift smoke asserts + 4 Kotlin smoke asserts.
5. **README / ROADMAP / NEXT_SESSION documentation pass** (separate doc-only commit before opening the PR).

## 11. Out of scope (deferred)

- Retention-window cleanup (physically purging `trash/` files older than 90 days). Defer to a separate `purge_trash` orchestrator that takes a retention duration. Sub-project C concern.
- `list_trashed_versions(uuid)` for callers who want to see older trashed copies before they're purged by restore. Future API; v1 ships restore-and-purge.
- A cross-language "golden vault with trashed block" KAT in `conformance.py`. Sub-project C will benefit from this; not a B.5 blocker.
- Multi-recipient trash (each recipient has their own view of a block's trash state). v1 is owner-only deletion; multi-party deletion semantics are a future-PR design.
