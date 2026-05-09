# secretary-ffi-bridge

The FFI-friendly facade of `secretary-core`. Single source of code truth
for the FFI surface shared between [`secretary-ffi-py`](../secretary-ffi-py/)
(PyO3 → Python) and [`secretary-ffi-uniffi`](../secretary-ffi-uniffi/)
(uniffi → Swift / Kotlin).

## Why this crate exists

Both binding-flavor crates need the same logic:
- Map the unlock entry points' core `UnlockError` variants (10 total —
  9 reachable from `open_with_password` / `open_with_recovery` plus
  one defensively forward-compat for `create_vault`) to a thinned
  5-variant FFI surface
- Wrap `core::UnlockedIdentity` in an opaque handle with explicit wipe
- Forward `open_with_password` and `open_with_recovery` calls into core

Without a shared crate, this logic would duplicate in both binding
crates and **drift** as new operations land. With this crate, drift is
**impossible at compile time** — both binding flavors share the same
underlying methods and project them through their respective binding
macros.

## Surface

- `FfiUnlockError` — 5-variant thinned error:
  `WrongPasswordOrCorrupt`, `WrongMnemonicOrCorrupt`,
  `InvalidMnemonic { detail }`, `VaultMismatch`,
  `CorruptVault { detail }`. Expresses user-actionable intent rather
  than mirroring core's internal enum structure.
- `UnlockedIdentity` — opaque handle. Two non-secret accessors
  (`display_name`, `user_uuid`) plus explicit `wipe()`. The wrapped
  secret material stays Rust-side.
- `open_with_password` — fallible operation: vault unlock by master
  password.
- `open_with_recovery` — fallible operation: vault unlock by 24-word
  BIP-39 recovery phrase. Mnemonic input is `&[u8]` (UTF-8 bytes); the
  bridge does `std::str::from_utf8` and surfaces malformed-UTF-8 input
  as `InvalidMnemonic { detail: "phrase contained invalid UTF-8" }`.
  Both unlock paths produce byte-identical `UnlockedIdentity` state on
  success — the caller cannot tell which entry point was used after
  the fact.

## Design rationale

### Thinned error type

Core's `UnlockError` has 10 variants reachable from the unlock entry
points (`open_with_password` / `open_with_recovery`), three wrapping
inner enums (`MalformedVaultToml(VaultTomlError)`, etc.). Mirroring
exactly to the foreign side either re-exposes ~15 inner types per
language (huge surface, churns on every `core/` internal refactor) or
collapses inners to strings (anti-pattern; foreign callers parse
strings to understand failure causes).

The thinned 5-variant shape:
- `WrongPasswordOrCorrupt` — "your password is wrong, try again".
  Returned by `open_with_password`. **Deliberately conflates
  wrong-password and corruption** per
  [`docs/threat-model.md`](../../docs/threat-model.md) §13's anti-oracle
  property; **MUST NOT** be split into separate variants on the foreign
  side.
- `WrongMnemonicOrCorrupt` — parallel to `WrongPasswordOrCorrupt` for
  the recovery path. Same anti-oracle conflation: AEAD tag failure
  under `recovery_kek` is indistinguishable from corruption to the
  cryptography. Returned by `open_with_recovery`.
- `InvalidMnemonic { detail }` — pre-decryption: the input does not
  validate as a 24-word BIP-39 phrase (wrong word count, unknown word,
  bad checksum, or invalid UTF-8). NOT a security oracle — the
  validation runs before any vault byte is touched, so an attacker
  submitting phrases learns "valid BIP-39 vs not" trivially via the
  BIP-39 spec itself. Surfacing the specific failure mode is a UI win
  with zero security cost. The `detail` carries inner-enum Display
  text; foreign callers render it for the user.
- `VaultMismatch` — "vault.toml and identity.bundle.enc reference
  different vaults; re-pair from backups". Triggered on either unlock
  path.
- `CorruptVault { detail }` — collapses {core::CorruptVault, all
  MalformedX, KdfFailure, WeakKdfParams}. The `detail` field carries
  the inner Display text for diagnostics; structured pattern-matching
  on the inner cause is intentionally not supported (corruption
  recovery is "restore from backup", not "branch on which file was
  malformed").

Internal core refactors fold automatically into `CorruptVault {
detail: <new Display> }` without rippling foreign-API changes. The
`From<core::unlock::UnlockError>` impl uses explicit match arms with
no wildcard, so a future core variant forces a compile error here
instead of silently mapping to a default.

### `Mutex<Option<...>>` inside `UnlockedIdentity`

Provides:
- **idempotent wipe** via `Option::take()` (multiple `wipe()` calls
  don't panic)
- **thread-safe accessors** (sub-microsecond locks for cloning a
  `String` or copying 16 bytes)
- **use-after-wipe non-throwing** semantics (`as_ref()` on `None`
  yields default values, matching the B.1 non-throwing accessor
  pattern)
- **prompt zeroize** — `take()` consumes the inner Option, `Drop`
  cascades through `Sensitive<...> ZeroizeOnDrop`

Mutex overhead is acceptable for the opaque-handle pattern; if profile
data ever shows it as a hot path (it won't — accessors are unlock-time
operations, not record-read-time), `RwLock` is a drop-in upgrade.

## Foreign-side projection notes

- The bridge crate names every handle's explicit-zeroize method `wipe()`
  for vocabulary uniformity (`UnlockedIdentity`, `MnemonicOutput`,
  `OpenVaultManifest`, `BlockReadOutput`, `Record`, `FieldHandle` all
  expose `wipe()`).
- The PyO3 projection (`secretary-ffi-py`) presents `UnlockedIdentity`
  with `display_name() / user_uuid() / close()` plus the `with` /
  `__enter__` / `__exit__` context-manager protocol — Python's idiomatic
  destructor name is `close()`. PyO3 forwards Python's `close()` to the
  bridge's `wipe()` internally. The five exception classes
  (`WrongPasswordOrCorrupt`, `WrongMnemonicOrCorrupt`,
  `InvalidMnemonic`, `VaultMismatch`, `CorruptVault`) are unchanged;
  `str(e)` carries the inner detail string for the two variants that
  have one.
- The uniffi projection (`secretary-ffi-uniffi`) calls `wipe()` directly
  through the UDL because uniffi 0.31's Kotlin codegen auto-generates
  `AutoCloseable.close()` on every interface handle (releases the Rust
  refcount), and a UDL-declared `close()` would collide. See
  `secretary-ffi-uniffi/src/lib.rs` for the rationale rustdoc.

  The `CorruptVault.message` → `CorruptVault.detail` rename that B.2
  introduced uniffi-side has been propagated into the bridge crate
  itself in B.3a (the field is now named `detail` in the bridge),
  eliminating the projection-only rename. The motivation was naming
  uniformity with `InvalidMnemonic { detail }` introduced in B.3a; the
  uniffi codegen still produces `detail` on the foreign side, just now
  without a Kotlin-only rename in between.

## Lints / invariants

- Pure-safe Rust. Workspace's `#![forbid(unsafe_code)]` applies; no
  carve-out (the binding-flavor crates carry their FFI-macro
  `unsafe_code = "deny"` carve-outs locally).
- `cargo clippy --release --workspace -- -D warnings` clean.
- `From<core::unlock::UnlockError>` impl uses explicit match arms with
  no wildcard so future core variants force a compile error instead of
  silently mapping to a default.

## Testing

```bash
cargo test --release -p secretary-ffi-bridge
```

81 unit + integration tests across five modules (post-B.4b):

- `error.rs` (14 tests) — `From<core::unlock::UnlockError>` mapping for
  every reachable variant + the defensive `WeakKdfParams` arm; the
  Display format pin; the `CorruptVault.message → detail` rename
  regression pin; the four `InvalidMnemonic` triggers (wrong word
  count, unknown word, bad checksum, UTF-8 failure).
- `identity.rs` (7 tests) — opaque-handle accessors, idempotent wipe,
  use-after-wipe non-throwing semantics, Mutex poisoning fall-through.
- `unlock.rs` (9 tests) — both unlock paths against
  `golden_vault_001/` + `golden_vault_002/`: success, wrong key,
  vault mismatch, corrupt vault, plus B.3a's mnemonic-specific cases
  (wrong phrase, invalid length, invalid UTF-8).
- `vault.rs` (26 tests) — both folder-in open paths against
  `golden_vault_001/` + `golden_vault_002/`: success, wrong password,
  wrong mnemonic, invalid mnemonic, vault mismatch, corrupt vault, and
  folder-not-found; `OpenVaultManifest` accessor shapes (vault_uuid,
  owner_user_uuid, block_count, block_summaries, find_block);
  `BlockSummary` field values pinned against KAT fixtures; `FfiVaultError`
  Display strings and `From` mapping for every `VaultError` and
  `UnlockError` variant; idempotent `wipe()` and use-after-wipe
  non-throwing semantics.
- `record/` (5 sub-files, ~12 unit tests) — opaque-handle wipe
  cascades (`BlockReadOutput → Record → FieldHandle`), `Arc`-clone
  shared-wipe semantics on `Record` / `FieldHandle`, idempotent
  `wipe()` on each handle, `expose_text` / `expose_bytes`
  bytes-vs-text discrimination (text field returns `Some(String)` /
  `None`-on-bytes; bytes field returns `Some(Vec<u8>)` / `None`-on-text).
- `tests/read_block.rs` (13 KAT-pinned integration tests against
  `golden_vault_001/`) — happy-path shape, metadata fields, text
  payload exposure, bytes payload exposure, wrong-UUID
  `BlockNotFound`, multi-record blocks, `Record::wipe()` then
  parent-cascade idempotence, and the snapshot-accessor TOCTOU pin.

Tests embed both `golden_vault_001/` and `golden_vault_002/` via
`include_bytes!` so no runtime filesystem dependency. Pinned KAT
values (display_name, user_uuid) match those asserted in the
foreign-side smoke runners — KAT drift cannot land silently.

## B.3a — Recovery-phrase unlock

Adds `open_with_recovery` to the bridge surface. Mnemonic input is
`&[u8]` (UTF-8 bytes), parallel to B.2's password input shape; the
bridge does `std::str::from_utf8` and surfaces malformed-UTF-8 input
as `InvalidMnemonic { detail: "phrase contained invalid UTF-8" }`.

`FfiUnlockError` grows from 3 → 5 variants:

| Variant | Path | Trigger |
|---|---|---|
| `WrongPasswordOrCorrupt` | password only | AEAD tag fail under `master_kek` |
| `WrongMnemonicOrCorrupt` | recovery only | AEAD tag fail under `recovery_kek` |
| `InvalidMnemonic { detail }` | recovery only | wrong word count, unknown word, bad checksum, or invalid UTF-8 — pre-decryption |
| `VaultMismatch` | both | UUID/timestamp mismatch |
| `CorruptVault { detail }` | both | malformed TOML/CBOR/bundle |

The §13 anti-oracle conflation property is preserved: each unlock
path's "wrong key" variant is independently conflated with corruption.
`InvalidMnemonic` is pre-decryption and not an oracle.

`CorruptVault.message` was renamed to `CorruptVault.detail` in B.3a
for naming uniformity with `InvalidMnemonic { detail }`. The uniffi
projection layer was already using `detail` in B.2 to avoid a Kotlin
`Throwable.message` collision; B.3a propagates the rename to the
bridge so all layers agree.

`WeakKdfParams` is mapped defensively into `CorruptVault { detail }`
because neither unlock entry point can return it under the current
core API (the v1 floor is enforced at vault-creation time, not at
unlock). When `create_vault` is exposed in B.3b, the mapping will be
re-validated and the variant will either get its own thinned variant
or stay folded — that decision belongs to B.3b's design pass.

## B.3b — Vault creation

Adds `create_vault` to the bridge surface — the third `pub fn` entry
point and the first that produces secret material in the **output**
direction.

```rust
pub fn create_vault(
    password: &[u8],
    display_name: &str,
    created_at_ms: u64,
) -> Result<CreateVaultOutput, FfiUnlockError>;
```

Bridge instantiates `OsRng` and `Argon2idParams::V1_DEFAULT` internally;
foreign callers cannot tune either knob. With `V1_DEFAULT` hardcoded,
`core::UnlockError::WeakKdfParams` is structurally unreachable through
this surface — the existing defensive fold-into-`CorruptVault` mapping
remains for forward-compat.

The return shape is a 4-field `CreateVaultOutput`:

| Field | Type | Direction |
|---|---|---|
| `vault_toml_bytes` | `Vec<u8>` | non-secret bytes; caller persists atomically |
| `identity_bundle_bytes` | `Vec<u8>` | non-secret bytes; caller persists atomically |
| `identity` | `UnlockedIdentity` | live opaque handle, ready for vault ops |
| `mnemonic` | `MnemonicOutput` | one-shot opaque handle for recovery phrase |

`MnemonicOutput` is a new opaque-handle type with one-shot
`take_phrase() -> Option<Vec<u8>>` and idempotent `wipe()`. The phrase
exits the `Sensitive<T>` boundary as caller-owned heap-allocated bytes;
callers MUST zeroize their copy after use (matches the input-side
caller-zeroize discipline of B.2 / B.3a, inverted in direction). Second
`take_phrase()` call returns `None` (one-shot semantics, NOT an error).

`CorruptVault`'s Display text was tweaked from `"vault is corrupt or
unreadable: {detail}"` to the path-neutral `"vault data integrity
failure: {detail}"` so the variant reads correctly on both the open
path and the new create path. Variant name and shape unchanged; the
5-variant cardinality from B.3a is structurally intact.

## B.4a — Folder-based vault open

Adds two new entry points — `open_vault_with_password` and
`open_vault_with_recovery` — that take a **folder path** rather than
raw bytes. This is the first folder-IO entry point on the bridge
surface; all subsequent B.4b/c/d operations (read_block, save_block,
share_block) inherit the same folder-ownership model.

```rust
pub fn open_vault_with_password(
    folder: &std::path::Path,
    password: &[u8],
) -> Result<OpenVaultOutput, FfiVaultError>;

pub fn open_vault_with_recovery(
    folder: &std::path::Path,
    mnemonic: &[u8],
) -> Result<OpenVaultOutput, FfiVaultError>;
```

The bridge reads `vault.toml`, `identity.bundle.enc`,
`manifest.cbor.enc`, and the owner contact card from the folder.
File I/O stays Rust-side; the binding-flavor crates receive typed
results.

> **Projection note:** the bridge takes `folder: &std::path::Path`. PyO3
> projects this from a Python `os.PathLike` / `str` via
> `std::path::PathBuf` (idiomatic for Python). uniffi has no `Path` type
> in its UDL grammar, so the uniffi forwarder takes `folder_path: bytes`
> (UTF-8) and validates inside Rust — invalid UTF-8 surfaces as
> `VaultError::FolderInvalid` with `detail: "folder path contained
> invalid UTF-8"`. Each binding flavor uses its idiomatic foreign type;
> the bridge `&Path` API is unaffected.

### Return shape: `OpenVaultOutput`

A two-field struct — the same shape as B.3b's `CreateVaultOutput` but
for the open direction:

| Field | Type | Notes |
|---|---|---|
| `identity` | `UnlockedIdentity` | Opaque handle; same type as B.2/B.3a/B.3b |
| `manifest` | `OpenVaultManifest` | New opaque handle; holds IBK + manifest + envelope + owner card |

### `OpenVaultManifest` accessors

| Method | Return type | Notes |
|---|---|---|
| `vault_uuid()` | `[u8; 16]` | 16-byte vault UUID |
| `owner_user_uuid()` | `[u8; 16]` | 16-byte owner UUID |
| `block_count()` | `u64` | Number of blocks in the manifest |
| `block_summaries()` | `Vec<BlockSummary>` | All block summaries |
| `find_block(uuid)` | `Option<BlockSummary>` | Lookup by UUID |
| `wipe()` | `()` | Zeroize IBK; idempotent |

`local_highest_clock` is always `None` in B.4a — rollback detection
is deferred to Sub-project C's sync orchestration layer. B.4b/c/d
will extend `OpenVaultManifest` with `read_block` / `save_block` /
`share_block` methods without changing its construction.

### `BlockSummary` value type

Five plaintext-in-the-manifest fields (no secret material):
`block_uuid`, `block_name`, `created_at_ms`, `last_modified_ms`,
`recipient_uuids`.

### `FfiVaultError` — new 6-variant error type

Mirrors `FfiUnlockError`'s 5 unlock-class variants byte-identically
(variant name + Display string) and adds one new variant:

| Variant | Trigger |
|---|---|
| `WrongPasswordOrCorrupt` | AEAD tag fail under master KEK |
| `WrongMnemonicOrCorrupt` | AEAD tag fail under recovery KEK |
| `InvalidMnemonic { detail }` | Pre-decryption BIP-39 validation failure |
| `VaultMismatch` | vault.toml / identity.bundle.enc UUID mismatch |
| `CorruptVault { detail }` | Malformed TOML/CBOR/bundle or manifest verify failure |
| `FolderInvalid { detail }` | Folder missing, unreadable, or required files absent |

`FfiVaultError` is a **separate type** from `FfiUnlockError` (it is
the folder-in error surface; `FfiUnlockError` is the bytes-in error
surface). The mirror property means foreign callers do not need to
maintain two error-handling patterns for the unlock variants.

`From<core::unlock::UnlockError>` uses explicit match arms with no
wildcard — a future core variant forces a compile error here.
`From<core::vault::orchestrators::VaultError>` provides the
`CorruptVault` and `FolderInvalid` paths from the manifest-layer error
surface.

## B.4b — Block read

Adds `read_block` as a free function on the bridge — the first
mutation-free block-access entry point and the eighth `pub fn` on
the bridge surface. The signature stays at the module root rather
than as a method on `OpenVaultManifest`:

```rust
pub fn read_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: &[u8; 16],
) -> Result<BlockReadOutput, FfiVaultError>;
```

Per project policy (free functions in reusable modules; structs only
for genuine state) the entry point is a free fn taking `&handle`
references. The two handles supply the necessary keying material
(IBK from `manifest`, reader secret keys from `identity`); no
mutation occurs on either side.

### Hybrid Record projection (decision §1)

Records contain mixed-sensitivity data. The bridge projects them
under a hybrid shape:

- **Non-secret metadata** — `record_uuid: [u8; 16]`, `record_type:
  String`, `tags: Vec<String>`, `created_at_ms: u64`, `last_mod_ms:
  u64`, `tombstone: bool` — projected as **value types**. Cheap to
  clone, no zeroize concerns.
- **Secret payload** — record field values (`String` for `Text`,
  `Vec<u8>` for `Bytes`) — projected through an **opaque
  `FieldHandle`** with `expose_text() -> Option<String>` /
  `expose_bytes() -> Option<Vec<u8>>` accessors. Each call CLONES
  the inner secret out; the foreign caller is responsible for
  zeroizing the returned value once consumed (Python `del s` /
  Swift `String` deinit / Kotlin `ByteArray.fill(0)` idioms).

`Record.unknown` and `RecordField.unknown` (forward-compat opaque
CBOR roundtripping) are NOT surfaced through the FFI in B.4b;
`tombstoned_at_ms` is also NOT surfaced (CRDT internal — the foreign
caller sees only the `tombstone: bool`).

### `BlockNotFound` — the new 7th `FfiVaultError` variant

`FfiVaultError` grew from 6 → 7 variants:

| Variant | Trigger |
|---|---|
| ... existing 6 ... | (unchanged from B.4a) |
| `BlockNotFound { uuid_hex }` | The given UUID is not present in the manifest's `blocks` table (or its summary is filtered out by trash; trash entries are invisible at the FFI through B.4d). The hex string is the lower-case hex encoding of the queried UUID — **not** zero-padded by length, since the input is always exactly 16 bytes and a wrong-length UUID is rejected upstream as a programmer bug. |

Decrypt failures (e.g. wrong content-encryption key, AEAD tag fail
because the on-disk file was corrupted) and file-missing failures
(the manifest references a UUID but `blocks/<uuid>.cbor.enc` is
absent) **both fold into `CorruptVault { detail }`** per the §13
anti-conflation discipline carried over from `open_vault_*`. A
foreign caller cannot tell whether the file is missing, the file is
present-but-tampered-with, or the per-block content key is wrong;
recovery is the same in all three cases (restore from backup or
re-share the block).

### `OpenVaultManifestInner.vault_folder: PathBuf` (bridge-internal)

To resolve `blocks/<uuid>.cbor.enc` from a UUID, the bridge needs
the vault's folder path. B.4a's `OpenVaultManifestInner` did not
carry this; B.4b extends it with `vault_folder: PathBuf` —
populated at construction time inside both
`open_vault_with_password` and `open_vault_with_recovery`. **No
public B.4a surface change**: the field is `pub(crate)`, accessed
only through new bridge-internal `pub(crate)` helpers
(`vault_folder()`, `manifest_snapshot()`, `owner_card_clone()`),
plus a snapshot accessor:

```rust
pub(crate) fn snapshot_for_read_block(
    &self,
) -> Option<(Manifest, ContactCard, PathBuf)>
```

`snapshot_for_read_block` folds three sequential `Mutex` acquires
into one — closing a theoretical TOCTOU window between
manifest-snapshot and folder-snapshot when a concurrent `wipe()` is
racing the read.

### v1 single-author scope (decision §9)

`read_block` assumes `manifest.owner_card` is the block's signing
identity. v1 vaults have a single author per vault by construction.
B.4d's `share_block` flow will add `contacts/<author_uuid>.card`
discovery and the multi-author read path; the B.4b code is
structured so that adding a `senders: HashMap<Uuid, ContactCard>`
parameter to the inner read path is mechanical.

### `record/` directory module split

The implementation lives in `ffi/secretary-ffi-bridge/src/record/`
— a directory module split into five sub-files per the project's
<500-line policy:

| File | Role |
|---|---|
| `record/mod.rs` | Module root; re-exports + module-level docs |
| `record/output.rs` | `BlockReadOutput` opaque handle (cascades `wipe()` to children) |
| `record/handle.rs` | `Record` opaque handle (cascades `wipe()` to its `FieldHandle`s; uses `Arc<Mutex<Option<...>>>` for clone-safe sharing) |
| `record/field.rs` | `FieldHandle` opaque handle (the `expose_text` / `expose_bytes` boundary) |
| `record/orchestration.rs` | `read_block` free fn — file load → AEAD decrypt → record decode → wrap in handles |

Integration tests are in `ffi/secretary-ffi-bridge/tests/read_block.rs`
(13 KAT-pinned tests against `golden_vault_001/`).

## References

- Spec (B.4b): [docs/superpowers/specs/2026-05-09-ffi-b4b-read-block-design.md](../../docs/superpowers/specs/2026-05-09-ffi-b4b-read-block-design.md)
- Plan (B.4b): [docs/superpowers/plans/2026-05-09-ffi-b4b-read-block.md](../../docs/superpowers/plans/2026-05-09-ffi-b4b-read-block.md)
- Spec (B.4a): [docs/superpowers/specs/2026-05-06-ffi-b4a-open-vault-design.md](../../docs/superpowers/specs/2026-05-06-ffi-b4a-open-vault-design.md)
- Plan (B.4a): [docs/superpowers/plans/2026-05-06-ffi-b4a-open-vault.md](../../docs/superpowers/plans/2026-05-06-ffi-b4a-open-vault.md)
- Spec (B.3a): [docs/superpowers/specs/2026-05-04-ffi-b3a-recovery-unlock-design.md](../../docs/superpowers/specs/2026-05-04-ffi-b3a-recovery-unlock-design.md)
- Plan (B.3a): [docs/superpowers/plans/2026-05-04-ffi-b3a-recovery-unlock.md](../../docs/superpowers/plans/2026-05-04-ffi-b3a-recovery-unlock.md)
- Spec (B.2): [docs/superpowers/specs/2026-05-04-ffi-b2-vault-unlock-design.md](../../docs/superpowers/specs/2026-05-04-ffi-b2-vault-unlock-design.md)
- Plan (B.2): [docs/superpowers/plans/2026-05-04-ffi-b2-vault-unlock.md](../../docs/superpowers/plans/2026-05-04-ffi-b2-vault-unlock.md)
- Sibling Python crate: [../secretary-ffi-py/README.md](../secretary-ffi-py/README.md)
- Sibling uniffi crate: [../secretary-ffi-uniffi/README.md](../secretary-ffi-uniffi/README.md)
