# Sub-project B.4a — FFI Folder-Based `open_vault`

**Date:** 2026-05-06
**Author:** Horst Herb (with Claude)
**Status:** Approved — ready for implementation plan
**Touches:** edits in `ffi/secretary-ffi-bridge/`, `ffi/secretary-ffi-py/`, `ffi/secretary-ffi-uniffi/`; no `core/` changes; no on-disk fixture changes.

## Background

Sub-project B.3b ([design](2026-05-05-ffi-b3b-create-vault-design.md), [PR #27](https://github.com/hherb/secretary/pull/27)) shipped `create_vault` through both PyO3 and uniffi via the shared `secretary-ffi-bridge` crate. With B.3b done, the FFI surface contains every `secretary_core::unlock` v1 entry point: `open_with_password`, `open_with_recovery`, and `create_vault`. All three are **bytes-in** — the foreign caller reads `vault.toml` + `identity.bundle.enc` from its own filesystem and hands the bytes to the bridge; Rust never touches foreign-owned files. That discipline was a deliberate boundary choice for the unlock subprotocol.

B.4 — record operations, the next sub-project — must read records out of encrypted block files (B.4b), encrypt and persist new block files (B.4c), and add recipients to existing block files (B.4d). The write paths (B.4c / B.4d) cannot survive bytes-in: the §9 atomicity guarantee depends on `tempfile::persist` for `rename(2)` semantics owned by Rust core, and duplicating that contract cross-language would weaken it. So at some point in the B.4 chain the FFI must transition to **folder-in**: the foreign caller hands over a vault folder path, and Rust core owns reads and atomic writes against it.

B.4a is that transition. It exposes `core::vault::open_vault(folder, unlocker, local_highest_clock)` through the FFI as the first folder-based entry point, returning identity + manifest both as opaque handles. It establishes the IO model B.4b/c/d will inherit, the new error type that covers post-unlock vault-level failures, and the manifest-summary type shape the foreign caller will use for "list the records I have" UI affordances. It does **not** yet expose record reading, record writing, or recipient management — those are deferred to B.4b/c/d in turn.

## Goals

1. Two new top-level `pub fn`s on the bridge: `open_vault_with_password(folder, password)` and `open_vault_with_recovery(folder, mnemonic)`. Both return `Result<OpenVaultOutput, FfiVaultError>`.
2. A new value-type output struct `OpenVaultOutput { identity: UnlockedIdentity, manifest: OpenVaultManifest }`. `UnlockedIdentity` is the **same** opaque handle B.2 / B.3a / B.3b return — re-used unchanged.
3. A new opaque handle `OpenVaultManifest` exposing read-only manifest accessors: `vault_uuid`, `owner_user_uuid`, `block_count`, `block_summaries`, `find_block`, `wipe`. Holds the IBK and `ManifestFile` envelope internally so B.4b/c can extend the same handle without re-opening.
4. A new value type `BlockSummary` with five plaintext-already-in-the-manifest fields: `block_uuid`, `block_name`, `created_at_ms`, `last_modified_ms`, `recipient_uuids`.
5. A new error type `FfiVaultError` with **6 flat variants** — 5 mirrored from `FfiUnlockError` for unlock-class failures (preserving the §13 anti-oracle conflation independently per error type) plus 1 new `FolderInvalid { detail }` for missing / inaccessible vault folders.
6. The bridge crate stays the single source of FFI code truth; PyO3 and uniffi project the new surface from it.
7. All gates green at session close: cargo workspace +~9 tests, pytest +~7, Swift smoke +~3 asserts, Kotlin smoke +~3 asserts. Conformance + freshness PASS unchanged.

## Non-goals (YAGNI)

- **No record types crossing the FFI yet.** `Record` / `RecordField` / `RecordFieldValue` deferred to B.4b. The block-level `BlockSummary` is plaintext-already-in-the-manifest metadata only.
- **No `read_block` / record decryption.** B.4b adds the decrypt-records-given-block-uuid entry point. B.4a's `OpenVaultManifest` holds the IBK internally so B.4b can extend rather than re-open.
- **No `save_block` / `share_block` / mutation.** B.4c adds the encrypted-write-and-update-manifest path; B.4d adds recipient management. B.4a's handle is read-only.
- **No `Trash` / tombstoned block entries exposed.** `Manifest.trash` is internal to v1 sync invariants. UI affordance for "show me deleted blocks" is a B.4c / B.4d concern.
- **No `vector_clock_summary` per-block.** Sync-orchestration internal; not useful in a foreign UI.
- **No `local_highest_clock` rollback parameter.** Bridge always passes `None`. Rollback is a stateful-sync concern (the caller has to remember a "last seen clock" across sessions); deferred to Sub-project C, which can either extend `open_vault_with_password` with an optional parameter or add a new `pub fn open_vault_with_clock` — both additive.
- **No owner contact card surface.** `OpenVault.owner_card` is held inside `OpenVaultManifest` for internal verification but **not exposed** as accessors. B.4d will surface `ContactCard` proper, with public-key accessors as part of its type-design conversation.
- **No public-key accessors on `UnlockedIdentity`.** Still deferred from B.2 / B.3a / B.3b. Will arrive whenever the first sharing operation needs them.
- **No `BlockSummary.fingerprint`.** BLAKE3-256 of the block file is internal integrity state; foreign UI doesn't need it.
- **No `BlockSummary.suite_id`.** Always 1 for v1.
- **No `BlockSummary.unknown` map.** Forward-compat slot; surfacing it through the FFI is unjustified until v2 introduces unknown keys with documented semantics.
- **No mutation of `OpenVaultManifest`.** B.4c will add `save_block(&mut self, ...)` and decide whether to keep the handle's `Mutex<Option<...>>` shape or transition to a writer-borrow model. Open question, not B.4a's.
- **No new on-disk fixture.** Both `golden_vault_001/` and `golden_vault_002/` already have a complete `manifest.cbor.enc` + owner contact card from A.5. B.4a uses both unchanged.
- **No conformance.py extension.** Same rationale as B.3a / B.3b — the manifest format is fully documented in `docs/vault-format.md` §4 and already verified end-to-end by the existing `conformance.py`. Adding a folder-based replay would not add spec-contract benefit.
- **No CI integration.** Still no `.github/workflows/`.

## Architecture

### Crate layout after B.4a

Strictly additive on B.3b. One new module on the bridge crate; no removed files.

```
ffi/
├── secretary-ffi-bridge/        ← single source of FFI code truth
│   └── src/
│       ├── lib.rs               ← edit: re-export open_vault_with_password, open_vault_with_recovery,
│       │                                 OpenVaultOutput, OpenVaultManifest, BlockSummary, FfiVaultError;
│       │                                 update crate-doc to reflect 5 → 7 pub fns
│       ├── error.rs             ← edit: add FfiVaultError enum (flat 6-variant) + From<core::VaultError>
│       │                                 + private bridge-internal From<FfiUnlockError> arm
│       │                                 (drift-free unlock-class variant translation)
│       ├── identity.rs          ← UNCHANGED (UnlockedIdentity re-used as-is)
│       ├── unlock.rs            ← UNCHANGED (B.2 / B.3a bytes-in surface)
│       ├── create.rs            ← UNCHANGED (B.3b)
│       └── vault.rs             ← NEW: open_vault_with_password, open_vault_with_recovery,
│                                          OpenVaultOutput, OpenVaultManifest, BlockSummary, +tests
│
├── secretary-ffi-py/             ← +2 #[pyfunction], +3 #[pyclass], +6 create_exception!, +pytest
└── secretary-ffi-uniffi/         ← +2 namespace fn, +2 dictionary, +1 interface, +1 [Error] enum,
                                     +Swift smoke asserts, +Kotlin smoke asserts
```

The bridge crate stays pure-safe Rust under `#![forbid(unsafe_code)]`. The two binding-flavor crates retain their existing crate-local `unsafe_code = "deny"` carve-outs from B.1 / B.1.1.

### What lives where

| Concern | secretary-ffi-bridge | secretary-ffi-py | secretary-ffi-uniffi |
|---|---|---|---|
| `open_vault_with_password(folder, password) -> Result<OpenVaultOutput, FfiVaultError>` | ✓ — calls `core::open_vault(folder, Unlocker::Password(&sb), None)` and splits | thin `#[pyfunction]` forwarder + wrapper-side `Vec<u8>` zeroize | thin `pub fn` forwarder + wrapper-side `Vec<u8>` zeroize |
| `open_vault_with_recovery(folder, mnemonic) -> Result<OpenVaultOutput, FfiVaultError>` | ✓ — calls `core::open_vault(folder, Unlocker::Recovery(&str), None)` and splits | thin `#[pyfunction]` forwarder + wrapper-side `Vec<u8>` zeroize | thin `pub fn` forwarder + wrapper-side `Vec<u8>` zeroize |
| `OpenVaultOutput { identity, manifest }` | ✓ — value struct (move-out semantics) | `#[pyclass]` newtype with take-once getters into the two handles | uniffi `dictionary` (UDL) carrying two `Arc<Interface>` fields |
| `UnlockedIdentity` (re-used unchanged) | unchanged from B.2 | unchanged from B.2 | unchanged from B.2 |
| `OpenVaultManifest` (NEW opaque handle) | ✓ — `Mutex<Option<OpenVaultManifestInner>>` newtype + `lock_or_recover` poisoning-safety helper + idempotent `wipe()` | `#[pyclass]` newtype with `__enter__`/`__exit__` | uniffi `interface` (UDL); `AutoCloseable` via uniffi 0.31 codegen |
| `BlockSummary` (value type) | ✓ — `pub struct` | `#[pyclass(frozen)]` | uniffi `dictionary` (UDL) |
| `FfiVaultError` (6-variant flat enum) | ✓ — thiserror-derived; `From<core::VaultError>` + private `From<FfiUnlockError>` | 6 `create_exception!`; `From<FfiVaultError> for PyErr` | `[Error]` enum in UDL with field projection |
| `OsRng` / `Argon2idParams` knobs | ✗ (no FFI knobs in B.4a — irrelevant; open path doesn't construct a vault) | ✗ | ✗ |

### `OpenVaultManifest` internal state

```rust
struct OpenVaultManifestInner {
    /// 32-byte Identity Block Key from core::OpenVault. Zeroized on drop.
    /// Held internally so B.4b's read_block can extend rather than re-open.
    identity_block_key: Sensitive<[u8; 32]>,
    /// Decrypted manifest body — plaintext block list + vault-level
    /// vector clock + kdf_params attestation.
    manifest: Manifest,
    /// On-disk manifest envelope (header + AEAD nonce + ct/tag + author
    /// fingerprint + §8 hybrid signature). Held so B.4c can re-sign on
    /// update without re-opening.
    manifest_file: ManifestFile,
    /// Owner's self-signed contact card, already self-verified against
    /// its own signature and against `manifest.author_fingerprint`.
    /// Held internally for B.4c/d signature operations; **not** exposed
    /// through the B.4a accessor surface (deferred to B.4d).
    owner_card: ContactCard,
}

pub struct OpenVaultManifest {
    inner: Mutex<Option<OpenVaultManifestInner>>,
}
```

Held in `Mutex<Option<OpenVaultManifestInner>>` — same `lock_or_recover` poisoning-safety helper used by `UnlockedIdentity` and `MnemonicOutput`. `wipe()` calls `Option::take()` which drops the inner; `Drop for OpenVaultManifestInner` zeroizes via `Sensitive`'s `ZeroizeOnDrop` on the IBK and source-order drop of every secret-bearing field on the bundle.

`Debug` for `OpenVaultManifest` is redacted (no leak via Debug), mirroring the B.2 / B.3a / B.3b pattern.

### Bridge entry point — orchestration sketch

```rust
// ffi/secretary-ffi-bridge/src/vault.rs (sketch — not implementation)

pub fn open_vault_with_password(
    folder: &Path,
    password: Vec<u8>,
) -> Result<OpenVaultOutput, FfiVaultError> {
    let secret_bytes = SecretBytes::from(password);  // moves bytes; Vec<u8> is consumed
    let core_out = core::vault::open_vault(
        folder,
        core::vault::Unlocker::Password(&secret_bytes),
        None,  // local_highest_clock — rollback deferred to Sub-project C
    )?;
    Ok(split_core_open_vault(core_out))
}

pub fn open_vault_with_recovery(
    folder: &Path,
    mnemonic: Vec<u8>,
) -> Result<OpenVaultOutput, FfiVaultError> {
    let phrase = std::str::from_utf8(&mnemonic)
        .map_err(|e| FfiVaultError::InvalidMnemonic { detail: format!("phrase contained invalid UTF-8: {e}") })?;
    let core_out = core::vault::open_vault(
        folder,
        core::vault::Unlocker::Recovery(phrase),
        None,
    )?;
    Ok(split_core_open_vault(core_out))
}

fn split_core_open_vault(core_out: core::vault::OpenVault) -> OpenVaultOutput {
    let core::vault::OpenVault {
        identity_block_key,
        identity,
        owner_card,
        manifest,
        manifest_file,
    } = core_out;
    OpenVaultOutput {
        identity: UnlockedIdentity::from_bundle(identity),
        manifest: OpenVaultManifest::new(OpenVaultManifestInner {
            identity_block_key,
            manifest,
            manifest_file,
            owner_card,
        }),
    }
}
```

Per-language wrapper layer (PyO3 / uniffi) zeroizes its `Vec<u8>` after the bridge call returns (success or error).

### Accessor surface — `OpenVaultManifest`

| Method | Returns | Implementation |
|---|---|---|
| `vault_uuid()` | `Vec<u8>` (length 16) | `inner.manifest.vault_uuid.to_vec()` |
| `owner_user_uuid()` | `Vec<u8>` (length 16) | `inner.manifest.owner_user_uuid.to_vec()` |
| `block_count()` | `u64` | `inner.manifest.blocks.len() as u64` |
| `block_summaries()` | `Vec<BlockSummary>` | iterates `inner.manifest.blocks`, projects each `BlockEntry` to `BlockSummary` |
| `find_block(uuid: Vec<u8>)` | `Option<BlockSummary>` | binary search by `block_uuid` (manifest invariant: ascending order) |
| `wipe()` | `()` | idempotent; `Option::take()` on the mutex-guarded inner |

After `wipe()`, every accessor returns the empty-default per the established B.2 / B.3a / B.3b pattern — empty `Vec<u8>`, `0` for `block_count`, empty `Vec<BlockSummary>`, `None` for `find_block`. No method panics, no method returns an error from a wiped handle (the empty default mirrors `UnlockedIdentity`'s post-wipe behavior).

### `BlockSummary` value type

```rust
pub struct BlockSummary {
    pub block_uuid: [u8; 16],          // uniffi: bytes (Data / ByteArray); pyo3: bytes
    pub block_name: String,
    pub created_at_ms: u64,
    pub last_modified_ms: u64,
    pub recipient_uuids: Vec<[u8; 16]>, // uniffi: sequence<bytes>; pyo3: list of bytes
}
```

All five fields are plaintext in the manifest already — no secret material crosses through `BlockSummary`. The struct is `Clone`, `Debug` (full Debug — nothing sensitive). At the foreign side: uniffi codegen produces a Swift `struct` / Kotlin `data class`; PyO3 produces a `#[pyclass(frozen)]` with all fields exposed as `#[pyo3(get)]`.

uniffi codegen rename note: per B.3b's experience, uniffi 0.31 may codegen `Vec<[u8; 16]>` as `sequence<bytes>?` requiring foreign-side conversion (Swift `[Data]?` element-wise, Kotlin `List<ByteArray>?` element-wise). Plan task for the smoke runners must verify the actual codegen output before pinning the exact foreign-side calling convention.

## Error surface — `FfiVaultError`

```rust
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum FfiVaultError {
    #[error("password is wrong, or vault data integrity failure")]
    WrongPassword,
    #[error("mnemonic is wrong, or vault data integrity failure")]
    WrongMnemonicOrCorrupt,
    #[error("invalid mnemonic: {detail}")]
    InvalidMnemonic { detail: String },
    #[error("vault.toml and identity bundle disagree about vault_uuid")]
    VaultMismatch,
    #[error("vault data integrity failure: {detail}")]
    CorruptVault { detail: String },
    #[error("vault folder is not accessible: {detail}")]
    FolderInvalid { detail: String },
}
```

Six flat variants. Five mirror `FfiUnlockError` exactly in name and Display text — a deliberate parallel surface, not a coincidence; foreign-side dispatch logic on a folder-in `FfiVaultError` reads identically to dispatch on a bytes-in `FfiUnlockError`.

The sixth variant `FolderInvalid { detail }` covers the new error class B.4a introduces: the foreign caller passed a folder path that doesn't exist, isn't readable, or doesn't contain the required files (`vault.toml`, `identity.bundle.enc`, `manifest.cbor.enc`, `contacts/<owner_uuid>.card`). All four "missing required file" cases collapse into `FolderInvalid` with the file name in `detail`.

### `From<core::VaultError> for FfiVaultError`

Drift-free translation strategy. The unlock-class variants are derived through a private bridge-internal helper rather than re-translated from `core::UnlockError` directly:

```rust
// ffi/secretary-ffi-bridge/src/error.rs (sketch)

impl From<core::vault::VaultError> for FfiVaultError {
    fn from(e: core::vault::VaultError) -> Self {
        use core::vault::VaultError;
        match e {
            VaultError::Unlock(unlock_err) => {
                // Single source of unlock-class translation.
                FfiUnlockError::from(unlock_err).into()
            }
            VaultError::Io { context, source }
                if matches!(
                    source.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                ) => {
                FfiVaultError::FolderInvalid { detail: format!("{context}: {source}") }
            }
            // Manifest decode, owner-card verification, UUID mismatch, KDF-params
            // mismatch, vector-clock overflow, signature primitive failure, etc.
            // — all post-unlock integrity failures fold into the catchall.
            other => FfiVaultError::CorruptVault { detail: format!("{other}") },
        }
    }
}

// Private bridge-internal arm. Pub(crate) only; not part of the FFI surface.
impl From<FfiUnlockError> for FfiVaultError {
    fn from(e: FfiUnlockError) -> Self {
        match e {
            FfiUnlockError::WrongPassword => FfiVaultError::WrongPassword,
            FfiUnlockError::WrongMnemonicOrCorrupt => FfiVaultError::WrongMnemonicOrCorrupt,
            FfiUnlockError::InvalidMnemonic { detail } => {
                FfiVaultError::InvalidMnemonic { detail }
            }
            FfiUnlockError::VaultMismatch => FfiVaultError::VaultMismatch,
            FfiUnlockError::CorruptVault { detail } => {
                FfiVaultError::CorruptVault { detail }
            }
        }
    }
}
```

The `From<FfiUnlockError>` arm is **the** translation logic for the five mirrored variants. If a future B.x adds a 6th variant to `FfiUnlockError`, this `From` arm is the single place to extend; `From<core::VaultError>` automatically picks up the new variant via delegation.

### §13 anti-oracle preservation

`WrongPassword` continues to absorb both "your password was wrong" and "vault data integrity failure that surfaced during password decap". `WrongMnemonicOrCorrupt` does the same for the recovery path. The Display text is path-neutral on both surfaces — the foreign caller cannot distinguish the unlock-secret-wrong case from the data-corrupt case, preserving the §13 property independently per error type.

`CorruptVault { detail }` absorbs all post-unlock integrity failures — manifest decode, owner-card self-verification, manifest author-fingerprint mismatch, vault-UUID mismatch (manifest header vs body), KDF-params mismatch (vault.toml vs manifest), vector-clock overflow on a device, signature primitive failure during manifest verify. These post-unlock failures don't leak unlock-secret information (the IBK was already recovered when they fired). The catchall here is granular enough — adding individual variants would expand the error surface without giving the foreign caller actionable distinctions.

`FolderInvalid { detail }` is a pre-unlock IO error; it occurs before any cryptographic operation runs, so cannot leak unlock-secret information. Its existence as a separate variant is justified by the user-actionable distinction "your path is wrong" (fix it) vs "your data is corrupt" (more serious problem).

## Data flow — success path

```
foreign caller
    folder_path: str        (Python)  /  Data filesystem path  (Swift)  /  String / File path  (Kotlin)
    password: bytearray     (Python)  /  Data                  (Swift)  /  ByteArray          (Kotlin)
        ↓
PyO3 #[pyfunction] open_vault_with_password
    or uniffi pub fn open_vault_with_password
        ↓
    convert folder path to PathBuf
    take ownership of password Vec<u8>
        ↓
secretary-ffi-bridge::open_vault_with_password(folder, password)
        ↓
    SecretBytes::from(password)  // Vec<u8> consumed; SecretBytes is Sensitive
    core::vault::open_vault(folder, Unlocker::Password(&sb), None)
        ↓
secretary_core::vault::open_vault
        ↓
    read vault.toml              from folder/vault.toml
    read identity.bundle.enc     from folder/identity.bundle.enc
    delegate to core::unlock::open_with_password
        ↓
        recover IBK + IdentityBundle
        ↓
    read manifest.cbor.enc       from folder/manifest.cbor.enc
    decrypt manifest body under IBK (XChaCha20-Poly1305)
    parse Manifest (canonical CBOR)
    verify §8 hybrid signature on the manifest envelope
    read contacts/<owner_uuid>.card
    self-verify owner card (Ed25519 ∧ ML-DSA-65 — both must verify)
    verify manifest.author_fingerprint == owner_card.fingerprint
    verify vault.toml.kdf_params == manifest.kdf_params
        ↓
    return core::vault::OpenVault {
        identity_block_key, identity, owner_card, manifest, manifest_file
    }
        ↓
secretary-ffi-bridge::open_vault_with_password (continues)
        ↓
    split core::OpenVault:
        identity        → UnlockedIdentity::from_bundle(identity)
        identity_block_key + manifest + manifest_file + owner_card
                        → OpenVaultManifest::new(OpenVaultManifestInner { ... })
        ↓
    return OpenVaultOutput { identity, manifest }
        ↓
PyO3 / uniffi wrapper (continues)
        ↓
    zeroize input password Vec<u8>
        (Drop of Vec<u8> doesn't auto-zeroize — explicit before return)
    wrap return value in foreign-side handles
        ↓
foreign caller
    holds two opaque handles, both AutoCloseable / RAII
    holds value-typed BlockSummary list (no secret material)
```

## §13 anti-oracle constraint extended summary

| Error type | Path | §13 conflation |
|---|---|---|
| `FfiUnlockError::WrongPassword` | bytes-in unlock (B.2) | "wrong password" or "corrupt unlock data" |
| `FfiUnlockError::WrongMnemonicOrCorrupt` | bytes-in unlock (B.3a) | "wrong mnemonic" or "corrupt unlock data" |
| `FfiVaultError::WrongPassword` | folder-in unlock (B.4a) | "wrong password" or "corrupt unlock data" *(same set as bytes-in — only `vault.toml` + `identity.bundle.enc` are read before unlock)* |
| `FfiVaultError::WrongMnemonicOrCorrupt` | folder-in unlock (B.4a) | same as above for recovery path |
| `FfiVaultError::CorruptVault` | folder-in (B.4a) | absorbs **more** cases than `FfiUnlockError::CorruptVault` because folder-in does post-unlock work: manifest decrypt/parse/verify, owner-card decode/self-verify, fingerprint cross-check, KDF-params cross-check. None of these post-unlock failures leak unlock-secret information (the IBK was already recovered when they fire), so granularity here is acceptable; the catchall is chosen for surface-area economy, not for §13 reasons. |

The §13 conflation principle still holds on the unlock-class variants: the "wrong secret" vs "corrupt unlock data" distinction remains attacker-unobservable. Display text stays path-neutral on every variant.

## Test plan

### Test fixtures

**No new on-disk fixtures.** Both `golden_vault_001/` and `golden_vault_002/` already include `manifest.cbor.enc` + `contacts/<owner_uuid>.card` as a complete vault-folder layout (since A.5). B.4a uses both unchanged. New JSON pinning fields (`block_summaries` array per fixture in its `*_inputs.json`) document expected block list contents — read by the test helpers.

### Bridge crate (~9 tests in `vault.rs`)

1. `test_open_vault_with_password_success_v1` — golden_vault_001/, correct password → returns `OpenVaultOutput`; identity.display_name + user_uuid match pinned values; manifest.vault_uuid + owner_user_uuid match pinned values; `block_count() > 0`.
2. `test_open_vault_with_recovery_success_v1` — golden_vault_001/, correct mnemonic → same shape as #1; manifest contents identical regardless of unlock path.
3. `test_open_vault_with_password_wrong_password` → `FfiVaultError::WrongPassword`.
4. `test_open_vault_with_recovery_wrong_mnemonic` → `FfiVaultError::WrongMnemonicOrCorrupt`.
5. `test_open_vault_with_recovery_invalid_mnemonic` (e.g. 3 words) → `FfiVaultError::InvalidMnemonic { detail }` mentions `expected 24 words, got 3`.
6. `test_open_vault_folder_does_not_exist` → `FfiVaultError::FolderInvalid { detail }` mentions the path.
7. `test_open_vault_folder_missing_identity_bundle` (folder exists, vault.toml exists, identity.bundle.enc deleted) → `FfiVaultError::FolderInvalid { detail }` mentions `identity.bundle.enc`.
8. `test_block_summaries_returns_pinned_layout_v1` — golden_vault_001/, asserts each `BlockSummary` field against `*_inputs.json` pin.
9. `test_open_vault_manifest_wipe_returns_empty_defaults` — call `wipe()`; subsequent accessors return empty `Vec<u8>`, `0` for `block_count`, empty `Vec<BlockSummary>`.

### pytest (~7 tests)

1. `test_open_vault_with_password_success` — bytes input; identity + manifest both populated; manifest.block_count() > 0.
2. `test_open_vault_with_recovery_success` — same as #1 via recovery path.
3. `test_open_vault_with_password_wrong_password_raises` → `WrongPassword` exception.
4. `test_open_vault_with_recovery_invalid_mnemonic_raises` → `InvalidMnemonic` exception with detail.
5. `test_open_vault_folder_does_not_exist_raises` → `FolderInvalid` exception with path in detail.
6. `test_block_summaries_round_trip` — assert every BlockSummary field shape against pinned JSON.
7. `test_with_block_double_close` — `with open_vault_with_password(...) as out: with out.identity as i: with out.manifest as m: ...` — assert RAII nesting works; both handles wipe on exit.

`bytearray` caller-zeroize parity test for the password input — same shape as B.2's coverage. New test helper `_golden_vault_block_summaries(n)` reads the pinned-in-JSON expected list.

### Swift smoke (~3 asserts in `tests/swift/main.swift`)

1. `open_vault_with_password` success → identity.displayName match + manifest.blockCount > 0.
2. `open_vault_with_password` wrong password → `FfiVaultError.wrongPassword` enum case.
3. `manifest.blockSummaries()` first entry's `blockName` matches pinned value.

### Kotlin smoke (~3 asserts in `tests/kotlin/Main.kt`)

Same three asserts in JVM idiom. Per B.3b's experience, watch for uniffi codegen renames on `Vec<[u8; 16]>` field shape (`sequence<bytes>?` → element-wise conversion in Kotlin).

### Cumulative test count after B.4a

| Layer | Before | After (target) |
|---|---|---|
| Cargo workspace | 498 + 9 ignored | ~509 + 9 ignored |
| pytest | 22 | ~29 |
| Swift smoke | 15 PASS | ~18 PASS |
| Kotlin smoke | 16 PASS lines | ~19 PASS lines |
| Bridge crate unit tests | 36 | ~45 |
| uniffi crate unit tests | 11 | ~13 (new mapping tests for FfiVaultError variants + BlockSummary projection) |

## B.3b vs B.4a boundary

| Concern | B.3b (`create_vault`) | B.4a (`open_vault_with_*`) |
|---|---|---|
| IO model | Bytes-in (caller persists output to disk) | **Folder-in** (Rust core reads from disk) |
| Direction | Output (returns vault.toml + identity.bundle bytes) | Input (returns parsed manifest + identity handle) |
| Sensitive-output marshalling | `MnemonicOutput` one-shot opaque handle | `OpenVaultManifest` opaque handle (long-lived, RAII-closed) |
| Error type | `FfiUnlockError` (5-variant unchanged) | `FfiVaultError` (NEW 6-variant flat enum) |
| RNG / KDF knobs at FFI | None (bridge instantiates `OsRng` + `V1_DEFAULT`) | None (no construction here; just open) |
| New `pub fn` count on bridge | +1 | +2 |
| New types on bridge | `CreateVaultOutput`, `MnemonicOutput` | `OpenVaultOutput`, `OpenVaultManifest`, `BlockSummary`, `FfiVaultError` |

## B.4a vs B.4b/c/d boundary

B.4a establishes:

- **Folder-IO ownership at the FFI** — Rust core owns reads (and will own atomic writes from B.4c). Foreign caller hands over a path string.
- **`OpenVaultManifest` opaque handle** — holds IBK + manifest + manifest_file + owner_card internally. B.4b extends with `read_block(block_uuid)` accessor; B.4c extends with `save_block(...)` mutation; B.4d extends with `share_block(...)` mutation. The handle's existence and the field set are the API foundation B.4b/c/d inherit.
- **`FfiVaultError` 6-variant catchall shape** — B.4b/c/d may add new variants (e.g. `BlockNotFound { uuid }` for B.4b) but the 5 unlock-class mirrored variants and the `FolderInvalid { detail }` variant carry forward unchanged.
- **`BlockSummary` value type** — read-only metadata projection. B.4b's `read_block` will return decrypted `Record` types; B.4c's `save_block` consumes them; the BlockSummary list is what the foreign caller iterates to find a `block_uuid` to operate on.

B.4a does **not** establish:

- Mutability semantics on `OpenVaultManifest` — B.4c's design conversation. The current `Mutex<Option<Inner>>` shape allows in-place mutation if `&mut self` accessors are added; whether to keep that shape or transition to a writer-borrow model is open.
- Record types crossing the FFI — B.4b. The `Record` / `RecordField` / `RecordFieldValue` types now wrap `SecretString` / `SecretBytes` (per PR #16), so zeroize-on-drop is structurally guaranteed; the type-design conversation is "how do they project to Python `dataclass` / Swift `struct` / Kotlin `data class` while preserving zeroize-discipline cross-language?".
- Contact card surface — B.4d. `ContactCard` has its own accessor design (public-key accessors, fingerprint, dual signature material) deferred until sharing operations need them.

## Rollout

1. Write implementation plan ([writing-plans skill](https://github.com/anthropics/superpowers/tree/main/skills/writing-plans)).
2. Execute via `superpowers:subagent-driven-development` — task-by-task with two-stage review (spec compliance → code quality), same rhythm as B.2 / B.3a / B.3b.
3. Open PR against `main`; squash-merge after final cross-cutting review.
4. Update `NEXT_SESSION.md` post-merge with the squash-SHA recording commit (matching the established pattern).

## References

- [B.3b spec](2026-05-05-ffi-b3b-create-vault-design.md) — last shipped sub-project; folder-IO transition rationale rooted here.
- [B.3a spec](2026-05-04-ffi-b3a-recovery-unlock-design.md) — `FfiUnlockError` 5-variant cardinality; `WrongMnemonicOrCorrupt` / `InvalidMnemonic` introduced.
- [B.2 spec](2026-05-04-ffi-b2-vault-unlock-design.md) — bridge crate established; `UnlockedIdentity` opaque handle established.
- `core/src/vault/orchestrators.rs::open_vault` — the wrapped function.
- `core/src/vault/manifest.rs::Manifest` and `BlockEntry` — the source-of-truth shapes for the projection.
- `docs/vault-format.md` §4 — manifest format normative spec.
- `docs/threat-model.md` §13 — anti-oracle constraint normative description.
