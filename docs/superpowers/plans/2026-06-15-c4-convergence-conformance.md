# C.4 Cross-Device Convergence Conformance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove, end-to-end, that two real device identities editing one user's vault and reconciling through a shared folder converge to the same logical state — independent of sync order — exercising the real `save_block` → `sync_once` → `prepare_merge` → `commit_with_decisions` orchestration.

**Architecture:** A new integration test (`core/tests/convergence.rs`) driven by a reusable harness (`core/tests/convergence_helpers/`). Each device edits a private working-copy of a shared baseline via real `save_block`; a cloud-sync emulation copies one device's files in as **canonical** and the other's in as **conflict-copy siblings** (the exact filenames `ingest_conflict_copies` scans). The conflict-copy holder syncs first (the **merger**: `sync_once`→`prepare_merge`→`commit_with_decisions`); the canonical holder syncs second (the **adopter**: `AppliedAutomatically`). Convergence is asserted on **decrypted logical state** (records + clocks), never on ciphertext bytes (fresh random nonces + randomized ML-DSA make bytes differ by construction). Convergence is self-checking — the two devices and the two orderings check each other — so no frozen golden vector and no deterministic keys are needed.

**Tech Stack:** Rust (stable), `secretary-core` public API (`vault::{create_vault-equivalent fast path, save_block, open_vault, Unlocker}`, `sync::{sync_once, prepare_merge, commit_with_decisions, SyncState, SyncOutcome, VetoDecision}`), `unlock::{create_vault_unchecked, open_with_password}`, `tempfile`, `rand_chacha`. Tests run under `cargo test --release`.

---

## Design references (read before starting)

- Spec: `docs/superpowers/specs/2026-06-15-c4-convergence-conformance-design.md`
- The merge/veto call sequence template: `core/tests/sync_merge_vetoes.rs` (especially `make_veto_fixture` + `commit_with_decisions_keep_local_overrides_peer_tombstone`).
- The fast-vault creation template: `core/tests/save_block.rs::make_fast_vault` and `core/tests/open_vault.rs` (mirror, do not reinvent).
- Conflict-copy filename rules: `core/src/sync/ingest.rs` (`enumerate_manifest_siblings` matches any name `starts_with("manifest.cbor.enc")` and `!= "manifest.cbor.enc"`; `enumerate_block_siblings` matches `starts_with("<uuid-hyphenated>.cbor.enc")` and `!=` it).
- Reuse surface in `core/tests/sync_helpers/mod.rs`: `decrypt_block_using_open(open, bytes) -> Result<BlockPlaintext, VaultError>`, `block_file_path(folder, &block_uuid) -> PathBuf`.

## Key API facts (verified — copy these exactly)

```rust
// fast vault (8 KiB Argon2id) — NOT the floor-enforcing public create_vault
fn fast_kdf() -> Argon2idParams { Argon2idParams::new(8, 1, 1) }
// create_vault_unchecked(&SecretBytes, display_name: &str, created_at_ms: u64, Argon2idParams, &mut rng)
//   -> CreatedVault { vault_toml_bytes, identity_bundle_bytes, identity, identity_block_key }

save_block(folder: &Path, open: &mut OpenVault, plaintext: BlockPlaintext,
           recipients: &[ContactCard], device_uuid: [u8; 16], now_ms: u64,
           rng: &mut (impl RngCore + CryptoRng)) -> Result<(), VaultError>

open_vault(folder: &Path, unlocker: Unlocker, local_highest_clock: Option<&[VectorClockEntry]>)
    -> Result<OpenVault, VaultError>
// OpenVault { identity_block_key, identity, owner_card: ContactCard, manifest: Manifest, manifest_file }
// Manifest { vector_clock: Vec<VectorClockEntry>, blocks: Vec<BlockEntry>, ... }
// Unlocker::Password(&SecretBytes)

open_with_password(vault_toml_bytes: &[u8], identity_bundle_bytes: &[u8], &SecretBytes)
    -> Result<UnlockedIdentity, UnlockError>   // needed by sync_once / prepare_merge

sync_once(folder: &Path, &UnlockedIdentity, &SyncState, now_ms: u64) -> Result<SyncOutcome, SyncError>
// SyncOutcome::{ NothingToDo, AppliedAutomatically { new_state }, ConcurrentDetected { bundle, plan, .. }, RollbackRejected(..) }

prepare_merge(folder: &Path, &UnlockedIdentity, &VaultBundle, &DiffPlan) -> Result<DraftMerge, SyncError>
// DraftMerge { vetoes: Vec<RecordTombstoneVeto>, .. }
// RecordTombstoneVeto { record_id: [u8;16], block_id: [u8;16], local_state: Record, disk_tombstone_at_ms: u64, disk_tombstoner_device: [u8;16] }

commit_with_decisions(folder: &Path, password: &SecretBytes, draft: DraftMerge,
                      decisions: Vec<VetoDecision>, now_ms: u64) -> Result<SyncState, SyncError>
// VetoDecision::{ KeepLocal { record_id: [u8;16] }, AcceptTombstone { record_id: [u8;16] } }

SyncState::empty(vault_uuid: [u8;16]) -> SyncState
SyncState::new(vault_uuid: [u8;16], clock: Vec<VectorClockEntry>) -> Result<SyncState, _>
// SyncState { vault_uuid: [u8;16], highest_vector_clock_seen: Vec<VectorClockEntry> }

// Record { record_uuid: [u8;16], record_type: String, fields: BTreeMap<String, RecordField>,
//          tags: Vec<String>, created_at_ms: u64, last_mod_ms: u64,
//          tombstone: bool, tombstoned_at_ms: u64, unknown: BTreeMap<String, UnknownValue> }
// RecordField { value: RecordFieldValue, last_mod: u64, device_uuid: [u8;16], unknown: BTreeMap<..> }
// RecordFieldValue::Text(SecretString)  // SecretString::from("..")
// BlockPlaintext { block_version: u32(=1), block_uuid: [u8;16], block_name: String,
//                  schema_version: u32(=1), records: Vec<Record>, unknown: BTreeMap<..> }
```

## Convergence mechanics (the model every scenario follows)

Baseline `create_vault` is **empty** (`vector_clock: Vec::new()`, `blocks: Vec::new()`). For scenarios where both devices edit the *same* record, the baseline is seeded with one record X (one `save_block` by a baseline "device 0").

Per scenario:
1. Deep-copy the baseline folder into `work_a/` and `work_b/`.
2. Device A edits `work_a` via `save_block(device_uuid = A_UUID, now_ms = t_a)`; device B edits `work_b` via `save_block(device_uuid = B_UUID, now_ms = t_b)`. (Scenario 1: only A edits.)
3. **Reconcile** into a fresh shared folder `S`: deep-copy the *canonical* device's folder into `S`, then (if the other device also edited) copy the *other* device's `manifest.cbor.enc` and its block file into `S` under conflict-copy sibling names.
4. **Merger** = the conflict-copy device. Its `SyncState.highest_vector_clock_seen` = its own post-edit manifest clock (concurrent with canonical). `sync_once` → `ConcurrentDetected` → `prepare_merge` → `commit_with_decisions(veto policy)`. Now `S`'s canonical manifest is the merged LUB.
5. **Adopter** = the canonical device. Its `SyncState` = its own post-edit clock (== pre-merge canonical clock). `sync_once` → `AppliedAutomatically` (merged LUB dominates).
6. Assert the convergence contract (Task 5's `assert_converged`).

**Order-independence** (scenarios 2–4): run the whole thing twice into two independent `S` folders — once with A canonical / B merger, once with B canonical / A merger — and assert both decrypt to the same logical state.

---

## File structure

```
core/tests/convergence.rs                       — the 4 scenario tests + order-independence (target < 400 LOC)
core/tests/convergence_helpers/mod.rs           — module wiring + shared consts/types (Device, Baseline, LogicalRecord)
core/tests/convergence_helpers/baseline.rs      — fast on-disk vault + seed record (mirror save_block.rs::make_fast_vault)
core/tests/convergence_helpers/device.rs        — Device handle: working-copy, edit (save_block), manifest_clock
core/tests/convergence_helpers/reconcile.rs     — cloud-sync emulation (canonical + conflict-copy sibling layout)
core/tests/convergence_helpers/sync_drive.rs    — merger/adopter sync drivers (sync_once→prepare→commit)
core/tests/convergence_helpers/assert.rs        — decrypt_state + assert_converged + quiescence
```

Each `tests/*.rs` is its own binary; `convergence.rs` declares `mod convergence_helpers;` and `mod sync_helpers;` (the latter for `decrypt_block_using_open` / `block_file_path`, referenced inside the helpers as `crate::sync_helpers::…`). Keep every helper file under 500 lines; if `device.rs`/`reconcile.rs` approach it, that's already the finest split — flag in review rather than over-splitting.

---

## Task 1: Baseline builder + harness scaffolding

**Files:**
- Create: `core/tests/convergence_helpers/mod.rs`
- Create: `core/tests/convergence_helpers/baseline.rs`
- Create: `core/tests/convergence.rs`

- [ ] **Step 1: Write the failing test**

Create `core/tests/convergence.rs`:

```rust
//! C.4 — cross-device convergence conformance. Two real device
//! identities edit one user's vault and reconcile through a shared
//! folder; the harness proves they converge to the same logical state
//! independent of sync order. See
//! docs/superpowers/specs/2026-06-15-c4-convergence-conformance-design.md.
#![forbid(unsafe_code)]

mod convergence_helpers;
mod sync_helpers;

use convergence_helpers::Baseline;

#[test]
fn baseline_creates_an_empty_openable_vault() {
    let baseline = Baseline::create();
    // A freshly created vault has no blocks and an empty manifest clock.
    let manifest = baseline.open_manifest();
    assert!(manifest.blocks.is_empty(), "fresh baseline must have no blocks");
    assert!(
        manifest.vector_clock.is_empty(),
        "fresh baseline must have an empty manifest vector clock",
    );
}
```

Create `core/tests/convergence_helpers/mod.rs`:

```rust
//! Reusable two-device convergence harness. See `convergence.rs`.
#![allow(dead_code)] // helpers land task-by-task; some are unused until later tasks

mod baseline;

pub use baseline::Baseline;
```

Create `core/tests/convergence_helpers/baseline.rs` with the `Baseline` type but a deliberately empty `create()` body so the test fails to compile/derive first:

```rust
use std::path::{Path, PathBuf};

use secretary_core::crypto::secret::SecretBytes;
use secretary_core::vault::Manifest;

/// A freshly created fast-KDF vault on disk, shared by all the devices
/// in one scenario. Owns the `TempDir` so the folder outlives the test.
pub struct Baseline {
    _tmp: tempfile::TempDir,
    folder: PathBuf,
    password: SecretBytes,
}

impl Baseline {
    pub fn create() -> Self {
        unimplemented!("Task 1 Step 3")
    }

    pub fn folder(&self) -> &Path {
        &self.folder
    }

    pub fn password(&self) -> &SecretBytes {
        &self.password
    }

    pub fn open_manifest(&self) -> Manifest {
        unimplemented!("Task 1 Step 3")
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --release --workspace --test convergence baseline_creates -- --nocapture`
Expected: FAIL — panics at `unimplemented!("Task 1 Step 3")`.

- [ ] **Step 3: Implement the baseline (mirror `save_block.rs::make_fast_vault`)**

Replace the `unimplemented!()` bodies. Port the proven fast-vault construction from `core/tests/save_block.rs::make_fast_vault` (create vault.toml + identity.bundle.enc + contacts/ + the empty signed manifest on disk). Use a fixed password and `Argon2idParams::new(8, 1, 1)`. Implement `open_manifest` via `open_vault`:

```rust
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use rand_core::RngCore;
use secretary_core::crypto::kdf::Argon2idParams;
use secretary_core::crypto::sig::{MlDsa65Secret, ED25519_SIG_LEN, ML_DSA_65_SIG_LEN};
use secretary_core::identity::card::{ContactCard, CARD_VERSION_V1};
use secretary_core::identity::fingerprint::fingerprint;
use secretary_core::unlock::{create_vault_unchecked, vault_toml};
use secretary_core::vault::orchestrators::format_uuid_hyphenated;
use secretary_core::vault::{
    encode_manifest_file, open_vault, sign_manifest, KdfParamsRef, ManifestHeader, Unlocker,
};
use secretary_core::version::{FORMAT_VERSION, SUITE_ID};
use std::collections::BTreeMap;
use std::fs;

pub const BASELINE_PASSWORD: &[u8] = b"c4-convergence-test-password";
pub const BASELINE_CREATED_AT_MS: u64 = 1_714_060_800_000;
const BASELINE_SEED: u8 = 0xC4;

impl Baseline {
    pub fn create() -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let folder = tmp.path().to_path_buf();
        let mut rng = ChaCha20Rng::from_seed([BASELINE_SEED; 32]);
        let password = SecretBytes::new(BASELINE_PASSWORD.to_vec());

        let created = create_vault_unchecked(
            &password,
            "C4 Convergence",
            BASELINE_CREATED_AT_MS,
            Argon2idParams::new(8, 1, 1),
            &mut rng,
        )
        .expect("create_vault_unchecked");

        let vt = vault_toml::decode(std::str::from_utf8(&created.vault_toml_bytes).unwrap())
            .expect("decode vault.toml");
        let pq_sk = MlDsa65Secret::from_bytes(created.identity.ml_dsa_65_sk.expose()).unwrap();

        let mut card = ContactCard {
            card_version: CARD_VERSION_V1,
            contact_uuid: created.identity.user_uuid,
            display_name: created.identity.display_name.clone(),
            x25519_pk: created.identity.x25519_pk,
            ml_kem_768_pk: created.identity.ml_kem_768_pk.clone(),
            ed25519_pk: created.identity.ed25519_pk,
            ml_dsa_65_pk: created.identity.ml_dsa_65_pk.clone(),
            created_at_ms: created.identity.created_at_ms,
            self_sig_ed: [0u8; ED25519_SIG_LEN],
            self_sig_pq: vec![0u8; ML_DSA_65_SIG_LEN],
        };
        card.sign(&created.identity.ed25519_sk, &pq_sk).unwrap();
        let owner_card_bytes = card.to_canonical_cbor().unwrap();
        let author_fp = fingerprint(&owner_card_bytes);

        let manifest_body = Manifest {
            manifest_version: 1,
            vault_uuid: vt.vault_uuid,
            format_version: FORMAT_VERSION,
            suite_id: SUITE_ID,
            owner_user_uuid: created.identity.user_uuid,
            vector_clock: Vec::new(),
            blocks: Vec::new(),
            trash: Vec::new(),
            kdf_params: KdfParamsRef {
                memory_kib: vt.kdf.memory_kib,
                iterations: vt.kdf.iterations,
                parallelism: vt.kdf.parallelism,
                salt: vt.kdf.salt,
            },
            unknown: BTreeMap::new(),
        };
        let header = ManifestHeader {
            vault_uuid: vt.vault_uuid,
            created_at_ms: BASELINE_CREATED_AT_MS,
            last_mod_ms: BASELINE_CREATED_AT_MS,
        };
        let mut nonce = [0u8; 24];
        rng.fill_bytes(&mut nonce);
        let mf = sign_manifest(
            header,
            &manifest_body,
            &created.identity_block_key,
            &nonce,
            author_fp,
            &created.identity.ed25519_sk,
            &pq_sk,
        )
        .unwrap();
        let mf_bytes = encode_manifest_file(&mf).unwrap();

        let owner_uuid_hex = format_uuid_hyphenated(&created.identity.user_uuid);
        fs::create_dir_all(folder.join("contacts")).unwrap();
        fs::write(folder.join("vault.toml"), &created.vault_toml_bytes).unwrap();
        fs::write(folder.join("identity.bundle.enc"), &created.identity_bundle_bytes).unwrap();
        fs::write(folder.join("manifest.cbor.enc"), &mf_bytes).unwrap();
        fs::write(
            folder.join("contacts").join(format!("{owner_uuid_hex}.card.cbor")),
            &owner_card_bytes,
        )
        .unwrap();

        Self { _tmp: tmp, folder, password }
    }

    pub fn open_manifest(&self) -> Manifest {
        let open = open_vault(&self.folder, Unlocker::Password(&self.password), None)
            .expect("open baseline");
        open.manifest
    }
}
```

> NOTE: If `format_uuid_hyphenated` is not re-exported at `secretary_core::vault::orchestrators::format_uuid_hyphenated`, copy the exact `use` path used by `core/tests/save_block.rs` (grep it). Match the contacts-file naming (`{owner_uuid_hex}.card.cbor`) to what `save_block.rs::make_fast_vault` writes; if it differs, mirror `save_block.rs` exactly — it is the known-good reference.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --release --workspace --test convergence baseline_creates -- --nocapture`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add core/tests/convergence.rs core/tests/convergence_helpers/
git commit -m "test(c4): convergence harness baseline (fast on-disk vault)"
```

---

## Task 2: Device handle — working-copy + real edit

**Files:**
- Create: `core/tests/convergence_helpers/device.rs`
- Modify: `core/tests/convergence_helpers/mod.rs` (add `mod device; pub use device::Device;`)
- Modify: `core/tests/convergence.rs` (add the test below)

A `Device` owns a deep copy of the baseline folder, a distinct `device_uuid`, and the shared password. `edit_record(...)` runs a real `save_block`.

- [ ] **Step 1: Write the failing test**

Add to `core/tests/convergence.rs`:

```rust
use convergence_helpers::Device;

const A_UUID: [u8; 16] = [0x0A; 16];
const X_RECORD: [u8; 16] = [0xAA; 16];
const X_BLOCK: [u8; 16] = [0xBB; 16];

#[test]
fn device_edit_writes_a_record_with_its_device_clock() {
    let baseline = Baseline::create();
    let mut a = Device::fork(&baseline, A_UUID, /*seed*/ 0xA0);
    a.edit_text_field(X_BLOCK, X_RECORD, "k", "alice", /*now_ms*/ 100);

    // The device's own working copy now holds the record, and the
    // manifest clock ticked exactly this device.
    let records = a.decrypt_block_records(X_BLOCK);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].record_uuid, X_RECORD);
    assert!(!records[0].tombstone);

    let clock = a.manifest_clock();
    assert!(
        clock.iter().any(|e| e.device_uuid == A_UUID && e.counter >= 1),
        "device A's edit must tick its own vector-clock entry",
    );
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --release --workspace --test convergence device_edit -- --nocapture`
Expected: FAIL — `Device` unresolved.

- [ ] **Step 3: Implement `Device`**

Create `core/tests/convergence_helpers/device.rs`:

```rust
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use secretary_core::crypto::secret::{SecretBytes, SecretString};
use secretary_core::vault::block::VectorClockEntry;
use secretary_core::vault::{
    open_vault, save_block, BlockPlaintext, Record, RecordField, RecordFieldValue, Unlocker,
};

use crate::convergence_helpers::Baseline;

/// One device's private replica of the shared vault. Owns a deep copy
/// of the baseline folder + a distinct device_uuid + a deterministic
/// RNG seed (the AEAD/signature randomness source for this device's
/// writes — distinct per device so two devices never share nonces).
pub struct Device {
    _tmp: tempfile::TempDir,
    folder: PathBuf,
    device_uuid: [u8; 16],
    password: SecretBytes,
    rng: ChaCha20Rng,
}

impl Device {
    /// Fork a private working copy of the baseline for this device.
    pub fn fork(baseline: &Baseline, device_uuid: [u8; 16], rng_seed: u8) -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let folder = tmp.path().to_path_buf();
        copy_dir_all(baseline.folder(), &folder).expect("deep-copy baseline");
        Self {
            _tmp: tmp,
            folder,
            device_uuid,
            password: SecretBytes::new(crate::convergence_helpers::baseline_password_bytes()),
            rng: ChaCha20Rng::from_seed([rng_seed; 32]),
        }
    }

    pub fn folder(&self) -> &Path {
        &self.folder
    }

    pub fn device_uuid(&self) -> [u8; 16] {
        self.device_uuid
    }

    /// Insert-or-update record `record_uuid` in block `block_uuid` with a
    /// single text field `(field_name -> value)`, via a real `save_block`.
    pub fn edit_text_field(
        &mut self,
        block_uuid: [u8; 16],
        record_uuid: [u8; 16],
        field_name: &str,
        value: &str,
        now_ms: u64,
    ) {
        let record = self.build_record_with_field(block_uuid, record_uuid, field_name, value, now_ms, false);
        self.save_records(block_uuid, vec![record], now_ms);
    }

    /// Tombstone record `record_uuid` in block `block_uuid` (delete), via
    /// a real `save_block`. `tombstoned_at_ms == last_mod_ms == now_ms`
    /// (well-formedness invariant).
    pub fn tombstone(&mut self, block_uuid: [u8; 16], record_uuid: [u8; 16], now_ms: u64) {
        let mut record =
            self.build_record_with_field(block_uuid, record_uuid, "k", "deleted", now_ms, true);
        record.tombstone = true;
        record.tombstoned_at_ms = now_ms;
        record.last_mod_ms = now_ms;
        self.save_records(block_uuid, vec![record], now_ms);
    }

    fn build_record_with_field(
        &self,
        _block_uuid: [u8; 16],
        record_uuid: [u8; 16],
        field_name: &str,
        value: &str,
        now_ms: u64,
        tombstone: bool,
    ) -> Record {
        let mut fields = BTreeMap::new();
        fields.insert(
            field_name.to_string(),
            RecordField {
                value: RecordFieldValue::Text(SecretString::from(value)),
                last_mod: now_ms,
                device_uuid: self.device_uuid,
                unknown: BTreeMap::new(),
            },
        );
        Record {
            record_uuid,
            record_type: "kv".to_string(),
            fields,
            tags: Vec::new(),
            created_at_ms: now_ms,
            last_mod_ms: now_ms,
            tombstone,
            tombstoned_at_ms: if tombstone { now_ms } else { 0 },
            unknown: BTreeMap::new(),
        }
    }

    fn save_records(&mut self, block_uuid: [u8; 16], records: Vec<Record>, now_ms: u64) {
        let mut open = open_vault(&self.folder, Unlocker::Password(&self.password), None)
            .expect("open working copy");
        let owner_card = open.owner_card.clone();
        let plaintext = BlockPlaintext {
            block_version: 1,
            block_uuid,
            block_name: "c4".to_string(),
            schema_version: 1,
            records,
            unknown: BTreeMap::new(),
        };
        save_block(
            &self.folder,
            &mut open,
            plaintext,
            &[owner_card],
            self.device_uuid,
            now_ms,
            &mut self.rng,
        )
        .expect("save_block");
    }

    /// Current manifest vector clock of this device's working copy.
    pub fn manifest_clock(&self) -> Vec<VectorClockEntry> {
        let open = open_vault(&self.folder, Unlocker::Password(&self.password), None)
            .expect("open working copy");
        open.manifest.vector_clock
    }

    /// Decrypt the named block in this device's working copy → its records.
    pub fn decrypt_block_records(&self, block_uuid: [u8; 16]) -> Vec<Record> {
        crate::convergence_helpers::decrypt_block_records(&self.folder, &self.password, block_uuid)
    }
}

/// Recursive directory copy (the cloud-sync layer copies bytes, not
/// re-encrypts). Mirrors a baseline folder into a device working copy.
pub fn copy_dir_all(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let to = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &to)?;
        } else {
            std::fs::copy(entry.path(), &to)?;
        }
    }
    Ok(())
}
```

Add to `core/tests/convergence_helpers/mod.rs`:

```rust
mod device;
pub use device::{copy_dir_all, Device};

use secretary_core::crypto::secret::SecretBytes;
use secretary_core::vault::{open_vault, Record, Unlocker};
use std::path::Path;

/// The shared baseline password as raw bytes (every device opens the
/// same vault).
pub fn baseline_password_bytes() -> Vec<u8> {
    baseline::BASELINE_PASSWORD.to_vec()
}

/// Decrypt one block file in `folder` and return its records. Reuses the
/// proven `sync_helpers::decrypt_block_using_open` (the convergence test
/// binary also declares `mod sync_helpers;`).
pub fn decrypt_block_records(folder: &Path, password: &SecretBytes, block_uuid: [u8; 16]) -> Vec<Record> {
    let open = open_vault(folder, Unlocker::Password(password), None).expect("open for decrypt");
    let path = crate::sync_helpers::block_file_path(folder, &block_uuid);
    let bytes = std::fs::read(&path).expect("read block file");
    crate::sync_helpers::decrypt_block_using_open(&open, &bytes)
        .expect("decrypt block")
        .records
}
```

Make `BASELINE_PASSWORD` visible to the module: in `baseline.rs` it is already `pub const`; ensure `mod.rs` can reach it via `baseline::BASELINE_PASSWORD` (declare `mod baseline;` before the `pub use`).

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test --release --workspace --test convergence device_edit -- --nocapture`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add core/tests/convergence.rs core/tests/convergence_helpers/
git commit -m "test(c4): Device handle — working-copy fork + real save_block edit"
```

---

## Task 3: Reconcile — cloud-sync conflict-copy layout

**Files:**
- Create: `core/tests/convergence_helpers/reconcile.rs`
- Modify: `core/tests/convergence_helpers/mod.rs` (`mod reconcile; pub use reconcile::{reconcile, SharedFolder};`)
- Modify: `core/tests/convergence.rs` (add the test below)

`reconcile` builds the shared folder `S`: deep-copy the canonical device's folder, then (if a merger device is supplied) copy the merger's manifest + block file in under conflict-copy sibling names recognized by `ingest`.

- [ ] **Step 1: Write the failing test**

Add to `core/tests/convergence.rs`:

```rust
use convergence_helpers::reconcile;

const B_UUID: [u8; 16] = [0x0B; 16];

#[test]
fn reconcile_lays_out_canonical_plus_conflict_copy() {
    let baseline = Baseline::create();
    let mut a = Device::fork(&baseline, A_UUID, 0xA0);
    let mut b = Device::fork(&baseline, B_UUID, 0xB0);
    a.edit_text_field(X_BLOCK, X_RECORD, "f1", "alice", 100);
    b.edit_text_field(X_BLOCK, X_RECORD, "f2", "bob", 100);

    // A canonical, B merger (B's files become conflict-copies in S).
    let shared = reconcile(&a, Some((&b, B_UUID)), X_BLOCK);

    // Canonical manifest + block present; exactly one manifest sibling
    // and one block sibling (B's conflict copies).
    let s = shared.folder();
    assert!(s.join("manifest.cbor.enc").exists());
    let manifest_siblings: Vec<_> = std::fs::read_dir(s)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("manifest.cbor.enc") && n != "manifest.cbor.enc")
        .collect();
    assert_eq!(manifest_siblings.len(), 1, "expected exactly one manifest conflict-copy");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --release --workspace --test convergence reconcile_lays_out -- --nocapture`
Expected: FAIL — `reconcile` unresolved.

- [ ] **Step 3: Implement `reconcile`**

Create `core/tests/convergence_helpers/reconcile.rs`:

```rust
use std::path::{Path, PathBuf};

use crate::convergence_helpers::{copy_dir_all, Device};

/// The reconciled shared folder both devices sync against. Owns its
/// `TempDir`.
pub struct SharedFolder {
    _tmp: tempfile::TempDir,
    folder: PathBuf,
}

impl SharedFolder {
    pub fn folder(&self) -> &Path {
        &self.folder
    }
}

/// Emulate a cloud-sync reconcile of two concurrent device writes into a
/// single shared folder.
///
/// - `canonical`: the device whose files become the canonical
///   `manifest.cbor.enc` / `blocks/<uuid>.cbor.enc`.
/// - `merger`: `Some((device, uuid))` whose `manifest.cbor.enc` and
///   `blocks/<uuid>.cbor.enc` are copied in as conflict-copy siblings
///   (the filenames `ingest_conflict_copies` scans); `None` for the
///   one-editor (auto-apply) scenario.
/// - `block_uuid`: the block both devices touched.
pub fn reconcile(
    canonical: &Device,
    merger: Option<(&Device, [u8; 16])>,
    block_uuid: [u8; 16],
) -> SharedFolder {
    let tmp = tempfile::tempdir().expect("tempdir");
    let folder = tmp.path().to_path_buf();
    copy_dir_all(canonical.folder(), &folder).expect("copy canonical into shared");

    if let Some((merger_dev, merger_uuid)) = merger {
        let suffix = format!(".sync-conflict-from-device-{:02x}", merger_uuid[0]);

        // Manifest conflict-copy.
        let merger_manifest = merger_dev.folder().join("manifest.cbor.enc");
        let manifest_sibling = folder.join(format!("manifest.cbor.enc{suffix}"));
        std::fs::copy(&merger_manifest, &manifest_sibling).expect("copy manifest sibling");

        // Block conflict-copy (only if the merger actually wrote the block).
        let merger_block = crate::sync_helpers::block_file_path(merger_dev.folder(), &block_uuid);
        if merger_block.exists() {
            let canonical_block = crate::sync_helpers::block_file_path(&folder, &block_uuid);
            let block_sibling_name =
                format!("{}{suffix}", canonical_block.file_name().unwrap().to_string_lossy());
            let block_sibling = canonical_block.with_file_name(block_sibling_name);
            std::fs::copy(&merger_block, &block_sibling).expect("copy block sibling");
        }
    }

    SharedFolder { _tmp: tmp, folder }
}
```

Add to `mod.rs`: `mod reconcile; pub use reconcile::{reconcile, SharedFolder};`

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test --release --workspace --test convergence reconcile_lays_out -- --nocapture`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add core/tests/convergence.rs core/tests/convergence_helpers/
git commit -m "test(c4): cloud-sync reconcile — canonical + conflict-copy sibling layout"
```

---

## Task 4: Sync drivers — merger (merge/commit) + adopter (auto-apply)

**Files:**
- Create: `core/tests/convergence_helpers/sync_drive.rs`
- Modify: `core/tests/convergence_helpers/mod.rs`
- Modify: `core/tests/convergence.rs`

Two drivers + a veto policy. The merger runs `sync_once`→`prepare_merge`→`commit_with_decisions`; the adopter runs `sync_once` expecting `AppliedAutomatically`. The harness needs an `UnlockedIdentity` (via `open_with_password`) for `sync_once`/`prepare_merge`.

- [ ] **Step 1: Write the failing test** (uses Scenario-2-shaped setup, proves both drivers end at `NothingToDo`)

Add to `core/tests/convergence.rs`:

```rust
use convergence_helpers::{sync_as_adopter, sync_as_merger, VetoPolicy};

#[test]
fn merger_then_adopter_both_quiesce_on_disjoint_fields() {
    let baseline = Baseline::create();
    let mut a = Device::fork(&baseline, A_UUID, 0xA0);
    let mut b = Device::fork(&baseline, B_UUID, 0xB0);
    a.edit_text_field(X_BLOCK, X_RECORD, "f1", "alice", 100);
    b.edit_text_field(X_BLOCK, X_RECORD, "f2", "bob", 100);

    // A canonical / B merger.
    let shared = reconcile(&a, Some((&b, B_UUID)), X_BLOCK);

    // B merges (disjoint fields → no veto needed).
    let b_state = sync_as_merger(&baseline, shared.folder(), &b, VetoPolicy::NoVetoExpected, 1_000);
    // A adopts the merged LUB.
    let a_state = sync_as_adopter(&baseline, shared.folder(), &a, 1_001);

    // Quiescence: re-running sync on each device's final state is a no-op.
    assert!(convergence_helpers::is_nothing_to_do(&baseline, shared.folder(), &b_state, 1_002));
    assert!(convergence_helpers::is_nothing_to_do(&baseline, shared.folder(), &a_state, 1_003));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --release --workspace --test convergence merger_then_adopter -- --nocapture`
Expected: FAIL — unresolved names.

- [ ] **Step 3: Implement the drivers**

Create `core/tests/convergence_helpers/sync_drive.rs`:

```rust
use std::path::Path;

use secretary_core::sync::{
    commit_with_decisions, prepare_merge, sync_once, SyncOutcome, SyncState, VetoDecision,
};
use secretary_core::unlock::{open_with_password, UnlockedIdentity};
use secretary_core::vault::block::VectorClockEntry;

use crate::convergence_helpers::{baseline_password_bytes, Baseline, Device};

/// How the merger resolves any tombstone-vs-edit veto in `prepare_merge`.
#[derive(Clone, Copy)]
pub enum VetoPolicy {
    /// The scenario must produce zero vetoes; assert that and pass `[]`.
    NoVetoExpected,
    /// Keep every locally-live record over a peer tombstone.
    KeepLocal,
    /// Honour every peer tombstone.
    AcceptTombstone,
}

fn unlocked_identity(baseline: &Baseline) -> UnlockedIdentity {
    let folder = baseline.folder();
    let vt = std::fs::read(folder.join("vault.toml")).expect("read vault.toml");
    let bundle = std::fs::read(folder.join("identity.bundle.enc")).expect("read bundle");
    open_with_password(&vt, &bundle, baseline.password()).expect("open_with_password")
}

fn vault_uuid(baseline: &Baseline) -> [u8; 16] {
    // The manifest body carries the authenticated vault_uuid.
    baseline.open_manifest().vault_uuid
}

/// Drive the merger device: its remembered state is its own post-edit
/// clock (concurrent with canonical), so `sync_once` returns
/// `ConcurrentDetected`; resolve per `policy` and commit. Returns the
/// post-commit `SyncState`.
pub fn sync_as_merger(
    baseline: &Baseline,
    shared: &Path,
    merger: &Device,
    policy: VetoPolicy,
    now_ms: u64,
) -> SyncState {
    let identity = unlocked_identity(baseline);
    let state = SyncState::new(vault_uuid(baseline), merger.manifest_clock())
        .expect("merger SyncState");
    match sync_once(shared, &identity, &state, now_ms).expect("merger sync_once") {
        SyncOutcome::ConcurrentDetected { bundle, plan, .. } => {
            let draft = prepare_merge(shared, &identity, &bundle, &plan).expect("prepare_merge");
            let decisions: Vec<VetoDecision> = match policy {
                VetoPolicy::NoVetoExpected => {
                    assert!(
                        draft.vetoes.is_empty(),
                        "scenario expected no vetoes, got {}",
                        draft.vetoes.len()
                    );
                    Vec::new()
                }
                VetoPolicy::KeepLocal => draft
                    .vetoes
                    .iter()
                    .map(|v| VetoDecision::KeepLocal { record_id: v.record_id })
                    .collect(),
                VetoPolicy::AcceptTombstone => draft
                    .vetoes
                    .iter()
                    .map(|v| VetoDecision::AcceptTombstone { record_id: v.record_id })
                    .collect(),
            };
            commit_with_decisions(shared, baseline.password(), draft, decisions, now_ms)
                .expect("commit_with_decisions")
        }
        other => panic!("merger expected ConcurrentDetected, got {other:?}"),
    }
}

/// Drive the adopter device: the merged canonical LUB dominates its
/// remembered (post-edit, or empty) clock, so `sync_once` returns
/// `AppliedAutomatically`. Returns the new `SyncState`.
pub fn sync_as_adopter(baseline: &Baseline, shared: &Path, adopter: &Device, now_ms: u64) -> SyncState {
    let identity = unlocked_identity(baseline);
    let adopter_clock = adopter.manifest_clock();
    let state = SyncState::new(vault_uuid(baseline), adopter_clock).expect("adopter SyncState");
    match sync_once(shared, &identity, &state, now_ms).expect("adopter sync_once") {
        SyncOutcome::AppliedAutomatically { new_state } => new_state,
        SyncOutcome::NothingToDo => state,
        other => panic!("adopter expected AppliedAutomatically, got {other:?}"),
    }
}

/// True iff re-running `sync_once` from `state` is a no-op (the
/// quiescence half of the convergence contract).
pub fn is_nothing_to_do(baseline: &Baseline, shared: &Path, state: &SyncState, now_ms: u64) -> bool {
    let identity = unlocked_identity(baseline);
    matches!(
        sync_once(shared, &identity, state, now_ms).expect("quiescence sync_once"),
        SyncOutcome::NothingToDo
    )
}

/// Adopter whose clock is empty (it never edited) — scenario 1.
pub fn sync_as_pure_adopter(baseline: &Baseline, shared: &Path, now_ms: u64) -> SyncState {
    let identity = unlocked_identity(baseline);
    let state = SyncState::empty(vault_uuid(baseline));
    match sync_once(shared, &identity, &state, now_ms).expect("pure adopter sync_once") {
        SyncOutcome::AppliedAutomatically { new_state } => new_state,
        other => panic!("pure adopter expected AppliedAutomatically, got {other:?}"),
    }
}

// Silence unused-import for VectorClockEntry if a later refactor drops it.
#[allow(unused_imports)]
use VectorClockEntry as _ConvergenceVectorClockEntry;
```

Add to `mod.rs`:
```rust
mod sync_drive;
pub use sync_drive::{is_nothing_to_do, sync_as_adopter, sync_as_merger, sync_as_pure_adopter, VetoPolicy};
```

> NOTE: confirm `UnlockedIdentity` is exported at `secretary_core::unlock::UnlockedIdentity` (it is used by `sync_merge_vetoes.rs`). If `commit_with_decisions` requires the merged-disk `now_ms` to be ≥ the manifest's `last_mod_ms`, keep scenario `now_ms` values monotonically larger than edit `now_ms` (the plan uses 100 for edits, 1_000+ for sync — already satisfied).

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test --release --workspace --test convergence merger_then_adopter -- --nocapture`
Expected: PASS. If `sync_once` returns `RollbackRejected` or `AppliedAutomatically` for the merger, the merger clock is not concurrent with canonical — re-check that A and B used distinct device_uuids and both edited from the same baseline (Step assumptions in "Convergence mechanics").

- [ ] **Step 5: Commit**

```bash
git add core/tests/convergence.rs core/tests/convergence_helpers/
git commit -m "test(c4): merger/adopter sync drivers + quiescence check"
```

---

## Task 5: `assert_converged` + decrypt-state contract

**Files:**
- Create: `core/tests/convergence_helpers/assert.rs`
- Modify: `core/tests/convergence_helpers/mod.rs`
- Modify: `core/tests/convergence.rs`

A `LogicalRecord` projection (the comparable, secret-free shape) + `decrypt_state` + `assert_converged` (logical equality across two orderings).

- [ ] **Step 1: Write the failing test**

Add to `core/tests/convergence.rs`:

```rust
use convergence_helpers::{decrypt_state, LogicalRecord};

#[test]
fn decrypt_state_projects_records_to_comparable_shape() {
    let baseline = Baseline::create();
    let mut a = Device::fork(&baseline, A_UUID, 0xA0);
    a.edit_text_field(X_BLOCK, X_RECORD, "f1", "alice", 100);
    let shared = reconcile(&a, None, X_BLOCK); // one-editor; A canonical

    let state: Vec<LogicalRecord> = decrypt_state(&baseline, shared.folder(), X_BLOCK);
    assert_eq!(state.len(), 1);
    assert_eq!(state[0].record_uuid, X_RECORD);
    assert!(!state[0].tombstone);
    assert!(state[0].field_names.contains(&"f1".to_string()));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --release --workspace --test convergence decrypt_state_projects -- --nocapture`
Expected: FAIL — unresolved names.

- [ ] **Step 3: Implement `assert.rs`**

Create `core/tests/convergence_helpers/assert.rs`:

```rust
use std::path::Path;

use crate::convergence_helpers::{decrypt_block_records, Baseline};

/// Secret-free, order-stable projection of a `Record` used for
/// cross-ordering convergence comparison. Field VALUES are not compared
/// directly (they are `SecretString`); instead the value is hashed into
/// a stable digest so equality is meaningful without exposing secrets.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LogicalRecord {
    pub record_uuid: [u8; 16],
    pub tombstone: bool,
    pub last_mod_ms: u64,
    pub field_names: Vec<String>,
    /// (field_name, blake3-of-plaintext-value) pairs, sorted by name.
    pub field_value_digests: Vec<(String, [u8; 32])>,
}

/// Decrypt the named block in `folder` and project to a sorted
/// `Vec<LogicalRecord>` (sorted by record_uuid for stable comparison).
pub fn decrypt_state(baseline: &Baseline, folder: &Path, block_uuid: [u8; 16]) -> Vec<LogicalRecord> {
    let records = decrypt_block_records(folder, baseline.password(), block_uuid);
    let mut out: Vec<LogicalRecord> = records
        .iter()
        .map(|r| {
            let mut field_names: Vec<String> = r.fields.keys().cloned().collect();
            field_names.sort();
            let mut field_value_digests: Vec<(String, [u8; 32])> = r
                .fields
                .iter()
                .map(|(k, v)| (k.clone(), digest_field_value(&v.value)))
                .collect();
            field_value_digests.sort_by(|a, b| a.0.cmp(&b.0));
            LogicalRecord {
                record_uuid: r.record_uuid,
                tombstone: r.tombstone,
                last_mod_ms: r.last_mod_ms,
                field_names,
                field_value_digests,
            }
        })
        .collect();
    out.sort();
    out
}

fn digest_field_value(value: &secretary_core::vault::RecordFieldValue) -> [u8; 32] {
    use secretary_core::vault::RecordFieldValue;
    let bytes: Vec<u8> = match value {
        RecordFieldValue::Text(s) => s.expose().as_bytes().to_vec(),
        // If other RecordFieldValue arms exist (e.g. Bytes), hash their
        // exposed bytes too — match exhaustively at implementation time.
        other => panic!("unhandled RecordFieldValue arm in convergence digest: {other:?}"),
    };
    *blake3::hash(&bytes).as_bytes()
}

/// The convergence contract's logical-equality assertion: two orderings
/// of the same scenario must decrypt to identical logical state.
pub fn assert_converged(order_ab: &[LogicalRecord], order_ba: &[LogicalRecord]) {
    assert_eq!(
        order_ab, order_ba,
        "order-independence violated: A-canonical and B-canonical orderings diverged",
    );
}
```

Add to `mod.rs`:
```rust
mod assert;
pub use assert::{assert_converged, decrypt_state, LogicalRecord};
```

> NOTE: `blake3` and `SecretString::expose()` — confirm the exact accessor name on `SecretString` (grep `core/src/crypto/secret.rs`; it may be `expose_secret()` or `expose()`). Match `RecordFieldValue` arms exhaustively (grep `enum RecordFieldValue`); the CLAUDE.md memory notes `Text(SecretString)` and `Bytes(SecretBytes)`. `blake3` is already a core dependency; if it is not a dev-dependency of the test target, add `blake3` under `[dev-dependencies]` in `core/Cargo.toml` (it is already a normal dependency, so this is a no-op or a single line).

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test --release --workspace --test convergence decrypt_state_projects -- --nocapture`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add core/tests/convergence.rs core/tests/convergence_helpers/ core/Cargo.toml
git commit -m "test(c4): LogicalRecord projection + decrypt_state + assert_converged"
```

---

## Task 6: Scenario 1 — auto-apply (one editor)

**Files:**
- Modify: `core/tests/convergence.rs`

- [ ] **Step 1: Write the failing test**

```rust
/// Scenario 1 (auto-apply): A edits record X; B never edits. After B
/// syncs it adopts A's state; both decrypt to A's record and re-syncing
/// is a no-op.
#[test]
fn scenario_auto_apply_converges() {
    let baseline = Baseline::create();
    let mut a = Device::fork(&baseline, A_UUID, 0xA0);
    let b = Device::fork(&baseline, B_UUID, 0xB0); // B does not edit

    a.edit_text_field(X_BLOCK, X_RECORD, "f1", "alice", 100);
    let shared = reconcile(&a, None, X_BLOCK); // A canonical, no conflict copy

    // B is a pure adopter (empty clock).
    let b_state = convergence_helpers::sync_as_pure_adopter(&baseline, shared.folder(), 1_000);

    // Logical: exactly A's record, live.
    let state = decrypt_state(&baseline, shared.folder(), X_BLOCK);
    assert_eq!(state.len(), 1);
    assert_eq!(state[0].record_uuid, X_RECORD);
    assert!(!state[0].tombstone);

    // Quiescence on both devices.
    assert!(convergence_helpers::is_nothing_to_do(&baseline, shared.folder(), &b_state, 1_001));
    let a_state = SyncStateForA(&baseline, &a);
    assert!(convergence_helpers::is_nothing_to_do(&baseline, shared.folder(), &a_state, 1_002));

    let _ = b; // B's working copy is irrelevant post-adopt; state is on disk
}

// Small inline helper: A's remembered state is its own post-edit clock.
#[allow(non_snake_case)]
fn SyncStateForA(baseline: &Baseline, a: &Device) -> secretary_core::sync::SyncState {
    secretary_core::sync::SyncState::new(baseline.open_manifest().vault_uuid, a.manifest_clock())
        .expect("A SyncState")
}
```

- [ ] **Step 2: Run to verify it fails**, then **Step 3** is empty (harness already supports it — this is a pure composition test), **Step 4: Run to verify it passes**.

Run: `cargo test --release --workspace --test convergence scenario_auto_apply -- --nocapture`
Expected: first run may already PASS (no new harness code). If it fails, the failure localizes to the auto-apply path in `sync_as_pure_adopter` — fix there.

- [ ] **Step 5: Commit**

```bash
git add core/tests/convergence.rs
git commit -m "test(c4): scenario 1 — auto-apply convergence"
```

---

## Task 7: Scenario 2 — concurrent disjoint fields (auto-merge) + order-independence

**Files:**
- Modify: `core/tests/convergence.rs`

This task also introduces the reusable order-independence runner used by scenarios 2–4.

- [ ] **Step 1: Write the failing test**

```rust
use convergence_helpers::VetoPolicy;

/// Run a both-edit scenario in one ordering: `canonical` device's files
/// are canonical, `merger` device merges. Returns the converged logical
/// state of the named block.
fn run_both_edit_ordering(
    baseline: &Baseline,
    canonical: &Device,
    merger: &Device,
    merger_uuid: [u8; 16],
    policy: VetoPolicy,
    block_uuid: [u8; 16],
) -> Vec<LogicalRecord> {
    let shared = reconcile(canonical, Some((merger, merger_uuid)), block_uuid);
    let merger_state = sync_as_merger(baseline, shared.folder(), merger, policy, 1_000);
    let adopter_state = sync_as_adopter(baseline, shared.folder(), canonical, 1_001);
    assert!(convergence_helpers::is_nothing_to_do(baseline, shared.folder(), &merger_state, 1_002));
    assert!(convergence_helpers::is_nothing_to_do(baseline, shared.folder(), &adopter_state, 1_003));
    decrypt_state(baseline, shared.folder(), block_uuid)
}

/// Scenario 2 (concurrent disjoint): A edits X.f1, B edits X.f2 from a
/// shared seeded baseline. CRDT auto-merges both fields (no veto). The
/// converged record carries BOTH fields, regardless of which device is
/// canonical.
#[test]
fn scenario_concurrent_disjoint_fields_converges() {
    let baseline = Baseline::create();
    // Seed X so both devices edit the SAME record.
    let mut seed = Device::fork(&baseline, [0x00; 16], 0x55);
    seed.edit_text_field(X_BLOCK, X_RECORD, "f0", "seed", 10);
    let baseline = baseline_from_seeded(baseline, &seed, X_BLOCK);

    let edit = |canonical_first: bool| {
        let mut a = Device::fork(&baseline, A_UUID, 0xA0);
        let mut b = Device::fork(&baseline, B_UUID, 0xB0);
        a.edit_text_field(X_BLOCK, X_RECORD, "f1", "alice", 100);
        b.edit_text_field(X_BLOCK, X_RECORD, "f2", "bob", 101);
        if canonical_first {
            run_both_edit_ordering(&baseline, &a, &b, B_UUID, VetoPolicy::NoVetoExpected, X_BLOCK)
        } else {
            run_both_edit_ordering(&baseline, &b, &a, A_UUID, VetoPolicy::NoVetoExpected, X_BLOCK)
        }
    };

    let order_ab = edit(true);
    let order_ba = edit(false);

    // Both fields present in each ordering.
    assert_eq!(order_ab.len(), 1);
    for fname in ["f1", "f2"] {
        assert!(order_ab[0].field_names.iter().any(|n| n == fname), "missing {fname}");
    }
    // Order-independence.
    convergence_helpers::assert_converged(&order_ab, &order_ba);
}
```

This needs a `baseline_from_seeded` helper that promotes a seeded device's working copy into a new shared baseline (so the seed record X is the common ancestor). Add it to the harness.

- [ ] **Step 2: Run to verify it fails** (unresolved `baseline_from_seeded`).

- [ ] **Step 3: Implement `baseline_from_seeded`**

Add to `core/tests/convergence_helpers/baseline.rs` (and re-export from `mod.rs`):

```rust
impl Baseline {
    /// Build a new baseline whose on-disk state is a deep copy of an
    /// already-edited device folder — used to seed a common-ancestor
    /// record both devices then edit. The password is unchanged (same
    /// vault identity).
    pub fn from_folder(src: &std::path::Path, password: SecretBytes) -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let folder = tmp.path().to_path_buf();
        crate::convergence_helpers::copy_dir_all(src, &folder).expect("copy seeded folder");
        Self { _tmp: tmp, folder, password }
    }
}
```

Add the free function to `mod.rs`:

```rust
/// Promote a seeded device's working copy into a fresh baseline whose
/// common-ancestor state includes the seed record.
pub fn baseline_from_seeded(prev: Baseline, seed: &Device, _block_uuid: [u8; 16]) -> Baseline {
    let password = SecretBytes::new(baseline_password_bytes());
    let new_baseline = Baseline::from_folder(seed.folder(), password);
    drop(prev); // release the now-unused empty baseline tempdir
    new_baseline
}
```

> NOTE: `SecretBytes` is already imported in `mod.rs` (Task 2). The seed device used device_uuid `[0x00; 16]`; the common-ancestor clock therefore carries `{00:1}`. A and B forks then tick `{A:1}` / `{B:1}` on top — still concurrent with each other, dominating the ancestor. Confirm `from_folder`'s `password` field access compiles (the field is private to `baseline.rs`; constructing `Self` there is fine).

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test --release --workspace --test convergence scenario_concurrent_disjoint -- --nocapture`
Expected: PASS. If the merger sees `AppliedAutomatically` instead of `ConcurrentDetected`, the seed step changed the common ancestor such that one side dominates — verify both A and B forked from the SAME `baseline` (the seeded one) and used distinct uuids.

- [ ] **Step 5: Commit**

```bash
git add core/tests/convergence.rs core/tests/convergence_helpers/
git commit -m "test(c4): scenario 2 — concurrent disjoint-field auto-merge + order-independence runner"
```

---

## Task 8: Scenario 3 — LWW field collision

**Files:**
- Modify: `core/tests/convergence.rs`

- [ ] **Step 1: Write the failing test**

```rust
/// Scenario 3 (LWW collision): A and B edit the SAME field of X with
/// different values and different last_mod. CRDT picks the later
/// last_mod. The converged value digest equals the later writer's, in
/// both orderings.
#[test]
fn scenario_lww_collision_converges() {
    let baseline = Baseline::create();
    let mut seed = Device::fork(&baseline, [0x00; 16], 0x55);
    seed.edit_text_field(X_BLOCK, X_RECORD, "k", "seed", 10);
    let baseline = baseline_from_seeded(baseline, &seed, X_BLOCK);

    // B writes LATER (now_ms 101 > 100) → B's value wins under LWW.
    let later_value_digest = {
        // Independent digest of the expected winning plaintext "bob-wins".
        *blake3::hash(b"bob-wins").as_bytes()
    };

    let edit = |canonical_first: bool| {
        let mut a = Device::fork(&baseline, A_UUID, 0xA0);
        let mut b = Device::fork(&baseline, B_UUID, 0xB0);
        a.edit_text_field(X_BLOCK, X_RECORD, "k", "alice-loses", 100);
        b.edit_text_field(X_BLOCK, X_RECORD, "k", "bob-wins", 101);
        if canonical_first {
            run_both_edit_ordering(&baseline, &a, &b, B_UUID, VetoPolicy::NoVetoExpected, X_BLOCK)
        } else {
            run_both_edit_ordering(&baseline, &b, &a, A_UUID, VetoPolicy::NoVetoExpected, X_BLOCK)
        }
    };

    let order_ab = edit(true);
    let order_ba = edit(false);

    // The surviving "k" digest is the later writer's, in both orderings.
    for state in [&order_ab, &order_ba] {
        let digest = state[0]
            .field_value_digests
            .iter()
            .find(|(n, _)| n == "k")
            .map(|(_, d)| *d)
            .expect("field k present");
        assert_eq!(digest, later_value_digest, "LWW must keep the later writer's value");
    }
    convergence_helpers::assert_converged(&order_ab, &order_ba);
}
```

- [ ] **Step 2: Run to verify it fails** (assertion fails if LWW resolution differs), **Step 3** likely no harness change.

Run: `cargo test --release --workspace --test convergence scenario_lww_collision -- --nocapture`
Expected after harness is correct: PASS.

> NOTE: if the field-level LWW tie-break uses the field's `last_mod` (the `RecordField.last_mod`) rather than the record `last_mod_ms`, the `edit_text_field` helper already sets `field.last_mod = now_ms`, so 101 > 100 holds at the field level too. If convergence picks "alice-loses", inspect `merge_record` in `core/src/vault/conflict.rs` for the exact field tie-break key and adjust the scenario's `now_ms` accordingly (do NOT weaken the assertion).

- [ ] **Step 4 / Step 5: verify + commit**

```bash
git add core/tests/convergence.rs
git commit -m "test(c4): scenario 3 — LWW field-collision convergence"
```

---

## Task 9: Scenario 4 — tombstone-veto (both decisions)

**Files:**
- Modify: `core/tests/convergence.rs`

- [ ] **Step 1: Write the failing test**

```rust
/// Scenario 4 (tombstone-veto): A keeps X live (edit at t=100); B
/// tombstones X (t=200 > 100) → `prepare_merge` emits one veto. Asserted
/// for BOTH decisions and BOTH orderings:
///  - KeepLocal     → X survives, live.
///  - AcceptTombstone → X stays tombstoned.
#[test]
fn scenario_tombstone_veto_keep_local_converges() {
    assert_tombstone_veto(VetoPolicy::KeepLocal, /*expect_tombstone*/ false);
}

#[test]
fn scenario_tombstone_veto_accept_delete_converges() {
    assert_tombstone_veto(VetoPolicy::AcceptTombstone, /*expect_tombstone*/ true);
}

fn assert_tombstone_veto(policy: VetoPolicy, expect_tombstone: bool) {
    let baseline = Baseline::create();
    let mut seed = Device::fork(&baseline, [0x00; 16], 0x55);
    seed.edit_text_field(X_BLOCK, X_RECORD, "k", "seed", 10);
    let baseline = baseline_from_seeded(baseline, &seed, X_BLOCK);

    // The merger MUST be the device holding the conflict copy. The veto
    // fires from the merger's perspective: a peer (canonical) tombstone
    // strictly later than the merger's live edit, OR vice-versa. To make
    // the veto deterministic, B (the tombstoner) is always the merger and
    // A (live editor) is always canonical; order-independence here swaps
    // the *role labels* by also running the mirrored construction.
    let run = |a_canonical: bool| {
        let mut a = Device::fork(&baseline, A_UUID, 0xA0); // live editor
        let mut b = Device::fork(&baseline, B_UUID, 0xB0); // tombstoner
        a.edit_text_field(X_BLOCK, X_RECORD, "k", "alice-live", 100);
        b.tombstone(X_BLOCK, X_RECORD, 200);
        if a_canonical {
            run_both_edit_ordering(&baseline, &a, &b, B_UUID, policy, X_BLOCK)
        } else {
            run_both_edit_ordering(&baseline, &b, &a, A_UUID, policy, X_BLOCK)
        }
    };

    let order_ab = run(true);
    let order_ba = run(false);

    for state in [&order_ab, &order_ba] {
        assert_eq!(state.len(), 1, "record X must be present (live or tombstoned)");
        assert_eq!(state[0].record_uuid, X_RECORD);
        assert_eq!(
            state[0].tombstone, expect_tombstone,
            "veto decision {policy:?} produced wrong tombstone state",
        );
    }
    convergence_helpers::assert_converged(&order_ab, &order_ba);
}
```

`VetoPolicy` must derive `Debug` for the `{policy:?}` format. Add `#[derive(Clone, Copy, Debug)]` on `VetoPolicy` in `sync_drive.rs`.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --release --workspace --test convergence scenario_tombstone_veto -- --nocapture`
Expected: FAIL initially if `VetoPolicy` lacks `Debug` (compile error) — add the derive (Step 3).

- [ ] **Step 3: Add `Debug` to `VetoPolicy`**

In `core/tests/convergence_helpers/sync_drive.rs`:

```rust
#[derive(Clone, Copy, Debug)]
pub enum VetoPolicy { /* unchanged */ }
```

- [ ] **Step 4: Run to verify both veto tests pass**

Run: `cargo test --release --workspace --test convergence scenario_tombstone_veto -- --nocapture`
Expected: PASS (both `keep_local` and `accept_delete`).

> NOTE — the load-bearing veto precondition (from `prepare_merge::tombstone_veto_set`): a veto fires only when canonical is LIVE, a peer is TOMBSTONED, and `peer.tombstoned_at_ms > canonical.last_mod_ms`. When B is canonical (mirrored ordering), B is the tombstoner — so the *merger* (A) is the live editor and the *peer* (canonical B) is the tombstone. Verify the veto still fires in that direction; if `prepare_merge` only vetoes when the LIVE record is canonical, the mirrored ordering may auto-resolve to tombstone instead of emitting a veto. If so, the correct convergence is still well-defined (both orderings must agree on the final tombstone state) — keep `assert_converged`, and relax only the `VetoPolicy` application in the mirrored case via the policy already returning `[]` when `draft.vetoes` is empty. Confirm empirically and document the observed behavior in the test comment.

- [ ] **Step 5: Commit**

```bash
git add core/tests/convergence.rs core/tests/convergence_helpers/
git commit -m "test(c4): scenario 4 — tombstone-veto convergence (keep-local + accept-delete)"
```

---

## Task 10: Lint gate, fmt, docs (README + ROADMAP)

**Files:**
- Modify: `README.md`
- Modify: `ROADMAP.md`

- [ ] **Step 1: Full gate — tests + clippy + fmt**

Run:
```bash
cargo test --release --workspace --test convergence
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all
```
Expected: convergence binary green; clippy clean (no new warnings); fmt no-ops or formats the new files. Fix any clippy findings in the helper modules (common ones: `needless_borrow`, `redundant_clone` on `owner_card`). Do NOT silence with blanket `#[allow]` beyond the deliberate module-level `dead_code` allowance in `mod.rs`.

- [ ] **Step 2: Update ROADMAP.md**

Add a C.4 entry under the sync (Sub-project C) section marking cross-device convergence conformance as delivered (Rust in-process, two devices; 4 scenarios + order-independence). Match the existing ROADMAP row style — grep for the C.3 entries and mirror their format. Note the deferred rungs (Python clean-room mirror; 3+ device topologies) as future work.

- [ ] **Step 3: Update README.md**

If README has a status/conformance section listing the conformance suites, add a brief dot-point: "Cross-device convergence (C.4): two device identities reconciling through a shared folder converge to identical logical state, order-independent — `core/tests/convergence.rs`." Keep it brief per the README style (no test-count walls).

- [ ] **Step 4: Verify docs render + final full-suite sanity**

Run:
```bash
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
```
Expected: whole workspace green; clippy clean.

- [ ] **Step 5: Commit**

```bash
git add README.md ROADMAP.md
git commit -m "docs(c4): record cross-device convergence conformance in README + ROADMAP"
```

---

## Acceptance (full gate)

```bash
cd /Users/hherb/src/secretary/.worktrees/c4-convergence-conformance
cargo test --release --workspace --test convergence        # all scenarios green
cargo test --release --workspace                            # whole suite green
cargo clippy --release --workspace --tests -- -D warnings   # clean
cargo fmt --all --check                                     # formatted
git diff main...HEAD --name-only | grep -vE '^(core/tests/|docs/|README.md|ROADMAP.md)'   # expect empty (additive test-only)
```

The last grep is the guardrail: C.4 must touch only `core/tests/**`, `docs/**`, `README.md`, `ROADMAP.md`. No `core/src`, no FFI, no on-disk-format / crypto / CRDT change.

---

## Risks & verification notes (resolve empirically during execution — do not weaken assertions)

1. **Merger must see `Concurrent`, not auto-apply.** The whole model rests on: merger's `SyncState` clock (its own post-edit manifest clock) being *concurrent* with the canonical manifest clock. This holds because A and B fork the same baseline and tick distinct device_uuids. Task 4's test is the first place this is exercised end-to-end; if it returns the wrong arm, fix the clock derivation before proceeding.
2. **`prepare_merge` veto direction (Task 9).** The veto precondition is asymmetric (live canonical vs later peer tombstone). The mirrored ordering may not emit a veto; the test tolerates that (policy returns `[]` when `draft.vetoes` is empty) but STILL asserts both orderings converge to the same tombstone state. Document the observed behavior.
3. **Field-LWW tie-break key (Task 8).** Confirm whether `merge_record` keys LWW on `RecordField.last_mod` or record `last_mod_ms`; the scenario sets both via `now_ms`, but if a tie occurs the device_uuid is the documented tiebreaker — adjust `now_ms` spread, never the assertion.
4. **API export paths.** A handful of `use` paths (`format_uuid_hyphenated`, `UnlockedIdentity`, `SecretString::expose`, `RecordFieldValue` arms) are noted inline; grep the existing tests (`save_block.rs`, `sync_merge_vetoes.rs`) for the canonical path if any import fails to resolve.
5. **KDF cost.** All vaults use `Argon2idParams::new(8, 1, 1)` (sub-floor, fast) via `create_vault_unchecked` — never the floor-enforcing `vault::create_vault`. Each scenario does a handful of opens; total runtime should stay well under the suite's existing budget.
6. **File size.** If `device.rs` or the scenario file in `convergence.rs` exceeds ~450 lines, split the scenarios into a second test file (`convergence_veto.rs`) sharing the same `convergence_helpers` (mirrors how `sync_merge_vetoes.rs` split from `sync_merge.rs`).
