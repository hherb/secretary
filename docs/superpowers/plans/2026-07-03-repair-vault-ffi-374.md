# repair_vault FFI projection + desktop "repair now?" UX — Implementation Plan (#374 Slice A)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the existing fail-closed `repair_vault` orchestrator reachable end-to-end — projected onto all three FFI bindings with two new typed error variants, plus a desktop "repair now?" reference UX and a device-secret-arm core test.

**Architecture:** Core `repair_vault` is unchanged (fail-closed semantics preserved). Two new `FfiVaultError` variants (`VaultNeedsRepair` promoted from open's `BlockFingerprintMismatch`; `RepairRejected` from repair's refusal) are threaded through every exhaustive-match consumer. Three bridge repair fns mirror the three open arms. The desktop wires the password arm: on a needs-repair open error, offer repair; on confirm, call `repair_vault` reusing the password still in the form.

**Tech Stack:** Rust (stable), `secretary-ffi-bridge` / `-uniffi` (udl + Swift/Kotlin harnesses) / `-py` (PyO3), Tauri 2 (Rust backend + Svelte/TypeScript frontend, pnpm + vitest).

**Spec:** `docs/superpowers/specs/2026-07-03-repair-vault-ffi-desktop-374-design.md`

## Global Constraints

- `#![forbid(unsafe_code)]` workspace-wide — no `unsafe`.
- Clippy must stay clean: `cargo clippy --release --workspace --tests -- -D warnings`.
- Rustdoc must stay warning-clean: `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace`.
- All cargo commands `--release` (crypto crates are slow in debug).
- Secret bytes: any `[u8; N]` stack copy handed to `SecretBytes::new`/`Sensitive::new` must be `.zeroize()`d immediately after (CLAUDE.md zeroize discipline).
- FFI input validation (credential lengths) lives at the **binding wrapper** (uniffi/pyo3), returning `InvalidArgument` — the bridge takes `&[u8; 16]`/`&[u8; 32]` and trusts its caller. [[project_secretary_input_validation_at_binding_wrapper]]
- Adding an `FfiVaultError` variant obligates: bridge conversion + uniffi `From` + uniffi udl `[Error]` enum + pyo3 error mapping + desktop `AppError` `From` + **Swift `ConformanceErrors.swift` + Kotlin `ConformanceErrors.kt`** (invisible to cargo/clippy — only `run_conformance.sh` catches a gap). [[project_secretary_ffivaulterror_workspace_match]]
- A new Tauri command in `generate_handler!` must be classified in `desktop/src/lib/ipc/writeCommands.ts` or the #280 coverage test fails (cargo passes; only `pnpm test` catches it). [[project_secretary_desktop_generate_handler_writecommands_coverage]]
- New/edited Rust files: keep under ~500 lines; split by responsibility. [[feedback_split_files_proactively]]
- Working dir for all commands: `/Users/hherb/src/secretary/.worktrees/repair-vault-ffi-374`. Verify with `pwd && git branch --show-current` (expect `feature/repair-vault-ffi-374`) before any cargo/git op. [[feedback_edit_tool_targets_main_not_worktree]] — Edit/Write/Read paths MUST spell out `.worktrees/repair-vault-ffi-374/...`.

---

## File Structure

**Core (Task 1):**
- Modify: `core/tests/crash_recovery.rs` — add one device-secret-arm repair test + `use` for `add_device_slot`.

**Bridge (Tasks 2, 3):**
- Modify: `ffi/secretary-ffi-bridge/src/error/vault/mod.rs` — 2 new variants + 2 rerouted arms.
- Modify: `ffi/secretary-ffi-bridge/src/error/vault/tests.rs` — flip 2 assertions.
- Create: `ffi/secretary-ffi-bridge/src/repair/mod.rs` + `ffi/secretary-ffi-bridge/src/repair/orchestration.rs` (three fns) + `ffi/secretary-ffi-bridge/src/repair/tests.rs`.
- Modify: `ffi/secretary-ffi-bridge/src/lib.rs` — `mod repair;` + re-exports.

**uniffi (Tasks 2, 4):**
- Modify: `ffi/secretary-ffi-uniffi/src/errors/vault.rs` — 2 enum variants + 2 `From` arms.
- Modify: `ffi/secretary-ffi-uniffi/src/secretary.udl` — 2 `[Error]` variants + 3 repair namespace fns.
- Modify: `ffi/secretary-ffi-uniffi/src/namespace/mod.rs` (+ new `namespace/repair.rs` if it keeps files small) — 3 repair wrappers.
- Modify: `ffi/secretary-ffi-uniffi/src/lib.rs` — re-exports.
- Modify: `ffi/secretary-ffi-uniffi/tests/swift/ConformanceErrors.swift` + `ffi/secretary-ffi-uniffi/tests/kotlin/ConformanceErrors.kt` — 2 arms each.

**pyo3 (Tasks 2, 5):**
- Modify: `ffi/secretary-ffi-py/src/errors.rs` — 2 exception classes + 2 mapping arms.
- Create: `ffi/secretary-ffi-py/src/repair.rs` — three fns.
- Modify: `ffi/secretary-ffi-py/src/lib.rs` — `mod repair;` + module registration.
- Create: `ffi/secretary-ffi-py/tests/test_repair.py`.

**Desktop backend (Tasks 2, 6):**
- Modify: `desktop/src-tauri/src/errors.rs` — 2 `AppError` variants + 2 `From<FfiVaultError>` arms.
- Create: `desktop/src-tauri/src/commands/repair.rs` — `repair_vault` command + `repair_vault_impl` + `read_vault_uuid_from_toml`.
- Modify: `desktop/src-tauri/src/session.rs` — `VaultSession::repair`.
- Modify: `desktop/src-tauri/src/commands/mod.rs` + `desktop/src-tauri/src/main.rs` — register the command.

**Desktop frontend (Task 7):**
- Modify: `desktop/src/lib/errors.ts` — 2 codes.
- Modify: `desktop/src/lib/ipc/*` — `repairVault` wrapper + `writeCommands.ts` classification.
- Modify: the unlock component (Task 7 locates it) — repair affordance.
- Modify/Create: vitest specs.

**Docs (Task 8):**
- Modify: `README.md`, `ROADMAP.md`, `NEXT_SESSION.md` handoff.

---

## Task 1: Core device-secret-arm repair test (part 4)

**Files:**
- Modify: `core/tests/crash_recovery.rs` (add `use` + one `#[test]` after `repair_vault_adopts_interrupted_save`, ~line 473)

**Interfaces:**
- Consumes: `secretary_core::vault::device_slot::add_device_slot(folder, &SecretBytes, &mut rng) -> EnrolledDevice { device_uuid: [u8;16], device_secret: SecretBytes }`; `Unlocker::DeviceSecret { device_uuid: &[u8;16], secret: &SecretBytes }`; existing helpers `make_fast_vault`, `make_simple_plaintext`, `format_uuid_hyphenated`, `save_block`, `open_vault`, `repair_vault`.
- Produces: nothing (test-only).

- [ ] **Step 1: Add the import**

In the `use secretary_core::vault::{...}` block (line ~30) OR as a standalone line, add access to `add_device_slot`:

```rust
use secretary_core::vault::device_slot::add_device_slot;
```

- [ ] **Step 2: Write the failing test**

Insert after `repair_vault_adopts_interrupted_save` (line ~473). This mirrors that test but enrolls a device slot and drives both the failing open and the repair through `Unlocker::DeviceSecret`:

```rust
/// #374 part 4: the crash-recovery adopt path must go through the SAME gated
/// adoption when the vault is unlocked via `Unlocker::DeviceSecret` (ADR 0009),
/// not only via password. Previously the device arm was covered only
/// transitively through the shared `unlock_vault_identity`; this pins it
/// end-to-end (device unlock is not a weaker open, per B.2 orchestrators).
#[test]
fn repair_vault_adopts_interrupted_save_via_device_secret() {
    let (dir, _mnemonic, pw) = make_fast_vault(0x37, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x37; 32]);

    // Enroll a device slot so the vault can be opened without the password.
    let enrolled = add_device_slot(folder, &pw, &mut rng).expect("enroll device slot");
    let dev_unlocker = || Unlocker::DeviceSecret {
        device_uuid: &enrolled.device_uuid,
        secret: &enrolled.device_secret,
    };

    // Stage a crashed save: v2 block on disk, v1 manifest committed.
    let mut open = open_vault(folder, dev_unlocker(), None).unwrap();
    let (writer_device_uuid, block_uuid) = ([0xda; 16], [0xba; 16]);
    let recipients = vec![open.owner_card.clone()];
    save_block(
        folder, &mut open, make_simple_plaintext(block_uuid, "v1"),
        &recipients, writer_device_uuid, 1_000, &mut rng,
    ).unwrap();
    let manifest_v1 = fs::read(folder.join("manifest.cbor.enc")).unwrap();
    save_block(
        folder, &mut open, make_simple_plaintext(block_uuid, "v2"),
        &recipients, writer_device_uuid, 2_000, &mut rng,
    ).unwrap();
    drop(open);
    fs::write(folder.join("manifest.cbor.enc"), &manifest_v1).unwrap();

    // Open via the device secret must fail typed on the residue.
    let err = open_vault(folder, dev_unlocker(), None).expect_err("residue must fail open");
    assert!(
        matches!(err, VaultError::BlockFingerprintMismatch { block_uuid: b, .. } if b == block_uuid),
        "got {err:?}"
    );

    // Repair via the device secret must adopt the on-disk v2 (same gate).
    let repaired = secretary_core::vault::repair_vault(
        folder, dev_unlocker(), None, enrolled.device_uuid, 3_000, &mut rng,
    ).expect("gated adoption must succeed via device secret");

    let entry = repaired.manifest.blocks.iter()
        .find(|b| b.block_uuid == block_uuid).expect("entry present");
    assert_eq!(entry.block_name, "v2", "adopted entry carries on-disk content");
    assert_eq!(entry.vector_clock_summary[0].counter, 2);
    drop(repaired);

    open_vault(folder, dev_unlocker(), None).expect("healthy after device-secret repair");
}
```

- [ ] **Step 3: Run — verify it fails to compile first (missing import) then passes**

Run: `cargo test --release --workspace --test crash_recovery repair_vault_adopts_interrupted_save_via_device_secret`
Expected: if the `use` is wrong, a compile error naming `add_device_slot`; once compiling, the test **passes** (the behavior already exists). If it *fails* at runtime, that is a real finding — stop and investigate (do not weaken the assertions).

- [ ] **Step 4: Confirm the whole file still compiles clean**

Run: `cargo test --release --workspace --test crash_recovery`
Expected: all crash_recovery tests PASS.

- [ ] **Step 5: Commit**

```bash
git add core/tests/crash_recovery.rs
git commit -m "test(core): repair_vault crash-recovery via Unlocker::DeviceSecret (#374)"
```

---

## Task 2: Two typed error variants, threaded through every consumer

This is a **wide but shallow** task: adding the variants breaks compilation in four exhaustive Rust matches at once (bridge conversion, uniffi `From`, pyo3 mapping, desktop `AppError`), so they must all land together, plus the two conformance harnesses.

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/error/vault/mod.rs`, `.../error/vault/tests.rs`
- Modify: `ffi/secretary-ffi-uniffi/src/errors/vault.rs`, `.../secretary.udl`
- Modify: `ffi/secretary-ffi-py/src/errors.rs`
- Modify: `desktop/src-tauri/src/errors.rs`
- Modify: `ffi/secretary-ffi-uniffi/tests/swift/ConformanceErrors.swift`, `.../tests/kotlin/ConformanceErrors.kt`

**Interfaces:**
- Produces (consumed by Tasks 3–7):
  - `FfiVaultError::VaultNeedsRepair { block_uuid_hex: String }`
  - `FfiVaultError::RepairRejected { block_uuid_hex: String, detail: String }`
  - uniffi `VaultError::VaultNeedsRepair { block_uuid_hex }`, `VaultError::RepairRejected { block_uuid_hex, detail }`
  - desktop `AppError::VaultNeedsRepair { block_uuid_hex: String }`, `AppError::RepairRejected { block_uuid_hex: String, detail: String }`

- [ ] **Step 1: Add the two bridge variants**

In `ffi/secretary-ffi-bridge/src/error/vault/mod.rs`, in the `FfiVaultError` enum (near the existing `CorruptVault`/`BlockNotFound` variants, mirror their doc + `#[error(...)]` style). Model `block_uuid_hex` on the existing `BlockNotFound { uuid_hex }` variant:

```rust
    /// The vault has crash residue that `repair_vault` may be able to adopt:
    /// an on-disk block whose bytes do not match the committed manifest
    /// fingerprint (core `BlockFingerprintMismatch`, from an interrupted write).
    /// Distinct from `CorruptVault` — this is the actionable "offer Repair"
    /// signal. `block_uuid_hex` is the lowercase-hyphenated UUID of the block.
    #[error("vault needs repair: block {block_uuid_hex} has crash residue")]
    VaultNeedsRepair { block_uuid_hex: String },

    /// `repair_vault` was attempted and refused to adopt a block (core
    /// `RepairRejected`). `detail` explains why — for equal-clock rejections it
    /// names the recipient delta. Fail-closed: no change was written. The app
    /// should surface `detail`; there is no automatic fix.
    #[error("repair rejected for block {block_uuid_hex}: {detail}")]
    RepairRejected { block_uuid_hex: String, detail: String },
```

- [ ] **Step 2: Reroute the two core errors in the bridge conversion**

In the same file's `From<VaultError> for FfiVaultError` (the big match, ~line 460-540): **remove** `VE::BlockFingerprintMismatch { .. }` and `VE::RepairRejected { .. }` from the terminal `CorruptVault` fold (lines ~530, ~536) and add dedicated arms before it. `BlockFileMissing` STAYS in the fold. Use the core helper for hex (mirror how `BlockNotFound`'s `uuid_hex` is produced elsewhere — search the file for `format_uuid_hyphenated` or `hex::encode`; match the existing convention):

```rust
            VE::BlockFingerprintMismatch { block_uuid, .. } => FfiVaultError::VaultNeedsRepair {
                block_uuid_hex: format_uuid_hyphenated(&block_uuid),
            },
            VE::RepairRejected { block_uuid, detail } => FfiVaultError::RepairRejected {
                block_uuid_hex: format_uuid_hyphenated(&block_uuid),
                detail,
            },
```

Update the fold comment (lines ~525-534) to drop the `BlockFingerprintMismatch`/`RepairRejected` mentions and keep only `BlockFileMissing`. (If `format_uuid_hyphenated` isn't already imported in this file, import it from the core path the sibling arms use, or use `hex::encode(block_uuid)` — match the file's existing style; grep the file first.)

- [ ] **Step 3: Flip the bridge error tests**

In `ffi/secretary-ffi-bridge/src/error/vault/tests.rs`, find the two tests that assert `BlockFingerprintMismatch` and `RepairRejected` fold to `CorruptVault` (grep `BlockFingerprintMismatch`/`RepairRejected` in that file). Change them to assert the new variants; keep the `BlockFileMissing`→`CorruptVault` test as-is. Example shape:

```rust
    let ffi: FfiVaultError = VaultError::BlockFingerprintMismatch {
        block_uuid: [0xAB; 16], /* other fields per the variant */
    }.into();
    assert!(matches!(ffi, FfiVaultError::VaultNeedsRepair { .. }));
```

(Read the existing test to copy the exact `VaultError::BlockFingerprintMismatch` construction — it has more than one field.)

- [ ] **Step 4: Run bridge tests — expect PASS**

Run: `cargo test --release -p secretary-ffi-bridge`
Expected: PASS (the two flipped assertions + everything else). If other crates now fail to compile, that's expected — continue threading below before the full-workspace run.

- [ ] **Step 5: Thread the uniffi error surface**

In `ffi/secretary-ffi-uniffi/src/errors/vault.rs`: add two variants to the `VaultError` enum (mirror `CorruptVault { detail }` / a `{ uuid_hex }`-carrying variant for doc + field style), and two arms to `impl From<FfiVaultError> for VaultError` (line ~141):

```rust
            FfiVaultError::VaultNeedsRepair { block_uuid_hex } => {
                VaultError::VaultNeedsRepair { block_uuid_hex }
            }
            FfiVaultError::RepairRejected { block_uuid_hex, detail } => {
                VaultError::RepairRejected { block_uuid_hex, detail }
            }
```

In `ffi/secretary-ffi-uniffi/src/secretary.udl`, add the two variants to the `[Error] enum VaultError { ... }` block (match the udl field syntax of a neighbouring variant that carries strings).

- [ ] **Step 6: Thread the pyo3 error surface**

In `ffi/secretary-ffi-py/src/errors.rs`: declare two new exception classes (mirror `VaultCorruptVault` / `VaultBlockNotFound` — `create_exception!` macro; grep the file for the pattern) and add two arms to the `match e { ... }` in the `FfiVaultError` mapping fn:

```rust
        FfiVaultError::VaultNeedsRepair { block_uuid_hex } => {
            VaultNeedsRepair::new_err(block_uuid_hex)
        }
        FfiVaultError::RepairRejected { block_uuid_hex, detail } => {
            VaultRepairRejected::new_err(format!("{block_uuid_hex}: {detail}"))
        }
```

Register the two new exception types wherever the module adds its exceptions (grep `add("Vault` or `add_class` / `m.add(` in `errors.rs`/`lib.rs`).

- [ ] **Step 7: Thread the desktop AppError**

In `desktop/src-tauri/src/errors.rs`: add two `AppError` variants (mirror `VaultCorrupt { detail }` and a `{ block_uuid_hex }` carrier):

```rust
    /// The opened vault has crash residue repair may adopt. Frontend offers "Repair now?".
    VaultNeedsRepair { block_uuid_hex: String },
    /// repair_vault refused; `detail` names the reason (recipient delta for equal-clock).
    RepairRejected { block_uuid_hex: String, detail: String },
```

Add two arms to `impl From<FfiVaultError> for AppError` (~line 397):

```rust
        FfiVaultError::VaultNeedsRepair { block_uuid_hex } => {
            AppError::VaultNeedsRepair { block_uuid_hex }
        }
        FfiVaultError::RepairRejected { block_uuid_hex, detail } => {
            AppError::RepairRejected { block_uuid_hex, detail }
        }
```

If `AppError` has a `#[serde(tag = "code")]`/serialization derive, ensure the two new variants get their wire `code` (grep how `VaultCorrupt` serializes — likely automatic snake_case: `vault_needs_repair` / `repair_rejected`; confirm the serde attr). Task 7's `errors.ts` must match these exact codes.

- [ ] **Step 8: Verify the full workspace compiles + tests pass**

Run: `cargo test --release --workspace`
Then: `cargo clippy --release --workspace --tests -- -D warnings`
Expected: both green. Fix any remaining exhaustive-match site the compiler names (it will name every one — that is the safety net working).

- [ ] **Step 9: Thread the Swift + Kotlin conformance harnesses**

In `ffi/secretary-ffi-uniffi/tests/swift/ConformanceErrors.swift`, add two `case` arms to the `switch e` in `vaultErrorName` (and any sibling extractor fn that switches over `VaultError` — grep `case .CorruptVault` in the file):

```swift
    case .VaultNeedsRepair: return "VaultNeedsRepair"
    case .RepairRejected: return "RepairRejected"
```

Mirror the same two arms in `ffi/secretary-ffi-uniffi/tests/kotlin/ConformanceErrors.kt` (`is VaultError.VaultNeedsRepair -> "VaultNeedsRepair"` etc. — match the file's `when` syntax).

- [ ] **Step 10: Run BOTH conformance scripts**

Run:
```bash
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
```
Expected: both PASS. (These are the only checks that compile the harnesses — cargo cannot see them.) [[project_secretary_ios_xcframework_build_watchdog]]: the Rust xcframework build inside these is multi-minute + silent; run it patiently, don't kill it.

- [ ] **Step 11: Commit**

```bash
git add ffi/ desktop/src-tauri/src/errors.rs
git commit -m "feat(ffi): typed VaultNeedsRepair + RepairRejected error variants (#374)"
```

---

## Task 3: Bridge `repair_vault` projection (three arms)

**Files:**
- Create: `ffi/secretary-ffi-bridge/src/repair/mod.rs`, `.../repair/orchestration.rs`, `.../repair/tests.rs`
- Modify: `ffi/secretary-ffi-bridge/src/lib.rs`

**Interfaces:**
- Consumes: core `repair_vault(folder, Unlocker, Option<&[VectorClockEntry]>, [u8;16], u64, &mut rng) -> Result<OpenVault, VaultError>`; `crate::vault::orchestration::{enforce_rollback_resistance, split_core_open_vault, OpenVaultOutput}` (both `pub(crate)`); `FfiVaultError`.
- Produces (consumed by Tasks 4, 5, 6):
  - `repair_vault_with_password(folder: &Path, password: &[u8], device_uuid: &[u8;16], now_ms: u64) -> Result<OpenVaultOutput, FfiVaultError>`
  - `repair_vault_with_recovery(folder: &Path, mnemonic_bytes: &[u8], device_uuid: &[u8;16], now_ms: u64) -> Result<OpenVaultOutput, FfiVaultError>`
  - `repair_vault_with_device_secret(folder: &Path, device_uuid: &[u8;16], device_secret: &[u8;32], now_ms: u64) -> Result<OpenVaultOutput, FfiVaultError>`

- [ ] **Step 1: Write the module + three fns**

Create `ffi/secretary-ffi-bridge/src/repair/orchestration.rs`. Confirm exact import paths against `src/vault/orchestration.rs` (the `OpenVaultOutput`/`split_core_open_vault`/`enforce_rollback_resistance` paths) and `src/device.rs` (SecretBytes usage):

```rust
//! FFI projection of the `repair_vault` crash-recovery orchestrator (#374).
//!
//! Three arms mirror the three `open_vault_with_*` arms. Each runs the same
//! §10 rollback-resistance check as a normal open before returning a handle —
//! repair is never a weaker open. `now_ms`/`device_uuid` follow the `save_block`
//! convention (caller-supplied; the manifest-clock tick keys on `device_uuid`).
use std::path::Path;

use rand_core::OsRng;
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::vault::{repair_vault, Unlocker};

use crate::error::FfiVaultError;
use crate::vault::orchestration::{
    enforce_rollback_resistance, split_core_open_vault, OpenVaultOutput,
};

/// Repair a crash-residue vault opened by master password. See
/// [`crate::open_vault_with_password`] for the open-only counterpart.
pub fn repair_vault_with_password(
    folder: &Path,
    password: &[u8],
    device_uuid: &[u8; 16],
    now_ms: u64,
) -> Result<OpenVaultOutput, FfiVaultError> {
    let pw = SecretBytes::new(password.to_vec());
    let core_out = repair_vault(folder, Unlocker::Password(&pw), None, *device_uuid, now_ms, &mut OsRng)?;
    enforce_rollback_resistance(&core_out)?;
    Ok(split_core_open_vault(core_out, folder.to_path_buf()))
    // pw drops here → ZeroizeOnDrop wipes the local copy.
}

/// Repair a crash-residue vault opened by 24-word BIP-39 recovery phrase.
pub fn repair_vault_with_recovery(
    folder: &Path,
    mnemonic_bytes: &[u8],
    device_uuid: &[u8; 16],
    now_ms: u64,
) -> Result<OpenVaultOutput, FfiVaultError> {
    let phrase = std::str::from_utf8(mnemonic_bytes).map_err(|_| FfiVaultError::InvalidMnemonic {
        detail: "phrase contained invalid UTF-8".to_string(),
    })?;
    let core_out = repair_vault(folder, Unlocker::Recovery(phrase), None, *device_uuid, now_ms, &mut OsRng)?;
    enforce_rollback_resistance(&core_out)?;
    Ok(split_core_open_vault(core_out, folder.to_path_buf()))
}

/// Repair a crash-residue vault opened by a per-device wrap secret (ADR 0009).
/// The single `device_uuid` selects the `devices/<uuid>.wrap` slot AND keys the
/// manifest-clock tick — the unlocking device is the slot's device.
pub fn repair_vault_with_device_secret(
    folder: &Path,
    device_uuid: &[u8; 16],
    device_secret: &[u8; 32],
    now_ms: u64,
) -> Result<OpenVaultOutput, FfiVaultError> {
    let secret = SecretBytes::new(device_secret.to_vec());
    let core_out = repair_vault(
        folder,
        Unlocker::DeviceSecret { device_uuid, secret: &secret },
        None,
        *device_uuid,
        now_ms,
        &mut OsRng,
    )?;
    enforce_rollback_resistance(&core_out)?;
    Ok(split_core_open_vault(core_out, folder.to_path_buf()))
}
```

Create `ffi/secretary-ffi-bridge/src/repair/mod.rs`:

```rust
//! `repair_vault` FFI projection (#374). See [`orchestration`].
mod orchestration;
pub use orchestration::{
    repair_vault_with_device_secret, repair_vault_with_password, repair_vault_with_recovery,
};

#[cfg(test)]
mod tests;
```

In `ffi/secretary-ffi-bridge/src/lib.rs`, add `pub mod repair;` and re-export the three fns alongside the existing `open_vault_with_*` re-exports (grep `open_vault_with_password` in lib.rs to find the re-export site).

- [ ] **Step 2: Write the integration tests**

Create `ffi/secretary-ffi-bridge/src/repair/tests.rs`. Model the crash-residue staging on `core/tests/crash_recovery.rs::repair_vault_adopts_interrupted_save` but drive through the bridge fns. Use the bridge's own test fixtures (grep the bridge test tree for an existing helper that creates a fast vault + saves a block via the bridge, e.g. in `src/save/` or `src/vault/tests.rs`; reuse it). Minimum cases:

```rust
// 1. happy-adopt (password arm): stage crashed save residue, assert
//    open_vault_with_password errs FfiVaultError::VaultNeedsRepair,
//    then repair_vault_with_password returns Ok and a re-open succeeds.
// 2. happy-adopt (device-secret arm): enroll a slot via the bridge's
//    add_device_slot projection, stage residue, repair via
//    repair_vault_with_device_secret → Ok.
// 3. rejected (recipient widening): stage a residue whose recipient set
//    ADDS a recipient; assert repair_vault_with_password errs
//    FfiVaultError::RepairRejected and detail mentions the added recipient.
// 4. idempotent: repair_vault_with_password on a HEALTHY vault returns Ok
//    and writes no new manifest fingerprint change.
```

Write these as real `#[test]` fns with concrete staging (copy the residue-staging sequence from `crash_recovery.rs`; the bridge test can call `secretary_core::vault::save_block` directly to stage, then assert via the bridge `repair_*` fns). Keep the file focused; if it approaches 500 lines, split staging helpers into a `repair/test_support.rs`.

- [ ] **Step 3: Run — expect the new tests to drive the behavior**

Run: `cargo test --release -p secretary-ffi-bridge repair`
Expected: the happy-adopt tests PASS; the rejected test PASSES asserting `RepairRejected`. Any failure here is a real integration finding — investigate, don't weaken.

- [ ] **Step 4: Clippy + doc**

Run:
```bash
cargo clippy --release -p secretary-ffi-bridge --tests -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps -p secretary-ffi-bridge
```
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add ffi/secretary-ffi-bridge/src/repair ffi/secretary-ffi-bridge/src/lib.rs
git commit -m "feat(ffi-bridge): project repair_vault (password/recovery/device arms) (#374)"
```

---

## Task 4: uniffi repair functions

**Files:**
- Modify: `ffi/secretary-ffi-uniffi/src/secretary.udl` (3 namespace fns)
- Modify: `ffi/secretary-ffi-uniffi/src/namespace/mod.rs` (or new `namespace/repair.rs`)
- Modify: `ffi/secretary-ffi-uniffi/src/lib.rs` (re-exports)

**Interfaces:**
- Consumes: bridge `repair_vault_with_{password,recovery,device_secret}` (Task 3); the credential-length validation + zeroize pattern from the existing `open_with_*` wrappers.
- Produces: uniffi namespace fns `repair_with_password` / `repair_with_recovery` / `repair_with_device_secret` returning `OpenVaultOutput`.

- [ ] **Step 1: Add the three udl namespace declarations**

In `ffi/secretary-ffi-uniffi/src/secretary.udl`, next to `open_with_device_secret` (line ~281) and the `open_with_*` decls, add (match the exact udl types used by `save_block`/`open_with_device_secret` — `bytes`, `u64`):

```
    [Throws=VaultError]
    OpenVaultOutput repair_with_password(bytes folder_path, bytes password, bytes device_uuid, u64 now_ms);
    [Throws=VaultError]
    OpenVaultOutput repair_with_recovery(bytes folder_path, bytes mnemonic, bytes device_uuid, u64 now_ms);
    [Throws=VaultError]
    OpenVaultOutput repair_with_device_secret(bytes folder_path, bytes device_uuid, bytes device_secret, u64 now_ms);
```

- [ ] **Step 2: Write the wrappers (TDD via the Rust host test)**

In `ffi/secretary-ffi-uniffi/src/namespace/mod.rs` (or a new `namespace/repair.rs` wired into `mod.rs` to keep files small), mirror `open_with_password` (line ~43) and `open_with_device_secret` for length validation + zeroize. Sketch:

```rust
pub fn repair_with_password(
    folder_path: Vec<u8>, password: Vec<u8>, device_uuid: Vec<u8>, now_ms: u64,
) -> Result<OpenVaultOutput, VaultError> {
    let uuid = to_array_16(&device_uuid)?; // returns VaultError::InvalidArgument on wrong len
    let folder = path_from_bytes(&folder_path);
    let out = secretary_ffi_bridge::repair_vault_with_password(&folder, &password, &uuid, now_ms)?;
    Ok(out.into())
    // zeroize the local device_uuid array + rely on Vec drop for password per the
    // existing open_with_password discipline (copy its exact pattern).
}
```

Do the same for recovery (`mnemonic: Vec<u8>`) and device_secret (validate both the 16-byte uuid and 32-byte secret → `InvalidArgument`; zeroize the 32-byte stack array). Reuse whatever `to_array_16`/`InvalidArgument` helper the existing `open_with_device_secret` wrapper uses — grep `open_with_device_secret` in `namespace/`.

Add the three fns to the `uniffi::include_scaffolding!`/re-export surface in `lib.rs` (line ~71 lists `open_with_device_secret, open_with_password` — add the three repair fns there).

- [ ] **Step 3: Compile the uniffi crate**

Run: `cargo test --release -p secretary-ffi-uniffi`
Expected: PASS (udl + wrappers compile; the udl-checker validates the new decls against the Rust fns).

- [ ] **Step 4: Run both conformance scripts again (smoke that the binding still loads)**

Run:
```bash
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
```
Expected: PASS (regenerated bindings expose the new fns; existing conformance unaffected).

- [ ] **Step 5: Commit**

```bash
git add ffi/secretary-ffi-uniffi
git commit -m "feat(ffi-uniffi): repair_with_{password,recovery,device_secret} (#374)"
```

---

## Task 5: pyo3 repair functions + pytest

**Files:**
- Create: `ffi/secretary-ffi-py/src/repair.rs`
- Modify: `ffi/secretary-ffi-py/src/lib.rs`
- Create: `ffi/secretary-ffi-py/tests/test_repair.py`

**Interfaces:**
- Consumes: bridge `repair_vault_with_*` (Task 3); the `errors.rs` mapping (Task 2); the stack-copy+zeroize + `from_py_object` discipline from `ffi/secretary-ffi-py/src/device.rs`.
- Produces: Python module fns `repair_with_password` / `repair_with_recovery` / `repair_with_device_secret`.

- [ ] **Step 1: Write the pyo3 fns**

Create `ffi/secretary-ffi-py/src/repair.rs`, mirroring `device.rs::open_with_device_secret` (line ~222) for the `&[u8]`→`[u8; N]` validation, stack zeroize, and `map_err(map_ffi_vault_error)` pattern. Three `#[pyfunction]`s taking `folder: &[u8]` (or `PathBuf`, match `device.rs`), the credential(s), `device_uuid: &[u8]`, `now_ms: u64`, returning the same Python object `open_with_device_secret` returns (grep its return type). Follow [[project_secretary_pyo3_028_fromtopyobject_deprecation]] for any `#[pyclass]` args.

- [ ] **Step 2: Register the module fns**

In `ffi/secretary-ffi-py/src/lib.rs`, add `mod repair;` and register the three fns in the `#[pymodule]` (grep `open_with_device_secret` in lib.rs — add the three repair fns to the same `m.add_function(wrap_pyfunction!(...))` block).

- [ ] **Step 3: Write the failing pytest**

Create `ffi/secretary-ffi-py/tests/test_repair.py`. Model setup on the existing device-slot / save tests (grep `tests/` for one that builds a vault + saves a block). Cases:

```python
def test_repair_with_password_adopts_crashed_save(tmp_path):
    # build vault, save v1, snapshot manifest, save v2, restore v1 manifest
    # assert open raises the needs-repair exception
    # assert repair_with_password(...) succeeds and re-open works
    ...

def test_repair_rejects_recipient_widening(tmp_path):
    # stage a residue that adds a recipient
    # assert repair_with_password raises the RepairRejected exception
    ...
```

Use the exception classes registered in Task 2 (import them from the module; grep how `test_*` imports `VaultCorruptVault`).

- [ ] **Step 4: Build + run**

Per [[project_secretary_maturin_uv_cache.md]] iteration trap, if pytest sees a stale `.so`, nuke the venv + uv cache. Run the module's test command (grep the repo/CI for the maturin+pytest invocation — likely `uv run` with `maturin develop` first).
Expected: both tests PASS.

- [ ] **Step 5: Commit**

```bash
git add ffi/secretary-ffi-py
git commit -m "feat(ffi-py): repair_with_* + pytest (#374)"
```

---

## Task 6: Desktop backend — `repair_vault` command

**Files:**
- Create: `desktop/src-tauri/src/commands/repair.rs`
- Modify: `desktop/src-tauri/src/session.rs`, `.../commands/mod.rs`, `.../main.rs`

**Interfaces:**
- Consumes: bridge `repair_vault_with_password` (Task 3); `AppError::{VaultNeedsRepair,RepairRejected,PathNotApproved}` (Task 2); `VaultSession` approval-slot API (`is_path_approved`, `PathPurpose::VaultFolder`, `MatchMode::Exact`); `settings::load_or_create_device_uuid_in`; `validate_vault_path` (from `commands/unlock.rs` — may need to make it `pub(crate)`).
- Produces: Tauri command `repair_vault(state, folder_path, password) -> Result<ManifestDto, AppError>`; helpers `repair_vault_impl`, `read_vault_uuid_from_toml`.

- [ ] **Step 1: Write the failing test for `read_vault_uuid_from_toml`**

In `desktop/src-tauri/src/commands/repair.rs`, `#[cfg(test)] mod tests`:

```rust
#[test]
fn reads_vault_uuid_from_toml() {
    let temp = tempfile::tempdir().unwrap();
    // A minimal vault.toml carrying a known vault_uuid.
    std::fs::write(
        temp.path().join("vault.toml"),
        b"vault_uuid = \"1f3a4b2c-9d8e-4f7a-b6c5-1a2b3c4d5e6f\"\n",
    ).unwrap();
    let got = read_vault_uuid_from_toml(temp.path()).unwrap();
    assert_eq!(
        got,
        [0x1f,0x3a,0x4b,0x2c,0x9d,0x8e,0x4f,0x7a,0xb6,0xc5,0x1a,0x2b,0x3c,0x4d,0x5e,0x6f]
    );
}

#[test]
fn missing_vault_uuid_field_errors() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("vault.toml"), b"[kdf]\n").unwrap();
    assert!(read_vault_uuid_from_toml(temp.path()).is_err());
}
```

- [ ] **Step 2: Implement `read_vault_uuid_from_toml`**

Parse the plaintext `vault_uuid` TOML string → 16 bytes. Use the `toml` crate if it's already a desktop dep (grep `toml` in `desktop/src-tauri/Cargo.toml`); else read the line and parse the UUID. Decode the hyphenated UUID to `[u8; 16]` (grep the desktop/core for an existing hyphenated-UUID parser to reuse; do not hand-roll if one exists). Return `AppError::VaultCorrupt`/`AppError::Io` on malformed input.

```rust
pub(crate) fn read_vault_uuid_from_toml(folder: &Path) -> Result<[u8; 16], AppError> {
    let toml_path = folder.join("vault.toml");
    let text = std::fs::read_to_string(&toml_path).map_err(|e| AppError::Io {
        detail: format!("read vault.toml: {e}"),
    })?;
    let doc: toml::Value = text.parse().map_err(|e| AppError::VaultCorrupt {
        detail: format!("parse vault.toml: {e}"),
    })?;
    let uuid_str = doc.get("vault_uuid").and_then(|v| v.as_str()).ok_or(
        AppError::VaultCorrupt { detail: "vault.toml missing vault_uuid".into() },
    )?;
    parse_hyphenated_uuid(uuid_str) // reuse existing helper or a small local one
        .ok_or(AppError::VaultCorrupt { detail: "vault.toml vault_uuid malformed".into() })
}
```

Run: `cargo test --release -p <desktop-crate-name> read` → both tests PASS.

- [ ] **Step 3: Add `VaultSession::repair`**

In `desktop/src-tauri/src/session.rs`, add a `repair` method mirroring `unlock` (lines 179-224) but resolving `device_uuid` BEFORE the open (repair needs it as input) and calling the bridge repair fn:

```rust
pub fn repair(&mut self, folder: &Path, password: &[u8]) -> Result<(), AppError> {
    if self.inner.is_some() {
        return Err(AppError::AlreadyUnlocked);
    }
    let vault_uuid = crate::commands::repair::read_vault_uuid_from_toml(folder)?;
    let device_uuid =
        settings::load_or_create_device_uuid_in(&self.device_data_dir, &vault_uuid)?;
    let output = secretary_ffi_bridge::repair_vault_with_password(
        folder, password, &device_uuid, now_ms(),
    )?;
    // ... identical settings-load + self.inner = Some(UnlockedSession { ... }) +
    //     idle reset + approval-clear tail as `unlock` (copy it verbatim).
    Ok(())
}
```

(Factor the shared post-open tail out of `unlock` into a private `fn populate_unlocked(&mut self, output, folder)` if it reduces duplication — DRY; but only if it stays a clean single-responsibility helper.)

- [ ] **Step 4: Write the command + impl**

In `desktop/src-tauri/src/commands/repair.rs`, mirror `unlock.rs`:

```rust
#[tauri::command]
pub async fn repair_vault(
    state: State<'_, Mutex<VaultSession>>,
    folder_path: String,
    password: Password,
) -> Result<ManifestDto, AppError> {
    repair_vault_impl(state.inner(), &folder_path, password.expose())
}

pub fn repair_vault_impl(
    state: &Mutex<VaultSession>,
    folder_path: &str,
    password: &[u8],
) -> Result<ManifestDto, AppError> {
    let folder = PathBuf::from(folder_path);
    {
        let session = lock_session(state)?;
        if !session.is_path_approved(PathPurpose::VaultFolder, &folder, MatchMode::Exact) {
            return Err(AppError::PathNotApproved { path: folder_path.to_string() });
        }
    }
    validate_vault_path(&folder, folder_path)?; // make pub(crate) in unlock.rs
    let mut session = lock_session(state)?;
    session.repair(&folder, password)?;
    session.with_unlocked(|u| {
        Ok(ManifestDto::from_manifest_with_warnings(&u.manifest, u.pending_warnings.clone()))
    })
}
```

Add the unapproved-folder test (mirror `unlock.rs::unapproved_folder_is_rejected_before_validation`).

- [ ] **Step 5: Register the command**

In `desktop/src-tauri/src/commands/mod.rs` add `pub mod repair;`. In `desktop/src-tauri/src/main.rs`, add `commands::repair::repair_vault` to the `generate_handler!` list (grep `unlock_with_password` in main.rs).

- [ ] **Step 6: Build + test the backend**

Run: `cargo test --release -p <desktop-crate-name>` and `cargo clippy --release -p <desktop-crate-name> --tests -- -D warnings`
Expected: green (incl. the new repair tests).

- [ ] **Step 7: Commit**

```bash
git add desktop/src-tauri
git commit -m "feat(desktop): repair_vault command + session.repair + vault_uuid reader (#374)"
```

---

## Task 7: Desktop frontend — "repair now?" UX

**Files:**
- Modify: `desktop/src/lib/errors.ts`
- Modify: `desktop/src/lib/ipc/` (wrapper + `writeCommands.ts`)
- Modify: the unlock component (locate via grep)
- Create/Modify: vitest spec(s)

**Interfaces:**
- Consumes: backend `repair_vault` command; `AppError` wire codes `vault_needs_repair` / `repair_rejected` (Task 2 — confirm exact serde codes first).
- Produces: a repair affordance in the unlock flow.

- [ ] **Step 1: Confirm the exact wire codes**

Run: grep the Rust `AppError` serialization for how `VaultNeedsRepair`/`RepairRejected` serialize (Task 2 Step 7). Expected snake_case: `vault_needs_repair`, `repair_rejected`. Use those literal strings below.

- [ ] **Step 2: Add the two codes to `errors.ts`**

In `desktop/src/lib/errors.ts`, add to the code union (line ~16) and the discriminated map (line ~65), mirroring `path_not_approved`:

```ts
  // union of codes:
  'vault_needs_repair',
  'repair_rejected',
  // discriminated map:
  | { code: 'vault_needs_repair'; blockUuidHex: string }
  | { code: 'repair_rejected'; blockUuidHex: string; detail: string }
```

Add human-readable message rendering in the `switch` (~line 129) mirroring `path_not_approved` (the `vault_needs_repair` case is handled as an *affordance* in the component, not a hard error, but still needs a fallback message).

- [ ] **Step 3: Add the ipc wrapper + write classification**

Add a `repairVault(folderPath, password)` wrapper next to the `unlockWithPassword` wrapper (grep `unlock_with_password` in `desktop/src/lib/ipc/`). Classify `repair_vault` as a **write** in `desktop/src/lib/ipc/writeCommands.ts` (grep how `unlock_with_password` or a write command like `save_block` is listed). Run `pnpm test` to confirm the #280 classification test passes.

- [ ] **Step 4: Write the failing vitest for the unlock-flow affordance**

Locate the unlock component (grep `unlock_with_password`/`unlockWithPassword` under `desktop/src`). Add a vitest (mirror an existing component test) asserting:
- when `unlockWithPassword` rejects with `{ code: 'vault_needs_repair', blockUuidHex }`, the UI shows a "Repair now?" control (not a hard error);
- clicking it calls `repairVault` with the same folder + password;
- on `repairVault` success, the flow proceeds as a normal unlock;
- on `repairVault` reject `{ code: 'repair_rejected', detail }`, the UI shows `detail` and no auto-fix.

Beware the [[project_secretary_vitest_mockrejectedvalue_quirk]] — use `mockRejectedValueOnce`.

- [ ] **Step 5: Implement the affordance in the component**

In the unlock component's error handling, branch on `err.code === 'vault_needs_repair'` to render the repair control instead of the generic error; wire its click to `repairVault(folder, password)` reusing the password still bound to the form field. On `repair_rejected`, render `detail`. If a `.svelte` attribute is edited, run `pnpm svelte-check` ([[project_secretary_svelte_smartquote_svelte_check]]).

- [ ] **Step 6: Run frontend checks**

Run: `cd desktop && pnpm svelte-check && pnpm test`
Expected: 0 svelte-check errors; all vitest pass (incl. the new affordance test + the #280 classification).

- [ ] **Step 7: Commit**

```bash
git add desktop/src
git commit -m "feat(desktop): 'repair now?' unlock affordance wiring repair_vault (#374)"
```

---

## Task 8: Docs + handoff

**Files:**
- Modify: `README.md`, `ROADMAP.md`
- Create: `docs/handoffs/2026-07-03-repair-vault-ffi-374-shipped.md`; retarget `NEXT_SESSION.md`

- [ ] **Step 1: README + ROADMAP**

Update the status sections: `repair_vault` is now reachable via FFI (all three arms) + a desktop "repair now?" reference UX; #374 parts 1/2/4 done, part 3 (informed-consent superset adoption) deferred. Keep README brief (dot points) per [[feedback_readme_style]].

- [ ] **Step 2: Verify the full gate suite**

Run (from the worktree root):
```bash
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all --check
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
uv run core/tests/python/conformance.py
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
cd desktop && pnpm svelte-check && pnpm test
```
Expected: all green. Record the results in the handoff.

- [ ] **Step 3: Write the handoff + retarget the symlink**

Author `docs/handoffs/2026-07-03-repair-vault-ffi-374-shipped.md` per the /nextsession baton convention (shipped commits + SHAs, what's next with acceptance criteria, open decisions/risks, exact resume commands). Retarget: `ln -snf docs/handoffs/2026-07-03-repair-vault-ffi-374-shipped.md NEXT_SESSION.md`. Commit BOTH as one commit on the feature branch. [[feedback_next_session_in_pr]]

- [ ] **Step 4: Commit + open PR**

```bash
git add README.md ROADMAP.md docs/handoffs NEXT_SESSION.md
git commit -m "docs: repair_vault FFI + desktop UX shipped; #374 handoff"
git push -u origin feature/repair-vault-ffi-374
gh pr create --fill  # body ends with the 🤖 Generated-with line; PR says "Fixes #374"
```

Per [[feedback_baton_push_and_open_pr_default]] push + open the PR without asking (user merges).

---

## Self-Review (completed)

**Spec coverage:** Part 1 (bridge projection + typed errors) → Tasks 2+3+4+5. Part 2 (desktop UX) → Tasks 6+7. Part 4 (device-secret test) → Task 1. Part 3 explicitly deferred (spec non-goal). Every spec component maps to a task. ✔

**Placeholder scan:** Binding-specific boilerplate (pyo3 exception registration, udl field syntax, Swift/Kotlin `when`/`switch` syntax, the unlock component location) is cited as "mirror this exact sibling + grep" rather than fabricated, because those signatures aren't safely knowable without reading the files — the implementer reads the cited pattern. All *behavioral* code (core test, bridge fns, error variants, desktop impl) is concrete. ✔

**Type consistency:** `block_uuid_hex: String` / `detail: String` field names are identical across `FfiVaultError`, uniffi `VaultError`, and desktop `AppError`. The three bridge fn names (`repair_vault_with_password/recovery/device_secret`) are referenced identically in Tasks 3/4/5/6. Wire codes `vault_needs_repair`/`repair_rejected` are confirmed-then-used (Task 7 Step 1). ✔
