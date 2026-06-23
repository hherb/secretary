# restore_block signed-timestamp selection (#205) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `restore_block` select the trashed file whose filename suffix **equals** the signed `TrashEntry.tombstoned_at_ms`, instead of the largest (attacker-controlled) suffix — closing the authentic-but-stale rollback gap (#205).

**Architecture:** One core selection change in `restore_block`, a new typed `VaultError::RestoreTargetMissing` for the "authentic file absent, only stale/forged copies remain" case (folds to the existing `FfiVaultError::CorruptVault` — no new FFI variant), and a lockstep update to the normative spec §7.1. Two TDD regression tests pin the behaviour.

**Tech Stack:** Rust (stable, `cargo test --release --workspace`), `thiserror`, existing `core/tests/trash_restore.rs` integration-test fixtures.

## Global Constraints

- Stable Rust; build/test always `--release` (crypto crates are slow in debug).
- `#![forbid(unsafe_code)]` workspace-wide — introduce no `unsafe`.
- Clippy must stay clean: `cargo clippy --release --workspace --tests -- -D warnings`.
- Tests generate crypto values at runtime via existing fixtures — **no hardcoded key/nonce literals** (CodeQL tripwire).
- Spec (`docs/vault-format.md`) is normative and must change in lockstep with observable behaviour; `conformance.py` does **not** exercise restore (verified) so it needs no change.
- Working dir is the worktree `/Users/hherb/src/secretary/.worktrees/restore-signed-ts` on branch `feature/restore-block-signed-timestamp`. Use absolute paths or chain `cd` in one call (shell state does not persist between Bash calls).

---

### Task 1: Bind `restore_block` selection to the signed `tombstoned_at_ms`

**Files:**
- Modify: `core/src/vault/mod.rs` (add `VaultError::RestoreTargetMissing` after `RestoreVerificationFailed`, ~line 293)
- Modify: `core/src/vault/orchestrators.rs` (selection logic ~lines 2022-2050; restore_block rustdoc ~lines 1930-1955)
- Modify: `ffi/secretary-ffi-bridge/src/error/vault/mod.rs` (add `From` arm before the catch-all integrity group, ~line 475)
- Modify: `ffi/secretary-ffi-bridge/src/error/vault/tests.rs` (add mapping tripwire test)
- Test: `core/tests/trash_restore.rs` (two new tests; update one doc comment + the module doc)

**Interfaces:**
- Consumes: `secretary_core::vault::{open_vault, save_block, trash_block, restore_block, Unlocker, VaultError}`; fixtures `make_fast_vault`, `make_simple_plaintext`, `format_uuid_hyphenated` (all already in `trash_restore.rs`).
- Produces: `VaultError::RestoreTargetMissing { block_uuid: [u8; 16], expected_tombstoned_at_ms: u64 }`.

- [ ] **Step 1: Write the first failing test (larger-suffix forgery ignored)**

Append to `core/tests/trash_restore.rs`:

```rust
// ---------------------------------------------------------------------------
// restore_block — #205: selection binds to the signed tombstoned_at_ms
// ---------------------------------------------------------------------------

/// #205 regression: `restore_block` MUST select the trashed file whose
/// suffix equals the signed `TrashEntry.tombstoned_at_ms`, NOT the file
/// with the largest suffix. An attacker with write access to `trash/`
/// plants a forged copy with a LARGER suffix; the pre-#205 largest-suffix
/// selection would pick it (and, on a corrupt plant, fail to verify).
/// Equality selection picks the authentic file and purges the plant.
#[test]
fn restore_block_ignores_larger_suffix_forgery() {
    let (dir, _mnemonic, pw) = make_fast_vault(9, b"hunter2", "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0xc9; 32]);

    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let device_uuid = [0xd9; 16];
    let block_uuid = [0xb9; 16];
    let plaintext = make_simple_plaintext(block_uuid, "authentic-current");
    let recipients = vec![open.owner_card.clone()];
    save_block(
        folder, &mut open, plaintext, &recipients, device_uuid, 1_000, &mut rng,
    )
    .unwrap();

    let trash_ts = 5_000u64;
    trash_block(folder, &mut open, block_uuid, device_uuid, trash_ts, &mut rng).unwrap();

    // Capture the authentic trashed bytes (suffix == signed tombstoned_at_ms).
    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    let trash_dir = folder.join("trash");
    let authentic = trash_dir.join(format!("{uuid_hex}.cbor.enc.{trash_ts}"));
    let authentic_bytes = fs::read(&authentic).unwrap();

    // Plant a corrupt forgery with a LARGER suffix. The largest-suffix
    // selection (pre-#205) would pick this and fail verification.
    let forgery_ts = 9_000u64;
    let forgery = trash_dir.join(format!("{uuid_hex}.cbor.enc.{forgery_ts}"));
    let mut corrupt = authentic_bytes.clone();
    let mid = corrupt.len() / 2;
    corrupt[mid] ^= 0xff; // flip a byte → fails decode/hybrid-verify if selected
    fs::write(&forgery, &corrupt).unwrap();

    // Restore MUST succeed by selecting the authentic (signed-ts) file.
    restore_block(folder, &mut open, block_uuid, device_uuid, 10_000, &mut rng).unwrap();

    // The restored live file is byte-identical to the authentic trashed
    // file (rename is a move), proving the forgery was NOT selected.
    let restored = folder.join("blocks").join(format!("{uuid_hex}.cbor.enc"));
    assert_eq!(
        fs::read(&restored).unwrap(),
        authentic_bytes,
        "restored file must be the authentic signed-timestamp copy, not the larger-suffix forgery",
    );
    assert!(!forgery.exists(), "larger-suffix forgery must be purged");
    assert!(!authentic.exists(), "authentic copy moved out of trash/");
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /Users/hherb/src/secretary/.worktrees/restore-signed-ts && cargo test --release --workspace --test trash_restore restore_block_ignores_larger_suffix_forgery`
Expected: FAIL — current largest-suffix logic selects the corrupt `9000` file → `restore_block` returns `RestoreVerificationFailed`, the `.unwrap()` panics.

- [ ] **Step 3: Add the `RestoreTargetMissing` variant**

In `core/src/vault/mod.rs`, immediately after the `RestoreVerificationFailed { … }` variant (closing brace ~line 293), insert:

```rust
    /// `restore_block`: a signed `TrashEntry` exists for this `block_uuid`,
    /// and one or more `trash/<uuid>.cbor.enc.*` files are present, but
    /// NONE has a suffix equal to the entry's `tombstoned_at_ms`. The
    /// authentic-current trashed file — whose suffix MUST equal the signed
    /// timestamp by the `trash_block` construction — is absent (removed or
    /// renamed), leaving only stale or attacker-planted copies. Restoring
    /// any of those would resurrect authentic-but-stale content (#205), so
    /// restore halts; the manifest is NOT modified and `trash/` is NOT
    /// modified. Distinct from `BlockNotInTrash` (no signed record that the
    /// block was ever trashed, or no trash file at all).
    #[error(
        "restore target for block {block_uuid:?} is missing: no trashed file's \
         suffix matches the signed tombstoned_at_ms {expected_tombstoned_at_ms}"
    )]
    RestoreTargetMissing {
        block_uuid: [u8; 16],
        expected_tombstoned_at_ms: u64,
    },
```

- [ ] **Step 4: Add the FFI bridge `From` arm**

In `ffi/secretary-ffi-bridge/src/error/vault/mod.rs`, immediately after the `VE::RestoreVerificationFailed { … } => FfiVaultError::CorruptVault { … }` arm (~line 475), insert:

```rust
            // restore_block (#205): the file whose suffix equals the signed
            // tombstoned_at_ms is absent — a signed-data ↔ on-disk-bytes
            // integrity failure, folded to CorruptVault exactly like
            // RestoreVerificationFailed (no dedicated FFI variant; the §13
            // anti-oracle policy conflates integrity failures here).
            VE::RestoreTargetMissing { block_uuid, expected_tombstoned_at_ms } => {
                FfiVaultError::CorruptVault {
                    detail: format!(
                        "restore target for block {} is missing (expected tombstoned_at_ms {expected_tombstoned_at_ms})",
                        hex::encode(block_uuid),
                    ),
                }
            }
```

- [ ] **Step 5: Implement equality selection in `restore_block`**

In `core/src/vault/orchestrators.rs`, replace the existing block (the `trash_entry_present` let-binding through the `purge_targets` collection, ~lines 2022-2050):

```rust
    let trash_entry_present = open
        .manifest
        .trash
        .iter()
        .any(|t| t.block_uuid == block_uuid);

    // Step 3: pick restore target + purge targets. The §7.1 contract is
    // strict: ...
    if matches.is_empty() || !trash_entry_present {
        return Err(VaultError::BlockNotInTrash { block_uuid });
    }
    matches.sort_by_key(|(ts, _)| *ts);
    let (_restore_ts, restore_path) = matches.last().cloned().expect("non-empty checked above");
    let purge_targets: Vec<PathBuf> = matches
        .iter()
        .rev()
        .skip(1)
        .map(|(_, p)| p.clone())
        .collect();
```

with:

```rust
    // Step 3: bind selection to the signed TrashEntry.tombstoned_at_ms.
    // The authentic trashed file's filename suffix EQUALS this signed
    // value by construction — trash_block writes the file
    // `<uuid>.cbor.enc.<now_ms>` and the TrashEntry {tombstoned_at_ms:
    // now_ms} in the same operation. The suffix alone is unauthenticated
    // filename metadata an attacker with write access to trash/ can forge;
    // selecting the largest suffix would let a planted older-but-owner-
    // signed copy with a larger suffix be restored (authentic-but-stale
    // rollback, #205). We therefore select by EQUALITY to the signed
    // timestamp, not by largest suffix.
    //
    // Error precedence:
    //   - no signed TrashEntry            → BlockNotInTrash (as before)
    //   - signed entry, but no trash file → BlockNotInTrash (as before)
    //   - signed entry, files present, but none with suffix == signed ts
    //                                     → RestoreTargetMissing (#205)
    let expected_ts = match open
        .manifest
        .trash
        .iter()
        .find(|t| t.block_uuid == block_uuid)
    {
        Some(entry) => entry.tombstoned_at_ms,
        None => return Err(VaultError::BlockNotInTrash { block_uuid }),
    };
    if matches.is_empty() {
        return Err(VaultError::BlockNotInTrash { block_uuid });
    }
    // At most one file can match — suffix ↔ filename is 1:1.
    let Some(restore_path) = matches
        .iter()
        .find(|(ts, _)| *ts == expected_ts)
        .map(|(_, p)| p.clone())
    else {
        return Err(VaultError::RestoreTargetMissing {
            block_uuid,
            expected_tombstoned_at_ms: expected_ts,
        });
    };
    // Purge targets = every other match (older stale copies AND larger-
    // suffix attacker plants).
    let purge_targets: Vec<PathBuf> = matches
        .iter()
        .filter(|(ts, _)| *ts != expected_ts)
        .map(|(_, p)| p.clone())
        .collect();
```

- [ ] **Step 6: Run the first test to verify it passes**

Run: `cd /Users/hherb/src/secretary/.worktrees/restore-signed-ts && cargo test --release --workspace --test trash_restore restore_block_ignores_larger_suffix_forgery`
Expected: PASS.

- [ ] **Step 7: Write the second test (RestoreTargetMissing rejection)**

Append to `core/tests/trash_restore.rs`:

```rust
/// #205: when a signed `TrashEntry` exists and trash files are present
/// but NONE has a suffix equal to the signed `tombstoned_at_ms` (the
/// authentic file was renamed to a larger suffix, leaving only a planted
/// — but genuinely owner-signed — copy), `restore_block` rejects with
/// `RestoreTargetMissing` rather than silently restoring the stale copy.
/// On the pre-#205 largest-suffix logic this would succeed (the rollback),
/// so this test also pins the security fix.
#[test]
fn restore_block_missing_signed_target_rejected() {
    let (dir, _mnemonic, pw) = make_fast_vault(10, b"hunter2", "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0xca; 32]);

    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let device_uuid = [0xda; 16];
    let block_uuid = [0xba; 16];
    let plaintext = make_simple_plaintext(block_uuid, "authentic");
    let recipients = vec![open.owner_card.clone()];
    save_block(
        folder, &mut open, plaintext, &recipients, device_uuid, 1_000, &mut rng,
    )
    .unwrap();

    let trash_ts = 5_000u64;
    trash_block(folder, &mut open, block_uuid, device_uuid, trash_ts, &mut rng).unwrap();

    // Attacker renames the authentic file to a LARGER suffix, removing the
    // suffix == signed tombstoned_at_ms file. Only a non-matching (but
    // genuinely owner-signed) copy remains; the manifest's signed
    // TrashEntry still says tombstoned_at_ms = 5000.
    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    let trash_dir = folder.join("trash");
    let authentic = trash_dir.join(format!("{uuid_hex}.cbor.enc.{trash_ts}"));
    let planted = trash_dir.join(format!("{uuid_hex}.cbor.enc.9000"));
    fs::rename(&authentic, &planted).unwrap();

    let err = restore_block(folder, &mut open, block_uuid, device_uuid, 10_000, &mut rng)
        .expect_err("restore must reject when no file matches the signed timestamp");
    assert!(
        matches!(
            err,
            VaultError::RestoreTargetMissing { block_uuid: b, expected_tombstoned_at_ms }
                if b == block_uuid && expected_tombstoned_at_ms == trash_ts
        ),
        "expected RestoreTargetMissing {{ expected_tombstoned_at_ms: {trash_ts} }}, got {err:?}",
    );
    // Manifest untouched: the TrashEntry is still present, no live BlockEntry.
    assert!(
        open.manifest.trash.iter().any(|t| t.block_uuid == block_uuid),
        "TrashEntry must remain after a rejected restore",
    );
    assert!(
        !open.manifest.blocks.iter().any(|b| b.block_uuid == block_uuid),
        "no BlockEntry must be created on a rejected restore",
    );
}
```

- [ ] **Step 8: Run the second test to verify it passes**

Run: `cd /Users/hherb/src/secretary/.worktrees/restore-signed-ts && cargo test --release --workspace --test trash_restore restore_block_missing_signed_target_rejected`
Expected: PASS.

- [ ] **Step 9: Add the FFI mapping tripwire test**

Append to `ffi/secretary-ffi-bridge/src/error/vault/tests.rs` (mirrors `from_core_vault_error_kdf_params_mismatch_maps_to_corrupt_vault`):

```rust
#[test]
fn from_core_vault_error_restore_target_missing_maps_to_corrupt_vault() {
    // #205: restore_block's signed-timestamp file is absent — a
    // signed-data ↔ on-disk-bytes integrity failure, folded to
    // CorruptVault like RestoreVerificationFailed (no dedicated FFI variant).
    let core_err = VaultError::RestoreTargetMissing {
        block_uuid: [0x11; 16],
        expected_tombstoned_at_ms: 1_714_060_900_000,
    };
    let ffi: FfiVaultError = core_err.into();
    assert!(matches!(ffi, FfiVaultError::CorruptVault { .. }));
}
```

- [ ] **Step 10: Update stale doc comments to match the new selection**

In `core/tests/trash_restore.rs`:
- Module doc (~line 7): change `scans `trash/<uuid>.cbor.enc.*`, picks the largest-timestamp file,` to `scans `trash/<uuid>.cbor.enc.*`, picks the file whose suffix matches the signed `TrashEntry.tombstoned_at_ms`,`.
- The `restore_block_purges_older_copies` doc comment (~line 453-456): change `restore_block` picks the newest timestamp and physically` to `restore_block` picks the file matching the signed `tombstoned_at_ms` (here the newest) and physically` (the test fixture's authentic file is suffix `4000` == the signed ts, so the existing assertions still hold).

In `core/src/vault/orchestrators.rs`, scan the `restore_block` rustdoc (~lines 1900-1955) and the inline step comments for any "largest suffix"/"largest-timestamp" phrasing and reword to "the file whose suffix equals the signed `tombstoned_at_ms`". (At minimum the function-level doc and the Step 2 scan comment block at ~line 1998-2007 referencing "largest-canonical-timestamp match in step 4".)

- [ ] **Step 11: Run the full workspace suite + clippy**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/restore-signed-ts
cargo test --release --workspace 2>&1 | tail -20
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -10
```
Expected: all test binaries pass (0 failed), clippy clean. If any *other* no-catch-all `VaultError` match fails to compile, thread it with a deliberate routing decision (none expected beyond the bridge `From`).

- [ ] **Step 12: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/restore-signed-ts
cargo fmt --all
git add core/src/vault/mod.rs core/src/vault/orchestrators.rs \
        ffi/secretary-ffi-bridge/src/error/vault/mod.rs \
        ffi/secretary-ffi-bridge/src/error/vault/tests.rs \
        core/tests/trash_restore.rs
git commit -m "fix(vault): bind restore_block selection to signed tombstoned_at_ms (#205)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Update the normative spec §7.1 in lockstep

**Files:**
- Modify: `docs/vault-format.md` §7.1 (steps 1-3, ~lines 471-473)

**Interfaces:**
- Consumes: nothing (documentation).
- Produces: spec text matching the Task 1 behaviour.

- [ ] **Step 1: Rewrite step 2 (selection)**

In `docs/vault-format.md`, replace step 2 of §7.1 (~line 472):

```
2. Pick the file with the **largest** suffix as the *restore target*. All other matching files are *purge targets*.
```

with:

```
2. Pick the file whose suffix **equals** the manifest's signed `TrashEntry.tombstoned_at_ms` as the *restore target*. All other matching files (older stale copies **and** any larger-suffix copies) are *purge targets*. The authentic-current trashed file's suffix equals the signed `tombstoned_at_ms` by construction (§7 writes the file and the `TrashEntry` together). The largest-suffix file is **not** trusted: the suffix is unauthenticated filename metadata that a malicious sync-folder host can forge, so binding selection to the signed timestamp is what prevents an attacker-planted larger-suffix copy from being restored as authentic-but-stale content. If **no** file's suffix equals the signed `tombstoned_at_ms`, restore **fails** — the authentic-current trashed file is missing (removed or renamed), and only stale or planted copies remain.
```

- [ ] **Step 2: Reword the step 1 and step 3 references to "largest"**

In §7.1:
- Step 1 (~line 471), closing sentence: change `Correctness is still gated by the §6.1 hybrid verify in step 3 on the largest-canonical-timestamp file.` to `Correctness is still gated by the §6.1 hybrid verify in step 3 on the file whose suffix equals the signed `TrashEntry.tombstoned_at_ms`.`
- Step 3 (~line 473): change `Read the restore-target's bytes.` is fine as-is, but if it names "largest", reword "largest-canonical-timestamp file" → "selected restore-target file".

- [ ] **Step 3: Verify no other "largest suffix" references remain in the spec**

Run: `cd /Users/hherb/src/secretary/.worktrees/restore-signed-ts && grep -n "largest" docs/vault-format.md`
Expected: no remaining reference describing restore selection by largest suffix (any survivors must be reworded or confirmed unrelated).

- [ ] **Step 4: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/restore-signed-ts
git add docs/vault-format.md
git commit -m "docs(vault-format): §7.1 restore selects signed tombstoned_at_ms, not largest suffix (#205)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage:**
- Core selection change → Task 1 Steps 5, 6.
- New `RestoreTargetMissing` variant → Task 1 Step 3; tested Step 7-8.
- FFI fold to `CorruptVault` (no new variant) → Task 1 Steps 4, 9.
- Spec §7.1 lockstep → Task 2.
- Two TDD tests → Task 1 Steps 1-2 (forgery ignored), 7-8 (missing target rejected).
- Existing-test/comment drift → Task 1 Step 10.
- `conformance.py` unaffected (restore not exercised) → noted in Global Constraints; no task needed.

**Placeholder scan:** none — every code step shows full code; every run step shows the command and expected result.

**Type consistency:** `RestoreTargetMissing { block_uuid: [u8; 16], expected_tombstoned_at_ms: u64 }` is identical across the variant definition (Task 1 Step 3), the core selection return (Step 5), the core test matcher (Step 7), and the FFI arm + mapping test (Steps 4, 9). `restore_block`/`trash_block`/`save_block` signatures match the existing `trash_restore.rs` call sites verbatim.
