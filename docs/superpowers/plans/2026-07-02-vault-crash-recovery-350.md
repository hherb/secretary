# Vault Crash-Recovery-on-Open (#350) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a crash between a block-file operation and its manifest write recoverable: reorder `trash_block` to manifest-first, sweep interrupted trash renames at open, and add an explicit `repair_vault` orchestrator that adopts owner-signed, clock-advancing on-disk blocks after a `save_block`/re-key crash.

**Architecture:** Approved design at `docs/superpowers/specs/2026-07-02-vault-crash-recovery-350-design.md` (READ IT FIRST — it is the contract). Core + spec only; two new `VaultError` variants fold to existing `FfiVaultError` variants across the bridge (no FFI surface change). New module `core/src/vault/repair.rs` holds the sweep + `repair_vault`; `orchestrators.rs` (2788 lines already) donates `pub(crate)` helpers rather than growing.

**Tech Stack:** stable Rust workspace, `thiserror`, `proptest`-free (plain `#[test]`s), tempfile-based integration tests.

## Global Constraints

- Build/test always `--release`: `cargo test --release --workspace` (crypto crates are unusable in debug).
- `cargo clippy --release --workspace --tests -- -D warnings` must stay clean; `cargo fmt --all` before every commit; `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace` must stay clean.
- `#![forbid(unsafe_code)]` — no unsafe anywhere.
- Zeroize discipline: any stack copy of secret-key bytes (`*….expose()`) must be `.zeroize()`d after moving into a `Sensitive` holder (pattern in `trash_block` step 7 / `restore_block` step 11).
- Tests must NOT hardcode crypto literals as keys/nonces (CodeQL); derive from a seeded `ChaCha20Rng` like `make_fast_vault` does.
- Never modify `core/tests/data/` fixtures; copy `golden_vault_001` to a tempdir when needed (in-file unit tests already have `open_golden_vault_manifest_inline` for this).
- Work in `/Users/hherb/src/secretary/.worktrees/vault-crash-recovery-350` on branch `feature/vault-crash-recovery-350`. Shell state does not persist between Bash calls — `cd` and the command must be chained in ONE call, and Edit/Write/Read tool paths must spell out `.worktrees/vault-crash-recovery-350/` (a bare `/Users/hherb/src/secretary/core/...` path would silently edit the MAIN checkout).
- Commit after every task (message style: `feat(core): …` / `test(core): …` / `docs: …`), ending with the `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` trailer.

**Key file coordinates (verified 2026-07-02 on `main`@`a5d1b04`):**
- `VaultError` enum: `core/src/vault/mod.rs:76` (closes ~line 361; `BlockFingerprintMismatch` at 337-360; `RestoreVerificationFailed` at 297-307; Display-pin test `block_fingerprint_mismatch_display_is_stable` at 367-383). NOT `#[non_exhaustive]`.
- `open_vault`: `core/src/vault/orchestrators.rs:511`; unlock arm 516-553; `verify_block_fingerprints` 684-706; `trash_block` 1932-2032; `restore_block` 2077-2474 (recipient resolution inline at 2299-2371); `tick_clock` 867-882 (private).
- Six exhaustive bridge matches to extend (each has a fold arm listing every remaining variant): `ffi/secretary-ffi-bridge/src/error/vault/mod.rs:348` (fold 508-532 → `CorruptVault`), `save/orchestration.rs:163`, `share/orchestration.rs:230`, `revoke/orchestration.rs:181`, `trash/orchestration.rs:100`, `restore/orchestration.rs:97` (folds → `SaveCryptoFailure`).
- Clock helper: `core/src/vault/conflict.rs:105` `pub fn clock_relation(local, incoming) -> ClockRelation` (`Equal` / `IncomingDominates` / `IncomingDominated` / `Concurrent`), re-exported from `secretary_core::vault`.
- `Manifest`/`BlockEntry`/`TrashEntry` all derive `Clone` (manifest.rs:334/361/387). `blake3_hash` = `use crate::crypto::hash::hash as blake3_hash;`. `Fingerprint = [u8; 16]`.

---

### Task 1: `VaultError::{BlockFileMissing, RepairRejected}` + bridge fold sweep

**Files:**
- Modify: `core/src/vault/mod.rs` (variants ~line 360, Display tests ~line 383)
- Modify: `ffi/secretary-ffi-bridge/src/error/vault/mod.rs:508-532`
- Modify: `ffi/secretary-ffi-bridge/src/{save,share,revoke,trash,restore}/orchestration.rs` (fold-arm heads)

**Interfaces:**
- Produces: `VaultError::BlockFileMissing { block_uuid: [u8; 16] }` and `VaultError::RepairRejected { block_uuid: [u8; 16], detail: String }`, both folding to `FfiVaultError::CorruptVault` (generic mapper) / `SaveCryptoFailure` (write-path mappers).

- [ ] **Step 1: Write the failing Display-pin tests** in the existing `mod tests` of `core/src/vault/mod.rs`, mirroring `block_fingerprint_mismatch_display_is_stable`:

```rust
    /// Pins the Display shape of `BlockFileMissing` (#350): the message
    /// must carry the failing block's UUID so operators can identify
    /// the missing file from a log line alone (#88).
    #[test]
    fn block_file_missing_display_is_stable() {
        let err = VaultError::BlockFileMissing {
            block_uuid: [0xAB; 16],
        };
        let msg = err.to_string();
        assert!(msg.contains("file missing"), "got: {msg}");
        assert!(msg.contains("ab"), "uuid hex must appear: {msg}");
    }

    /// Pins the Display shape of `RepairRejected` (#350): uuid + the
    /// gate-failure detail must both surface.
    #[test]
    fn repair_rejected_display_is_stable() {
        let err = VaultError::RepairRejected {
            block_uuid: [0xCD; 16],
            detail: "clock relation Concurrent".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("repair rejected"), "got: {msg}");
        assert!(msg.contains("cd"), "uuid hex must appear: {msg}");
        assert!(msg.contains("Concurrent"), "detail must appear: {msg}");
    }
```

- [ ] **Step 2: Run to verify failure (compile error — variants don't exist)**

Run: `cd /Users/hherb/src/secretary/.worktrees/vault-crash-recovery-350 && cargo test --release -p secretary-core --lib block_file_missing_display 2>&1 | tail -20`
Expected: FAIL — `no variant named BlockFileMissing`.

- [ ] **Step 3: Add the two variants** in `core/src/vault/mod.rs`, immediately after `BlockFingerprintMismatch` (after line 360), matching house doc style:

```rust
    /// A manifest-listed block file is absent from `blocks/` (#350).
    ///
    /// Typed replacement for the anonymous `Io(NotFound)` the
    /// fingerprint check used to produce — carries the failing block's
    /// UUID (closes the missing-file half of the #88 debuggability
    /// gap). NOT repairable by [`repair_vault`]: repair cannot invent
    /// bytes. The likely cause is a torn cloud sync that delivered the
    /// manifest before the block file; recovery is to retry after the
    /// sync completes.
    ///
    /// [`repair_vault`]: crate::vault::repair_vault
    #[error("block {block_uuid:02x?} file missing from blocks/")]
    BlockFileMissing { block_uuid: [u8; 16] },

    /// [`repair_vault`](crate::vault::repair_vault) refused to adopt an
    /// on-disk block whose fingerprint mismatches the manifest (#350).
    ///
    /// Adoption is gated on hybrid verify (Ed25519 ∧ ML-DSA-65) ∧
    /// strict clock dominance ∧ header cross-checks ∧ recipient
    /// resolution; `detail` names the failed gate. Repair is
    /// all-or-nothing — when any block is rejected the manifest is not
    /// written.
    #[error("repair rejected for block {block_uuid:02x?}: {detail}")]
    RepairRejected {
        block_uuid: [u8; 16],
        detail: String,
    },
```

(Note: the `[repair_vault]` intra-doc links only resolve after Task 6 exports it; use plain text `repair_vault` in the doc comments for THIS task and upgrade to intra-doc links in Task 6, so `cargo doc -D warnings` stays green at every commit.)

- [ ] **Step 4: Run lib tests — pass; workspace build — fails in bridge**

Run: `cargo test --release -p secretary-core --lib vault::tests 2>&1 | tail -5` → new tests PASS.
Run: `cargo build --release --workspace 2>&1 | grep -c "non-exhaustive patterns\|not covered"` → non-zero (six matches broken; this breakage is the #40 design working as intended).

- [ ] **Step 5: Extend the six fold-arm heads.** In each mapper, add the two variants to the existing `e @ (… | VE::ContactCardUuidMismatch { .. } | VE::BlockFingerprintMismatch { .. })` head, keeping list order (append after `BlockFingerprintMismatch { .. }`):

```rust
                | VE::BlockFingerprintMismatch { .. }
                | VE::BlockFileMissing { .. }
                | VE::RepairRejected { .. })
```

Locations: `error/vault/mod.rs` fold arm (508-532, maps to `FfiVaultError::CorruptVault`), and the `SaveCryptoFailure` fold arms in `save/orchestration.rs` (168-201), `share/orchestration.rs` (251-279), `revoke/orchestration.rs` (203-229), `trash/orchestration.rs` (115-147), `restore/orchestration.rs` (142-168). Do NOT add new `FfiVaultError` variants (that would break the Swift/Kotlin conformance harnesses — out of scope by design).

- [ ] **Step 6: Full verify + commit**

Run: `cargo test --release --workspace 2>&1 | tail -5` → 0 failures. `cargo clippy --release --workspace --tests -- -D warnings` → clean. `cargo fmt --all`.

```bash
git add core/src/vault/mod.rs ffi/secretary-ffi-bridge/src
git commit -m "feat(core): typed BlockFileMissing + RepairRejected VaultError variants (#350)"
```

---

### Task 2: `verify_block_fingerprints` surfaces `BlockFileMissing`

**Files:**
- Modify: `core/src/vault/orchestrators.rs:684-706` (fn + doc comment) and the pinned unit test at ~2659-2694

**Interfaces:**
- Consumes: `VaultError::BlockFileMissing` (Task 1).
- Produces: `open_vault` on a manifest-listed-but-absent block now fails `BlockFileMissing { block_uuid }` instead of anonymous `Io`.

- [ ] **Step 1: Flip the pinned test** `verify_block_fingerprints_io_error_on_missing_block` (orchestrators.rs ~2666 — its own doc comment says to flip it when the typed variant lands). Rename and rewrite:

```rust
    /// #350/#88: a missing block file surfaces as the UUID-tagged
    /// `BlockFileMissing`, not an anonymous `Io(NotFound)`. Other I/O
    /// failures (permissions, etc.) still surface as `VaultError::Io`.
    #[test]
    fn verify_block_fingerprints_missing_block_is_typed() {
        let (folder, _tmp, manifest) = open_golden_vault_manifest_inline();
        let block_uuid = manifest.blocks[0].block_uuid;
        let block_path = folder.join(BLOCKS_SUBDIR).join(format!(
            "{}{}",
            format_uuid_hyphenated(&block_uuid),
            BLOCK_FILE_EXTENSION
        ));
        std::fs::remove_file(&block_path).expect("remove block file");

        let err = verify_block_fingerprints(&folder, &manifest)
            .expect_err("missing block file must surface an error");
        match err {
            VaultError::BlockFileMissing { block_uuid: got } => {
                assert_eq!(got, block_uuid, "error must carry the failing uuid");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --release -p secretary-core --lib verify_block_fingerprints_missing 2>&1 | tail -10`
Expected: FAIL — still gets `Io`.

- [ ] **Step 3: Implement** — replace the `std::fs::read` mapping inside `verify_block_fingerprints` (line ~692):

```rust
        let bytes = std::fs::read(&block_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                // #350/#88: a listed-but-absent block gets a typed,
                // uuid-carrying error. Not repairable — see the
                // variant's doc; recovery is a completed sync.
                VaultError::BlockFileMissing {
                    block_uuid: entry.block_uuid,
                }
            } else {
                VaultError::Io {
                    context: "failed to read block file for fingerprint check",
                    source: e,
                }
            }
        })?;
```

Update the fn's doc comment: the "On the I/O failure path …" paragraph (684-680 region) now says NotFound → `BlockFileMissing` (uuid-tagged); other kinds remain `Io` with the #88 note scoped to those.

- [ ] **Step 4: Run test suite**

Run: `cargo test --release --workspace 2>&1 | tail -5` → 0 failures (grep the run for any OTHER test asserting the old context string: `grep -rn "failed to read block file" core/ ffi/` must only hit the fn itself).

- [ ] **Step 5: Commit**

```bash
git add core/src/vault/orchestrators.rs
git commit -m "feat(core): verify_block_fingerprints types missing block files as BlockFileMissing (#350, #88)"
```

---

### Task 3: `trash_block` manifest-first with staged in-memory commit

**Files:**
- Modify: `core/src/vault/orchestrators.rs:1893-2032` (`trash_block` + its doc comment; `TRASH_SUBDIR` const → `pub(crate)`)
- Test: `core/tests/trash_restore.rs` (append)

**Interfaces:**
- Consumes: nothing new.
- Produces: `trash_block`'s manifest write is the commit point; the physical rename is best-effort (failure still `Ok`). On `Err`, `open.manifest`/`open.manifest_file` are genuinely untouched. `pub(crate) const TRASH_SUBDIR: &str = "trash";` (Task 4 uses it).

- [ ] **Step 1: Write the two failing tests** (append to `core/tests/trash_restore.rs`; both `#[cfg(unix)]` since they use permission bits):

```rust
// ---------------------------------------------------------------------------
// trash_block — #350 manifest-first ordering
// ---------------------------------------------------------------------------

/// #350: the manifest write is the commit point; the physical rename is
/// best-effort. With `trash/` unwritable the rename must fail, yet
/// trash_block returns Ok, the on-disk manifest carries the TrashEntry,
/// the block file is still in `blocks/`, the vault re-opens, and
/// restore_block resumes from the un-moved `blocks/` file (#351 path).
#[cfg(unix)]
#[test]
fn trash_block_rename_failure_still_commits_manifest() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, _mnemonic, pw) = make_fast_vault(41, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x41; 32]);
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let device_uuid = [0xd4; 16];
    let block_uuid = [0xb4; 16];
    let plaintext = make_simple_plaintext(block_uuid, "sticky");
    let recipients = vec![open.owner_card.clone()];
    save_block(folder, &mut open, plaintext, &recipients, device_uuid, 1_000, &mut rng).unwrap();

    // Pre-create trash/ read-only so the rename (NOT the manifest write) fails.
    let trash_dir = folder.join("trash");
    fs::create_dir_all(&trash_dir).unwrap();
    fs::set_permissions(&trash_dir, fs::Permissions::from_mode(0o555)).unwrap();

    trash_block(folder, &mut open, block_uuid, device_uuid, 2_000, &mut rng)
        .expect("manifest committed => trash succeeds despite rename failure");

    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    assert!(
        folder.join("blocks").join(format!("{uuid_hex}.cbor.enc")).is_file(),
        "physical move failed, file must still be in blocks/"
    );
    assert!(open.manifest.trash.iter().any(|t| t.block_uuid == block_uuid));
    assert!(!open.manifest.blocks.iter().any(|b| b.block_uuid == block_uuid));

    // The vault re-opens (orphan blocks/ file is not manifest-listed)…
    drop(open);
    let mut reopened = open_vault(folder, Unlocker::Password(&pw), None)
        .expect("residue must not wedge open (#350)");
    // …and restore resumes from the un-moved blocks/ file.
    restore_block(folder, &mut reopened, block_uuid, device_uuid, 3_000, &mut rng)
        .expect("restore must resume from blocks/ (#351 shape)");
    assert!(reopened.manifest.blocks.iter().any(|b| b.block_uuid == block_uuid));

    fs::set_permissions(&trash_dir, fs::Permissions::from_mode(0o755)).unwrap();
}

/// #350: on a manifest-write failure trash_block returns Err and the
/// in-memory `open.manifest` / `open.manifest_file` are UNTOUCHED (the
/// previously-documented-but-false contract), and the block file was
/// not renamed (proving manifest-first ordering).
#[cfg(unix)]
#[test]
fn trash_block_manifest_write_failure_leaves_state_untouched() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, _mnemonic, pw) = make_fast_vault(42, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x42; 32]);
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let device_uuid = [0xd5; 16];
    let block_uuid = [0xb5; 16];
    let plaintext = make_simple_plaintext(block_uuid, "untouched");
    let recipients = vec![open.owner_card.clone()];
    save_block(folder, &mut open, plaintext, &recipients, device_uuid, 1_000, &mut rng).unwrap();

    let blocks_before = open.manifest.blocks.clone();
    let trash_before = open.manifest.trash.clone();
    let clock_before = open.manifest.vector_clock.clone();

    // Read-only vault folder: write_atomic cannot create its tempfile.
    fs::set_permissions(folder, fs::Permissions::from_mode(0o555)).unwrap();
    let err = trash_block(folder, &mut open, block_uuid, device_uuid, 2_000, &mut rng)
        .expect_err("manifest write must fail in a read-only folder");
    fs::set_permissions(folder, fs::Permissions::from_mode(0o755)).unwrap();

    assert!(matches!(err, VaultError::Io { .. }), "got {err:?}");
    assert_eq!(open.manifest.blocks, blocks_before, "in-memory blocks mutated on Err");
    assert_eq!(open.manifest.trash, trash_before, "in-memory trash mutated on Err");
    assert_eq!(open.manifest.vector_clock, clock_before, "in-memory clock mutated on Err");
    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    assert!(
        folder.join("blocks").join(format!("{uuid_hex}.cbor.enc")).is_file(),
        "manifest-first: no rename may happen before the manifest write"
    );
}
```

- [ ] **Step 2: Run to verify both fail**

Run: `cargo test --release --workspace --test trash_restore trash_block_rename_failure trash_block_manifest_write 2>&1 | tail -10`
Expected: first FAILS (today the rename precedes the manifest write, so the read-only `trash/` aborts with `Err`); second FAILS on the `blocks == blocks_before` assert (today's code mutates in-memory state before the failed write). If test-name filtering syntax gives trouble use `cargo test --release --workspace --test trash_restore 2>&1 | tail -20`.

- [ ] **Step 3: Rewrite `trash_block`** (keep signature). New body order — steps 1-2 unchanged (locate entry, capture `content_fingerprint`), then:

```rust
    // Steps 2-4 (#350 manifest-first): STAGE the post-trash manifest on
    // clones; nothing observable (in-memory or on-disk) changes until
    // the manifest write succeeds. The write is the commit point — the
    // physical rename below it is best-effort completion.
    let mut staged = open.manifest.clone();
    staged.blocks.remove(entry_idx);
    staged.trash.push(TrashEntry {
        block_uuid,
        tombstoned_at_ms: now_ms,
        tombstoned_by: device_uuid,
        fingerprint: Some(content_fingerprint),
        unknown: std::collections::BTreeMap::new(),
    });
    tick_clock(&mut staged.vector_clock, &device_uuid)?;

    // Step 5: refresh header → fresh AEAD nonce → re-sign → atomic-write.
    // (identical key-rewrap + sign + encode + write_atomic code as today's
    // step 7, but signing `&staged` instead of `&open.manifest`)
    ...
    io::write_atomic(&manifest_path, &manifest_bytes).map_err(|e| VaultError::Io {
        context: "trash_block: failed to write manifest.cbor.enc",
        source: e,
    })?;

    // Step 6: COMMIT the staged state in memory. From here the trash has
    // happened; nothing below may fail the call.
    open.manifest = staged;
    open.manifest_file = new_manifest_file;

    // Step 7: best-effort physical move blocks/<uuid>.cbor.enc →
    // trash/<uuid>.cbor.enc.<now_ms>. Failure (crash before this line,
    // EXDEV cross-filesystem config, permissions) is swallowed: the
    // signed manifest already says trashed; the leftover blocks/ file is
    // a benign orphan open_vault ignores, restore_block resumes from
    // (#351), and the open-time sweep relocates (#350).
    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    let src = folder.join(BLOCKS_SUBDIR).join(format!("{uuid_hex}{BLOCK_FILE_EXTENSION}"));
    let dst = folder.join(TRASH_SUBDIR).join(format!("{uuid_hex}{BLOCK_FILE_EXTENSION}.{now_ms}"));
    let _ = std::fs::create_dir_all(folder.join(TRASH_SUBDIR))
        .and_then(|()| std::fs::rename(&src, &dst));

    Ok(())
```

Also: change `const TRASH_SUBDIR` (line 1895) to `pub(crate) const`; rewrite the fn doc comment — the numbered sequence (manifest-first), the "On `Err`" contract (now true), and REPLACE the entire "# Crash-consistency gap (#350)" section with a "# Crash consistency (#350)" section describing: commit point = manifest write; crash/EXDEV residue = signed-trashed + `blocks/` orphan; recovery = open-time sweep + #351 restore-resume; EXDEV is no longer an abort.

- [ ] **Step 4: Run the full suite** (existing happy-path trash tests must still pass — the observable end state is identical when the rename succeeds)

Run: `cargo test --release --workspace 2>&1 | tail -5` → 0 failures.

- [ ] **Step 5: Commit**

```bash
git add core/src/vault/orchestrators.rs core/tests/trash_restore.rs
git commit -m "feat(core): trash_block is manifest-first; rename is best-effort completion (#350)"
```

---

### Task 4: `repair.rs` module + open-time trash-completion sweep

**Files:**
- Create: `core/src/vault/repair.rs`
- Modify: `core/src/vault/mod.rs` (add `mod repair;`), `core/src/vault/orchestrators.rs` (call sweep from `open_vault` after `verify_block_fingerprints`)
- Test: Create `core/tests/crash_recovery.rs` (fixture helpers copied from `trash_restore.rs` per local no-shared-test-crate convention: `fast_kdf`, `make_fast_vault`, `format_uuid_hyphenated`, `make_simple_plaintext` — copy them verbatim including doc comments, plus the import block, adjusting the file-head doc to describe #350)

**Interfaces:**
- Consumes: `TRASH_SUBDIR` (pub(crate), Task 3), `BLOCKS_SUBDIR`, `BLOCK_FILE_EXTENSION`, `format_uuid_hyphenated` (all already `pub`/`pub(crate)` in orchestrators), `crate::crypto::hash::hash as blake3_hash`.
- Produces: `pub(crate) fn complete_pending_trash_renames(folder: &Path, manifest: &Manifest)` in `core/src/vault/repair.rs`, called by `open_vault` (and by `repair_vault` in Task 6).

- [ ] **Step 1: Write the failing tests** in the new `core/tests/crash_recovery.rs` (after the copied fixture helpers):

```rust
/// Build the manifest-first #350 trash-crash residue: a normally
/// trashed block whose physical file is moved back into `blocks/`
/// (equivalent to a crash before trash_block's best-effort rename).
/// Returns the trash-path the sweep is expected to produce.
fn make_trash_residue(
    folder: &std::path::Path,
    open: &mut secretary_core::vault::OpenVault,
    block_uuid: [u8; 16],
    device_uuid: [u8; 16],
    trash_ms: u64,
    rng: &mut ChaCha20Rng,
) -> (std::path::PathBuf, std::path::PathBuf) {
    trash_block(folder, open, block_uuid, device_uuid, trash_ms, rng).unwrap();
    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    let trash_path = folder.join("trash").join(format!("{uuid_hex}.cbor.enc.{trash_ms}"));
    let blocks_path = folder.join("blocks").join(format!("{uuid_hex}.cbor.enc"));
    fs::rename(&trash_path, &blocks_path).expect("simulate crash: undo the rename");
    (blocks_path, trash_path)
}

/// #350: open_vault's best-effort sweep completes an interrupted trash
/// rename — gated on the signed TrashEntry.fingerprint.
#[test]
fn open_vault_sweep_relocates_interrupted_trash() {
    let (dir, _mnemonic, pw) = make_fast_vault(51, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x51; 32]);
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let (device_uuid, block_uuid) = ([0xd6; 16], [0xb6; 16]);
    let plaintext = make_simple_plaintext(block_uuid, "sweep-me");
    let recipients = vec![open.owner_card.clone()];
    save_block(folder, &mut open, plaintext, &recipients, device_uuid, 1_000, &mut rng).unwrap();
    let (blocks_path, trash_path) =
        make_trash_residue(folder, &mut open, block_uuid, device_uuid, 2_000, &mut rng);
    drop(open);

    let reopened = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    assert!(trash_path.is_file(), "sweep must relocate the orphan to its §7 trash path");
    assert!(!blocks_path.exists(), "orphan must be gone from blocks/");
    // Restore still works after the sweep (normal trash-file path now).
    drop(reopened);
    let mut open2 = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    restore_block(folder, &mut open2, block_uuid, device_uuid, 3_000, &mut rng).unwrap();
}

/// #350 sweep negative gate: orphan bytes not matching the signed
/// TrashEntry.fingerprint are NOT moved (attacker-planted file).
#[test]
fn sweep_skips_orphan_with_wrong_fingerprint() {
    let (dir, _mnemonic, pw) = make_fast_vault(52, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x52; 32]);
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let (device_uuid, block_uuid) = ([0xd7; 16], [0xb7; 16]);
    let plaintext = make_simple_plaintext(block_uuid, "tamper");
    let recipients = vec![open.owner_card.clone()];
    save_block(folder, &mut open, plaintext, &recipients, device_uuid, 1_000, &mut rng).unwrap();
    let (blocks_path, trash_path) =
        make_trash_residue(folder, &mut open, block_uuid, device_uuid, 2_000, &mut rng);
    // Overwrite the orphan with junk of a different hash.
    fs::write(&blocks_path, b"not the committed bytes").unwrap();
    drop(open);

    let _reopened = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    assert!(blocks_path.is_file(), "junk orphan must not be moved");
    assert!(!trash_path.exists(), "no trash file may be minted from junk");
}

/// #350 sweep negative gate: a TrashEntry whose UUID is live again
/// (trash → re-save same uuid) must not steal the live file, even if
/// an attacker crafts fingerprint agreement. We simulate by re-saving
/// the same uuid after a residue: live entry exists, so the sweep must
/// skip regardless of the orphan/live file's hash.
#[test]
fn sweep_skips_live_uuid() {
    let (dir, _mnemonic, pw) = make_fast_vault(53, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x53; 32]);
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let (device_uuid, block_uuid) = ([0xd8; 16], [0xb8; 16]);
    let plaintext = make_simple_plaintext(block_uuid, "gen-1");
    let recipients = vec![open.owner_card.clone()];
    save_block(folder, &mut open, plaintext, &recipients, device_uuid, 1_000, &mut rng).unwrap();
    let (blocks_path, trash_path) =
        make_trash_residue(folder, &mut open, block_uuid, device_uuid, 2_000, &mut rng);
    // Re-save the same uuid: clobbers the orphan with new live content;
    // manifest now has BOTH a live entry and the TrashEntry.
    let plaintext2 = make_simple_plaintext(block_uuid, "gen-2");
    save_block(folder, &mut open, plaintext2, &recipients, device_uuid, 3_000, &mut rng).unwrap();
    drop(open);

    let reopened = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    assert!(blocks_path.is_file(), "live file must stay in blocks/");
    assert!(!trash_path.exists(), "sweep must not touch a live uuid");
    assert!(reopened.manifest.blocks.iter().any(|b| b.block_uuid == block_uuid));
}

/// #350 sweep negative gate: legacy TrashEntry { fingerprint: None }
/// (pre-#293) gives the sweep no content commitment — skip.
#[test]
fn sweep_skips_legacy_entry_without_fingerprint() {
    let (dir, _mnemonic, pw) = make_fast_vault(54, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x54; 32]);
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let (device_uuid, block_uuid) = ([0xd9; 16], [0xb9; 16]);
    let plaintext = make_simple_plaintext(block_uuid, "legacy");
    let recipients = vec![open.owner_card.clone()];
    save_block(folder, &mut open, plaintext, &recipients, device_uuid, 1_000, &mut rng).unwrap();
    let (blocks_path, trash_path) =
        make_trash_residue(folder, &mut open, block_uuid, device_uuid, 2_000, &mut rng);

    // Strip the fingerprint from the TrashEntry and re-sign the manifest
    // (tests hold the owner identity, so this is a legitimate re-sign).
    let mut manifest = open.manifest.clone();
    for t in &mut manifest.trash {
        t.fingerprint = None;
    }
    let header = ManifestHeader {
        vault_uuid: open.manifest_file.header.vault_uuid,
        created_at_ms: open.manifest_file.header.created_at_ms,
        last_mod_ms: 2_500,
    };
    let pq_sk = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).unwrap();
    let mut nonce = [0u8; 24];
    rng.fill_bytes(&mut nonce);
    let mf = sign_manifest(
        header,
        &manifest,
        &open.identity_block_key,
        &nonce,
        open.manifest_file.author_fingerprint,
        &open.identity.ed25519_sk,
        &pq_sk,
    )
    .unwrap();
    fs::write(folder.join("manifest.cbor.enc"), encode_manifest_file(&mf).unwrap()).unwrap();
    drop(open);

    let _reopened = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    assert!(blocks_path.is_file(), "legacy entry: orphan must not be moved");
    assert!(!trash_path.exists());
}
```

(NOTE for the implementer: `sign_manifest` takes `&created.identity.ed25519_sk` directly in `make_fast_vault` — the same `&open.identity.ed25519_sk` works here because both are the bundle's `Ed25519Secret`. Mirror `make_fast_vault`'s import list.)

- [ ] **Step 2: Run to verify failures**

Run: `cargo test --release --workspace --test crash_recovery 2>&1 | tail -15`
Expected: `open_vault_sweep_relocates_interrupted_trash` FAILS (no sweep exists — trash_path never appears); the three negative-gate tests may PASS vacuously today (nothing moves anything) — that is fine; they pin the gates against regressions once the sweep exists.

- [ ] **Step 3: Implement the module.** Create `core/src/vault/repair.rs`:

```rust
//! #350 crash-recovery: the open-time trash-completion sweep (this
//! task) and the explicit [`repair_vault`] orchestrator (added on top).
//!
//! Split out of `orchestrators.rs` (already ~2.8k lines) — one concept
//! per file: everything here exists to converge a crash-interrupted
//! vault back to the §6.5/§7 on-disk shape without weakening the
//! manifest-as-integrity-commitment.

use std::path::Path;

use crate::crypto::hash::hash as blake3_hash;

use super::manifest::Manifest;
use super::orchestrators::{
    format_uuid_hyphenated, BLOCKS_SUBDIR, BLOCK_FILE_EXTENSION, TRASH_SUBDIR,
};

/// Best-effort completion of trash renames interrupted between
/// `trash_block`'s manifest commit and its physical move (#350).
///
/// For every signed `TrashEntry` whose §7 trash file is absent: if the
/// UUID is not live in `manifest.blocks` and `blocks/<uuid>.cbor.enc`
/// exists with bytes hashing to the entry's signed `fingerprint`, the
/// file is renamed to `trash/<uuid>.cbor.enc.<tombstoned_at_ms>`.
///
/// Rename-only: no manifest mutation, no signing, no trust-state
/// change — the gate is the *signed* content commitment, so an attacker
/// who plants an arbitrary `blocks/` file cannot steer the sweep.
/// Idempotent; every I/O failure is swallowed (a vault that cannot
/// complete the move, e.g. cross-filesystem trash/, stays in the benign
/// orphan state that `restore_block` resumes from).
pub(crate) fn complete_pending_trash_renames(folder: &Path, manifest: &Manifest) {
    let trash_dir = folder.join(TRASH_SUBDIR);
    let blocks_dir = folder.join(BLOCKS_SUBDIR);
    for entry in &manifest.trash {
        // Legacy pre-#293 entry: no signed commitment → no safe gate.
        let Some(committed_fp) = entry.fingerprint else {
            continue;
        };
        // Live-and-trashed (trash → re-save same uuid): never touch the
        // live file, regardless of hashes.
        if manifest
            .blocks
            .iter()
            .any(|b| b.block_uuid == entry.block_uuid)
        {
            continue;
        }
        let uuid_hex = format_uuid_hyphenated(&entry.block_uuid);
        let trash_path = trash_dir.join(format!(
            "{uuid_hex}{BLOCK_FILE_EXTENSION}.{}",
            entry.tombstoned_at_ms
        ));
        if trash_path.exists() {
            continue; // move already completed
        }
        let blocks_path = blocks_dir.join(format!("{uuid_hex}{BLOCK_FILE_EXTENSION}"));
        let Ok(bytes) = std::fs::read(&blocks_path) else {
            continue; // no orphan (or unreadable — best-effort)
        };
        if *blake3_hash(&bytes).as_bytes() != committed_fp {
            continue; // not the committed bytes — planted or clobbered
        }
        let _ = std::fs::create_dir_all(&trash_dir)
            .and_then(|()| std::fs::rename(&blocks_path, &trash_path));
    }
}
```

In `core/src/vault/mod.rs` add `mod repair;` next to the other module decls. In `open_vault` (orchestrators.rs, after the `verify_block_fingerprints(folder, &manifest_body)?;` line):

```rust
    // #350: best-effort completion of trash renames interrupted between
    // trash_block's manifest commit and its physical move. Rename-only
    // and gated on the signed TrashEntry.fingerprint — see
    // repair::complete_pending_trash_renames.
    super::repair::complete_pending_trash_renames(folder, &manifest_body);
```

(Adjust the path to `crate::vault::repair::…` if `super::` doesn't resolve from within orchestrators.rs — both are equivalent here.)

- [ ] **Step 4: Run the new tests + full suite**

Run: `cargo test --release --workspace --test crash_recovery 2>&1 | tail -10` → all PASS.
Run: `cargo test --release --workspace 2>&1 | tail -5` → 0 failures. `cargo clippy --release --workspace --tests -- -D warnings` → clean.

- [ ] **Step 5: Commit**

```bash
git add core/src/vault/repair.rs core/src/vault/mod.rs core/src/vault/orchestrators.rs core/tests/crash_recovery.rs
git commit -m "feat(core): open-time best-effort completion of interrupted trash renames (#350)"
```

---

### Task 5: extract `resolve_recipient_uuids` from `restore_block` (pure refactor)

**Files:**
- Modify: `core/src/vault/orchestrators.rs` (restore_block step 5, lines ~2299-2371, moves into a new `pub(crate)` fn in the same file)

**Interfaces:**
- Produces: `pub(crate) fn resolve_recipient_uuids(folder: &Path, owner_card: &ContactCard, wraps: &[RecipientWrap]) -> Result<Vec<[u8; 16]>, VaultError>` — resolves every `recipient_fingerprint` to a `contact_uuid` (owner card first, then self-verified `contacts/*.card`), erroring `MissingRecipientCard` on any unresolved fingerprint. Task 6's `repair_vault` calls this.

- [ ] **Step 1: Extract.** Move restore_block's step-5 body verbatim into (placed just above `restore_block`):

```rust
/// Resolve every `recipient_fingerprint` in a block file's §6.2 wrap
/// table to a `contact_uuid`: the owner card matches in memory; any
/// other fingerprint requires a `contacts/*.card` scan where each card
/// must pass its embedded Ed25519 ∧ ML-DSA-65 self-verification before
/// its `contact_uuid` is trusted (see the security note inside — cards
/// failing self-verify are skipped, not fatal). Unresolved →
/// [`VaultError::MissingRecipientCard`].
///
/// Shared by `restore_block` (§7.1 step 4) and `repair_vault` (#350) —
/// both rebuild a manifest `BlockEntry.recipients` from an on-disk
/// block file.
pub(crate) fn resolve_recipient_uuids(
    folder: &Path,
    owner_card: &ContactCard,
    wraps: &[block::RecipientWrap],
) -> Result<Vec<[u8; 16]>, VaultError> {
    use std::collections::HashMap;
    let owner_fp = fingerprint(&owner_card.to_canonical_cbor()?);
    let mut fp_to_uuid: HashMap<[u8; 16], [u8; 16]> = HashMap::new();
    fp_to_uuid.insert(owner_fp, owner_card.contact_uuid);
    // … (lines 2306-2371 verbatim, with `block_file.recipients` → `wraps`,
    //    `open.owner_card` → `owner_card`, and the three
    //    `"restore_block: …"` Io context strings generalised to
    //    "failed to read_dir contacts/" / "failed to iterate contacts/ entry"
    //    / "failed to read contact card"; keep the long self-verify
    //    security comment verbatim)
    Ok(recipients_uuids)
}
```

In `restore_block`, replace the moved region with:

```rust
    // Step 5: resolve recipient_fingerprint → contact_uuid (shared with
    // repair_vault — see resolve_recipient_uuids).
    let recipients_uuids = resolve_recipient_uuids(folder, &open.owner_card, &block_file.recipients)?;
```

(`owner_fp` is still computed earlier in restore_block for the decrypt call — leave that untouched; the helper recomputes it internally, which is one extra BLAKE3 over a card — negligible.)

- [ ] **Step 2: Run full suite (pure refactor — everything must stay green)**

Run: `cargo test --release --workspace 2>&1 | tail -5` → 0 failures; `cargo clippy --release --workspace --tests -- -D warnings` → clean.

- [ ] **Step 3: Commit**

```bash
git add core/src/vault/orchestrators.rs
git commit -m "refactor(core): extract resolve_recipient_uuids for reuse by repair_vault (#350)"
```

---

### Task 6: `repair_vault` orchestrator

**Files:**
- Modify: `core/src/vault/orchestrators.rs` (extract `unlock_vault_identity` from open_vault steps 1-2; widen `tick_clock` + `read_and_verify_manifest` to `pub(crate)`)
- Modify: `core/src/vault/repair.rs` (add `repair_vault`)
- Modify: `core/src/vault/mod.rs` (re-export: add `repair_vault` to the orchestrator `pub use` list via `pub use repair::repair_vault;`; upgrade Task 1's plain-text doc mentions to intra-doc links)
- Test: `core/tests/crash_recovery.rs` (append)

**Interfaces:**
- Consumes: `unlock_vault_identity`, `read_and_verify_manifest`, `tick_clock`, `resolve_recipient_uuids`, `complete_pending_trash_renames`, `clock_relation`/`ClockRelation` (from `super::conflict`), `decode_block_file`/`decrypt_block` (from `super::block`), `sign_manifest`/`encode_manifest_file` (from `super::manifest`), `io::write_atomic`.
- Produces:

```rust
pub fn repair_vault(
    folder: &Path,
    unlocker: Unlocker<'_>,
    local_highest_clock: Option<&[VectorClockEntry]>,
    device_uuid: [u8; 16],
    now_ms: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<OpenVault, VaultError>
```

- [ ] **Step 1: Write the failing happy-path tests** (append to `core/tests/crash_recovery.rs`):

```rust
// ---------------------------------------------------------------------------
// repair_vault — #350 save_block / re-key crash residue
// ---------------------------------------------------------------------------

/// #350 happy path: a save_block update whose manifest write was lost
/// (crash simulated by restoring the pre-save manifest bytes) makes
/// open_vault fail BlockFingerprintMismatch; repair_vault adopts the
/// newer owner-signed block, rebuilds the entry, and returns a live
/// OpenVault; a subsequent open_vault is green.
#[test]
fn repair_vault_adopts_interrupted_save() {
    let (dir, _mnemonic, pw) = make_fast_vault(61, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x61; 32]);
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let (device_uuid, block_uuid) = ([0xda; 16], [0xba; 16]);
    let recipients = vec![open.owner_card.clone()];
    save_block(folder, &mut open, make_simple_plaintext(block_uuid, "v1"),
               &recipients, device_uuid, 1_000, &mut rng).unwrap();
    let manifest_v1 = fs::read(folder.join("manifest.cbor.enc")).unwrap();
    save_block(folder, &mut open, make_simple_plaintext(block_uuid, "v2"),
               &recipients, device_uuid, 2_000, &mut rng).unwrap();
    drop(open);
    // Crash simulation: the v2 block hit disk, the v2 manifest didn't.
    fs::write(folder.join("manifest.cbor.enc"), &manifest_v1).unwrap();

    let err = open_vault(folder, Unlocker::Password(&pw), None)
        .expect_err("residue must fail open");
    assert!(
        matches!(err, VaultError::BlockFingerprintMismatch { block_uuid: b, .. } if b == block_uuid),
        "got {err:?}"
    );

    let repaired = secretary_core::vault::repair_vault(
        folder, Unlocker::Password(&pw), None, device_uuid, 3_000, &mut rng,
    )
    .expect("gated adoption must succeed on genuine crash residue");

    let entry = repaired.manifest.blocks.iter()
        .find(|b| b.block_uuid == block_uuid).expect("entry present");
    assert_eq!(entry.block_name, "v2", "adopted entry carries the on-disk content");
    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    let disk = fs::read(folder.join("blocks").join(format!("{uuid_hex}.cbor.enc"))).unwrap();
    assert_eq!(entry.fingerprint, *secretary_core::crypto::hash::hash(&disk).as_bytes());
    // Block clock adopted verbatim: device ticked twice (v1 + v2).
    assert_eq!(entry.vector_clock_summary.len(), 1);
    assert_eq!(entry.vector_clock_summary[0].counter, 2);
    drop(repaired);

    open_vault(folder, Unlocker::Password(&pw), None)
        .expect("vault must be healthy after repair");
}

/// #350: a crashed revocation re-key repairs to the REDUCED recipient
/// set (the on-disk §6.2 table), not the stale manifest one.
#[test]
fn repair_vault_adopts_interrupted_revocation() {
    let (dir, _mnemonic, pw) = make_fast_vault(62, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x62; 32]);
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let (device_uuid, block_uuid) = ([0xdb; 16], [0xbb; 16]);

    // Co-recipient B: mint an identity bundle, write its card to
    // contacts/ (pattern from core/tests/revoke_block.rs).
    let mut rng_b = ChaCha20Rng::from_seed([0x63; 32]);
    let id_b = secretary_core::unlock::bundle::generate("Bee", 1_714_060_800_000, &mut rng_b);
    let card_b = make_signed_card(&id_b);
    let card_b_bytes = card_b.to_canonical_cbor().unwrap();
    fs::write(
        folder.join("contacts").join(format!("{}.card", format_uuid_hyphenated(&card_b.contact_uuid))),
        &card_b_bytes,
    ).unwrap();

    let recipients = vec![open.owner_card.clone(), card_b.clone()];
    save_block(folder, &mut open, make_simple_plaintext(block_uuid, "shared"),
               &recipients, device_uuid, 1_000, &mut rng).unwrap();
    let manifest_pre = fs::read(folder.join("manifest.cbor.enc")).unwrap();

    let author_card = open.owner_card.clone();
    let author_sk_ed: secretary_core::crypto::sig::Ed25519Secret =
        secretary_core::crypto::secret::Sensitive::new(*open.identity.ed25519_sk.expose());
    let author_sk_pq = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).unwrap();
    secretary_core::vault::revoke_block_recipient(
        folder, &mut open,
        secretary_core::vault::BlockUuid::new(block_uuid),
        &author_card, &author_sk_ed, &author_sk_pq, &recipients,
        secretary_core::vault::RecipientUuid::new(card_b.contact_uuid),
        secretary_core::vault::DeviceUuid::new(device_uuid),
        2_000, &mut rng,
    ).unwrap();
    drop(open);
    fs::write(folder.join("manifest.cbor.enc"), &manifest_pre).unwrap();

    let repaired = secretary_core::vault::repair_vault(
        folder, Unlocker::Password(&pw), None, device_uuid, 3_000, &mut rng,
    ).unwrap();
    let entry = repaired.manifest.blocks.iter()
        .find(|b| b.block_uuid == block_uuid).unwrap();
    assert_eq!(entry.recipients.len(), 1, "revoked recipient must be gone");
    assert_eq!(entry.recipients[0], repaired.owner_card.contact_uuid);
}
```

(Copy `make_signed_card` from `trash_restore.rs` into the fixture section — it takes an `&IdentityBundle`, which `unlock::bundle::generate` returns. `revoke_block_recipient`'s exact param list is at orchestrators.rs:1743; `existing_recipient_cards` is the pre-revocation card set, and the uuid params are the `BlockUuid`/`RecipientUuid`/`DeviceUuid` newtypes — construct with `::new(...)` as shown (pattern: `core/tests/revoke_block.rs:750-775`).)

- [ ] **Step 2: Run to verify failure (compile error — `repair_vault` doesn't exist)**

Run: `cargo test --release --workspace --test crash_recovery 2>&1 | tail -10`
Expected: FAIL — `cannot find function repair_vault`.

- [ ] **Step 3: Extract `unlock_vault_identity`** in orchestrators.rs (open_vault steps 1-2, lines 516-553, moved verbatim):

```rust
/// Read `vault.toml` + `identity.bundle.enc` and unlock via the given
/// [`Unlocker`] arm. Shared by [`open_vault`] and
/// [`crate::vault::repair_vault`] so the repair path is never a weaker
/// open (same credential surface, same typed errors).
pub(crate) fn unlock_vault_identity(
    folder: &Path,
    unlocker: Unlocker<'_>,
) -> Result<(Vec<u8>, UnlockedIdentity), VaultError> {
    // (moved steps 1-2; returns (vault_toml_bytes, unlocked))
}
```

`open_vault` becomes `let (vault_toml_bytes, unlocked) = unlock_vault_identity(folder, unlocker)?;` and continues unchanged. Also change `fn tick_clock` → `pub(crate) fn tick_clock` and `fn read_and_verify_manifest` → `pub(crate) fn read_and_verify_manifest` (doc comments note the repair.rs consumer).

- [ ] **Step 4: Implement `repair_vault`** in `core/src/vault/repair.rs` (full doc comment: purpose, the three gates, all-or-nothing, "same manifest verify-before-decrypt as open_vault — not a weaker open", idempotence, and that `BlockFileMissing` aborts):

```rust
pub fn repair_vault(
    folder: &Path,
    unlocker: Unlocker<'_>,
    local_highest_clock: Option<&[VectorClockEntry]>,
    device_uuid: [u8; 16],
    now_ms: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<OpenVault, VaultError> {
    // Same unlock + §10-checked manifest verify as open_vault.
    let (vault_toml_bytes, unlocked) = unlock_vault_identity(folder, unlocker)?;
    let (owner_card, mut manifest, manifest_file, _envelope_bytes) =
        read_and_verify_manifest(folder, &vault_toml_bytes, &unlocked, local_highest_clock)?;

    // Owner verify/decrypt keys — mirrors restore_block's key prep,
    // hoisted once outside the per-block loop. Zeroize the stack copy.
    let owner_pk_bundle = owner_card.pk_bundle_bytes()?;
    let owner_fp = fingerprint(&owner_card.to_canonical_cbor()?);
    let owner_pq_pk = MlDsa65Public::from_bytes(&owner_card.ml_dsa_65_pk)?;
    let mut x_sk_bytes = *unlocked.identity.x25519_sk.expose();
    let owner_x_sk: kem::X25519Secret = Sensitive::new(x_sk_bytes);
    x_sk_bytes.zeroize();
    let owner_pq_sk_reader = MlKem768Secret::from_bytes(unlocked.identity.ml_kem_768_sk.expose())
        .map_err(block::BlockError::from)?;

    // Pass 1 — read-only classification. All-or-nothing: any gate
    // failure returns before anything is staged or written.
    let blocks_dir = folder.join(BLOCKS_SUBDIR);
    let mut adoptions: Vec<(usize, BlockEntry)> = Vec::new();
    for (idx, entry) in manifest.blocks.iter().enumerate() {
        let uuid_hex = format_uuid_hyphenated(&entry.block_uuid);
        let path = blocks_dir.join(format!("{uuid_hex}{BLOCK_FILE_EXTENSION}"));
        let bytes = std::fs::read(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                VaultError::BlockFileMissing { block_uuid: entry.block_uuid }
            } else {
                VaultError::Io { context: "repair_vault: failed to read block file", source: e }
            }
        })?;
        let got = *blake3_hash(&bytes).as_bytes();
        if got == entry.fingerprint {
            continue; // healthy
        }
        // Gate 1 — authenticity: decode + AEAD-decrypt + hybrid verify
        // (Ed25519 ∧ ML-DSA-65, both halves) under the owner card.
        let block_file = block::decode_block_file(&bytes).map_err(|e| {
            VaultError::RepairRejected {
                block_uuid: entry.block_uuid,
                detail: format!("decode: {e}"),
            }
        })?;
        // Gate 2 — binding: the file must BE this block of this vault.
        if block_file.header.block_uuid != entry.block_uuid {
            return Err(VaultError::RepairRejected {
                block_uuid: entry.block_uuid,
                detail: "file header block_uuid does not match the manifest entry".to_string(),
            });
        }
        if block_file.header.vault_uuid != manifest.vault_uuid {
            return Err(VaultError::RepairRejected {
                block_uuid: entry.block_uuid,
                detail: "file header vault_uuid does not match this vault".to_string(),
            });
        }
        // Gate 3 — freshness: authenticity is not currency (an owner-
        // signed OLDER copy verifies fine). The on-disk clock must
        // STRICTLY dominate the committed summary — exactly the shape an
        // interrupted save leaves (it ticked the block clock). Equal,
        // dominated (rollback plant), or concurrent (torn multi-device
        // state we must not guess about) are all refused.
        match clock_relation(&entry.vector_clock_summary, &block_file.header.vector_clock) {
            ClockRelation::IncomingDominates => {}
            relation => {
                return Err(VaultError::RepairRejected {
                    block_uuid: entry.block_uuid,
                    detail: format!(
                        "clock relation {relation:?}: on-disk block must strictly dominate \
                         the manifest entry"
                    ),
                });
            }
        }
        let plaintext = block::decrypt_block(
            &block_file,
            &owner_fp,
            &owner_pk_bundle,
            &owner_card.ed25519_pk,
            &owner_pq_pk,
            &owner_fp,
            &owner_pk_bundle,
            &owner_x_sk,
            &owner_pq_sk_reader,
        )
        .map_err(|e| VaultError::RepairRejected {
            block_uuid: entry.block_uuid,
            detail: format!("decrypt/verify: {e}"),
        })?;
        // Gate 4 — the rebuilt entry's recipients come from the §6.2
        // table (so a crashed re-key adopts the REDUCED set).
        let recipients = resolve_recipient_uuids(folder, &owner_card, &block_file.recipients)?;
        adoptions.push((
            idx,
            BlockEntry {
                block_uuid: entry.block_uuid,
                block_name: plaintext.block_name.clone(),
                fingerprint: got,
                recipients,
                vector_clock_summary: block_file.header.vector_clock.clone(),
                suite_id: block_file.header.suite_id,
                created_at_ms: block_file.header.created_at_ms,
                // The original write's own stamp — repair is not a
                // content change (mirrors clock-verbatim above).
                last_mod_ms: block_file.header.last_mod_ms,
                // Preserve the committed entry's unknown map: repair
                // replaces the *content commitment*, not v2 metadata.
                unknown: entry.unknown.clone(),
            },
        ));
    }

    if adoptions.is_empty() {
        // Healthy vault: repair degrades to a plain open (idempotent).
        complete_pending_trash_renames(folder, &manifest);
        return Ok(OpenVault {
            identity_block_key: unlocked.identity_block_key,
            identity: unlocked.identity,
            owner_card,
            manifest,
            manifest_file,
        });
    }
    for (idx, new_entry) in adoptions {
        manifest.blocks[idx] = new_entry;
    }
    tick_clock(&mut manifest.vector_clock, &device_uuid)?;

    // Re-sign + atomic-write — same key-rewrap shape as trash_block
    // step 7 (zeroize the ed25519 stack copy).
    let new_header = ManifestHeader {
        vault_uuid: manifest_file.header.vault_uuid,
        created_at_ms: manifest_file.header.created_at_ms,
        last_mod_ms: now_ms,
    };
    let mut ed_sk_bytes = *unlocked.identity.ed25519_sk.expose();
    let owner_ed_sk: Ed25519Secret = Sensitive::new(ed_sk_bytes);
    ed_sk_bytes.zeroize();
    let owner_pq_sk = MlDsa65Secret::from_bytes(unlocked.identity.ml_dsa_65_sk.expose())?;
    let aead_nonce = aead::random_nonce(rng);
    let new_manifest_file = manifest::sign_manifest(
        new_header,
        &manifest,
        &unlocked.identity_block_key,
        &aead_nonce,
        manifest_file.author_fingerprint,
        &owner_ed_sk,
        &owner_pq_sk,
    )?;
    let manifest_bytes = manifest::encode_manifest_file(&new_manifest_file)?;
    io::write_atomic(&folder.join(MANIFEST_FILENAME), &manifest_bytes).map_err(|e| {
        VaultError::Io {
            context: "repair_vault: failed to write manifest.cbor.enc",
            source: e,
        }
    })?;

    complete_pending_trash_renames(folder, &manifest);
    Ok(OpenVault {
        identity_block_key: unlocked.identity_block_key,
        identity: unlocked.identity,
        owner_card,
        manifest,
        manifest_file: new_manifest_file,
    })
}
```

Imports needed in repair.rs beyond Task 4's (mirror orchestrators.rs lines 22-44 style): `rand_core::{CryptoRng, RngCore}`, `zeroize::Zeroize as _`, `crate::crypto::aead`, `crate::crypto::kem::{self, MlKem768Secret}`, `crate::crypto::secret::Sensitive`, `crate::crypto::sig::{Ed25519Secret, MlDsa65Public, MlDsa65Secret}` (check exact paths in orchestrators.rs's import block), `crate::identity::fingerprint::fingerprint`, `crate::unlock` types, `super::conflict::{clock_relation, ClockRelation}`, `super::manifest::{self, BlockEntry, ManifestHeader}`, `super::orchestrators::{unlock_vault_identity, read_and_verify_manifest, resolve_recipient_uuids, tick_clock, OpenVault, Unlocker, MANIFEST_FILENAME}` (widen `MANIFEST_FILENAME` to `pub(crate)` if private), `super::{block, io}`, `super::block::VectorClockEntry`. In `mod.rs` add `pub use repair::repair_vault;` and upgrade Task 1's plain-text mentions to intra-doc links.

- [ ] **Step 5: Run the new tests + full suite**

Run: `cargo test --release --workspace --test crash_recovery 2>&1 | tail -10` → all PASS.
Run: `cargo test --release --workspace 2>&1 | tail -5` → 0 failures; clippy + `cargo doc` clean (intra-doc links now resolve).

- [ ] **Step 6: Commit**

```bash
git add core/src/vault/repair.rs core/src/vault/orchestrators.rs core/src/vault/mod.rs core/tests/crash_recovery.rs
git commit -m "feat(core): repair_vault — gated adoption of crash-residue blocks (#350)"
```

---

### Task 7: repair rejection + missing + idempotence tests

**Files:**
- Test: `core/tests/crash_recovery.rs` (append; plus a small local `copy_dir_recursive` helper — write it fresh, ~15 lines walking `read_dir` and copying files/dirs recursively; note #186 tracks deduping the bridge's copies, do NOT import across crates)

**Interfaces:**
- Consumes: everything from Task 6. These tests pin the security gates; they should mostly pass already — any failure is a Task 6 bug to fix (do NOT weaken a test to get green; per project rule, a gate that doesn't hold is a design problem to surface).

- [ ] **Step 1: Write the tests**

```rust
/// Minimal recursive dir copy for vault-state forking (see #186 for the
/// planned shared helper; kept local per test-crate convention).
fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let target = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir_recursive(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// #350 gate: a genuinely owner-signed but OLDER block copy planted
/// over the live file is a rollback, not crash residue — clock
/// dominated → RepairRejected, and the manifest is untouched.
#[test]
fn repair_vault_rejects_rollback_plant() {
    let (dir, _mnemonic, pw) = make_fast_vault(71, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x71; 32]);
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let (device_uuid, block_uuid) = ([0xdc; 16], [0xbc; 16]);
    let recipients = vec![open.owner_card.clone()];
    save_block(folder, &mut open, make_simple_plaintext(block_uuid, "v1"),
               &recipients, device_uuid, 1_000, &mut rng).unwrap();
    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    let block_path = folder.join("blocks").join(format!("{uuid_hex}.cbor.enc"));
    let v1_bytes = fs::read(&block_path).unwrap();
    save_block(folder, &mut open, make_simple_plaintext(block_uuid, "v2"),
               &recipients, device_uuid, 2_000, &mut rng).unwrap();
    drop(open);
    fs::write(&block_path, &v1_bytes).unwrap(); // the rollback plant
    let manifest_before = fs::read(folder.join("manifest.cbor.enc")).unwrap();

    let err = secretary_core::vault::repair_vault(
        folder, Unlocker::Password(&pw), None, device_uuid, 3_000, &mut rng,
    ).expect_err("rollback must be refused");
    assert!(
        matches!(err, VaultError::RepairRejected { block_uuid: b, ref detail }
                 if b == block_uuid && detail.contains("clock relation")),
        "got {err:?}"
    );
    assert_eq!(
        fs::read(folder.join("manifest.cbor.enc")).unwrap(), manifest_before,
        "all-or-nothing: rejected repair must not write the manifest"
    );
}

/// #350 gate: fork the vault pre-save, save independently in the fork,
/// transplant the fork's block file — equal clock (same device) and
/// concurrent clock (different device) must BOTH be refused.
#[test]
fn repair_vault_rejects_equal_and_concurrent_clocks() {
    let (dir, _mnemonic, pw) = make_fast_vault(72, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x72; 32]);
    let (device_a, device_b, block_uuid) = ([0xaa; 16], [0xbb; 16], [0xbd; 16]);
    let uuid_hex = format_uuid_hyphenated(&block_uuid);

    // Fork BEFORE the block exists, twice.
    let fork_equal = tempfile::tempdir().unwrap();
    let fork_conc = tempfile::tempdir().unwrap();
    copy_dir_recursive(folder, fork_equal.path());
    copy_dir_recursive(folder, fork_conc.path());

    // Main: save under device A → manifest summary {A:1}.
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let recipients = vec![open.owner_card.clone()];
    save_block(folder, &mut open, make_simple_plaintext(block_uuid, "main"),
               &recipients, device_a, 1_000, &mut rng).unwrap();
    drop(open);
    let block_path = folder.join("blocks").join(format!("{uuid_hex}.cbor.enc"));

    for (fork, device, expect) in [
        (fork_equal.path(), device_a, "Equal"),
        (fork_conc.path(), device_b, "Concurrent"),
    ] {
        let mut rng_f = ChaCha20Rng::from_seed([0x73; 32]);
        let mut open_f = open_vault(fork, Unlocker::Password(&pw), None).unwrap();
        let recip_f = vec![open_f.owner_card.clone()];
        save_block(fork, &mut open_f, make_simple_plaintext(block_uuid, "fork"),
                   &recip_f, device, 1_500, &mut rng_f).unwrap();
        drop(open_f);
        // Transplant: same owner, same vault_uuid, different bytes.
        fs::copy(fork.join("blocks").join(format!("{uuid_hex}.cbor.enc")), &block_path).unwrap();

        let err = secretary_core::vault::repair_vault(
            folder, Unlocker::Password(&pw), None, device_a, 3_000, &mut rng,
        ).expect_err("non-dominating clock must be refused");
        assert!(
            matches!(err, VaultError::RepairRejected { ref detail, .. } if detail.contains(expect)),
            "expected {expect} rejection, got {err:?}"
        );
    }
}

/// #350: a listed block whose file is simply GONE is not repairable —
/// typed BlockFileMissing from open_vault AND repair_vault.
#[test]
fn missing_block_file_is_typed_and_unrepairable() {
    let (dir, _mnemonic, pw) = make_fast_vault(73, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x74; 32]);
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let (device_uuid, block_uuid) = ([0xde; 16], [0xbe; 16]);
    let recipients = vec![open.owner_card.clone()];
    save_block(folder, &mut open, make_simple_plaintext(block_uuid, "gone"),
               &recipients, device_uuid, 1_000, &mut rng).unwrap();
    drop(open);
    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    fs::remove_file(folder.join("blocks").join(format!("{uuid_hex}.cbor.enc"))).unwrap();

    let e1 = open_vault(folder, Unlocker::Password(&pw), None).expect_err("open");
    assert!(matches!(e1, VaultError::BlockFileMissing { block_uuid: b } if b == block_uuid), "got {e1:?}");
    let e2 = secretary_core::vault::repair_vault(
        folder, Unlocker::Password(&pw), None, device_uuid, 2_000, &mut rng,
    ).expect_err("repair cannot invent bytes");
    assert!(matches!(e2, VaultError::BlockFileMissing { block_uuid: b } if b == block_uuid), "got {e2:?}");
}

/// #350: repair_vault on a healthy vault is a plain open — nothing
/// written (manifest bytes byte-identical).
#[test]
fn repair_vault_is_idempotent_on_healthy_vault() {
    let (dir, _mnemonic, pw) = make_fast_vault(74, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x75; 32]);
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let (device_uuid, block_uuid) = ([0xdf; 16], [0xbf; 16]);
    let recipients = vec![open.owner_card.clone()];
    save_block(folder, &mut open, make_simple_plaintext(block_uuid, "healthy"),
               &recipients, device_uuid, 1_000, &mut rng).unwrap();
    drop(open);
    let before = fs::read(folder.join("manifest.cbor.enc")).unwrap();

    let repaired = secretary_core::vault::repair_vault(
        folder, Unlocker::Password(&pw), None, device_uuid, 2_000, &mut rng,
    ).expect("healthy vault must open through repair");
    assert!(repaired.manifest.blocks.iter().any(|b| b.block_uuid == block_uuid));
    drop(repaired);
    assert_eq!(fs::read(folder.join("manifest.cbor.enc")).unwrap(), before,
               "healthy repair must not rewrite the manifest");
}
```

(Note: the equal-clock fork uses the SAME password-derived vault copied byte-for-byte, so `Unlocker::Password(&pw)` opens the forks too. The fork saves use a different rng seed so the fork's block bytes genuinely differ from main's.)

- [ ] **Step 2: Run**

Run: `cargo test --release --workspace --test crash_recovery 2>&1 | tail -15`
Expected: all PASS. If any rejection test fails, the Task 6 gate has a hole — fix `repair_vault`, never the test.

- [ ] **Step 3: Full suite + commit**

Run: `cargo test --release --workspace 2>&1 | tail -5`; clippy clean; `cargo fmt --all`.

```bash
git add core/tests/crash_recovery.rs
git commit -m "test(core): pin repair_vault security gates — rollback, equal/concurrent clocks, missing file, idempotence (#350)"
```

---

### Task 8: spec updates + verification gates

**Files:**
- Modify: `docs/vault-format.md` (§6.5 recovery paragraph ~line 436; §7 deletion sequence ~lines 445-465; §9 ordering paragraph ~line 520)
- Verify-only: `core/tests/python/conformance.py` untouched (no observable-format change)

**Interfaces:** none (normative text).

- [ ] **Step 1: §6.5** — replace the sentence "The recovery path is: detect the inconsistency on next read, re-load the block, re-fingerprint, and offer to update the manifest." (line ~436) with:

```markdown
Steps 9 and 10 must be atomic-as-a-pair from the user's perspective: a crash between writing the block and updating the manifest leaves the manifest pointing at an old block fingerprint, which surfaces on the next read as a typed fingerprint-mismatch error naming the block (a manifest-listed block whose file is *absent* surfaces as a typed missing-file error instead). Recovery is an explicit repair operation (`repair_vault` in the reference implementation) that the client offers to the user: it re-runs the §1 open sequence (same credentials, same verify-before-decrypt, same §10 rollback check), then — per mismatched block, all-or-nothing — re-loads the on-disk block and adopts it into a re-signed manifest **only if** (a) the block file passes the full §6.4 read flow under the owner's card (Ed25519 ∧ ML-DSA-65, both halves), (b) its header `vault_uuid`/`block_uuid` match, and (c) a **two-tier clock-freshness rule** holds. Tier 1: the file's header vector clock **strictly dominates** the manifest entry's `vector_clock_summary` — the exact shape an interrupted §6.5 content write leaves (the write ticked the block clock). Tier 2: the clocks are **equal** AND the file's recipient set is a **strict subset** of the committed entry's — the shape an interrupted §6.5.1 revocation leaves, since re-keys re-encrypt the same plaintext without ticking the block clock, meaning the only possible equal-clock delta is the recipient set and a subset can only narrow access (fail-closed: a planted retained owner-signed copy can at worst un-share a recipient, never re-grant one). Everything else is refused: a dominated clock (rollback plant), an equal-clock non-subset — which includes the residue of an interrupted §8 share (recipient-set *widening*); that residue is a documented limitation, not auto-repairable, until an explicit informed-consent adoption path exists — an equal-clock equal-set byte difference (forgery shape), and concurrent clocks (torn multi-device state repair must not guess about). Wall-clock `last_mod_ms` values MUST NOT be used as a freshness discriminator (they carry no monotonicity guarantee). The adopted entry's `recipients` are rebuilt from the file's §6.2 table (so an interrupted §6.5.1 revocation repairs to the *reduced* recipient set), and its `vector_clock_summary` is taken verbatim from the file header. The missing-file case is **not** repairable — repair cannot invent block bytes; the probable cause is a torn cloud sync and the recovery is a completed sync. Conformance: `core/tests/crash_recovery.rs::repair_vault_adopts_interrupted_save` / `repair_vault_adopts_interrupted_revocation` / `repair_vault_rejects_rollback_plant` / `repair_vault_rejects_equal_and_concurrent_clocks` pin this contract.
```

- [ ] **Step 2: §7** — rewrite the deletion sequence (keep the retention/grammar paragraphs):

```markdown
Deleting a block:

1. Add an entry to `manifest.trash`: `{block_uuid, tombstoned_at_ms, tombstoned_by, fingerprint}`, where `fingerprint` is the BLAKE3-256 of the (unchanged) block file bytes — i.e. the `BlockEntry.fingerprint` of the block being trashed. This is the content commitment §7.1 verifies on restore.
2. Remove the block's entry from `manifest.blocks`.
3. Re-sign and atomically write the manifest. **This write is the deletion's commit point**: from here the block is trashed regardless of what happens to the physical file.
4. Best-effort: move `blocks/<block-uuid>.cbor.enc` → `trash/<block-uuid>.cbor.enc.<unix-millis>`. A failure here (crash, cross-filesystem `EXDEV`, permissions) does **not** un-trash the block: the file remains in `blocks/` as a benign orphan that readers ignore (it is no longer manifest-listed), that §7.1 restore treats as its resume source, and that the open-time sweep (below) relocates once the move becomes possible.
5. After a retention window (default 90 days), `trash/` files older than the window are physically removed.

**Open-time completion sweep.** On each successful open, for every `manifest.trash` entry carrying a `fingerprint` whose expected `trash/` file is absent: if the `block_uuid` is not live in `manifest.blocks` and `blocks/<block-uuid>.cbor.enc` exists with bytes hashing to the signed `fingerprint`, the reader renames it to its step-4 trash path. The sweep is rename-only (no manifest change, no re-signing), idempotent, and best-effort; because the gate is the *signed* content commitment, a planted `blocks/` file cannot steer it. Conformance: `core/tests/crash_recovery.rs::open_vault_sweep_relocates_interrupted_trash` / `sweep_skips_orphan_with_wrong_fingerprint` / `sweep_skips_live_uuid` / `sweep_skips_legacy_entry_without_fingerprint`.
```

And replace the EXDEV paragraph ("The "Move" in step 1 …", ~line 464) with: the move in step 4 is `rename(2)` semantics — atomic on a single filesystem; on a cross-filesystem configuration (`EXDEV`) the deletion still commits at step 3 and the physical move stays pending (the orphan is swept once the vault is re-located to a single filesystem). Renumber the "step 1" references in the retention/grammar paragraphs to step 4.

- [ ] **Step 3: §9** — replace the final paragraph ("When updating a block and the manifest together …") with:

```markdown
When a block file and the manifest change together, the ordering rule is: **never persist a manifest state that references block bytes that are not on disk.** For content writes (§6.5) that means block first, manifest second — a crash leaves a fresh orphan or a stale-fingerprint entry, both detectable and recoverable (§6.5 repair). For deletion (§7) it means manifest first, move second — the same write that commits the trash removes the block's entry, so the manifest never points at the moved-away file; a crash leaves only an unlisted orphan (§7 sweep). The reverse orderings would leave the manifest pointing at a non-existent or wrong-fingerprint block with no recovery gate.
```

- [ ] **Step 4: Run every gate**

```bash
cd /Users/hherb/src/secretary/.worktrees/vault-crash-recovery-350
cargo fmt --all && cargo test --release --workspace 2>&1 | tail -5
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace 2>&1 | tail -3
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py
bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh
```

Expected: all green. `spec_test_name_freshness.py` must resolve the new `crash_recovery.rs::…` citations added in Steps 1-2 (they exist since Tasks 4-7). `conformance.py` green proves no observable-format drift.

- [ ] **Step 5: Commit**

```bash
git add docs/vault-format.md
git commit -m "docs(spec): §6.5 typed repair contract, §7 manifest-first deletion + sweep, §9 ordering invariant (#350)"
```

---

## Post-plan (session wrap, not tasks for implementer subagents)

- Opus whole-branch review; fix findings per feedback_fix_all_review_issues.
- File the follow-up GitHub issue: "FFI projection of repair_vault + platform 'repair now?' UX" (bridge fn, typed `FfiVaultError` surfacing decision, desktop/iOS/Android wiring), referencing #350 and the design doc.
- README.md / ROADMAP.md check; NEXT_SESSION.md handoff (symlink model) committed on this branch; push + open PR (durably authorized).
