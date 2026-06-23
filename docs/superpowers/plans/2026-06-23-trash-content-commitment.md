# Trash Content Commitment (#293) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bind a restored block's content to the signed manifest by carrying the block's BLAKE3-256 fingerprint through the trash→restore lifecycle, closing the #293 in-place-overwrite rollback vector that #205's suffix-equality fix cannot defend.

**Architecture:** `TrashEntry` gains an optional `fingerprint: Option<[u8; 32]>` (BLAKE3-256 of the trashed block bytes, captured at `trash_block` from the removed `BlockEntry.fingerprint`). `restore_block` recomputes BLAKE3-256 of the selected file's bytes and rejects on mismatch *before* the point-of-no-return rename. The field is optional and unknown-routed, so legacy entries (and the on-disk format) are unaffected — no `format_version` bump.

**Tech Stack:** Rust (stable), `secretary-core` crate, `ciborium` canonical CBOR, BLAKE3 (`crate::crypto::hash::hash`), integration tests in `core/tests/`, `proptest`.

## Global Constraints

- **Frozen v1 format** — no `format_version` / `manifest_version` bump. The new field is optional (emitted only when `Some`) and any unrecognized key still routes to `unknown` (forward-compat preserved). Copied verbatim from spec "Scope guard".
- `#![forbid(unsafe_code)]` workspace-wide — do not introduce `unsafe`.
- Clippy must stay clean with `-D warnings` (lib + tests).
- Always build/test `--release` (crypto crates are slow in debug).
- Preserve the "both halves" hybrid-verify property at every signature site — this change adds a *content* check; it does not touch the §6.1 Ed25519 ∧ ML-DSA-65 verify, which still runs.
- Error surface: a content-commitment mismatch reuses `VaultError::RestoreVerificationFailed { block_uuid, detail }` (folds to `FfiVaultError::CorruptVault`). **No new `VaultError` / `FfiVaultError` variant** → no `.udl` / pyo3 / Swift / Kotlin conformance-harness churn.
- Reuse the existing `KEY_FINGERPRINT = "fingerprint"` constant (`core/src/vault/manifest.rs:95`) — the same string already names `BlockEntry.fingerprint`; trash entries are a separate map, so no collision.
- Working directory: `/Users/hherb/src/secretary/.worktrees/trash-content-commitment`, branch `feature/trash-content-commitment`. Verify with `pwd && git branch --show-current` before any `cargo`/`git` call.

---

### Task 1: `TrashEntry` optional content-commitment field + CBOR round-trip

Add the field and its canonical-CBOR encode/decode. Production `trash_block` is wired with a temporary `None` placeholder so the workspace compiles; Task 2 flips it to `Some`.

**Files:**
- Modify: `core/src/vault/manifest.rs` — `TrashEntry` struct (~356), `trash_entry_to_value` encoder (~546), `parse_trash_entry` decoder (~935), `populated_manifest` test helper (~1887), new unit test in `mod tests`.
- Modify: `core/src/vault/orchestrators.rs:1867` — add `fingerprint: None` to the `trash_block` literal (temporary; Task 2 replaces).
- Modify: `core/tests/proptest.rs:1418` — `trash_entry_strategy` generates `Some`/`None` so the existing manifest encode/decode proptest covers both.
- Test: `core/src/vault/manifest.rs` `mod tests` (unit round-trip).

**Interfaces:**
- Produces: `TrashEntry.fingerprint: Option<[u8; BLOCK_FINGERPRINT_LEN]>` (where `BLOCK_FINGERPRINT_LEN = 32`). Encoded under key `"fingerprint"` **only when `Some`**; decoded to `None` when absent.

- [ ] **Step 1: Write the failing unit test**

In `core/src/vault/manifest.rs`, inside `mod tests` (after the existing `populated_manifest` helper), add:

```rust
#[test]
fn trash_entry_fingerprint_some_round_trips() {
    // A TrashEntry carrying a content commitment must survive a full
    // encode → decode cycle with the fingerprint intact (#293).
    let mut m = populated_manifest();
    m.trash[0].fingerprint = Some([0x7a; BLOCK_FINGERPRINT_LEN]);
    let bytes = encode_manifest(&m).unwrap();
    let decoded = decode_manifest(&bytes).unwrap();
    assert_eq!(
        decoded.trash[0].fingerprint,
        Some([0x7a; BLOCK_FINGERPRINT_LEN]),
        "Some(fingerprint) must round-trip"
    );
    // The typed key must NOT leak into the forward-compat `unknown` map.
    assert!(
        decoded.trash[0].unknown.is_empty(),
        "fingerprint must decode as a typed field, not into unknown"
    );
}

#[test]
fn trash_entry_fingerprint_none_omits_key() {
    // A legacy-shaped entry (no commitment) must encode WITHOUT the
    // "fingerprint" key and decode back to None — byte-compatible with
    // pre-#293 manifests.
    let mut m = populated_manifest();
    m.trash[0].fingerprint = None;
    let bytes = encode_manifest(&m).unwrap();
    let decoded = decode_manifest(&bytes).unwrap();
    assert_eq!(decoded.trash[0].fingerprint, None, "None must round-trip");
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --release -p secretary-core --lib trash_entry_fingerprint -- --nocapture`
Expected: FAIL to compile — `no field 'fingerprint' on type 'TrashEntry'`.

- [ ] **Step 3: Implement the field + encode/decode + literal sites**

In `core/src/vault/manifest.rs`, add the field to the `TrashEntry` struct (after `tombstoned_by`):

```rust
pub struct TrashEntry {
    pub block_uuid: [u8; UUID_LEN],
    pub tombstoned_at_ms: u64,
    /// `device_uuid` that performed the deletion.
    pub tombstoned_by: [u8; UUID_LEN],
    /// BLAKE3-256 of the trashed block file bytes, captured at trash time
    /// (the value the live `BlockEntry.fingerprint` committed to). Binds the
    /// restored content's freshness to the signed manifest (#293). `None`
    /// for entries written before this field existed (legacy vaults); restore
    /// then falls back to suffix-equality + §6.1 hybrid-verify only.
    pub fingerprint: Option<[u8; BLOCK_FINGERPRINT_LEN]>,
    /// Forward-compat unknown keys preserved verbatim per the §6.3.2 pattern.
    pub unknown: BTreeMap<String, UnknownValue>,
}
```

In `trash_entry_to_value` (encoder), emit the key only when `Some`, before the `unknown` loop (`canonical_sort_entries` re-sorts on output):

```rust
fn trash_entry_to_value(entry: &TrashEntry) -> Result<Value, ManifestError> {
    let mut inner: Vec<(Value, Value)> = vec![
        (
            Value::Text(KEY_BLOCK_UUID.into()),
            Value::Bytes(entry.block_uuid.to_vec()),
        ),
        (
            Value::Text(KEY_TOMBSTONED_AT_MS.into()),
            Value::Integer(entry.tombstoned_at_ms.into()),
        ),
        (
            Value::Text(KEY_TOMBSTONED_BY.into()),
            Value::Bytes(entry.tombstoned_by.to_vec()),
        ),
    ];
    // #293: optional content commitment. Reuses the "fingerprint" key
    // (separate map from BlockEntry, so no collision). Omitted when None so
    // legacy-shaped entries stay byte-identical (no format bump).
    if let Some(fp) = entry.fingerprint {
        inner.push((Value::Text(KEY_FINGERPRINT.into()), Value::Bytes(fp.to_vec())));
    }
    for (k, v) in &entry.unknown {
        inner.push((Value::Text(k.clone()), unknown_value_inner(v)?));
    }
    let sorted = canonical_sort_entries(&inner)?;
    Ok(Value::Map(sorted))
}
```

In `parse_trash_entry` (decoder), add a typed arm and thread the field. Add the local and the match arm, and set it in the returned struct:

```rust
fn parse_trash_entry(v: Value) -> Result<TrashEntry, ManifestError> {
    let entries = match v {
        Value::Map(m) => m,
        _ => {
            return Err(ManifestError::WrongType {
                field: KEY_TRASH,
                expected: "map (trash entry)",
            })
        }
    };
    let mut block_uuid: Option<[u8; UUID_LEN]> = None;
    let mut tombstoned_at_ms: Option<u64> = None;
    let mut tombstoned_by: Option<[u8; UUID_LEN]> = None;
    let mut fingerprint: Option<[u8; BLOCK_FINGERPRINT_LEN]> = None;
    let mut unknown: BTreeMap<String, UnknownValue> = BTreeMap::new();

    for (k, val) in entries {
        let key = take_text_key(k)?;
        match key.as_str() {
            KEY_BLOCK_UUID => {
                block_uuid = Some(take_fixed_bytes::<UUID_LEN>(val, KEY_BLOCK_UUID)?);
            }
            KEY_TOMBSTONED_AT_MS => {
                tombstoned_at_ms = Some(take_u64(val, KEY_TOMBSTONED_AT_MS)?);
            }
            KEY_TOMBSTONED_BY => {
                tombstoned_by = Some(take_fixed_bytes::<UUID_LEN>(val, KEY_TOMBSTONED_BY)?);
            }
            KEY_FINGERPRINT => {
                fingerprint =
                    Some(take_fixed_bytes::<BLOCK_FINGERPRINT_LEN>(val, KEY_FINGERPRINT)?);
            }
            _ => {
                unknown.insert(key, value_to_unknown(val)?);
            }
        }
    }

    Ok(TrashEntry {
        block_uuid: block_uuid.ok_or(ManifestError::MissingField {
            field: KEY_BLOCK_UUID,
        })?,
        tombstoned_at_ms: tombstoned_at_ms.ok_or(ManifestError::MissingField {
            field: KEY_TOMBSTONED_AT_MS,
        })?,
        tombstoned_by: tombstoned_by.ok_or(ManifestError::MissingField {
            field: KEY_TOMBSTONED_BY,
        })?,
        fingerprint,
        unknown,
    })
}
```

In the `populated_manifest` test helper (~1887), set an explicit `Some` so the existing manifest-file round-trip tests also exercise the field:

```rust
        let trash = vec![TrashEntry {
            block_uuid: [0xde; UUID_LEN],
            tombstoned_at_ms: 1_714_060_900_000,
            tombstoned_by: [0xaa; UUID_LEN],
            fingerprint: Some([0xcd; BLOCK_FINGERPRINT_LEN]),
            unknown: BTreeMap::new(),
        }];
```

In `core/src/vault/orchestrators.rs:1867` (`trash_block`), add the temporary placeholder (Task 2 replaces with `Some`):

```rust
    open.manifest.trash.push(TrashEntry {
        block_uuid,
        tombstoned_at_ms: now_ms,
        tombstoned_by: device_uuid,
        fingerprint: None, // populated in Task 2
        unknown: std::collections::BTreeMap::new(),
    });
```

In `core/tests/proptest.rs:1418`, extend `trash_entry_strategy` to generate `Some`/`None` so the manifest round-trip proptest covers both shapes:

```rust
    fn trash_entry_strategy() -> impl Strategy<Value = TrashEntry> {
        (
            arr16(),
            any::<u64>(),
            arr16(),
            prop::option::of(arr32_fp()), // arr32_fp(): in-scope [u8; FINGERPRINT_LEN] strategy
        )
            .prop_map(
                |(block_uuid, tombstoned_at_ms, tombstoned_by, fingerprint)| TrashEntry {
                    block_uuid,
                    tombstoned_at_ms,
                    tombstoned_by,
                    fingerprint,
                    unknown: BTreeMap::new(),
                },
            )
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --release -p secretary-core --lib trash_entry_fingerprint`
Expected: PASS (both new tests).
Run: `cargo test --release --workspace --test proptest`
Expected: PASS (manifest round-trip proptest now covers Some/None).

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/trash-content-commitment
git add core/src/vault/manifest.rs core/src/vault/orchestrators.rs core/tests/proptest.rs
git commit -m "feat(vault): add optional content commitment to TrashEntry (#293)

Optional fingerprint: Option<[u8;32]> on TrashEntry, encoded under the
existing \"fingerprint\" key only when Some (legacy entries byte-identical,
no format bump). Decoder threads a typed arm; proptest covers Some/None.
trash_block wired with a None placeholder pending Task 2.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: `trash_block` populates the commitment

**Files:**
- Modify: `core/src/vault/orchestrators.rs` — `trash_block` (~1829–1872): capture the removed `BlockEntry.fingerprint`, write it into the `TrashEntry`.
- Test: `core/tests/trash_restore.rs` — new test in the `trash_block` section (after `trash_block_then_reopen_round_trip`, ~line 393).

**Interfaces:**
- Consumes: `TrashEntry.fingerprint` from Task 1.
- Produces: after `trash_block`, the appended `TrashEntry.fingerprint == Some(<the trashed block's BlockEntry.fingerprint>)`.

- [ ] **Step 1: Write the failing test**

In `core/tests/trash_restore.rs`, add:

```rust
// ---------------------------------------------------------------------------
// trash_block — content commitment (#293)
// ---------------------------------------------------------------------------

/// `trash_block` captures the live `BlockEntry.fingerprint` into the new
/// `TrashEntry.fingerprint` (the content commitment that `restore_block`
/// later verifies, #293).
#[test]
fn trash_block_captures_content_commitment() {
    let (dir, _mnemonic, pw) = make_fast_vault(20, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x20; 32]);

    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let device_uuid = [0xd2; 16];
    let block_uuid = [0xb2; 16];
    let recipients = vec![open.owner_card.clone()];
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "secret"),
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();

    // Capture the live block's fingerprint BEFORE trashing.
    let live_fp = open
        .manifest
        .blocks
        .iter()
        .find(|b| b.block_uuid == block_uuid)
        .expect("block must be live before trash")
        .fingerprint;

    trash_block(folder, &mut open, block_uuid, device_uuid, 2_000, &mut rng).unwrap();

    let entry = open
        .manifest
        .trash
        .iter()
        .find(|t| t.block_uuid == block_uuid)
        .expect("TrashEntry for the trashed block");
    assert_eq!(
        entry.fingerprint,
        Some(live_fp),
        "trash_block must commit the live BlockEntry.fingerprint into the TrashEntry",
    );
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --release --workspace --test trash_restore trash_block_captures_content_commitment`
Expected: FAIL — `assertion failed: left == right`, left is `None` (Task 1 placeholder).

- [ ] **Step 3: Implement the capture in `trash_block`**

In `core/src/vault/orchestrators.rs`, after locating `entry_idx` (Step 1 of `trash_block`, ~line 1835) capture the fingerprint before the `remove`:

```rust
    // Step 1: locate the block.
    let entry_idx = open
        .manifest
        .blocks
        .iter()
        .position(|b| b.block_uuid == block_uuid)
        .ok_or(VaultError::BlockNotFound { block_uuid })?;
    // #293: capture the live content commitment before removing the entry.
    // The file is moved (rename) unchanged into trash/, so this BLAKE3-256
    // (authenticated at the most recent open_vault) is exactly the hash of
    // the trashed bytes restore will recompute and check.
    let content_fingerprint = open.manifest.blocks[entry_idx].fingerprint;
```

Then in Step 5 (the `TrashEntry` push), replace the placeholder:

```rust
    open.manifest.trash.push(TrashEntry {
        block_uuid,
        tombstoned_at_ms: now_ms,
        tombstoned_by: device_uuid,
        fingerprint: Some(content_fingerprint),
        unknown: std::collections::BTreeMap::new(),
    });
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test --release --workspace --test trash_restore trash_block_captures_content_commitment`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/trash-content-commitment
git add core/src/vault/orchestrators.rs core/tests/trash_restore.rs
git commit -m "feat(vault): trash_block commits the block content fingerprint (#293)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: `restore_block` verifies the commitment + teeth tests

The security core. Verify BLAKE3-256(selected bytes) == committed fingerprint *before* the rename; reject mismatches via `RestoreVerificationFailed`. Legacy `None` falls back to the existing #205 path.

**Files:**
- Modify: `core/src/vault/orchestrators.rs` — `restore_block`: capture `committed_fp` alongside `expected_ts` (~2050), add the commitment check after the file read (~2087, before the rename at ~2222).
- Test: `core/tests/trash_restore.rs` — two new tests after `restore_block_missing_signed_target_rejected` (end of file, ~1297).

**Interfaces:**
- Consumes: `TrashEntry.fingerprint` (Task 1), `blake3_hash` (already imported in orchestrators.rs as `use crate::crypto::hash::hash as blake3_hash`).
- Produces: on commitment mismatch, `VaultError::RestoreVerificationFailed { block_uuid, detail }` with `detail` containing `"content commitment mismatch"`; manifest + `trash/` untouched.

- [ ] **Step 1: Write the failing tests**

In `core/tests/trash_restore.rs`, append:

```rust
/// #293: an attacker with write access to the synced trash/ folder overwrites
/// the suffix-matching file IN PLACE with a previously-retained, genuinely
/// owner-signed, OLDER copy of the same block_uuid. The §6.1 hybrid-verify
/// passes (authenticity != currency), and the suffix still equals the signed
/// tombstoned_at_ms — so #205's suffix-equality cannot defend it. The content
/// commitment in the signed TrashEntry rejects it: BLAKE3 of the stale bytes
/// != the committed fingerprint. On `main` (no commitment) this restore would
/// SUCCEED and resurrect the stale secret (the rollback this test pins shut).
#[test]
fn restore_block_rejects_in_place_overwrite_with_stale_signed_copy() {
    let (dir, _mnemonic, pw) = make_fast_vault(21, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x21; 32]);

    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let device_uuid = [0xd3; 16];
    let block_uuid = [0xb3; 16];
    let recipients = vec![open.owner_card.clone()];

    // First save: STALE content. Capture its valid owner-signed bytes.
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "stale-old-secret"),
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();
    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    let live_path = folder.join("blocks").join(format!("{uuid_hex}.cbor.enc"));
    let stale_bytes = fs::read(&live_path).unwrap();

    // Second save (update — same block_uuid): the AUTHENTIC-CURRENT content.
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "authentic-current-secret"),
        &recipients,
        device_uuid,
        2_000,
        &mut rng,
    )
    .unwrap();

    let trash_ts = 5_000u64;
    trash_block(folder, &mut open, block_uuid, device_uuid, trash_ts, &mut rng).unwrap();

    // The authentic-current envelope is at suffix == signed ts; the signed
    // TrashEntry commits to ITS fingerprint.
    let trash_dir = folder.join("trash");
    let authentic = trash_dir.join(format!("{uuid_hex}.cbor.enc.{trash_ts}"));
    let authentic_bytes = fs::read(&authentic).unwrap();
    assert_ne!(
        stale_bytes, authentic_bytes,
        "sanity: the two valid envelopes must differ in content",
    );

    // ATTACK: overwrite the suffix-matching file IN PLACE with the valid stale
    // envelope. Suffix unchanged (== signed ts); bytes are genuinely signed.
    fs::write(&authentic, &stale_bytes).unwrap();

    let err = restore_block(folder, &mut open, block_uuid, device_uuid, 10_000, &mut rng)
        .expect_err("restore must reject an in-place stale-content overwrite");
    assert!(
        matches!(
            &err,
            VaultError::RestoreVerificationFailed { block_uuid: b, detail }
                if *b == block_uuid && detail.contains("content commitment mismatch")
        ),
        "expected RestoreVerificationFailed(content commitment mismatch), got {err:?}",
    );
    // Manifest + trash untouched; no live block; nothing renamed into blocks/.
    assert!(
        open.manifest.trash.iter().any(|t| t.block_uuid == block_uuid),
        "TrashEntry must remain after a rejected restore",
    );
    assert!(
        !open.manifest.blocks.iter().any(|b| b.block_uuid == block_uuid),
        "no BlockEntry must be created on a rejected restore",
    );
    assert!(
        !live_path.exists(),
        "nothing must be renamed into blocks/ on a rejected restore",
    );
}

/// #293: a legacy TrashEntry (fingerprint None — trashed by a pre-#293 client)
/// must still restore via the #205 suffix-equality + §6.1 hybrid-verify path.
/// We simulate the legacy shape by nulling the in-memory committed fingerprint
/// (restore_block reads the commitment from the open, already-verified
/// manifest). The authentic file is unchanged, so restore succeeds.
#[test]
fn restore_block_legacy_entry_without_fingerprint_falls_back() {
    let (dir, _mnemonic, pw) = make_fast_vault(22, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x22; 32]);

    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let device_uuid = [0xd4; 16];
    let block_uuid = [0xb4; 16];
    let recipients = vec![open.owner_card.clone()];
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "secret"),
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();
    trash_block(folder, &mut open, block_uuid, device_uuid, 2_000, &mut rng).unwrap();

    // Simulate a legacy (pre-#293) signed TrashEntry: no content commitment.
    for t in &mut open.manifest.trash {
        if t.block_uuid == block_uuid {
            t.fingerprint = None;
        }
    }

    restore_block(folder, &mut open, block_uuid, device_uuid, 3_000, &mut rng)
        .expect("legacy (None-commitment) restore must succeed via suffix-equality");
    assert!(
        open.manifest.blocks.iter().any(|b| b.block_uuid == block_uuid),
        "block must be live after legacy restore",
    );
    assert!(
        !open.manifest.trash.iter().any(|t| t.block_uuid == block_uuid),
        "TrashEntry must be gone after legacy restore",
    );
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --release --workspace --test trash_restore restore_block_rejects_in_place_overwrite_with_stale_signed_copy restore_block_legacy_entry_without_fingerprint_falls_back`
Expected: `restore_block_rejects_in_place_overwrite_with_stale_signed_copy` FAILS — restore returns `Ok` (no commitment check yet) so `expect_err` panics. `restore_block_legacy_entry_without_fingerprint_falls_back` PASSES already (defensive; None path is the current behavior).

- [ ] **Step 3: Implement the commitment check in `restore_block`**

In `core/src/vault/orchestrators.rs`, change the `expected_ts` lookup (~2050) to also capture the committed fingerprint:

```rust
    let (expected_ts, committed_fp) = match open
        .manifest
        .trash
        .iter()
        .find(|t| t.block_uuid == block_uuid)
    {
        Some(entry) => (entry.tombstoned_at_ms, entry.fingerprint),
        None => return Err(VaultError::BlockNotInTrash { block_uuid }),
    };
```

Then, immediately after the restore-target bytes are read (Step 4, after `let bytes = std::fs::read(&restore_path)...?;`, ~line 2087) and before `decode_block_file`, add the commitment check:

```rust
    // #293: content-freshness binding. If the signed TrashEntry commits to a
    // BLAKE3-256 of the trashed bytes (captured at trash_block), the selected
    // file's bytes MUST hash to it. This rejects an in-place overwrite of the
    // suffix-matching file with a genuinely-owner-signed but OLDER copy —
    // authenticity is not currency, so the §6.1 hybrid-verify below cannot
    // catch it, and #205's suffix-equality does not defend it. The check runs
    // before any rename/purge, so the manifest and trash/ stay untouched on
    // reject. `None` = legacy entry (pre-#293) → fall through to the existing
    // suffix-equality + hybrid-verify path.
    if let Some(committed_fp) = committed_fp {
        let got = *blake3_hash(&bytes).as_bytes();
        if got != committed_fp {
            return Err(VaultError::RestoreVerificationFailed {
                block_uuid,
                detail: "content commitment mismatch: trashed file bytes do not \
                         match the signed TrashEntry.fingerprint"
                    .to_string(),
            });
        }
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --release --workspace --test trash_restore`
Expected: PASS (all trash/restore tests, including the two new ones and the unchanged #205 tests).

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/trash-content-commitment
git add core/src/vault/orchestrators.rs core/tests/trash_restore.rs
git commit -m "fix(vault): restore_block verifies content commitment to close #293

Recompute BLAKE3-256 of the selected trash file and reject when it differs
from the signed TrashEntry.fingerprint, before the point-of-no-return rename.
Closes the in-place-overwrite stale-rollback vector #205's suffix-equality
could not defend. Legacy (None-commitment) entries fall back to the #205 path.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Docs in lockstep + full gate

Update the normative spec, threat model, and README to match the new behavior; run the full verification gate.

**Files:**
- Modify: `docs/vault-format.md` — §4.2 CDDL trash entry (~225), §7 deletion step 2 (~449), §7.1 restore (new content-commitment step ~473).
- Modify: `docs/threat-model.md` — §2.1 rollback table (~80).
- Modify: `README.md` — B.5 restore row (~173).

**Interfaces:** none (docs + verification only).

- [ ] **Step 1: Update `docs/vault-format.md` §4.2 CDDL**

Replace the trash-entry block (~223–227):

```
  "trash": [                                      ; tombstoned blocks
    {
      "block_uuid":     <bstr 16>,
      "tombstoned_at_ms": <u64>,
      "tombstoned_by":  <bstr 16>,                 ; device_uuid that performed the deletion
      "fingerprint":    <bstr 32, optional>        ; BLAKE3-256 of the trashed block file bytes,
                                                   ; captured at trash time. Binds restored content
                                                   ; freshness to the signed manifest (§7.1 step 3a).
                                                   ; Absent for entries written by pre-this-version
                                                   ; clients; restore then falls back to suffix +
                                                   ; hybrid-verify only.
    },
    ...
  ],
```

- [ ] **Step 2: Update `docs/vault-format.md` §7 deletion step 2**

Replace step 2 (~449):

```
2. Add an entry to `manifest.trash`: `{block_uuid, tombstoned_at_ms, tombstoned_by, fingerprint}`, where `fingerprint` is the BLAKE3-256 of the (moved, unchanged) block file bytes — i.e. the `BlockEntry.fingerprint` of the block being trashed. This is the content commitment §7.1 verifies on restore.
```

- [ ] **Step 3: Update `docs/vault-format.md` §7.1 with the content-commitment step**

Insert a new step 3a immediately after step 3 (the hybrid-verify step, ~473):

```
3a. **Content-commitment check (rollback-freshness binding).** If the matching `TrashEntry` carries a `fingerprint` (present for blocks trashed by this version or later), compute the BLAKE3-256 of the restore-target's bytes and require it to equal `TrashEntry.fingerprint`. A mismatch halts restore as an integrity failure (typed `RestoreVerificationFailed`) — the manifest and `trash/` are NOT modified. This binds the restored content's *freshness* to the signed manifest: §6.1 hybrid-verify proves *authenticity* (the bytes were genuinely owner-signed) but not *currency*, so without this step an attacker with write access to `trash/` could overwrite the suffix-matching file in place with a previously-retained, genuinely owner-signed *older* copy and roll the block back (e.g. a rotated password reverts). If the `TrashEntry` has no `fingerprint` (a legacy entry written before this commitment existed), this step is skipped and restore proceeds on the suffix-equality (step 2) + hybrid-verify (step 3) bindings alone — the residual rollback exposure is limited to blocks trashed by an older client and is documented in the threat model. An attacker cannot *induce* the legacy path: `TrashEntry` is inside the signed manifest, so stripping the `fingerprint` invalidates the signature and restore is never reached.
```

- [ ] **Step 4: Update `docs/threat-model.md` §2.1 rollback table**

Replace the block-level rollback row (~80):

```
| Substitute an older valid block file (rollback at block level) | Per-block fingerprint in the signed manifest binds the manifest's view of the block to specific bytes. An older block's bytes have an older fingerprint; manifest signature fails. For a *trashed* block awaiting restore, the signed `TrashEntry.fingerprint` (vault-format §7.1 step 3a) extends the same content commitment through the trash→restore lifecycle: an in-place overwrite of the suffix-matching trash file with an older, genuinely owner-signed copy is rejected because its BLAKE3-256 differs from the committed value. (Residual: blocks trashed by a pre-commitment client carry no `TrashEntry.fingerprint` and fall back to suffix-equality + hybrid-verify until re-trashed; an attacker cannot induce this state because the commitment is inside the signed manifest.) |
```

- [ ] **Step 5: Update `README.md` B.5 restore row**

In the B.5 row (~173), replace the clause `full-decrypts + hybrid-verifies (defense in depth) before any manifest mutation` with:

```
full-decrypts + hybrid-verifies AND checks the signed `TrashEntry.fingerprint` content commitment (#293 — rejects an in-place overwrite of the suffix-matching trash file with an older owner-signed copy; legacy commitment-less entries fall back to suffix-equality) before any manifest mutation
```

- [ ] **Step 6: Run the full verification gate**

```bash
cd /Users/hherb/src/secretary/.worktrees/trash-content-commitment
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py
```

Expected:
- `cargo test`: all binaries OK, 0 FAILED.
- `cargo clippy`: clean, no warnings.
- `cargo fmt --check`: no diff.
- `conformance.py`: PASS (golden vault still decrypts; it has no trash entries, so the new optional key is never exercised there — confirms no clean-room drift).
- `spec_test_name_freshness.py`: only the 3 pre-existing #290 false-positives, no NEW drift. (If the two new test names need citing, the checker is not a CI gate; note any new entries but do not block on them.)

- [ ] **Step 7: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/trash-content-commitment
git add docs/vault-format.md docs/threat-model.md README.md
git commit -m "docs: TrashEntry content commitment (#293) — vault-format §7.1, threat-model, README

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage:**
- `TrashEntry.fingerprint` optional typed field → Task 1. ✔
- Encoder omits when `None` (no format bump) → Task 1 Step 3. ✔
- Decoder typed arm + unknown still routed → Task 1 Step 3 + `trash_entry_fingerprint_some_round_trips` asserts `unknown.is_empty()`. ✔
- `trash_block` populates from removed `BlockEntry.fingerprint` → Task 2. ✔
- `restore_block` verifies before rename; reuse `RestoreVerificationFailed`; `None` → fallback → Task 3. ✔
- No-downgrade-strip property → asserted by design (signed manifest) + documented in §7.1 step 3a / threat-model; not separately unit-testable without forging a signature (out of scope). ✔
- Teeth test (in-place overwrite) + legacy fallback test + happy-path commitment assertion → Task 3 + Task 2. ✔
- Docs: vault-format §4.2/§7/§7.1, threat-model §2.1, README B.5 → Task 4. ✔
- conformance.py unchanged (verified: decodes block file + KAT merges, not manifest trash) → Task 4 Step 6 confirms. ✔

**Placeholder scan:** No TBD/TODO; every code step shows complete code. The `fingerprint: None` in Task 1 Step 3 (`trash_block`) is an explicit, labelled temporary replaced in Task 2 Step 3 — not a placeholder gap.

**Type consistency:** `Option<[u8; BLOCK_FINGERPRINT_LEN]>` (= `Option<[u8; 32]>`) used uniformly across struct/encoder/decoder/strategy/tests. `committed_fp: Option<[u8; 32]>` in `restore_block` matches the field type. `blake3_hash(&bytes).as_bytes()` returns `&[u8; 32]`; `*…` deref + compare to `[u8; 32]` is consistent. `RestoreVerificationFailed { block_uuid, detail }` matches the existing variant shape (verified at `core/src/vault/mod.rs:290`).
