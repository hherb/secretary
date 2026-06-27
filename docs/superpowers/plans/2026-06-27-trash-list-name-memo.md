# Trash-list name memo (#172) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make repeat Trash-view opens skip the per-block AEAD decrypt by memoizing `block_uuid → (ts, block_name)` on the `OpenVaultManifest` handle.

**Architecture:** A session-scoped, self-invalidating in-memory memo keyed by the on-disk `<ts>` filename suffix. On a hit (same uuid + same `ts`) the name is served from cache and the decrypt is skipped; on a miss the block is decrypted as today and the result cached. The cache lives in a new `Mutex<HashMap>` field on the handle, is pruned to the live trash set on every call, and is cleared on `wipe`. No on-disk format, spec, or FFI-surface change.

**Tech Stack:** Rust (stable), `secretary-ffi-bridge` crate, `std::collections::HashMap`, `std::sync::Mutex`.

## Global Constraints

- `#![forbid(unsafe_code)]` workspace-wide — no `unsafe`.
- Clippy must stay clean with `-D warnings` (lib + tests).
- `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace` must stay warning-clean (intra-doc links resolve).
- All work happens in worktree `/Users/hherb/src/secretary/.worktrees/trash-list-memo-172`, branch `feature/trash-list-memo-172`. Use absolute paths or `cd` within one Bash call (shell state does not persist).
- Tests are `--release` (crypto crates are slow in debug): `cargo test --release --workspace`.
- No change to the public FFI surface: `list_trashed_blocks(identity, manifest) -> Result<Vec<TrashedBlock>, FfiVaultError>` and `TrashedBlock` are unchanged. No uniffi/pyo3/Swift/Kotlin conformance change.
- Block names are non-secret in the bridge (already plaintext in `BlockSummary`); the cache holds plain `String` (not `Sensitive`) but is cleared on `wipe`.

---

### Task 1: `newest_trash_file` returns the `<ts>` alongside the path

The memo is keyed by the file version `ts`. `newest_trash_file` already parses `ts` internally but discards it. Make it return `(PathBuf, u64)` so the caller gets the key for free. Pure refactor — no behavior change; the three existing integration tests must still pass.

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/trash/list.rs` (`newest_trash_file` signature + its single call site in `list_trashed_blocks`)

**Interfaces:**
- Produces: `fn newest_trash_file(trash_dir: &Path, block_uuid: &[u8; 16]) -> Result<Option<(PathBuf, u64)>, FfiVaultError>` — the `u64` is the canonical-decimal `<ts>` suffix of the selected (newest) file.

- [ ] **Step 1: Change the return type and the `best` accumulator**

In `ffi/secretary-ffi-bridge/src/trash/list.rs`, change the `newest_trash_file` signature and return so it yields the `ts`. The function body already tracks `best: Option<(u64, PathBuf)>`; just return both elements instead of dropping the `u64`.

Replace the signature line:

```rust
fn newest_trash_file(
    trash_dir: &Path,
    block_uuid: &[u8; 16],
) -> Result<Option<(PathBuf, u64)>, FfiVaultError> {
```

Replace the final return line `Ok(best.map(|(_, p)| p))` with:

```rust
    Ok(best.map(|(ts, p)| (p, ts)))
```

Update the doc-comment's first sentence to read: `… and return the path with the highest `<ts>` suffix together with that `<ts>` (newest-wins …)`.

- [ ] **Step 2: Update the call site in `list_trashed_blocks`**

In the same file, the loop currently binds `let path = newest_trash_file(...)?.ok_or_else(...)?;`. Change it to destructure the tuple (the `ts` is unused *in this task* — prefix with `_` to keep clippy quiet; Task 3 consumes it):

```rust
        let (path, _ts) = newest_trash_file(&trash_dir, &entry.block_uuid)?.ok_or_else(|| {
            FfiVaultError::CorruptVault {
                detail: format!(
                    "trash entry has no matching file for {}",
                    hex::encode(entry.block_uuid)
                ),
            }
        })?;
```

- [ ] **Step 3: Run the existing tests to confirm no behavior change**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/trash-list-memo-172 && cargo test --release -p secretary-ffi-bridge --test trash_list
```
Expected: PASS — `trashed_block_appears_in_list_by_name`, `list_selects_newest_trash_file_and_skips_non_canonical`, `list_trashed_blocks_empty_when_nothing_trashed` all green (3 passed).

- [ ] **Step 4: Clippy clean**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/trash-list-memo-172 && cargo clippy --release -p secretary-ffi-bridge --tests -- -D warnings
```
Expected: exit 0, no warnings.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/trash-list-memo-172 && git add ffi/secretary-ffi-bridge/src/trash/list.rs && git commit -m "refactor(#172): newest_trash_file returns (path, ts)

Surfaces the canonical-decimal <ts> filename suffix to the caller so the
upcoming name memo can key on the file version for free. Pure refactor;
no behavior change.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Add the `name_cache` field + accessors to `OpenVaultManifest`

Add the memo storage and its two `pub(crate)` accessors to the handle, wired into `new()` and `wipe()`. Unit-test the get/put/prune logic directly (it's pure map manipulation behind a `Mutex`).

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/vault/manifest.rs` (struct field, `new`, `wipe`, two accessors, a unit-test module)

**Interfaces:**
- Consumes: `lock_or_recover` (already imported in this file from `crate::sync_helpers`).
- Produces:
  - `pub(crate) fn trash_name_cache_get(&self, block_uuid: &[u8; 16], ts: u64) -> Option<String>` — returns the cached name iff an entry exists for `block_uuid` whose stored `ts` equals the argument.
  - `pub(crate) fn trash_name_cache_put_and_prune(&self, updates: Vec<([u8; 16], u64, String)>, live_uuids: &std::collections::HashSet<[u8; 16]>)` — inserts/overwrites each `(uuid, ts, name)`, then retains only entries whose uuid is in `live_uuids`. Single lock acquisition.

- [ ] **Step 1: Write the failing unit tests**

Add this test module at the bottom of `ffi/secretary-ffi-bridge/src/vault/manifest.rs`. It exercises the accessors against a real handle built from `golden_vault_001` (the same fixture the integration tests use), since `OpenVaultManifest` has no public constructor outside `open_vault_*`.

```rust
#[cfg(test)]
mod name_cache_tests {
    use std::collections::HashSet;
    use std::path::{Path, PathBuf};

    use crate::open_vault_with_password;

    const VAULT_001_PASSWORD: &[u8] = b"correct horse battery staple";

    fn fixture_folder(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../core/tests/data")
            .join(name)
    }

    fn copy_dir_recursive(src: &Path, dst: &Path) {
        std::fs::create_dir_all(dst).unwrap();
        for entry in std::fs::read_dir(src).unwrap() {
            let entry = entry.unwrap();
            let from = entry.path();
            let to = dst.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_dir_recursive(&from, &to);
            } else {
                std::fs::copy(&from, &to).unwrap();
            }
        }
    }

    fn open_writable_golden_001() -> (tempfile::TempDir, super::OpenVaultManifest) {
        let tmp = tempfile::tempdir().unwrap();
        copy_dir_recursive(&fixture_folder("golden_vault_001"), tmp.path());
        let out = open_vault_with_password(tmp.path(), VAULT_001_PASSWORD).unwrap();
        (tmp, out.manifest)
    }

    #[test]
    fn put_then_get_hits_on_matching_ts_and_misses_otherwise() {
        let (_tmp, manifest) = open_writable_golden_001();
        let uuid = [0xAB; 16];
        let live: HashSet<[u8; 16]> = [uuid].into_iter().collect();

        manifest.trash_name_cache_put_and_prune(vec![(uuid, 42, "Logins".into())], &live);

        assert_eq!(manifest.trash_name_cache_get(&uuid, 42), Some("Logins".to_string()));
        // Wrong ts → miss (file version advanced).
        assert_eq!(manifest.trash_name_cache_get(&uuid, 43), None);
        // Unknown uuid → miss.
        assert_eq!(manifest.trash_name_cache_get(&[0xCD; 16], 42), None);
    }

    #[test]
    fn prune_drops_uuids_absent_from_live_set() {
        let (_tmp, manifest) = open_writable_golden_001();
        let kept = [0x11; 16];
        let dropped = [0x22; 16];

        // First call caches both.
        let both: HashSet<[u8; 16]> = [kept, dropped].into_iter().collect();
        manifest.trash_name_cache_put_and_prune(
            vec![(kept, 1, "Keep".into()), (dropped, 1, "Drop".into())],
            &both,
        );
        assert_eq!(manifest.trash_name_cache_get(&dropped, 1), Some("Drop".to_string()));

        // Second call: `dropped` is no longer live (e.g. restored) → pruned out.
        let only_kept: HashSet<[u8; 16]> = [kept].into_iter().collect();
        manifest.trash_name_cache_put_and_prune(vec![], &only_kept);
        assert_eq!(manifest.trash_name_cache_get(&kept, 1), Some("Keep".to_string()));
        assert_eq!(manifest.trash_name_cache_get(&dropped, 1), None);
    }

    #[test]
    fn wipe_clears_the_cache() {
        let (_tmp, manifest) = open_writable_golden_001();
        let uuid = [0x33; 16];
        let live: HashSet<[u8; 16]> = [uuid].into_iter().collect();
        manifest.trash_name_cache_put_and_prune(vec![(uuid, 7, "Secret".into())], &live);
        assert_eq!(manifest.trash_name_cache_get(&uuid, 7), Some("Secret".to_string()));

        manifest.wipe();
        // After wipe the cache holds no residual names.
        assert_eq!(manifest.trash_name_cache_get(&uuid, 7), None);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/trash-list-memo-172 && cargo test --release -p secretary-ffi-bridge name_cache_tests 2>&1 | tail -20
```
Expected: FAIL to compile — `trash_name_cache_put_and_prune` / `trash_name_cache_get` do not exist yet.

- [ ] **Step 3: Add the import, the field, and wire `new` + `wipe`**

In `ffi/secretary-ffi-bridge/src/vault/manifest.rs`:

At the top, add to the `use std::...` imports (the file already has `use std::sync::Mutex;`):

```rust
use std::collections::{HashMap, HashSet};
```

Add the new field to the `OpenVaultManifest` struct, after the `mid_call_hook` field:

```rust
    /// Memo: `block_uuid → (ts, block_name)` for the Trash view's
    /// by-name projection. Keyed by the on-disk `<ts>` filename suffix so
    /// it is self-invalidating — a re-trash (higher `ts`) is an automatic
    /// miss, a restore is pruned out. Lets repeat `list_trashed_blocks`
    /// calls skip the per-block AEAD decrypt (#172).
    ///
    /// Holds plain `String` names, not `Sensitive`: block names are
    /// non-secret in the bridge (already plaintext in
    /// [`super::inner::BlockSummary`]). Still cleared on [`Self::wipe`] to
    /// match the handle's secret-lifecycle. In a separate `Mutex` from
    /// `inner` so a cache read never contends with a manifest mutation.
    name_cache: Mutex<HashMap<[u8; 16], (u64, String)>>,
```

In `OpenVaultManifest::new`, initialise the field:

```rust
    pub(crate) fn new(inner: OpenVaultManifestInner) -> Self {
        Self {
            inner: Mutex::new(Some(inner)),
            mid_call_hook: Mutex::new(None),
            name_cache: Mutex::new(HashMap::new()),
        }
    }
```

In `OpenVaultManifest::wipe`, clear the cache (add after the existing `let _drop = … .take();` line, before the closing brace):

```rust
        // Drop any memoized trash names too — keeps a wiped handle free of
        // residual (non-secret but handle-scoped) names.
        lock_or_recover(&self.name_cache).clear();
```

- [ ] **Step 4: Add the two accessors**

Add these methods inside the `impl OpenVaultManifest { … }` block (e.g. just before the closing `}` of the impl):

```rust
    /// Look up a memoized trashed-block name. Returns `Some(name)` iff an
    /// entry exists for `block_uuid` whose stored `ts` equals `ts` (same
    /// on-disk file version). A differing `ts` (file re-trashed) or absent
    /// uuid is a miss. Part of the #172 Trash-view decrypt memo.
    pub(crate) fn trash_name_cache_get(&self, block_uuid: &[u8; 16], ts: u64) -> Option<String> {
        lock_or_recover(&self.name_cache)
            .get(block_uuid)
            .filter(|(cached_ts, _)| *cached_ts == ts)
            .map(|(_, name)| name.clone())
    }

    /// Apply this call's freshly-decrypted `(uuid, ts, name)` results to
    /// the memo, then prune the memo down to `live_uuids` (the current
    /// `manifest.trash` set) so restored/stale entries do not accumulate.
    /// One lock acquisition. Part of the #172 Trash-view decrypt memo.
    pub(crate) fn trash_name_cache_put_and_prune(
        &self,
        updates: Vec<([u8; 16], u64, String)>,
        live_uuids: &HashSet<[u8; 16]>,
    ) {
        let mut cache = lock_or_recover(&self.name_cache);
        for (uuid, ts, name) in updates {
            cache.insert(uuid, (ts, name));
        }
        cache.retain(|uuid, _| live_uuids.contains(uuid));
    }
```

- [ ] **Step 5: Run the unit tests to verify they pass**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/trash-list-memo-172 && cargo test --release -p secretary-ffi-bridge name_cache_tests 2>&1 | tail -20
```
Expected: PASS — 3 passed (`put_then_get_hits_on_matching_ts_and_misses_otherwise`, `prune_drops_uuids_absent_from_live_set`, `wipe_clears_the_cache`).

- [ ] **Step 6: Clippy + doc clean**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/trash-list-memo-172 && cargo clippy --release -p secretary-ffi-bridge --tests -- -D warnings && RUSTDOCFLAGS="-D warnings" cargo doc --no-deps -p secretary-ffi-bridge
```
Expected: exit 0, no warnings (intra-doc link `[`super::inner::BlockSummary`]` resolves).

- [ ] **Step 7: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/trash-list-memo-172 && git add ffi/secretary-ffi-bridge/src/vault/manifest.rs && git commit -m "feat(#172): name_cache field + accessors on OpenVaultManifest

Self-invalidating (uuid, ts) memo for the Trash-view name projection.
get hits only on matching ts; put_and_prune applies this call's results
then retains only the live-trash uuid set. Cleared on wipe. Unit-tested.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Wire the memo into `list_trashed_blocks` + behavioral integration tests

Consult the memo per entry; on a hit skip the decrypt, on a miss decrypt and record the result; after the loop apply + prune in one shot. Prove the behavior with two integration tests that observe memoization through output alone (no test-only instrumentation).

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/trash/list.rs` (`list_trashed_blocks` body + module doc-comment)
- Modify: `ffi/secretary-ffi-bridge/tests/trash_list.rs` (add two tests + a small in-place-tamper helper)

**Interfaces:**
- Consumes: `OpenVaultManifest::trash_name_cache_get` / `trash_name_cache_put_and_prune` (Task 2); `newest_trash_file` returning `(PathBuf, u64)` (Task 1).

- [ ] **Step 1: Write the failing integration tests**

Add to `ffi/secretary-ffi-bridge/tests/trash_list.rs`. First add a helper that overwrites a file's bytes in place (corrupting the ciphertext without changing the name/`ts`), placed near `find_trash_file`:

```rust
/// Overwrite a file's contents in place with `new_bytes` (same path, so
/// the `<ts>` suffix is unchanged). Used to corrupt a trash file's
/// ciphertext to prove whether a list call re-decrypts it.
fn overwrite_in_place(path: &Path, new_bytes: &[u8]) {
    std::fs::write(path, new_bytes).expect("overwrite trash file in place");
}
```

Then the two behavioral tests:

```rust
/// A second `list_trashed_blocks` with the SAME on-disk `<ts>` serves the
/// name from the memo without re-decrypting: we corrupt the ciphertext in
/// place after the first list, and the second list still returns the
/// correct name (a re-decrypt would have surfaced a typed error).
#[test]
fn cache_hit_serves_name_without_redecrypt() {
    let opened = open_writable_golden_001();
    let block_uuid = [0x53u8; 16];
    create_block(
        &opened.identity,
        &opened.manifest,
        block_uuid,
        "Server keys".into(),
        DEVICE_UUID,
        1_000,
    )
    .expect("create_block");
    trash_block(&opened.identity, &opened.manifest, block_uuid, DEVICE_UUID, 2_000)
        .expect("trash_block");

    // First list populates the memo (uuid, ts → "Server keys").
    let first = list_trashed_blocks(&opened.identity, &opened.manifest).expect("first list");
    assert_eq!(
        first.iter().find(|t| t.block_uuid == block_uuid).unwrap().block_name,
        "Server keys",
    );

    // Corrupt the trash file's bytes in place (ts suffix unchanged).
    let vault_dir = opened._tmp.path();
    let trash_file = find_trash_file(vault_dir, &block_uuid);
    overwrite_in_place(&trash_file, b"this is not a valid block file envelope");

    // Second list: same (uuid, ts) → memo hit → name still resolves,
    // proving the corrupt bytes were never decrypted.
    let second = list_trashed_blocks(&opened.identity, &opened.manifest)
        .expect("second list must succeed from cache");
    assert_eq!(
        second.iter().find(|t| t.block_uuid == block_uuid).unwrap().block_name,
        "Server keys",
    );
}

/// A newer `<ts>` is a different memo key, so the listing must re-decrypt
/// the newest file rather than serve the stale cached name. We drop a
/// CORRUPT higher-ts file after the first list; the second list keys on
/// the new ts → miss → re-decrypt → typed error (not the stale name).
#[test]
fn newer_ts_forces_redecrypt_not_stale_cache() {
    let opened = open_writable_golden_001();
    let block_uuid = [0x54u8; 16];
    create_block(
        &opened.identity,
        &opened.manifest,
        block_uuid,
        "Recovery codes".into(),
        DEVICE_UUID,
        1_000,
    )
    .expect("create_block");
    trash_block(&opened.identity, &opened.manifest, block_uuid, DEVICE_UUID, 2_000)
        .expect("trash_block");

    // First list caches (uuid, old_ts → "Recovery codes").
    let first = list_trashed_blocks(&opened.identity, &opened.manifest).expect("first list");
    assert_eq!(
        first.iter().find(|t| t.block_uuid == block_uuid).unwrap().block_name,
        "Recovery codes",
    );

    // Drop a CORRUPT higher-ts file for the same uuid. newest-wins selects
    // it; its (uuid, new_ts) is not in the memo → must decrypt → error.
    let vault_dir = opened._tmp.path();
    let original = find_trash_file(vault_dir, &block_uuid);
    let corrupt_newer = original.with_file_name(format!(
        "{}.99999",
        original.file_name().unwrap().to_str().unwrap().rsplit_once('.').unwrap().0,
    ));
    std::fs::write(&corrupt_newer, b"corrupt newer-ts envelope").expect("write corrupt newer file");

    let result = list_trashed_blocks(&opened.identity, &opened.manifest);
    assert!(
        result.is_err(),
        "newer ts is a cache miss; decrypting the corrupt newest file must error, \
         not silently serve the stale cached name",
    );
}
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/trash-list-memo-172 && cargo test --release -p secretary-ffi-bridge --test trash_list cache_hit_serves_name_without_redecrypt newer_ts_forces_redecrypt_not_stale_cache 2>&1 | tail -25
```
Expected: FAIL. Without the memo, `cache_hit_serves_name_without_redecrypt` fails because the second list re-decrypts the corrupted file and returns `Err` (the `.expect("second list must succeed from cache")` panics). (`newer_ts_forces_redecrypt_not_stale_cache` may already pass since today's code always decrypts — that's fine; it's a guard against a future regression where the memo over-serves.)

- [ ] **Step 3: Wire the memo into `list_trashed_blocks`**

In `ffi/secretary-ffi-bridge/src/trash/list.rs`, replace the tail of `list_trashed_blocks` — **from the `let trash_dir = …` line through the function's final `Ok(out)`** (i.e. everything after the `snapshot_for_read_block` block). The new body collects the live-uuid set, checks the memo per entry, decrypts only on a miss, and applies+prunes after the loop. The replacement (which ends with its own `Ok(out)` — do not leave the original `Ok(out)` behind):

```rust
    let trash_dir = vault_folder.join("trash");
    let mut out: Vec<TrashedBlock> = Vec::with_capacity(manifest_body.trash.len());
    // Misses decrypted this call, applied to the memo after the loop.
    let mut cache_updates: Vec<([u8; 16], u64, String)> = Vec::new();
    // The current live-trash uuid set; the memo is pruned to this so
    // restored/stale entries do not accumulate.
    let live_uuids: std::collections::HashSet<[u8; 16]> =
        manifest_body.trash.iter().map(|e| e.block_uuid).collect();

    for entry in &manifest_body.trash {
        let (path, ts) = newest_trash_file(&trash_dir, &entry.block_uuid)?.ok_or_else(|| {
            FfiVaultError::CorruptVault {
                detail: format!(
                    "trash entry has no matching file for {}",
                    hex::encode(entry.block_uuid)
                ),
            }
        })?;

        // Memo hit (same uuid + same on-disk ts) → skip the decrypt.
        let block_name = if let Some(name) = manifest.trash_name_cache_get(&entry.block_uuid, ts) {
            name
        } else {
            let bytes = std::fs::read(&path).map_err(|e| FfiVaultError::FolderInvalid {
                detail: format!("failed to read trash file: {e}"),
            })?;
            // Decrypt only to read the name. `plaintext` drops (zeroizes)
            // at the end of this block — record material never escapes.
            let plaintext = decrypt_block_file_bytes(identity, &owner_card, &bytes)?;
            let name = plaintext.block_name.clone();
            cache_updates.push((entry.block_uuid, ts, name.clone()));
            name
        };

        out.push(TrashedBlock {
            block_uuid: entry.block_uuid,
            block_name,
            tombstoned_at_ms: entry.tombstoned_at_ms,
            tombstoned_by: entry.tombstoned_by,
        });
    }

    // Apply this call's freshly-decrypted names and prune to the live set.
    manifest.trash_name_cache_put_and_prune(cache_updates, &live_uuids);

    Ok(out)
```

Note: `manifest` (the `&OpenVaultManifest`) is the function parameter, already in scope — `snapshot_for_read_block` was called on it at the top of the function.

- [ ] **Step 4: Update the module doc-comment**

In the same file, extend the module-level `//!` doc (top of file) to describe the memo. Append after the existing final sentence ("Record plaintext NEVER escapes this function."):

```rust
//!
//! As of #172 the decrypted name is memoized on the
//! [`OpenVaultManifest`](crate::OpenVaultManifest) handle, keyed by
//! `(block_uuid, <ts>)` — the on-disk file version. Repeat calls with an
//! unchanged file hit the memo and skip the decrypt; a re-trash (higher
//! `<ts>`) or restore self-invalidates. Names are non-secret in the
//! bridge (already plaintext in the manifest's block summaries) and the
//! memo is cleared on handle `wipe`.
```

- [ ] **Step 5: Run the trash_list test file to verify all pass**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/trash-list-memo-172 && cargo test --release -p secretary-ffi-bridge --test trash_list 2>&1 | tail -25
```
Expected: PASS — 5 passed (3 original + 2 new memo tests).

- [ ] **Step 6: Clippy + doc clean for the crate**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/trash-list-memo-172 && cargo clippy --release -p secretary-ffi-bridge --tests -- -D warnings && RUSTDOCFLAGS="-D warnings" cargo doc --no-deps -p secretary-ffi-bridge
```
Expected: exit 0, no warnings (the `crate::OpenVaultManifest` intra-doc link resolves).

- [ ] **Step 7: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/trash-list-memo-172 && git add ffi/secretary-ffi-bridge/src/trash/list.rs ffi/secretary-ffi-bridge/tests/trash_list.rs && git commit -m "feat(#172): memoize trashed-block names in list_trashed_blocks

Repeat Trash-view opens now hit the (uuid, ts) memo and skip the
per-block AEAD decrypt; first sight still decrypts. Two behavioral tests
prove a same-ts hit skips re-decrypt and a newer ts forces re-decrypt.

Closes #172

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Full workspace gate

Prove the change is green across the whole workspace and all the quality gates before opening the PR.

**Files:** none (verification only).

- [ ] **Step 1: Full workspace test**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/trash-list-memo-172 && cargo test --release --workspace 2>&1 | tail -15
```
Expected: all pass, 0 failed (count = prior 1456 + 5 new bridge tests = 1461; the exact total is not load-bearing — `0 failed` is).

- [ ] **Step 2: Clippy, fmt, doc, lean-binding gates**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/trash-list-memo-172 && \
  cargo clippy --release --workspace --tests -- -D warnings && \
  cargo fmt --all --check && \
  RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace && \
  bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh
```
Expected: every command exit 0. (No FFI surface changed, so the lean-binding guard and the Swift/Kotlin conformance harnesses are unaffected — no need to run `run_conformance.sh`.)

- [ ] **Step 3: Confirm the diff touches no format/spec/FFI-surface files**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/trash-list-memo-172 && git diff --stat main...HEAD
```
Expected: only `ffi/secretary-ffi-bridge/src/{trash/list.rs,vault/manifest.rs}`, `ffi/secretary-ffi-bridge/tests/trash_list.rs`, and the two `docs/superpowers/` design+plan files. No `core/`, no `docs/{crypto-design,vault-format,threat-model}.md`, no `conformance.py`, no `*.json` KAT, no uniffi/pyo3 `.rs`.

---

## Self-Review notes

- **Spec coverage:** memo storage + accessors (Task 2) ✓; `ts` key surfaced (Task 1) ✓; hit-skips-decrypt + miss-decrypts + prune (Task 3) ✓; clear-on-wipe (Task 2 Step 3 + test) ✓; behavioral TDD tests #1/#2 (Task 3) ✓; existing tests retained (Task 1 Step 3) ✓; full gate incl. fmt/clippy/doc/lean-binding (Task 4) ✓.
- **Type consistency:** `trash_name_cache_get(&self, &[u8;16], u64) -> Option<String>` and `trash_name_cache_put_and_prune(&self, Vec<([u8;16],u64,String)>, &HashSet<[u8;16]>)` are used identically in Task 2 (def + unit tests) and Task 3 (call sites). `newest_trash_file -> Result<Option<(PathBuf,u64)>,_>` is consistent between Task 1 (def) and Task 3 (call). `HashSet`/`HashMap` imported in manifest.rs (Task 2 Step 3); `list.rs` uses the fully-qualified `std::collections::HashSet` inline (no new import needed there).
- **Non-secret rationale** for holding `String` in the cache is documented at the field and in the module doc, consistent with the spec's security section.
