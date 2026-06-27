# Trash-list name memo (#172) — design

**Date:** 2026-06-27
**Issue:** #172 — *Trash view: `list_trashed_blocks` does a full decrypt per trashed block on every open*
**Scope:** `secretary-ffi-bridge` only. No core, no on-disk format, no spec/`conformance.py`, no FFI surface change.

## Problem

[`list_trashed_blocks`](../../../ffi/secretary-ffi-bridge/src/trash/list.rs) recovers each trashed block's human-readable `block_name` by **fully AEAD-decrypting + hybrid-verifying** the newest `trash/<uuid>.cbor.enc.<ts>` file for every entry in `manifest.trash`, then dropping the plaintext. Because AEAD is all-or-nothing, there is no "decrypt just the name" — the whole block plaintext (all record material) is decrypted to project one string.

Consequence: every open/refresh of the desktop Trash view is **O(n) full block decrypts**, repeated on every call even when nothing changed. Correctness and secret hygiene are fine today (record plaintext never escapes the function); the cost is the concern.

`TrashEntry` (the frozen manifest type) carries `block_uuid`, `tombstoned_at_ms`, `tombstoned_by`, `fingerprint: Option<[u8; 32]>`, and `unknown` — **no `block_name`**. Persisting the name into `TrashEntry` would touch the frozen on-disk format (+ spec + `conformance.py`) and is explicitly ruled out by the issue.

## Approach: self-invalidating in-memory memo on the handle

Add a session-scoped memo, keyed by the on-disk file version, that lets repeat listings skip the decrypt.

- **Cache:** `block_uuid -> (ts, block_name)` held in a new `Mutex<HashMap<[u8; 16], (u64, String)>>` field on the [`OpenVaultManifest`](../../../ffi/secretary-ffi-bridge/src/vault/manifest.rs) handle. Lives exactly as long as the open vault; **cleared on `wipe`** so a closed handle holds no residual names.
- **Version key = the `<ts>` filename suffix.** `newest_trash_file` already parses the canonical-decimal `<ts>` during its directory scan, so the key is free — no extra `stat`/IO. The cache key is `(block_uuid, ts)`: the pair *is* the file version.
- **Per-entry flow** in `list_trashed_blocks`:
  1. Locate the newest trash file → `(path, ts)` (as today; `newest_trash_file` returns the `ts` too).
  2. **Hit** (`uuid` cached *and* cached `ts == ts`) → use the cached name; **skip read+decrypt**.
  3. **Miss** → `read` + `decrypt_block_file_bytes` as today; project `block_name`; insert `(uuid, ts, name)`.
  4. After the loop, **prune** the cache to the current `manifest.trash` uuid set (drops restored/legacy entries; bounds memory to the live trash size).

### Why no explicit invalidation is needed

The `(uuid, ts)` pair is the version, so the memo is self-invalidating:

- **Re-trash** writes a new file with a strictly-higher `ts` → key changes → automatic miss → re-decrypt.
- **Restore** removes the entry from `manifest.trash` → pruned out on the next list.
- A **tampered ciphertext at the same `ts`** is the one case the memo intentionally serves from cache without re-decrypt — acceptable because the name is non-secret (below) and the value was hybrid-verified when first cached. Restore itself always re-verifies on disk (§6.1), so trust for *restoring* content is never sourced from this memo.

### Why it is secure

Block names are **not record-secret material** in the bridge. Active block names already live in plaintext in `BlockEntry`/`BlockSummary` (`inner.rs`: *"no secret material crosses through `BlockSummary`… Plaintext within the encrypted manifest"*) and are returned across the FFI as a plain `String`. Memoizing a trashed name in a `String` is no weaker than what active blocks already do. Record plaintext still never escapes `list_trashed_blocks`. The memo is cleared on `wipe`, matching the handle's secret-lifecycle even though names are non-secret.

### Alternative considered and rejected

Key on `TrashEntry.fingerprint` (BLAKE3 in the *signed* manifest) instead of `ts`. Rejected: `fingerprint` is `Option` (`None` for legacy vaults written before #293), whereas `ts` is present for every file, free to read, and tied to *the exact file decrypted*. The signed-fingerprint freshness guarantee is load-bearing for **restore** (which re-verifies on disk regardless), not for a name-projection memo.

## Components touched

| File | Change |
|---|---|
| `vault/manifest.rs` | New `name_cache: Mutex<HashMap<[u8;16],(u64,String)>>` field on `OpenVaultManifest`; init `new()`; clear in `wipe`; two `pub(crate)` accessors: `trash_name_cache_get(uuid, ts) -> Option<String>` and `trash_name_cache_put_and_prune(updates, live_uuids)` (single lock). |
| `trash/list.rs` | `newest_trash_file` returns `(PathBuf, u64)` (path + `ts`); `list_trashed_blocks` consults/populates the memo and prunes. Doc-comment updated to describe the memo + its security rationale. |
| `tests/trash_list.rs` | Add the two behavioral memo tests below; existing 3 tests unchanged. |

No public/FFI signature changes: `list_trashed_blocks(identity, manifest) -> Vec<TrashedBlock>` and `TrashedBlock` are unchanged. The memo is entirely internal to the handle.

### Lock discipline

The decrypt loop must **not** hold the `name_cache` lock across decrypts. Pattern: take a short read-lock per entry for the hit check (clone the `String` out), release; do the decrypt outside any lock; accumulate `(uuid, ts, name)` misses in a local `Vec`; after the loop, one `put_and_prune` under a single lock. This mirrors the existing handle discipline of never holding the manifest `Mutex` across N file decrypts.

## Testing (TDD, behavioral — no test-only instrumentation)

Written and observed to fail before the implementation, per the repo's TDD discipline. Both prove memo behavior through observable output only — no decrypt-counter hook.

1. **`cache_hit_serves_name_without_redecrypt`** — list once (populates memo); overwrite the trash file's ciphertext bytes *in place* with garbage (filename/`ts` suffix unchanged); list again → `block_name` still resolves correctly. A re-decrypt would surface a typed crypto error; a cache hit returns the cached name. Proves the decrypt was skipped.
2. **`newer_ts_forces_redecrypt_not_stale_cache`** — list once (memo holds `(uuid, old_ts, name)`); write a *corrupt* higher-`ts` file for the same uuid; list again → the new `(uuid, new_ts)` is a miss → re-decrypt of the newest file → surfaces the typed crypto/corrupt error (not the stale cached name). Proves the version key invalidates correctly.

Existing coverage retained: `trashed_block_appears_in_list_by_name`, `list_selects_newest_trash_file_and_skips_non_canonical`, `list_trashed_blocks_empty_when_nothing_trashed`.

### Full gate before PR

```
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all --check
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh
```

## Out of scope / non-goals

- No change to `TrashEntry` or any on-disk byte format → no spec / `conformance.py` / KAT-JSON change.
- No change to the public FFI surface (`list_trashed_blocks`, `TrashedBlock`) → no uniffi/pyo3 projection, Swift/Kotlin conformance harness untouched.
- First open of a fresh handle is still O(n) decrypts (the name genuinely only exists in ciphertext on first sight). The memo optimizes repeat opens/refreshes within a session — the actual reported cost.
- No cross-session/on-disk persistence of the memo.

## Risks

- **Stale-name-at-same-`ts`:** only if a trash file's ciphertext is mutated *without* advancing the `ts` suffix. That is not a path any vault operation produces (re-trash always advances `ts`); it can only arise from out-of-band tampering, where serving a non-secret cached name is harmless and restore still re-verifies on disk. Documented as an accepted property, not a bug.
- **Memory:** bounded by `prune`-to-live-trash on every call → O(current trash size) strings, freed at `wipe`.
