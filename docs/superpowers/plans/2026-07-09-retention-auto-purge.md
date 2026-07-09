# Retention auto-purge (#402) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `docs/vault-format.md` §7 step 5 — an explicit, caller-invoked core function that permanently purges every trashed block older than a retention window, plus a pure preview function to list what would be purged.

**Architecture:** A new pure module `core/src/vault/retention.rs` holds the pure eligibility selector (`expired_trash_entries`), the 90-day default constant, and the `auto_purge_expired` orchestrator. The orchestrator reuses a `purge_batch_commit` helper extracted from `purge.rs` (the same batch-commit `empty_trash` uses), so retention purge and empty-trash share one audited commit path. `open_vault`, both open-time sweeps, all FFI, and the on-disk format are unchanged.

**Tech Stack:** Rust (stable), `secretary-core`; `serde_json` for KAT fixtures; Python (`uv`) clean-room conformance; `proptest` for property tests.

## Global Constraints

- **Core-only slice** — no FFI / bridge / desktop / mobile change; no `manifest_version` bump; `manifest.rs` has **zero diff** (`TrashEntry.purged_at_ms` already exists from #399).
- `#![forbid(unsafe_code)]` — workspace lint; do not introduce `unsafe`.
- Clippy must stay clean with `-D warnings` (lib + tests).
- No magic numbers — the window is the named constant `DEFAULT_RETENTION_WINDOW_MS = 90 * 24 * 60 * 60 * 1000` (u64).
- Wall-clock (`tombstoned_at_ms`, `now_ms`) gates cleanup **timing only**, never a merge decision — see design §3.3. It is an accepted durability risk, explicitly *not* a security freshness signal.
- Spec is normative: docs updated first (Task 1); `conformance.py` proves `docs/` alone computes eligibility.
- Files stay < 500 lines where reasonable ([[feedback_split_files_proactively]]).
- Test crypto values come from a seeded RNG, never hard-coded literals ([[feedback_test_crypto_random_not_hardcoded]]).
- `uv` only for Python — never `pip`.
- Every task ends green on: `cargo test --release --workspace`, `cargo clippy --release --workspace --tests -- -D warnings`, `cargo fmt --all --check`.

**Design doc:** `docs/superpowers/specs/2026-07-09-retention-auto-purge-design.md`.

**All commands run from the worktree root:** `/Users/hherb/src/secretary/.worktrees/retention-402`.

---

## File Structure

- **Create** `core/src/vault/retention.rs` — `DEFAULT_RETENTION_WINDOW_MS`, `ExpiredEntry`, `is_expired` (private), `expired_trash_indices` (`pub(crate)`), `expired_trash_entries` (pub), `RetentionPurgeReport`, `auto_purge_expired`. Unit + inline proptest.
- **Modify** `core/src/vault/purge.rs` — extract `pub(crate) fn purge_batch_commit(...)`; refactor `empty_trash` to call it (no behaviour change).
- **Modify** `core/src/vault/mod.rs` — `pub mod retention;` + re-export the public items.
- **Create** `core/tests/data/retention_kat.json` — cross-language eligibility vectors.
- **Create** `core/tests/retention.rs` — Rust KAT replay + integration (mutation-verified) + idempotence/subset tests.
- **Modify** `core/tests/python/conformance.py` — `py_expired_trash_entries` + `section4c_retention_kat`.
- **Modify** `docs/vault-format.md` (§7 step 5), `docs/crypto-design.md` (§11.3 GC paragraph cross-ref).
- **Modify** `README.md`, `ROADMAP.md`.

---

## Task 1: Normative docs (spec contract first)

**Files:**
- Modify: `docs/vault-format.md` (§7 step 5, around line 467)
- Modify: `docs/crypto-design.md` (tombstone-GC paragraph, around line 571)

**Interfaces:**
- Consumes: nothing.
- Produces: the normative rule Tasks 2/6/7 implement and the test-name citations (`expired_trash_entries_kat_replays_match_rust`, `auto_purge_expired_purges_old_keeps_fresh`, `section4c_retention_kat`).

- [ ] **Step 1: Expand `docs/vault-format.md` §7 step 5**

Replace the single line:
```
5. After a retention window (default 90 days), `trash/` files older than the window are physically removed.
```
with:
```
5. **Retention auto-purge (§7 step 5, #402).** An explicit, caller-invoked operation permanently purges every trashed block older than a retention window (default 90 days). It is **not** automatic on open — `open_vault` stays read-only; the platform decides when to invoke it. A `TrashEntry` is eligible iff **all** hold: (a) `purged_at_ms` is absent (not already purged); (b) its `block_uuid` is not live in `manifest.blocks` (a concurrent restore always wins — the exact "not live" gate the open-time sweeps use); (c) `now_ms − tombstoned_at_ms > window_ms`, computed with a saturating subtraction so a future-dated `tombstoned_at_ms` (clock skew on the trashing device) yields age 0 and is never eligible. The boundary is exclusive (`>`, not `>=`): an entry exactly `window_ms` old is not yet eligible. Auto-purge reuses the §7.2 `purge` mechanism verbatim — it sets `purged_at_ms`, so the **tombstone persists** in the signed manifest (peers still observe the deletion) while the **ciphertext is removed**. A batch is committed with a single manifest re-sign (one shared `now_ms`, one clock tick, one signature, one write), then best-effort `trash/` file removal, mirroring `empty_trash`.

   **Wall-clock is a cleanup-timing signal here, never a merge-freshness signal.** The retention age reads `tombstoned_at_ms` (wall-clock) only to decide *when* local ciphertext is discarded; it never influences which bytes win a merge, no security invariant reads it, and it drives the exact same `purged_at_ms` state transition as the user-initiated `empty_trash` — so it adds no security surface over §7.2. The residual exposure is purely a **durability** risk (a badly-fast clock could purge an owner-only block slightly early); it is bounded by the 90-day window, blocked in the early direction by the saturating subtraction, opt-in policy the platform accepts by invoking it, and previewable via the pure eligibility query below. This is deliberately distinct from the prohibition on using wall-clock `last_mod_ms` as a merge-freshness signal (§6.5.1 / crypto-design §11.3, exploitable per #350).

   A pure query lists eligible entries without side effects so a platform can show "N items will be permanently deleted" before committing. Conformance: `core/tests/retention.rs::expired_trash_entries_kat_replays_match_rust`, `core/tests/retention.rs::auto_purge_expired_purges_old_keeps_fresh`, `core/tests/python/conformance.py::section4c_retention_kat`.
```

- [ ] **Step 2: Cross-reference in `docs/crypto-design.md`**

Find the paragraph (around line 571):
```
Tombstones are garbage-collected only after a configurable retention window (default: 90 days) to ensure all syncing devices have observed the deletion before the on-disk evidence is removed.
```
Append a sentence:
```
 Retention auto-purge (vault-format §7 step 5, #402) removes the trashed block's **ciphertext** once it is older than this window, but the `TrashEntry` **tombstone itself persists** in the signed manifest — the two have distinct lifetimes: the ciphertext is purged at the retention window, while tombstone GC (removing the `TrashEntry` entirely) is a separate, not-yet-implemented concern that must wait until every device has observed the deletion.
```

- [ ] **Step 3: Verify docs build clean**

Run: `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace 2>&1 | tail -5`
Expected: no warnings (these are `.md` docs, but run to confirm nothing else regressed). Also eyeball the two edits render as intended.

- [ ] **Step 4: Commit**

```bash
git add docs/vault-format.md docs/crypto-design.md
git commit -m "docs(spec): retention auto-purge rule — vault-format §7 step 5 (#402)"
```

---

## Task 2: Pure eligibility selector + module scaffold

**Files:**
- Create: `core/src/vault/retention.rs`
- Modify: `core/src/vault/mod.rs` (add `pub mod retention;` after line 32, and a re-export near line 60)
- Test: inline `#[cfg(test)] mod tests` in `retention.rs` (unit + proptest)

**Interfaces:**
- Consumes: `crate::vault::manifest::Manifest`, `crate::vault::manifest::TrashEntry`.
- Produces:
  - `pub const DEFAULT_RETENTION_WINDOW_MS: u64`
  - `pub struct ExpiredEntry { pub block_uuid: [u8; 16], pub tombstoned_at_ms: u64, pub age_ms: u64 }`
  - `pub(crate) fn expired_trash_indices(manifest: &Manifest, window_ms: u64, now_ms: u64) -> Vec<usize>`
  - `pub fn expired_trash_entries(manifest: &Manifest, window_ms: u64, now_ms: u64) -> Vec<ExpiredEntry>`

- [ ] **Step 1: Write the failing unit tests**

Create `core/src/vault/retention.rs` with the test module first (the module items will be added in Step 3). Use a tiny manifest builder that only fills the fields the selector reads.

```rust
//! Retention auto-purge (#402): pure eligibility selection for
//! permanently purging trashed blocks older than a retention window, plus
//! the `auto_purge_expired` orchestrator. `docs/vault-format.md` §7 step 5.
//!
//! The selector is pure and I/O-free ([[feedback_pure_functions]]); the
//! commit reuses `purge::purge_batch_commit` (the same batch path
//! `empty_trash` uses) so both share one audited manifest-write sequence.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::manifest::{Manifest, TrashEntry};
    use std::collections::BTreeMap;

    fn empty_manifest() -> Manifest {
        // Construct via the crate's test constructor if one exists; else
        // Default. `expired_trash_entries` reads only `trash` and `blocks`.
        Manifest::default()
    }

    fn trash_entry(block_uuid: [u8; 16], tombstoned_at_ms: u64, purged: Option<u64>) -> TrashEntry {
        TrashEntry {
            block_uuid,
            tombstoned_at_ms,
            tombstoned_by: [0u8; 16],
            fingerprint: None,
            purged_at_ms: purged,
            unknown: BTreeMap::new(),
        }
    }

    const WINDOW: u64 = 100;

    #[test]
    fn old_not_purged_not_live_is_eligible() {
        let mut m = empty_manifest();
        m.trash.push(trash_entry([1u8; 16], 1_000, None));
        // now - tombstoned = 5000 - 1000 = 4000 > 100
        let got = expired_trash_entries(&m, WINDOW, 5_000);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].block_uuid, [1u8; 16]);
        assert_eq!(got[0].tombstoned_at_ms, 1_000);
        assert_eq!(got[0].age_ms, 4_000);
    }

    #[test]
    fn already_purged_is_skipped() {
        let mut m = empty_manifest();
        m.trash.push(trash_entry([1u8; 16], 1_000, Some(2_000)));
        assert!(expired_trash_entries(&m, WINDOW, 5_000).is_empty());
    }

    #[test]
    fn too_young_is_skipped() {
        let mut m = empty_manifest();
        // age = 50 < window 100
        m.trash.push(trash_entry([1u8; 16], 4_950, None));
        assert!(expired_trash_entries(&m, WINDOW, 5_000).is_empty());
    }

    #[test]
    fn boundary_equal_window_is_skipped() {
        let mut m = empty_manifest();
        // age exactly == window; exclusive boundary => not eligible
        m.trash.push(trash_entry([1u8; 16], 4_900, None));
        assert!(expired_trash_entries(&m, WINDOW, 5_000).is_empty());
    }

    #[test]
    fn future_dated_tombstone_saturates_to_zero_age_skipped() {
        let mut m = empty_manifest();
        // tombstoned_at_ms > now => saturating_sub => age 0 => never eligible
        m.trash.push(trash_entry([1u8; 16], 9_000, None));
        assert!(expired_trash_entries(&m, WINDOW, 5_000).is_empty());
    }

    #[test]
    fn live_uuid_is_skipped_even_if_old() {
        let mut m = empty_manifest();
        m.trash.push(trash_entry([7u8; 16], 1_000, None));
        // Same uuid live in blocks => concurrent restore won => never purge.
        push_live_block(&mut m, [7u8; 16]);
        assert!(expired_trash_entries(&m, WINDOW, 5_000).is_empty());
    }

    #[test]
    fn default_window_is_ninety_days() {
        assert_eq!(DEFAULT_RETENTION_WINDOW_MS, 90 * 24 * 60 * 60 * 1000);
    }
}
```

Note: `push_live_block` and `Manifest::default()` / `Manifest` field access must match the crate. Before writing implementation, run `grep -n "pub struct Manifest" -A25 core/src/vault/manifest.rs` and confirm `blocks: Vec<BlockEntry>` and `trash: Vec<TrashEntry>` field names and whether a test builder exists; if `Manifest` has no `Default`, add a small local `fn empty_manifest()` that constructs it with the minimal required fields (copy the pattern from an existing `manifest.rs` test). Implement `push_live_block` by pushing a minimal `BlockEntry` with `block_uuid` set (mirror an existing `BlockEntry` test builder — grep `core/src/vault/manifest.rs` for one).

- [ ] **Step 2: Run tests to verify they fail (compile error — items undefined)**

Run: `cargo test --release -p secretary-core retention:: 2>&1 | tail -15`
Expected: FAIL — `cannot find value DEFAULT_RETENTION_WINDOW_MS` / `cannot find function expired_trash_entries`.

- [ ] **Step 3: Write the minimal implementation (above the test module)**

```rust
use crate::vault::manifest::Manifest;

/// Default trash retention window: 90 days in milliseconds
/// (`docs/vault-format.md` §7 step 5). Named to avoid a magic number;
/// the value is `90 * 24 * 60 * 60 * 1000` = 7_776_000_000 ms, which
/// exceeds `u32::MAX`, hence `u64`.
pub const DEFAULT_RETENTION_WINDOW_MS: u64 = 90 * 24 * 60 * 60 * 1000;

/// One trash entry eligible for retention auto-purge — the pure
/// preview record a platform shows before committing a purge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiredEntry {
    /// The trashed block's UUID.
    pub block_uuid: [u8; 16],
    /// The signed death-clock the age was computed from.
    pub tombstoned_at_ms: u64,
    /// `now_ms.saturating_sub(tombstoned_at_ms)` — how far past trashing
    /// this entry is (always `> window_ms` for an eligible entry).
    pub age_ms: u64,
}

/// Indices into `manifest.trash` of every entry eligible for retention
/// auto-purge (design §3.1): not already purged, not live in
/// `manifest.blocks`, and strictly older than `window_ms`. Pure. Shared
/// by [`expired_trash_entries`] (public preview) and
/// [`auto_purge_expired`] (commit target selection).
pub(crate) fn expired_trash_indices(
    manifest: &Manifest,
    window_ms: u64,
    now_ms: u64,
) -> Vec<usize> {
    manifest
        .trash
        .iter()
        .enumerate()
        .filter(|(_, e)| {
            e.purged_at_ms.is_none()
                && now_ms.saturating_sub(e.tombstoned_at_ms) > window_ms
                && !manifest
                    .blocks
                    .iter()
                    .any(|b| b.block_uuid == e.block_uuid)
        })
        .map(|(i, _)| i)
        .collect()
}

/// Pure, side-effect-free preview of the entries retention auto-purge
/// would permanently remove for `(window_ms, now_ms)`. No I/O, no
/// recipient classification (that is best-effort, inside the commit
/// path). `docs/vault-format.md` §7 step 5 (#402).
pub fn expired_trash_entries(
    manifest: &Manifest,
    window_ms: u64,
    now_ms: u64,
) -> Vec<ExpiredEntry> {
    expired_trash_indices(manifest, window_ms, now_ms)
        .into_iter()
        .map(|i| {
            let e = &manifest.trash[i];
            ExpiredEntry {
                block_uuid: e.block_uuid,
                tombstoned_at_ms: e.tombstoned_at_ms,
                age_ms: now_ms.saturating_sub(e.tombstoned_at_ms),
            }
        })
        .collect()
}
```

- [ ] **Step 4: Register the module**

In `core/src/vault/mod.rs`, add after line 32 (`pub mod record;` region — keep alphabetical with neighbours):
```rust
pub mod retention;
```
and near the existing re-exports (around line 60):
```rust
pub use retention::{expired_trash_entries, DEFAULT_RETENTION_WINDOW_MS, ExpiredEntry};
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --release -p secretary-core retention:: 2>&1 | tail -15`
Expected: PASS (all 7 unit tests).

- [ ] **Step 6: Add inline property tests**

Append to the `tests` module (add `use proptest::prelude::*;` — confirm `proptest` is a dev-dependency of `secretary-core` with `grep -n proptest core/Cargo.toml`; it is, per `conflict.rs`'s proptests):
```rust
proptest! {
    /// Every returned entry genuinely satisfies all three eligibility
    /// clauses, and every non-returned trash entry fails at least one —
    /// selection is exactly the predicate, for arbitrary trash lists.
    #[test]
    fn selection_matches_predicate(
        seeds in proptest::collection::vec((any::<u8>(), 0u64..10_000, any::<bool>()), 0..20),
        window in 0u64..5_000,
        now in 0u64..10_000,
    ) {
        let mut m = empty_manifest();
        for (i, (uuid_seed, t, purged)) in seeds.iter().enumerate() {
            // distinct uuids so liveness/dedup is unambiguous
            let mut uuid = [*uuid_seed; 16];
            uuid[0] = i as u8;
            m.trash.push(trash_entry(uuid, *t, if *purged { Some(1) } else { None }));
        }
        let picked: std::collections::HashSet<usize> =
            expired_trash_indices(&m, window, now).into_iter().collect();
        for (i, e) in m.trash.iter().enumerate() {
            let eligible = e.purged_at_ms.is_none()
                && now.saturating_sub(e.tombstoned_at_ms) > window
                && !m.blocks.iter().any(|b| b.block_uuid == e.block_uuid);
            prop_assert_eq!(picked.contains(&i), eligible);
        }
    }
}
```

- [ ] **Step 7: Run the whole crate test + clippy + fmt**

Run:
```bash
cargo test --release -p secretary-core retention:: 2>&1 | tail -8
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -5
cargo fmt --all --check
```
Expected: tests PASS; clippy clean; fmt clean.

- [ ] **Step 8: Commit**

```bash
git add core/src/vault/retention.rs core/src/vault/mod.rs
git commit -m "feat(core): pure retention eligibility selector + 90d default (#402)"
```

---

## Task 3: Extract `purge_batch_commit` from `empty_trash`

**Files:**
- Modify: `core/src/vault/purge.rs` (extract from `empty_trash`, lines ~287-362)

**Interfaces:**
- Consumes: `OpenVault`, `orchestrators::{tick_clock, resign_and_write_manifest}`, `remove_trash_files` (already in `purge.rs`).
- Produces: `pub(crate) fn purge_batch_commit(folder: &Path, open: &mut OpenVault, target_indices: &[usize], now_ms: u64, device_uuid: [u8; 16], rng: &mut (impl RngCore + CryptoRng)) -> Result<(usize, usize), VaultError>` returning `(files_removed, files_failed)`. **Precondition (caller-guaranteed):** every index is a `manifest.trash` entry that is not-purged and not-live; classification (if any) is done by the caller *before* this call, while files are still present.

- [ ] **Step 1: Add the extracted helper (pure commit path)**

Insert into `core/src/vault/purge.rs` (after `remove_trash_files`, before `empty_trash`):
```rust
/// Batch commit for permanent purge, shared by [`empty_trash`] and
/// `retention::auto_purge_expired`. Stages `purged_at_ms = Some(now_ms)`
/// on every `target_indices` entry of one manifest clone, ticks the vault
/// clock **once**, re-signs **once**, atomic-writes **once**, swaps the
/// staged state into `open`, then best-effort removes every purged UUID's
/// `trash/` files in one directory scan. Returns `(files_removed,
/// files_failed)`.
///
/// **Precondition:** `target_indices` is non-empty and every index is a
/// not-already-purged, not-live `manifest.trash` entry (a live-and-trashed
/// UUID must never be purged — the two lists are mutually exclusive). The
/// caller performs any recipient classification *before* calling, while
/// the trash files are still guaranteed present. The manifest write is the
/// commit point; nothing after it may fail the call.
pub(crate) fn purge_batch_commit(
    folder: &Path,
    open: &mut OpenVault,
    target_indices: &[usize],
    now_ms: u64,
    device_uuid: [u8; 16],
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(usize, usize), VaultError> {
    let mut staged = open.manifest.clone();
    for &idx in target_indices {
        staged.trash[idx].purged_at_ms = Some(now_ms);
    }
    tick_clock(&mut staged.vector_clock, &device_uuid)?;
    let new_manifest_file = resign_and_write_manifest(
        folder,
        &staged,
        &open.identity,
        &open.identity_block_key,
        &open.manifest_file.header,
        now_ms,
        open.manifest_file.author_fingerprint,
        rng,
        "purge_batch_commit: failed to write manifest.cbor.enc",
    )?;
    open.manifest = staged;
    open.manifest_file = new_manifest_file;

    let target_uuids: Vec<[u8; 16]> = target_indices
        .iter()
        .map(|&idx| open.manifest.trash[idx].block_uuid)
        .collect();
    Ok(remove_trash_files(folder, &target_uuids))
}
```

- [ ] **Step 2: Refactor `empty_trash` to call it**

Replace the body of `empty_trash` from the `// Single commit point:` comment through the `Ok(report)` return with a call to `purge_batch_commit`. The target-collection and classification loop stay; only the inline stage/tick/sign/write/swap/remove is replaced:
```rust
    // Single batch commit via the shared primitive (Task 3).
    let (removed, failed) =
        purge_batch_commit(folder, open, &targets, now_ms, device_uuid, rng)?;
    report.purged_count = targets.len();
    report.files_removed += removed;
    report.files_failed += failed;
    Ok(report)
```
(Delete the now-duplicated `staged`/`tick_clock`/`resign_and_write_manifest`/swap/`remove_trash_files` block and its `target_uuids` builder — `purge_batch_commit` owns that. Keep the classification loop that fills `shared_count`/`owner_only_count`/`unknown_count`.)

- [ ] **Step 3: Run the existing purge/empty_trash tests (must stay green — no behaviour change)**

Run: `cargo test --release --workspace --test purge 2>&1 | tail -12`
Expected: PASS — every existing `purge.rs` integration test, unchanged. This is the regression proof that the extraction preserved `empty_trash` behaviour (including `empty_trash_purges_all_unpurged_in_single_resign` and the shared-`now_ms` assertion).

- [ ] **Step 4: Clippy + fmt**

Run:
```bash
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -5
cargo fmt --all --check
```
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add core/src/vault/purge.rs
git commit -m "refactor(core): extract purge_batch_commit shared by empty_trash (#402)"
```

---

## Task 4: `auto_purge_expired` orchestrator + integration test

**Files:**
- Modify: `core/src/vault/retention.rs` (add `RetentionPurgeReport` + `auto_purge_expired`)
- Modify: `core/src/vault/mod.rs` (extend the retention re-export)
- Create: `core/tests/retention.rs` (integration, mutation-verified)

**Interfaces:**
- Consumes: `expired_trash_indices` (Task 2), `purge::purge_batch_commit` (Task 3), `purge::classify_trash_target` (already `pub(crate)` in `purge.rs` — confirm; if only module-private, widen to `pub(crate)`), `OpenVault`.
- Produces:
  - `pub struct RetentionPurgeReport { pub purged_count: usize, pub shared_count: usize, pub owner_only_count: usize, pub unknown_count: usize, pub files_removed: usize, pub files_failed: usize, pub window_ms: u64 }` (derives `Debug, Clone`; **not** `Default` — see note)
  - `pub fn auto_purge_expired(folder: &Path, open: &mut OpenVault, window_ms: u64, now_ms: u64, device_uuid: [u8; 16], rng: &mut (impl RngCore + CryptoRng)) -> Result<RetentionPurgeReport, VaultError>`

- [ ] **Step 1: Write the failing integration test**

Create `core/tests/retention.rs`. Reuse the fixture pattern from `core/tests/purge.rs` (copy `fast_kdf` / `make_fast_vault` / the open + save + trash helpers — no shared test-helper crate exists; the codebase duplicates these per test file, see `purge.rs`'s header note). Then:
```rust
#[test]
fn auto_purge_expired_purges_old_keeps_fresh() {
    // Stage a vault with two owner-only trashed blocks:
    //   OLD  trashed at t=1_000  (age 9_000 > window 100)  -> purged
    //   FRESH trashed at t=9_950 (age    50 < window 100)  -> kept
    let (folder, mut open, device, mut rng) = stage_two_trashed_blocks(
        /* old_uuid  */ [0xA1; 16], /* old_tombstoned_ms  */ 1_000,
        /* new_uuid  */ [0xB2; 16], /* new_tombstoned_ms  */ 9_950,
    );

    let window_ms = 100;
    let now_ms = 10_000;
    let report =
        auto_purge_expired(&folder, &mut open, window_ms, now_ms, device, &mut rng).unwrap();

    assert_eq!(report.purged_count, 1, "only the OLD block is purged");
    assert_eq!(report.window_ms, window_ms);

    // OLD: purged_at_ms set + trash file gone.
    let old = open.manifest.trash.iter().find(|t| t.block_uuid == [0xA1; 16]).unwrap();
    assert!(old.purged_at_ms.is_some(), "OLD marked purged");
    assert!(trash_file_absent(&folder, [0xA1; 16], 1_000), "OLD ciphertext removed");

    // FRESH: untouched.
    let fresh = open.manifest.trash.iter().find(|t| t.block_uuid == [0xB2; 16]).unwrap();
    assert!(fresh.purged_at_ms.is_none(), "FRESH not purged");
    assert!(!trash_file_absent(&folder, [0xB2; 16], 9_950), "FRESH ciphertext retained");

    // Signed manifest still verifies after the write: re-open the vault.
    reopen_ok(&folder);
}
```
Add the helpers `stage_two_trashed_blocks`, `trash_file_absent`, `reopen_ok` (adapt from `purge.rs`: `stage_two_trashed_blocks` = `make_fast_vault` → open → `save_block` × 2 → `trash_block(...,old_tombstoned_ms,...)` and `trash_block(...,new_tombstoned_ms,...)`; `trash_file_absent` checks `folder/trash/<uuid-hyphenated>.cbor.enc.<ms>` does not exist; `reopen_ok` = `open_vault(..., password unlocker, None).unwrap()`).

- [ ] **Step 2: Run to verify it fails (compile error — `auto_purge_expired` undefined)**

Run: `cargo test --release --workspace --test retention auto_purge_expired_purges_old_keeps_fresh 2>&1 | tail -15`
Expected: FAIL — `cannot find function auto_purge_expired`.

- [ ] **Step 3: Implement `RetentionPurgeReport` + `auto_purge_expired`**

Add to `core/src/vault/retention.rs` (above the test module), and add the needed `use` lines (`std::path::Path`, `rand_core::{CryptoRng, RngCore}`, `crate::vault::{OpenVault, VaultError}`, `crate::vault::purge::{classify_trash_target, purge_batch_commit}`):
```rust
/// Aggregate outcome of an [`auto_purge_expired`] call.
///
/// `window_ms` echoes the caller's window so a report is self-describing
/// even when `purged_count == 0`. Not `Default`: the empty-target return
/// still carries the real `window_ms`.
#[derive(Debug, Clone)]
pub struct RetentionPurgeReport {
    /// Entries newly marked purged by this call.
    pub purged_count: usize,
    /// Of `purged_count`, classified shared (≥1 non-owner recipient).
    pub shared_count: usize,
    /// Of `purged_count`, classified owner-only.
    pub owner_only_count: usize,
    /// Of `purged_count`, unclassifiable (trash file unreadable — honest
    /// "unknown", never fabricated).
    pub unknown_count: usize,
    /// On-disk `trash/` files removed across every purged entry.
    pub files_removed: usize,
    /// `trash/` removals that errored (benign orphans; logged, never fatal).
    pub files_failed: usize,
    /// The retention window this call applied.
    pub window_ms: u64,
}

/// Permanently purge every trashed block older than `window_ms` — the
/// retention auto-purge operation (`docs/vault-format.md` §7 step 5, #402).
///
/// Eligibility is the pure [`expired_trash_indices`] rule: not already
/// purged, not live in `manifest.blocks`, and `now_ms − tombstoned_at_ms >
/// window_ms` (saturating, exclusive boundary). Targets are classified for
/// reporting (best-effort, before the write) and committed in one batch via
/// `purge::purge_batch_commit` — one shared `now_ms`, one clock tick, one
/// signature, one write — then their `trash/` files are best-effort removed.
///
/// An empty target set returns a zero-count report **without touching the
/// manifest** (no clock tick, no re-sign, no write), mirroring
/// [`empty_trash`](crate::vault::empty_trash).
///
/// Wall-clock (`tombstoned_at_ms`) gates cleanup timing only, never a merge
/// decision — see the design doc §3.3 / vault-format §7 step 5. This is the
/// same `purged_at_ms` state transition as user-initiated `empty_trash`;
/// it adds no security surface.
pub fn auto_purge_expired(
    folder: &Path,
    open: &mut OpenVault,
    window_ms: u64,
    now_ms: u64,
    device_uuid: [u8; 16],
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<RetentionPurgeReport, VaultError> {
    let targets = expired_trash_indices(&open.manifest, window_ms, now_ms);
    let mut report = RetentionPurgeReport {
        purged_count: 0,
        shared_count: 0,
        owner_only_count: 0,
        unknown_count: 0,
        files_removed: 0,
        files_failed: 0,
        window_ms,
    };
    if targets.is_empty() {
        return Ok(report);
    }

    // Classify BEFORE the write, while trash files are still present
    // (reporting-only, best-effort — mirrors empty_trash).
    for &idx in &targets {
        let block_uuid = open.manifest.trash[idx].block_uuid;
        let tombstoned_at_ms = open.manifest.trash[idx].tombstoned_at_ms;
        match classify_trash_target(folder, &block_uuid, tombstoned_at_ms, &open.owner_card) {
            Some((true, _)) => report.shared_count += 1,
            Some((false, _)) => report.owner_only_count += 1,
            None => report.unknown_count += 1,
        }
    }

    let (removed, failed) =
        purge_batch_commit(folder, open, &targets, now_ms, device_uuid, rng)?;
    report.purged_count = targets.len();
    report.files_removed = removed;
    report.files_failed = failed;
    Ok(report)
}
```
Then extend the `mod.rs` re-export:
```rust
pub use retention::{
    auto_purge_expired, expired_trash_entries, RetentionPurgeReport, DEFAULT_RETENTION_WINDOW_MS,
    ExpiredEntry,
};
```
If `classify_trash_target` is module-private in `purge.rs`, change its `fn` to `pub(crate) fn`.

- [ ] **Step 4: Run the integration test to verify it passes**

Run: `cargo test --release --workspace --test retention auto_purge_expired_purges_old_keeps_fresh 2>&1 | tail -12`
Expected: PASS.

- [ ] **Step 5: Mutation-verify the age filter is load-bearing (per #401's lesson)**

Temporarily change `expired_trash_indices` so the age clause always passes (e.g. replace `now_ms.saturating_sub(e.tombstoned_at_ms) > window_ms` with `true`). Run the test:
```bash
cargo test --release --workspace --test retention auto_purge_expired_purges_old_keeps_fresh 2>&1 | tail -8
```
Expected: **FAIL** — with the age clause defeated, FRESH is also purged (`report.purged_count == 2`, `fresh.purged_at_ms.is_some()`), so the assertions break. This proves the filter is exercised, not vacuous. **Revert the mutation** and re-run to confirm PASS.

- [ ] **Step 6: Clippy + fmt + commit**

Run:
```bash
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -5
cargo fmt --all --check
git add core/src/vault/retention.rs core/src/vault/mod.rs core/tests/retention.rs
git commit -m "feat(core): auto_purge_expired retention orchestrator (#402)"
```

---

## Task 5: Idempotence + subset-of-empty_trash integration tests

**Files:**
- Modify: `core/tests/retention.rs`

**Interfaces:**
- Consumes: `auto_purge_expired`, `empty_trash` (both re-exported), the Task 4 helpers.
- Produces: nothing (test-only).

- [ ] **Step 1: Write the idempotence test**

```rust
#[test]
fn auto_purge_expired_is_idempotent() {
    let (folder, mut open, device, mut rng) = stage_two_trashed_blocks(
        [0xA1; 16], 1_000, [0xB2; 16], 9_950,
    );
    let (window_ms, now_ms) = (100u64, 10_000u64);

    let first = auto_purge_expired(&folder, &mut open, window_ms, now_ms, device, &mut rng).unwrap();
    assert_eq!(first.purged_count, 1);
    let clock_after_first = open.manifest.vector_clock.clone();

    // Second run at a LATER now_ms: OLD is already purged (skipped by the
    // not-purged clause); FRESH is still too young. Nothing to do.
    let second =
        auto_purge_expired(&folder, &mut open, window_ms, now_ms + 1, device, &mut rng).unwrap();
    assert_eq!(second.purged_count, 0, "no entry re-purged");
    assert_eq!(
        open.manifest.vector_clock, clock_after_first,
        "empty target set => no second re-sign / clock tick"
    );
}
```

- [ ] **Step 2: Write the subset test (ties retention to the audited primitive)**

```rust
#[test]
fn auto_purge_expired_is_subset_of_empty_trash() {
    // With OLD past the window and FRESH within it, auto_purge_expired
    // purges exactly {OLD}; empty_trash on the same state purges {OLD,FRESH}.
    // The age filter only ever removes targets, never adds.
    let (folder, mut open, device, mut rng) = stage_two_trashed_blocks(
        [0xA1; 16], 1_000, [0xB2; 16], 9_950,
    );
    let auto = auto_purge_expired(&folder, &mut open, 100, 10_000, device, &mut rng).unwrap();
    assert_eq!(auto.purged_count, 1);

    // Now empty_trash the remainder: FRESH (still not purged, not live).
    let rest = empty_trash(&folder, &mut open, device, 11_000, &mut rng).unwrap();
    assert_eq!(rest.purged_count, 1, "empty_trash mops up the within-window entry auto-purge left");

    // Together they purge every eligible entry — auto_purge's set ⊆ empty_trash's set.
    assert!(open.manifest.trash.iter().all(|t| t.purged_at_ms.is_some()));
}
```

- [ ] **Step 3: Run both**

Run: `cargo test --release --workspace --test retention 2>&1 | tail -12`
Expected: PASS (all retention integration tests).

- [ ] **Step 4: Clippy + fmt + commit**

Run:
```bash
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -5
cargo fmt --all --check
git add core/tests/retention.rs
git commit -m "test(core): auto_purge_expired idempotence + subset-of-empty_trash (#402)"
```

---

## Task 6: Cross-language KAT — fixture + Rust replay

**Files:**
- Create: `core/tests/data/retention_kat.json`
- Modify: `core/tests/retention.rs` (add the replay test + local parse helpers)

**Interfaces:**
- Consumes: `expired_trash_entries` (Task 2), `serde_json`.
- Produces: `retention_kat.json` (version 1) — consumed by Task 7's Python replay. Test name: `expired_trash_entries_kat_replays_match_rust`.

- [ ] **Step 1: Write the fixture**

Create `core/tests/data/retention_kat.json`. Each vector supplies a `window_ms`, `now_ms`, an input `trash` list and (optionally) a `blocks` live-uuid list, and the `expected` eligible UUIDs (hex, hyphen-free 32-char):
```json
{
  "version": 1,
  "note": "Retention auto-purge eligibility KAT (#402). Cross-language: Rust core/tests/retention.rs::expired_trash_entries_kat_replays_match_rust and Python conformance.py::section4c_retention_kat both replay this and must agree.",
  "vectors": [
    {
      "name": "old_not_purged_not_live_is_eligible",
      "window_ms": 100, "now_ms": 5000,
      "blocks": [],
      "trash": [{ "block_uuid_hex": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", "tombstoned_at_ms": 1000, "purged_at_ms": null }],
      "expected_uuids_hex": ["a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"]
    },
    {
      "name": "already_purged_skipped",
      "window_ms": 100, "now_ms": 5000,
      "blocks": [],
      "trash": [{ "block_uuid_hex": "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2", "tombstoned_at_ms": 1000, "purged_at_ms": 2000 }],
      "expected_uuids_hex": []
    },
    {
      "name": "too_young_skipped",
      "window_ms": 100, "now_ms": 5000,
      "blocks": [],
      "trash": [{ "block_uuid_hex": "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3", "tombstoned_at_ms": 4950, "purged_at_ms": null }],
      "expected_uuids_hex": []
    },
    {
      "name": "boundary_equal_window_skipped",
      "window_ms": 100, "now_ms": 5000,
      "blocks": [],
      "trash": [{ "block_uuid_hex": "a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4", "tombstoned_at_ms": 4900, "purged_at_ms": null }],
      "expected_uuids_hex": []
    },
    {
      "name": "future_dated_saturates_skipped",
      "window_ms": 100, "now_ms": 5000,
      "blocks": [],
      "trash": [{ "block_uuid_hex": "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5", "tombstoned_at_ms": 9000, "purged_at_ms": null }],
      "expected_uuids_hex": []
    },
    {
      "name": "live_uuid_skipped_even_if_old",
      "window_ms": 100, "now_ms": 5000,
      "blocks": ["a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6"],
      "trash": [{ "block_uuid_hex": "a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6", "tombstoned_at_ms": 1000, "purged_at_ms": null }],
      "expected_uuids_hex": []
    },
    {
      "name": "mixed_list_selects_only_eligible",
      "window_ms": 100, "now_ms": 10000,
      "blocks": ["b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3"],
      "trash": [
        { "block_uuid_hex": "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1", "tombstoned_at_ms": 1000, "purged_at_ms": null },
        { "block_uuid_hex": "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2", "tombstoned_at_ms": 9950, "purged_at_ms": null },
        { "block_uuid_hex": "b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3", "tombstoned_at_ms": 1000, "purged_at_ms": null },
        { "block_uuid_hex": "b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4", "tombstoned_at_ms": 1000, "purged_at_ms": 500 }
      ],
      "expected_uuids_hex": ["b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1"]
    }
  ]
}
```

- [ ] **Step 2: Write the failing replay test**

Add to `core/tests/retention.rs` (adapt `parse_hex_array::<16>` and a minimal manifest builder — copy `parse_hex_array` from `core/tests/conflict.rs`; build a `Manifest` filling only `trash` from `trash[]` and `blocks` from `blocks[]` — push a minimal `BlockEntry` per live uuid, mirroring `conflict.rs`/`purge.rs` builders):
```rust
#[test]
fn expired_trash_entries_kat_replays_match_rust() {
    use secretary_core::vault::expired_trash_entries;
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests").join("data").join("retention_kat.json");
    let raw = std::fs::read_to_string(&path).expect("read retention_kat.json");
    let kat: serde_json::Value = serde_json::from_str(&raw).expect("parse retention_kat.json");
    assert_eq!(kat["version"], 1);

    for vector in kat["vectors"].as_array().expect("vectors[]") {
        let name = vector["name"].as_str().expect("name");
        let window_ms = vector["window_ms"].as_u64().expect("window_ms");
        let now_ms = vector["now_ms"].as_u64().expect("now_ms");
        let manifest = build_manifest_from_kat(vector);
        let got: std::collections::BTreeSet<[u8; 16]> =
            expired_trash_entries(&manifest, window_ms, now_ms)
                .into_iter().map(|e| e.block_uuid).collect();
        let expected: std::collections::BTreeSet<[u8; 16]> = vector["expected_uuids_hex"]
            .as_array().expect("expected_uuids_hex[]").iter()
            .map(|v| parse_hex_array::<16>(v.as_str().unwrap())).collect();
        assert_eq!(got, expected, "vector {name}");
    }
}
```
Add `build_manifest_from_kat(vector) -> Manifest` (reads `trash[]` → `TrashEntry` with `tombstoned_by=[0;16]`, `fingerprint=None`, `purged_at_ms` from JSON `null`/number, empty `unknown`; reads `blocks[]` hex → minimal live `BlockEntry`).

- [ ] **Step 3: Run to verify it fails, then passes**

Run: `cargo test --release --workspace --test retention expired_trash_entries_kat 2>&1 | tail -12`
Expected: FAIL first only if the fixture/helpers are wrong; once helpers compile and the fixture is correct, PASS. (The selector already exists from Task 2, so this validates fixture↔code agreement.)

- [ ] **Step 4: Clippy + fmt + commit**

Run:
```bash
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -5
cargo fmt --all --check
git add core/tests/data/retention_kat.json core/tests/retention.rs
git commit -m "test(core): retention_kat.json + Rust eligibility replay (#402)"
```

---

## Task 7: Python clean-room conformance replay

**Files:**
- Modify: `core/tests/python/conformance.py` (add `py_expired_trash_entries`, `retention_kat_path`, `section4c_retention_kat`; wire into `main`)

**Interfaces:**
- Consumes: `core/tests/data/retention_kat.json` (Task 6).
- Produces: `section4c_retention_kat() -> tuple[bool, list[str]]` wired into `main`'s pass/fail aggregation, mirroring `section4b_trash_merge_kat` (around lines 2970 / 4149-4206).

- [ ] **Step 1: Add the clean-room selector + fixture path (near `section4b`/`trash_merge_kat_path`, ~line 2357)**

```python
def retention_kat_path() -> Path:
    return Path(__file__).resolve().parents[1] / "data" / "retention_kat.json"


def py_expired_trash_entries(
    trash: list[dict], live_uuids: set[str], window_ms: int, now_ms: int
) -> set[str]:
    """Clean-room retention eligibility (docs/vault-format.md §7 step 5).

    An entry is eligible iff: not already purged, its uuid is not live,
    and now_ms - tombstoned_at_ms > window_ms (saturating: a future-dated
    tombstone yields age 0). Returns the set of eligible block_uuid hex.
    """
    out: set[str] = set()
    for e in trash:
        if e.get("purged_at_ms") is not None:
            continue
        uuid_hex = e["block_uuid_hex"]
        if uuid_hex in live_uuids:
            continue
        age = max(0, now_ms - int(e["tombstoned_at_ms"]))  # saturating
        if age > window_ms:
            out.add(uuid_hex)
    return out
```

- [ ] **Step 2: Add the section runner (mirror `section4b_trash_merge_kat`, ~line 2970)**

```python
def section4c_retention_kat() -> tuple[bool, list[str]]:
    """§4c: replay retention_kat.json; assert clean-room eligibility
    matches each vector's expected UUID set (cross-language with Rust
    core/tests/retention.rs::expired_trash_entries_kat_replays_match_rust)."""
    lines: list[str] = []
    path = retention_kat_path()
    if not path.exists():
        print(f"MISSING: retention_kat.json at {path}", file=sys.stderr)
        return False, lines
    kat = json.loads(path.read_text())
    if kat.get("version") != 1:
        return False, [f"unexpected retention_kat version {kat.get('version')}"]
    ok = True
    for v in kat["vectors"]:
        live = set(v.get("blocks", []))
        got = py_expired_trash_entries(v["trash"], live, v["window_ms"], v["now_ms"])
        expected = set(v["expected_uuids_hex"])
        status = "PASS" if got == expected else "FAIL"
        if got != expected:
            ok = False
        lines.append(f"  §4c {v['name']}: {status}")
    return ok, lines
```
(Confirm `json` and `sys` are already imported at the top of `conformance.py`; they are, per `section4b`.)

- [ ] **Step 3: Wire into `main` (mirror the section4b block at ~4149 and ~4189/4206)**

After the `section4b` invocation in `main`:
```python
    section4c_ok, section4c_lines = section4c_retention_kat()
    for ln in section4c_lines:
        print(ln)
```
Add `and section4c_ok` to the overall pass conjunction (near line 4189), and an explicit failure print near line 4206:
```python
    if not section4c_ok:
        print("SECTION 4c FAILED: retention eligibility KAT mismatch", file=sys.stderr)
```

- [ ] **Step 4: Run conformance**

Run: `uv run core/tests/python/conformance.py 2>&1 | tail -20`
Expected: exit 0; the `§4c <name>: PASS` lines for all 7 vectors present.

- [ ] **Step 5: Differential-replay + full workspace (cross-language gate)**

Run:
```bash
cargo test --release --workspace --features differential-replay 2>&1 | tail -8
cargo test --release --workspace 2>&1 | tail -8
```
Expected: no failures.

- [ ] **Step 6: Commit**

```bash
git add core/tests/python/conformance.py
git commit -m "test(conformance): clean-room retention eligibility replay §4c (#402)"
```

---

## Task 8: README + ROADMAP

**Files:**
- Modify: `README.md` (project-status trash/purge line)
- Modify: `ROADMAP.md` (#402 entry)

**Interfaces:**
- Consumes: nothing.
- Produces: nothing.

- [ ] **Step 1: Update status prose**

In `README.md`, find the purge/trash status line (grep `git grep -n "empty-trash\|purge\|#399\|#401" README.md`) and note retention auto-purge shipped: e.g. add "retention auto-purge (auto-delete trash past a 90-day window, #402)" to the trash-lifecycle bullet. Keep it a brief dot point ([[feedback_readme_style]]).

In `ROADMAP.md`, mark #402 shipped in the relevant Sub-project A / trash-lifecycle section (grep `git grep -n "#402\|retention\|#401" ROADMAP.md`), noting it's core-only with FFI + platform UX deferred as follow-ups.

- [ ] **Step 2: Verify docs unaffected + commit**

Run: `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace 2>&1 | tail -3`
Expected: clean.
```bash
git add README.md ROADMAP.md
git commit -m "docs: note retention auto-purge shipped (#402)"
```

---

## Final gate (before requesting review / opening PR)

Run all from the worktree root and confirm each is green:
```bash
cargo test --release --workspace                                  # full suite, NO FAILURES
cargo test --release --workspace --features differential-replay   # cross-language replay
cargo clippy --release --workspace --tests -- -D warnings         # clean
cargo fmt --all --check                                           # clean
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace        # clean
uv run core/tests/python/conformance.py                           # exit 0; §4c 7/7 PASS
uv run core/tests/python/spec_test_name_freshness.py              # no new drift from the added citations
```

Then follow [[feedback_next_session_in_pr]]: author the handoff at `docs/handoffs/2026-07-09-retention-auto-purge-402-shipped.md`, retarget `NEXT_SESSION.md`, commit both on the branch, push, and open the PR.
