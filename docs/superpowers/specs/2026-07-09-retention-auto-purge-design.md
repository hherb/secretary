# Retention auto-purge (#402) — design

**Issue:** [#402](https://github.com/hherb/secretary/issues/402) — "Retention auto-purge (§7 step 5: auto-delete trash past the window on open)".
**Date:** 2026-07-09.
**Scope:** Core-layer only (`secretary-core`). No FFI / bridge / desktop / mobile change. No on-disk format, crypto, signature-site, or `manifest_version` change. Direct offspring of #399 (purge / empty-trash lifecycle) and sibling of #401 (conflict-copy trash-list reconciliation).

## 1. Problem

`docs/vault-format.md` §7 step 5 specifies a retention window (default 90 days) after which trashed ciphertext is physically removed, but **no code implements it**. #399 shipped the two explicit, user-initiated verbs (`purge_block`, `empty_trash`) and deliberately deferred retention auto-purge because it removes data by **age policy** rather than a per-item user action — a distinct, durability-sensitive concern.

Retention auto-purge is, precisely, *"purge every `TrashEntry` older than the window."* It is `empty_trash` restricted by an age predicate.

## 2. Decisions (resolved in brainstorming)

1. **Explicit caller-invoked core function — NOT automatic on open.** `open_vault` stays read-only (its two existing sweeps are best-effort and non-mutating, and it takes no `rng`/`device_uuid`/`now_ms`). Making it a signer would break that property and the fast sync-poll distinction (`read_vault_manifest`). The platform decides *when* to invoke retention (after open, on a schedule) and owns the UX.
2. **Caller supplies `window_ms`; core exposes `DEFAULT_RETENTION_WINDOW_MS` (90 days).** The window is **not** persisted in `vault.toml`/`manifest` — that would be a frozen-format change. Divergent windows across devices are safe: purge is monotonic and merges (an earlier-purging device converges the others via the existing open-time sweep — crypto-design §11.6 / #401).
3. **Pure preview function + commit function.** A pure `expired_trash_entries(manifest, window_ms, now_ms)` (no I/O, no mutation) lists eligible entries so a platform can show "N items will be permanently deleted" before committing; `auto_purge_expired(...)` commits. The preview function is needed internally anyway (it selects the commit targets), so exposing it is nearly free.
4. **Dedicated pure module `core/src/vault/retention.rs`** (mirrors #401's `trash_merge.rs`), reusing a `purge_batch_commit` helper extracted from `purge.rs` that **both** `empty_trash` and `auto_purge_expired` call. Keeps every file < 500 lines and gives review one commit-path to audit.

## 3. Semantics

### 3.1 Eligibility (pure `expired_trash_entries`)

A `TrashEntry` is eligible for retention purge iff **all** hold:

1. `purged_at_ms.is_none()` — not already purged (idempotent; re-run is cheap).
2. `block_uuid` is **not live** in `manifest.blocks` — the exact not-live gate `empty_trash` and both sweeps use. A concurrent restore always wins (the restored block is live again, so it is never purged).
3. `now_ms.saturating_sub(tombstoned_at_ms) > window_ms` — **strictly** older than the window. `saturating_sub` so a future-dated `tombstoned_at_ms` (skew on the trashing device) yields age 0 → never eligible. Skew can therefore never cause an *early* purge from a fast trashing clock.

The boundary is exclusive: `age == window_ms` is **not** eligible (`>`, not `>=`).

Returns `Vec<ExpiredEntry> { block_uuid: [u8;16], tombstoned_at_ms: u64, age_ms: u64 }` — pure, no I/O, no recipient classification (classification stays best-effort inside the commit path, exactly as in `empty_trash`). This same selection drives both UI preview and the commit function's target set.

### 3.2 Commit (`auto_purge_expired`)

```
auto_purge_expired(folder, &mut open, window_ms, now_ms, device_uuid, rng)
    -> Result<RetentionPurgeReport, VaultError>
```

1. Select eligible `manifest.trash` indices via the pure `expired_trash_entries` rule (§3.1).
2. Empty target set → return `RetentionPurgeReport::default()` **without touching the manifest** (no clock tick, no re-sign, no write). Mirrors `empty_trash`'s no-op-on-empty.
3. Otherwise classify each target's recipients (best-effort, reporting-only, before the write — reuses `purge.rs::classify_trash_target`).
4. `purge_batch_commit(folder, &mut open, indices, now_ms, device_uuid, rng)` — the shared primitive: stage every target's `purged_at_ms = Some(now_ms)` on one manifest clone, tick the vault clock **once**, re-sign **once**, atomic-write **once**; swap staged state into `open`; then best-effort `fs::remove_file` across every purged UUID in one directory scan (per-file failure logged via `tracing::warn!`, never fatal).
5. Return `RetentionPurgeReport { purged_count, shared_count, owner_only_count, unknown_count, files_removed, files_failed, window_ms }`.

`purge_batch_commit` is extracted verbatim from the current `empty_trash` body (steps "stage → tick → re-sign → write → swap → remove files"); `empty_trash` is refactored to call it with the all-not-purged-not-live index set, so the two entry points share one audited commit path.

### 3.3 The wall-clock question (accepted durability risk, not a security gate)

`CLAUDE.md` / crypto-design forbid wall-clock (`last_mod_ms`) as a **merge freshness signal** — a timestamp-gated variant was proven exploitable in #350 (revoked-recipient re-grant). Retention age uses `tombstoned_at_ms`, also wall-clock, so the distinction is stated explicitly and normatively:

- Retention age gates **cleanup *timing*** (when local ciphertext is discarded), **never a merge decision** (which bytes win). No security invariant reads it. The equal-clock invariant, manifest signing, merge order, and every signature site are untouched.
- `auto_purge_expired` performs the **exact same state transition** as `empty_trash`: it sets `purged_at_ms` on already-tombstoned, owner-signed entries. It re-encrypts nothing, re-keys nothing, ticks no block clock. **Zero new security surface** over the shipped `empty_trash`.
- The residual risk is pure **durability**: a device with a badly-fast clock could purge an owner-only block slightly early. Mitigations: (a) the 90-day window dwarfs realistic skew; (b) `saturating_sub` blocks the early direction from a fast trashing clock; (c) it is opt-in policy the platform accepts by invoking it; (d) the pure preview function enables show-before-delete.

This is documented as an accepted durability risk, explicitly contrasted with the forbidden freshness-signal use, so a future reader does not conflate the two.

## 4. Module & API surface

New file `core/src/vault/retention.rs`:

- `pub const DEFAULT_RETENTION_WINDOW_MS: u64` = 90 days in millis (`90 * 24 * 60 * 60 * 1000`), named (no magic number).
- `pub struct ExpiredEntry { pub block_uuid: [u8; 16], pub tombstoned_at_ms: u64, pub age_ms: u64 }`.
- `pub fn expired_trash_entries(manifest: &Manifest, window_ms: u64, now_ms: u64) -> Vec<ExpiredEntry>` — pure.
- `pub struct RetentionPurgeReport { purged_count, shared_count, owner_only_count, unknown_count, files_removed, files_failed: usize, window_ms: u64 }` (`Default`).
- `pub fn auto_purge_expired(folder, open: &mut OpenVault, window_ms, now_ms, device_uuid, rng) -> Result<RetentionPurgeReport, VaultError>`.

`core/src/vault/purge.rs`: extract `pub(crate) fn purge_batch_commit(...)` from `empty_trash`; `empty_trash` refactored to call it. No behaviour change to `empty_trash` (verified by its existing tests staying green unmodified).

Unchanged: `open_vault`, both sweeps (`complete_pending_trash_renames`, `sweep_purged_trash_files`), all FFI, all on-disk format, `manifest.rs` (zero diff — `TrashEntry.purged_at_ms` already exists from #399).

## 5. Testing (TDD)

**Cross-language (the eligibility rule is the contract):**
- New `core/tests/data/retention_kat.json` — vectors: eligible (old / not-purged / not-live); skipped-already-purged; skipped-live; skipped-too-young; boundary (`age == window` → not eligible); future-dated / `saturating_sub` skew (age 0 → skip).
- Rust replay asserting `expired_trash_entries` selects exactly the expected UUID set.
- Python clean-room `py_expired_trash_entries` + a `conformance.py` section replaying the same fixture (proves `docs/` alone suffices to compute eligibility).

**Rust unit / property / integration:**
- Unit tests on `expired_trash_entries` — each eligibility clause, the exclusive boundary, `saturating_sub` skew.
- Property: `auto_purge_expired` is **idempotent** (twice == once; second run purges nothing new, no second re-sign) and **order-independent** in `manifest.trash`.
- Property: `auto_purge_expired(window)`'s purged set is a **subset** of `empty_trash`'s (the age filter only ever removes targets) — ties the new fn to the audited primitive.
- Integration (real vault, **mutation-verified** per #401's lesson): stage two trashed blocks, one aged past the window and one fresh → `auto_purge_expired` → old one purged (`purged_at_ms` set, `trash/` file gone, signed manifest verifies), fresh one **untouched**. Mutation check: deleting the age-filter line flips the fresh block to purged — proving the filter is load-bearing, not vacuous.

**Gates (all green before merge):** `cargo test --release --workspace`; `--features differential-replay`; `cargo clippy --release --workspace --tests -- -D warnings`; `cargo fmt --all --check`; `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace`; `uv run core/tests/python/conformance.py` (exit 0).

## 6. Docs (normative — spec is the contract)

- `docs/vault-format.md §7 step 5` — expand the one-liner into the full rule: eligibility (§3.1), explicit caller-invoked (not automatic on open), reuse of the §7.2 purge mechanism (tombstone persists, ciphertext removed), `saturating_sub` skew handling, and the §3.3 accepted-durability-risk note.
- `docs/crypto-design.md §11.4` — cross-reference clarifying retention auto-purge removes *ciphertext* while the *tombstone* persists for the GC window (two distinct lifetimes).
- Add conformance test-name citations per the `spec_test_name_freshness.py` convention.

## 7. Scope boundaries (what #402 does NOT do)

- **No tombstone GC** — `auto_purge_expired` never removes a `TrashEntry` from `manifest.trash`; purged tombstones stay terminal. Removing the tombstone itself (crypto-design §11.4 GC) is a separate, unshipped concern. Retention purge removes only ciphertext.
- **No automatic-on-open wiring** — `open_vault` and both sweeps unchanged; platform invocation only.
- **No FFI / bridge / desktop / mobile** this slice — core-only, like #401.
- **No format / crypto / signature-site / equal-clock change; no `manifest_version` bump; `#![forbid(unsafe_code)]` intact.**

**Follow-ups to file (not built here):** FFI projection of `auto_purge_expired` + `expired_trash_entries`; platform scheduling & preview UX (desktop / iOS / Android).
