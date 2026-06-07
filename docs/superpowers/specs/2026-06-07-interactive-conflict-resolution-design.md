# Interactive conflict resolution — the veto-resolution UX over `DraftMerge`

**Date:** 2026-06-07
**Sub-projects:** C (sync orchestration) + D (desktop UI) — the first slice that closes the
human-in-the-loop merge loop end-to-end.
**Status:** design approved; ready for implementation plan.

## 1. Problem

D.1.13/D.1.14 shipped the desktop sync verb. When a sync pass hits a **record-tombstone veto** — a
record the local side still has live that a peer deleted — the bridge's `sync_vault` **pauses,
writes nothing, and returns only a count** (`ConflictsPending { veto_count }`). The desktop surfaces
that as the dead-end string **"N conflicts need resolution — coming soon"**
([sync.ts](../../../desktop/src/lib/sync.ts)). There is no way for a user to actually resolve the
conflict; the vault stays un-synced indefinitely.

The core engine is **already built for this**. `core/src/sync` has the full three-step machinery:
`sync_once` → `prepare_merge` (produces a `DraftMerge` with a `vetoes: Vec<RecordTombstoneVeto>`
list) → `commit_with_decisions(draft, decisions, now_ms)` (applies one `VetoDecision` per veto and
atomically writes). `cli/src/pipeline.rs::run_one` drives this interactively for the CLI via a
synchronous `VetoUx` callback. **What's missing is a stateless surface the desktop can drive across
two async FFI calls** (the decision happens in a modal that may be open for minutes), plus the DTOs,
commands, and UI to make it real.

This is the C/D pairing that makes `ConflictsPending` actionable.

## 2. Goal

Give a user with an unlocked vault, when "Sync now" hits a tombstone veto:

- A **resolution modal** listing each disputed record by **plaintext metadata only** (record type,
  tags, field names, "you edited HH:MM / peer deleted HH:MM on device …") with a per-record
  **Keep mine / Accept delete** choice (default **Keep mine** — the no-data-loss safe default).
- A **read-only "auto-merged" notice** showing which field-level LWW overwrites happened silently in
  the same merge (record + field name only — no values), so the user knows e.g. a password was
  replaced by a newer peer edit. (Scope decision §4-B below.)
- A single **Apply & finish sync** action that commits all decisions atomically; the pill then shows
  "Synced" and refreshes the manifest.

The flow is **continuous**: the resolution modal opens in the same gesture as the sync click,
reusing the password already entered. The user never walks away with the vault in an undecided state.

## 3. Approach decisions (brainstormed)

| Decision | Choice | Rationale |
|---|---|---|
| **What is a "conflict"** | Record-tombstone vetoes (decisions) **+** read-only field-collision notice | Vetoes are the only thing core asks a human about (§11/D3 frozen merge); field-collision data is already computed — surfacing it (metadata-only) is cheap and removes "did sync silently clobber my password?" anxiety. |
| **When resolution happens** | **Continuous** — modal opens in the same flow as the sync click | Simplest mental model; no persistent pending-conflict state; password already in hand. The deferred/badge model can layer on later. |
| **How the draft survives the two stateless FFI calls** | **Recompute on commit** (bridge holds nothing) | The merge is deterministic; the freshness gate already exists in `commit_with_decisions`. No plaintext held between calls, no FFI statefulness — consistent with the frozen-bridge / stateless / zeroize discipline. Costs one extra `prepare_merge` of only the diverging blocks. |
| **Modal contents** | Metadata-only cards, default Keep-mine, single Apply, no bulk/reveal | Matches the app's reveal-on-click secret-hygiene model; tight scope. Bulk actions / reveal-to-decide are explicit non-goals for this slice. |

## 4. Scope

**In scope**

**A. `core/src/sync` — surface the already-computed field collisions (metadata only).**
- `prepare_merge` ([prepare.rs](../../../core/src/sync/prepare.rs)) already runs `merge_block`, which
  returns `RecordCollision`/`FieldCollision` lists, but discards them. Add a **metadata-only**
  collision summary to `DraftMerge` ([draft.rs](../../../core/src/sync/draft.rs)):
  `collisions: Vec<RecordCollisionSummary>` where `RecordCollisionSummary { record_id: RecordId,
  field_names: Vec<String> }`. **No secret values** (`FieldCollision.winner`/`.loser` are
  `RecordField` and stay inside the merge step) — this keeps `DraftMerge`'s zeroize discipline
  intact (`field_names` are plaintext metadata, like the browse-path `FieldMetaDto`).
- **No merge-semantics change.** The 4 CRDT proptests and `conformance.py`'s `py_merge_*` are
  untouched; this only projects existing data onto the draft.

**B. `cli/src/pipeline.rs` — two new stateless pipeline helpers.**
- `sync_pass_inspect(...) -> InspectOutcome` — `sync_once`; on the clean arms behaves exactly like
  `sync_pass_pause_on_conflict` (advances state for `AppliedAutomatically`/`SilentMerge`, commits
  the empty-veto `MergedClean`); on the **non-empty-veto** arm runs `prepare_merge` and **returns
  the draft's `vetoes` + `collisions` + `manifest_hash`**, committing nothing and advancing no state.
- `sync_pass_commit_decisions(..., expected_manifest_hash, decisions, now_ms) -> SyncPassOutcome` —
  `sync_once` → `prepare_merge` (recompute) → **assert the fresh `draft.manifest_hash ==
  expected_manifest_hash`** (the token from inspect; mismatch → `SyncError::EvidenceStale`, disk
  untouched) → `commit_with_decisions(draft, decisions, now_ms)`. `commit_with_decisions` also
  re-validates the manifest hash internally and that decisions exactly cover the veto set.
- These do **not** drive `VetoUx` — that's the whole point (the decision is supplied out-of-band by
  call 2, not by a synchronous in-process callback like `run_one`).

**C. `ffi/secretary-ffi-bridge` — enrich one outcome arm + one new function + DTOs.**
- Enrich `SyncOutcomeDto::ConflictsPending` to carry
  `{ vetoes: Vec<VetoDto>, collisions: Vec<CollisionDto>, manifest_hash: Vec<u8> }`
  (replaces the bare `veto_count`; count is derivable). `VetoDto`/`CollisionDto` are
  **metadata-only** projections (record uuid hex, record type, tags, field names, `local_last_mod_ms`,
  `peer_tombstoned_at_ms`, `peer_device_hex`). `sync_vault` now calls `sync_pass_inspect`.
- New `sync_commit_decisions(vault_folder, password, decisions: Vec<VetoDecisionDto>,
  manifest_hash: Vec<u8>, now_ms) -> SyncOutcomeDto` calling `sync_pass_commit_decisions`.
  `VetoDecisionDto = { record_uuid_hex: String, keep_local: bool }`.
- **Un-collapse** the veto-decision errors: `commit_with_decisions`'s `EvidenceStale`,
  `MissingVetoDecision`, `UnknownVetoDecision` map to **distinct** `FfiVaultError` variants
  (today the bridge folds them into `SyncFailed` — now they're reachable and must be distinguished).

**D. `ffi` uniffi + pyo3 — expose the new surface.**
- Add `sync_commit_decisions` + the new DTOs/enum-shape to the UDL and pyo3 bindings. **Regenerate
  `core/tests/data/conformance_kat.json`** (human-reviewed diff) and run **both** Swift + Kotlin
  `run_conformance.sh`, plus thread every new `FfiVaultError` variant through the
  `ConformanceErrors.{swift,kt}` harnesses (per [[project_secretary_ffivaulterror_workspace_match]]).

**E. `desktop/src-tauri` — command + DTOs.**
- New Tauri command `sync_commit_decisions(password, decisions, manifest_hash)` + testable `_impl`
  (same `#[tauri::command]` + `_impl` + `lock_session` + `with_unlocked` + `map_ffi_error` shape as
  [commands/sync.rs](../../../desktop/src-tauri/src/commands/sync.rs)). Enrich the desktop
  `SyncOutcomeDto::ConflictsPending` + add `VetoDto`/`CollisionDto`/`VetoDecisionDto`
  ([dtos/sync.rs](../../../desktop/src-tauri/src/dtos/sync.rs)) with serde wire-format unit tests.

**F. `desktop/src` — the UI.**
- `ConflictResolutionDialog.svelte` — centered native `<dialog>` mirroring `SyncPasswordDialog`
  (callback props, `showModal()` via `$effect`, Esc → cancel). Renders one card per veto with the
  Keep/Accept toggle, the collapsible auto-merge notice, and Apply/Cancel.
- IPC wrapper `syncCommitDecisions(...)` ([ipc.ts](../../../desktop/src/lib/ipc.ts)); new `AppError`
  codes + `userMessageFor` ([errors.ts](../../../desktop/src/lib/errors.ts)).
- Pure helpers ([lib/sync.ts](../../../desktop/src/lib/sync.ts)): a conflict-summary formatter
  (record label from type+tags; timestamps reuse `formatRelativeTime`), a decision-collection
  helper (`collectDecisions(vetoes, choices) -> VetoDecisionDto[]`), and a `decisionsComplete` guard.
- Wire into the `SyncPill` flow: after `sync_now` returns `ConflictsPending(details)`, open the
  dialog (reusing the held password from `SyncPasswordDialog`); on Apply, call
  `syncCommitDecisions`; on success show the synced notice + `refreshManifest()`.

**Out of scope (deferred)**

- **Reveal-to-decide.** Showing the actual secret values (winner/loser of a field collision, or a
  vetoed record's field values) to help the user decide. `FieldCollision` already preserves both
  values for this, but it's a separate (reveal-gated) feature.
- **Bulk actions** ("Keep all" / "Accept all delete").
- **Deferred resolution** (badge / persistent pending-conflict state, resolve-later).
- **Background auto-sync** interplay (the `notify` daemon loop) — separate slice.
- **Mobile/Python UI.** This slice makes the *bridge surface* available to all bindings (#187-style
  projection rides along), but the resolution UI is desktop-only here.

## 5. Data flow

**Call 1 — `sync_now(password)` (existing command, enriched outcome):**
```
sync_once
 ├─ NothingToDo / AppliedAutomatically / SilentMerge / MergedClean / RollbackRejected → return (as today)
 └─ ConcurrentDetected + diverging blocks → prepare_merge → draft
      ├─ draft.vetoes empty → commit_with_decisions([]) → MergedClean (as today)
      └─ draft.vetoes non-empty → COMMIT NOTHING, return
           ConflictsPending { vetoes:[meta], collisions:[meta], manifestHash }
```
Desktop: `ConflictsPending(details)` → open `ConflictResolutionDialog`.

**Between calls:** user toggles per-record choices. Password stays in component `$state`
(reused for call 2), cleared on success **and** cancel/Esc.

**Call 2 — `sync_commit_decisions(password, decisions, manifestHash)` (new):**
```
sync_once → prepare_merge (recompute, deterministic)
 → assert fresh draft.manifestHash == manifestHash   (mismatch → EvidenceStale, disk untouched)
 → commit_with_decisions(draft, decisions, now_ms) → MergedClean
```
Desktop: success → pill "Synced" + `refreshManifest()`. `EvidenceStale` → auto-rerun `sync_now`,
reopen the dialog with the fresh set.

**Three safety properties:** (1) call 1 persists nothing, so re-running is always safe; (2) the
`manifestHash` token threads call 1 → call 2 so a mid-modal disk write is refused, not clobbered;
(3) `commit_with_decisions` validates decisions exactly cover the recomputed veto set.

## 6. Error handling (typed, no silent failure)

| Code | Cause | User message (title / hint) |
|---|---|---|
| `sync_evidence_stale` *(reuse)* | call-2 `manifestHash` mismatch — vault changed during the modal | "Vault changed during resolution" / "Re-running sync to pick up the latest." → desktop auto-reruns `sync_now`, reopens modal |
| `sync_decisions_incomplete` *(new)* | `Missing`/`UnknownVetoDecision` (defensive; UI shouldn't produce it) | "Couldn't apply your choices" / "Some conflicts weren't resolved — please try again." |
| `sync_in_progress` *(reuse)* | lockfile held (daemon/other window) | as D.1.13 |
| `sync_failed` *(reuse)* | other bridge `SyncFailed` | as D.1.13 |

Modal renders failures inline (`role="alert"`) and **stays open** to retry, except the stale case
(closes + auto-reruns sync). Password cleared on every terminal outcome. The only permitted swallow
remains `SyncPill.loadStatus` (informational `sync_status` read) — unchanged.

## 7. Testing (TDD per layer)

- **core (`prepare.rs`):** `prepare_merge` populates the collision summary with the right
  `(record_id, field_names)` for a concurrent merge that has both a veto and a field collision; assert
  the summary is metadata-only (no value type reachable). CRDT proptests untouched.
- **cli (`cli/tests/sync_pass_integration.rs`, `TempDir`):** `inspect` returns veto+collision
  metadata + `manifest_hash` with **disk byte-unchanged** and state not advanced; `commit_decisions`
  — `KeepLocal` keeps the record live, `AcceptTombstone` writes the tombstone, state advances,
  re-sync is clean; **freshness** — mutate the vault between inspect and commit → `EvidenceStale`,
  disk untouched.
- **ffi bridge:** DTO serde wire-format pinning (enriched `ConflictsPending` + the three new DTOs);
  a `TempDir` happy-path through `sync_commit_decisions`. Regenerate `conformance_kat.json`
  (reviewed diff) + run both `run_conformance.sh`.
- **desktop (seam-only-hermetic, per D.1.14):** Rust `NotUnlocked` seam + DTO wire-format unit tests;
  TS pure-helper table tests (formatter, `collectDecisions`, `decisionsComplete`); Vitest component
  tests for `ConflictResolutionDialog` (cards render, toggle, Apply collects decisions, error keeps
  open) using **`mockRejectedValueOnce`** ([[project_secretary_vitest_mockrejectedvalue_quirk]]).
  Each Rust task's verify step includes **`cargo fmt --all --check`** (D.1.14 plan-improvement note).
- **Manual GUI smoke** on a **`cp -R` temp copy** of the golden vault
  ([[feedback_smoke_test_temp_copy_golden_vault]]). Requires a **two-device divergence fixture** that
  actually produces a veto (a peer copy with a tombstone newer than a local live edit); constructing
  that fixture is part of the smoke setup and is documented in the plan.

## 8. Risks / open items

- **Two-device veto fixture.** The hardest test-setup piece: the automated cli/ffi tests must build a
  bundle with a canonical (local-live) + copy (peer-tombstoned) divergence. The existing
  `sync_pass_integration.rs` / `sync_pass_kat.rs` already construct concurrent states — reuse their
  builders; #186 (shared bridge test-helper dedup) may help and could be folded in if cheap.
- **`manifest_hash` over the FFI boundary.** Carried as opaque `Vec<u8>` (BLAKE3-256, 32 bytes); the
  desktop treats it as an opaque token, never inspects it. Pin its serde shape in a test.
- **FFI enum-shape change.** Enriching `ConflictsPending` + adding `FfiVaultError` variants is the
  workspace-wide exhaustive-match obligation + conformance KAT regen + Swift/Kotlin harness threading
  ([[project_secretary_ffivaulterror_workspace_match]]). Budget for it; it is the bulk of the
  "not a pure-desktop slice" cost.
- **Determinism of recompute.** Relies on `prepare_merge` being a pure function of (disk, identity).
  The freshness assert is the backstop if that assumption is ever violated by a concurrent writer.

## 9. Acceptance criteria

1. "Sync now" on a vault with a tombstone veto opens a resolution modal listing each disputed record
   by metadata + the auto-merge notice; nothing is written until Apply.
2. Keep-mine keeps the record live on disk; Accept-delete writes the tombstone; both verified by a
   clean follow-up sync.
3. A disk change while the modal is open yields `EvidenceStale` → auto-rerun, never a clobber.
4. Full workspace gauntlet green (`cargo test`/`clippy -D warnings`/`fmt --check`), desktop
   frontend gauntlet green, **and** Swift + Kotlin conformance scripts pass with the regenerated KAT.
5. Manual GUI smoke on a temp golden-vault copy with the two-device fixture passes (recorded in PR).
