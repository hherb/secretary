# NEXT_SESSION.md — FFI projection of record-edit primitives (Slice 1 of iOS record CRUD) ✅

**Session date:** 2026-06-13. Flow: `/nextsession` → confirmed prior arc (#217, iOS vault selection) merged → cleaned up the `ios-vault-selection` worktree/branch → brainstormed the next direction → picked **iOS record editing**, full CRUD, **decomposed into 2 slices** (FFI projection first, iOS UI second) → spec (Approach: project the bridge primitives onto both bindings) → 7-task TDD plan → subagent-driven implementation (fresh implementer + spec & code-quality review per task, all fixes applied) → full gauntlet green.

**Status:** ✅ **code-complete + all-bindings-green** on branch `feature/ffi-record-edit-primitives`. PR: see §4. This is **Slice 1 of 2** — it lands the FFI surface; the iOS record-CRUD UI is **Slice 2** (§2).

## Why this slice existed (the prior handoff was imprecise)

The #217 handoff claimed "the FFI already exposes `save_block`/`append_record`/`edit_record`/`tombstone_record`." Investigation found that only **half** true: the Rust *bridge* has the granular record-edit primitives, but the **uniffi/pyo3 bindings exposed only block-level ops** (`save_block`/`share_block`/`trash_block`/`restore_block`). And `save_block` is **replace-semantics** — round-tripping an edit through it would re-stamp every field clock and drop forward-compat `unknown` data (the exact CRDT corruption `edit_record` exists to avoid). So "iOS record editing" genuinely needed an FFI slice first; this is it.

## (1) What we shipped this session

**The four record-edit bridge primitives (`append_record` / `edit_record` / `tombstone_record` / `resurrect_record`) are now projected onto both the uniffi (Swift) and pyo3 (Python) bindings**, with a new `RecordContent` foreign input type and binding-boundary proof of the CRDT per-field-clock-preservation property. **Touches only `ffi/` — no `core` / on-disk-format / UDL-error / KAT change** (`git diff main..HEAD --name-only | grep '\.rs$'` is entirely under `ffi/`).

| Layer | What landed | Key commits |
|---|---|---|
| **Spec + plan** | design spec (2-slice decomposition; project bridge primitives) + 7-task TDD plan; corrected mid-flight when `read_block`-surfaces-tombstones was discovered | `27ea2a9` `aeaa8da` `83dbbbb` `08e2784` |
| **uniffi `RecordContent`** | value type (`record_type` / `tags` / `fields`, reuses `FieldInput`/`FieldInputValue`) + UDL dictionary + crate-root re-export | `d6f1864` |
| **uniffi 4 fns** | `append_record`/`edit_record`/`tombstone_record`/`resurrect_record` in a new `namespace/record_edit.rs` (submodule+re-export, like `sync.rs`); all 3 uuids length-validated → `InvalidArgument`; errors mapped, not swallowed; `#[allow(too_many_arguments)]` parity with `share_block` | `3538f72` `9e06525` |
| **Swift smoke** | `SmokeRecordEdit.swift` — 5 asserts incl. the per-field-clock proof via `FieldHandle.deviceUuid()`; wired into `run.sh` + `main.swift`; **53/53 green** | `57d6201` |
| **Kotlin smoke** | `SmokeRecordEdit.kt` — byte-for-byte parity with Swift; wired into `run.sh` + `Main.kt`; **green** | `5771ff7` |
| **pyo3 4 fns + pyclass** | `record_edit.rs` (`RecordContent` `#[pyclass]` + 4 `#[pyfunction]`s); a `FieldInput::to_bridge()` accessor keeps `FieldInputValue.inner` private; full error-surface docstrings | `e12ca98` `b43a7be` |
| **pyo3 pytest** | `test_record_edit.py` — 5 round-trips incl. clock proof; **5 passed, full pyo3 suite 83 passed** | `802097f` |
| **Docs** | README FFI-status row + ROADMAP bullet + this handoff/symlink | (this commit) |

Branch from `main` @ `0093c3d`. **Squash-merge collapses to one commit on `main`.**

### Properties (verified across the per-task reviews + the final gauntlet)
- **CRDT-correct edits, not replace-semantics** — routes to the bridge `edit_record` etc.; untouched per-field `last_mod`/`device_uuid`, `created_at_ms`, `tombstoned_at_ms`, and all `unknown` maps are preserved by the bridge. **Proven at the binding boundary**, not trusted: the edit-changes-pass-but-not-user test asserts the untouched field keeps its seed `device_uuid` (0x07) while the changed field gets the edit device (0x09) — in Swift, Kotlin, AND pyo3.
- **No weaker open / no new attack surface** — pure projection: length-validate the 3 uuids binding-side (→ `InvalidArgument`/`ValueError`), convert `RecordContent` to the bridge type (wrapping payloads in zeroize carriers), call the bridge, map `FfiVaultError`. No secret material stashed past the call.
- **No new `FfiVaultError` variant** — `BlockNotFound`/`RecordNotFound` pre-existed. Proven by the **unchanged 27/27 Swift + Kotlin conformance** runs (the only check that catches binding/harness drift cargo/clippy can't see).
- **Encapsulation** — pyo3 `FieldInputValue.inner` stays private; cross-module access via the `to_bridge()` accessor.

### Acceptance (green — full gauntlet run this session)
```
cargo fmt --all --check                                   → clean
cargo clippy --release --workspace --tests -- -D warnings → clean
cargo test --release --workspace                          → all pass, 0 failed
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh          → 53/53 PASS (incl. 5 record-edit)
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh         → all PASS (record-edit parity)
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh  → 27/27 (unchanged)
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh → 27/27 (unchanged)
cd ffi/secretary-ffi-py && uv run --with pytest pytest    → 83 passed (incl. 5 new)
git diff main..HEAD --name-only | grep '\.rs$'            → only under ffi/ (no core)
```

## (2) What's next — Slice 2: iOS record-CRUD UI

The FFI surface is now ready. **Slice 2** builds the native-iOS record editing UI on it (its own spec → plan → implement → review cycle):
- **Acceptance:** in a selected, unlocked vault, add a new record, edit an existing record's fields, and soft-delete (tombstone) / restore a record — lossless write, host-tested view models + simulator XCTest + on-device smoke.
- **Swift work:** a write port + `UniffiVaultSession` adapter methods over the 4 new fns; edit/add/delete view models; an edit screen; `RootView` routing into edit; the `now_ms`/`device_uuid` plumbing (the device unlock flow already has a device uuid).
- **⚠️ Key UI constraint surfaced this slice:** `read_block` surfaces **all** records including tombstoned ones (exposing deletion via the per-record `tombstone()` flag) — it does **not** filter them. So the browse/edit UI must filter live-vs-deleted itself (cf. desktop D.1.5's Rust-gated `include_deleted` read parameter — consider whether the iOS read path wants the same, or filters client-side).

Other candidate slices (pick with the user): iOS vault create/import (mirrors desktop D.1.3); Rust-core backlog **#193** (`pipeline.rs` refactor), **#192** (collision-population test).

**Open follow-up issues:** carried **#192 / #193 / #186 / #189 / #190 / #161 / #162 / #167**.

## (3) Open decisions and risks

- **Dependabot PR #219 (pyo3 0.28.3 → 0.29.0, a major bump) is open and untriaged.** This slice was built against 0.28.3. A 0.29 major could carry breaking changes for the bridge crate (cf. the 0.28 `FromPyObject` deprecation history). Triage it before/after Slice 2; the new `record_edit.rs` uses the same 0.28 idioms as `save.rs`, so it will move with the rest of the crate.
- **`read_block` surfaces tombstoned records** (see §2 ⚠️) — not a bug, but a Slice-2 UI design input. The spec + plan were corrected mid-slice (`08e2784`) when this was discovered; the tests assert the `tombstone()` flag flip, not a record-count drop.
- **No on-disk-format / frozen-spec / `FfiVaultError`-variant change** — verified by construction and by the unchanged conformance runs.

## (4) Exact commands to resume

```bash
# 1) PR (opened this session — confirm / review / merge):
cd /Users/hherb/src/secretary && gh pr list --head feature/ffi-record-edit-primitives

# 2) Merge (squash) once reviewed, then housekeeping:
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/ffi-record-edit-primitives && git branch -D feature/ffi-record-edit-primitives
git worktree prune && git worktree list

# 3) Next slice (Slice 2 — iOS record-CRUD UI): brainstorm → plan → execute
git worktree add .worktrees/<slug> -b feature/<slug> main

# Re-run this slice's gauntlet on the branch (macOS + Xcode + Kotlin toolchain present):
cd /Users/hherb/src/secretary/.worktrees/ffi-record-edit-primitives
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
cd ffi/secretary-ffi-py && uv run --with pytest pytest
```

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Authored once; the symlink is the pointer. `main` did NOT move during this session (branch point == `0093c3d`), so the symlink retarget merges cleanly. Both this handoff + the retargeted symlink are committed on the feature branch ([[feedback_next_session_in_pr]]).

## Closing inventory

- **Branch on close:** `main` @ `0093c3d`; `feature/ffi-record-edit-primitives` carries spec + plan + the 7-task implementation (each with its review fixes) + this handoff/symlink. Squash-merge → one commit on `main`.
- **Acceptance:** green — see §1. No `core` / frozen-format / `FfiVaultError`-variant / conformance-KAT change.
- **Per-task reviews:** every task passed spec-compliance + code-quality review; all raised issues fixed on the branch (no deferred debt). The notable mid-slice catch: `read_block` surfaces tombstoned records (test expectation corrected, `08e2784`).
- **README.md / ROADMAP.md:** updated — record-edit FFI projection ✅.
- **Outstanding:** Dependabot #219 (pyo3 0.29 major) untriaged (§3). Slice 2 (iOS record-CRUD UI) is the next build.
- **NEXT_SESSION.md:** symlink retargeted to this file.
