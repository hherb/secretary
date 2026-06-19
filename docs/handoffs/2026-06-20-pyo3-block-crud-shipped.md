# NEXT_SESSION.md — pyo3 projection of the block-CRUD primitives ✅ (SHIPPED — all gates green; PR open)

**Session date:** 2026-06-20. Flow: `/nextsession` → the prior baton (#261 FFI secret-residue, PR #265) had **already been squash-merged** (`main` @ `0a0e5f92`), and so had the *next* designated task — **Block CRUD tier (uniffi)** — which a parallel session shipped as **PR #266** (CLEAN/MERGEABLE). I flagged the parallel-session collision rather than duplicating it. The user **merged PR #266** (`main` @ `ba582468`) and chose the #266 handoff's own top next item: **pyo3 projection of the three block-CRUD ops**. Housekeeping (removed merged `block-record-crud` worktree + branch; left `hardcore-robinson` / `d4-browser-autofill` untouched) → TDD (red → green) → focused code review → parity fixups → this handoff.

**Status:** ✅ **code-complete; full gauntlet green.** Branch `feature/pyo3-block-crud` (worktree `.worktrees/pyo3-block-crud`), branched from `main` @ `ba582468`. **`core/` and the on-disk format / crypto spec are untouched** — this is a pyo3 (Python FFI) projection only; no `core` / UDL / Swift / Kotlin / conformance-KAT change. PR to be opened (see §4).

## (1) What we shipped this session

**The central idea:** the three block-CRUD bridge primitives — `secretary_ffi_bridge::{create_block, rename_block, move_record}` — were projected onto **uniffi** in PR #266 but the **pyo3** half was explicitly deferred ("we can do pyo3 later"). This session adds that half, completing binding parity for the tier.

| Layer | What landed |
|---|---|
| **pyo3 impl** | New `ffi/secretary-ffi-py/src/block_crud.rs` — three thin `#[pyfunction]` wrappers mirroring the uniffi `namespace/block_crud.rs` and the sibling `record_edit.rs`. Each length-validates uuid args (16 bytes → `ValueError` via `uuid_array_or_value_error`); `move_record` additionally enforces `source_block_uuid != target_block_uuid` at the wrapper (`ValueError`). Errors map via `ffi_vault_error_to_pyerr`. |
| **pyo3 registration** | `ffi/secretary-ffi-py/src/lib.rs`: `mod block_crud;` + `use block_crud::{create_block, move_record, rename_block};` + three `m.add_function(...)` in the `#[pymodule]` (block-CRUD comment block after the record-edit block). |
| **pytest** | New `ffi/secretary-ffi-py/tests/test_block_crud.py` — 11 cases: round-trip per op (create→empty-block read-back; rename→name-changed + records preserved; move→target holds the record under its fresh uuid + source tombstoned), same-block→`ValueError`, per-arg wrong-length→`ValueError` (both block_uuid + device_uuid on create/rename; source_block_uuid on move), absent-block→`VaultBlockNotFound`, absent-source-record→`VaultRecordNotFound`. |
| **Docs** | ROADMAP: new `[x]` row (pyo3 projection of the block-CRUD primitives, 2026-06-20). README: new "FFI bindings (block CRUD …)" row covering both halves (uniffi 2026-06-19 + pyo3 2026-06-20) — this also closes a gap, since PR #266 added no README row for the tier. |

**Feature commit:** `6de36625` (squash-merge collapses fix + handoff → one commit on `main`).

### Acceptance (automated — all green this session)
```
# From the worktree root (.worktrees/pyo3-block-crud):
cargo clippy --release --workspace --tests -- -D warnings                 # clean
cargo test  --release --workspace                                         # all pass, no failures

# pyo3 — maturin + uv. NOTE the cache trap (see §3): use maturin develop
# then run pytest with --no-sync so uv does NOT re-sync a stale wheel over it:
cd ffi/secretary-ffi-py
uv run maturin develop --release
uv run --no-sync pytest tests/test_block_crud.py -q                       # 11 passed
uv run --no-sync pytest -q                                                # 95 passed (full suite)

# Guardrail (core/spec/uniffi untouched):
git diff main...HEAD --name-only | grep -E 'core/|crypto-design|vault-format|\.udl'   → empty
```

### Deliberate design decisions (so a future reader doesn't "fix" them)
- **New file `block_crud.rs`, not folded into `record_edit.rs`.** Block-level create/rename + move are a distinct concept from record-edit; one concept per file (matches the uniffi side, which has a dedicated `namespace/block_crud.rs`). Keeps both files small.
- **Same-block guard + uuid-length checks live at the pyo3 wrapper, NOT the bridge.** The bridge takes `[u8; 16]` and trusts its caller on `source ≠ target` (per `move_record.rs`'s doc). Wrapper-level validation → `ValueError`. This mirrors uniffi (which raises `VaultError::InvalidArgument`) and the project rule [[project_secretary_input_validation_at_binding_wrapper]]. **Do not add a bridge-level variant for these.**
- **No new `FfiVaultError` variant.** `BlockNotFound` / `RecordNotFound` / `CorruptVault` / the save-tail classes all pre-existed and are already registered in `lib.rs`. So conformance stays 27/27 — no need to touch the Swift/Kotlin `ConformanceErrors.{swift,kt}` harnesses ([[project_secretary_ffivaulterror_workspace_match]] did NOT apply here).
- **Bridge signatures unchanged.** The pyo3 wrappers call the existing bridge fns verbatim; the bridge already shipped + was reviewed in #266.
- **Validation order:** all uuid-length checks run *before* the same-block check, matching uniffi — a same-length-but-wrong-length pair still gets the length error first.

## (2) What's next
- **Open + squash-merge this PR** (§4), then housekeeping (remove this worktree + branch).
- **Wire the three block-CRUD ops into a UI** — they are FFI-only now (no iOS/Android/desktop affordance). Natural next: an Android/iOS "move record to another block" + "new/rename folder" affordance over the existing browse/edit infra. **Acceptance:** on-device create→move→read-back round-trip through the platform UI.
- **iOS biometric re-auth before a write** — separate follow-up (ROADMAP C.3 remaining; carried since the #261 baton).
- **On-device sync veto round-trip** still needs a seeded concurrent state ([[project_secretary_sync_veto_needs_seeded_state]]).

**Open follow-up issues (carried):** #224 / #234 / #192 / #193 / #190 / #189 / #186 / #161 / #162 / #167 / #251 / #252 / #255. (#251 — block-plaintext residency — is the decrypted-block lifetime, distinct from this slice.)

## (3) Open decisions and risks
- **maturin + uv cache stickiness ([[project_secretary_maturin_uv_cache]]) bit this session.** `uv run pytest` re-syncs the env and reinstalls a **stale** editable wheel over the `maturin develop` build, so the new symbols vanished and every test failed with `AttributeError: no attribute 'create_block'` even after a successful rebuild. **Fix:** `uv run maturin develop --release` then `uv run --no-sync pytest …` (the `--no-sync` skips the re-sync). The nuclear option (nuke `.venv` + uv cache) also works but `--no-sync` is the cheap reliable loop. Document the working command in any new pyo3 work.
- **No on-device / cross-language run needed.** This is a pyo3-only projection of already-reviewed bridge primitives; uniffi/Swift/Kotlin and `core` are untouched (guardrail empty), so the Swift/Kotlin conformance + smoke runners would add no signal beyond the cargo + pytest gauntlet. They stay 27/27 by construction (no UDL / FfiVaultError change).

## (4) Exact commands to resume
```bash
# 0) Push the branch + open the PR (this session left it committed but unpushed):
cd /Users/hherb/src/secretary/.worktrees/pyo3-block-crud
git push -u origin feature/pyo3-block-crud
gh pr create --fill   # or with a title/body; base main

# Re-run the gauntlet (from the worktree, before merge):
cargo clippy --release --workspace --tests -- -D warnings
cargo test  --release --workspace
( cd ffi/secretary-ffi-py && uv run maturin develop --release && uv run --no-sync pytest -q )

# Guardrail (core/spec/uniffi untouched this slice):
git diff main...HEAD --name-only | grep -E 'core/|crypto-design|vault-format|\.udl'   # empty

# 1) After the PR merges, housekeeping (from the MAIN checkout, not this worktree):
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/pyo3-block-crud && git branch -D feature/pyo3-block-crud
git worktree prune && git worktree list   # leaves hardcore-robinson + d4-browser-autofill untouched
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Authored once; the symlink is the pointer. Both this handoff + the retargeted symlink are committed on the feature branch ([[feedback_next_session_in_pr]]). If you resume this branch for fixups, first `git fetch origin && git merge origin/main` (branch-version-wins on the handoff path) before editing ([[feedback_next_session_main_authoritative]]).

## Closing inventory
- **Branch on close:** `main` @ `ba582468`; `feature/pyo3-block-crud` committed (`6de36625` feature + this handoff commit). PR to open per §4. Squash-merge → one commit on `main`.
- **Acceptance:** green — cargo test `--workspace` (no failures), clippy `--tests -D warnings` clean, pyo3 pytest 95 passed (11 new block-CRUD cases). Guardrail empty (no `core/` / spec / `.udl` change).
- **README.md / ROADMAP.md:** both updated (block-CRUD pyo3 projection; README also gains the tier's first table row).
- **NEXT_SESSION.md:** symlink retargeted to this file.
