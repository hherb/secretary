# NEXT_SESSION.md — D.1.13 ✅ sync bridge primitive (`sync_vault` + `sync_status`, pause-on-conflict)

**Session date:** 2026-06-06 (D.1.13 — the Rust/FFI half of "surface sync state"; the desktop status panel + manual "Sync now" UI is the follow-on **D.1.14**). Brainstormed scope via `superpowers:brainstorming` → authored spec + 7-task TDD plan via `superpowers:writing-plans` → executed via `superpowers:subagent-driven-development` (fresh implementer per task + a spec-compliance review + a code-quality review after each + a final whole-branch review).
**Status:** D.1.13 ✅ code-complete on branch `feature/d113-sync-primitive`; **PR not yet opened/merged** (this session ends at branch-ready). Full automated gauntlet **green**. Final whole-branch review: **APPROVE TO MERGE**, zero Critical/Important.
**No manual smoke gate this slice** — D.1.13 is headless Rust/FFI (no UI). The desktop is unaffected at runtime (only mandatory `AppError` plumbing added, unused until D.1.14). The visual smoke belongs to **D.1.14** when the sync UI lands.

## (1) What we shipped this session

The bridge-thick sync primitive, decomposed (mirrors **D.1.10** revoke-primitive → **D.1.11** revoke-UI): D.1.13 = the primitive; **D.1.14 = the desktop UI**.

- **cli feature-gate** — a default `daemon` feature on `secretary-cli` gates `clap`/`notify`/`tracing-subscriber`/`rpassword`/`serde_json` + the `secretary-sync` bin + the daemon/TTY-only modules, so `secretary-ffi-bridge` depends on `secretary-cli` with `default-features = false` and the **mobile bindings stay lean** (verified: `cargo tree -p secretary-ffi-uniffi --no-default-features` has no `notify`/`clap`). The `.state.cbor` format stays single-sourced in `cli::state`.
- **`sync_pass_pause_on_conflict`** (`cli/src/pipeline.rs`) — a `run_one` sibling that auto-applies every SAFE arm (NothingToDo / AppliedAutomatically / SilentMerge / concurrent-with-zero-vetoes → MergedClean) but returns **`ConflictsPending { veto_count }` writing NOTHING and advancing NO state** the instant a tombstone veto needs a human decision. No `VetoUx`. Pinned end-to-end by a real concurrent-veto golden-vault test asserting `state == state_before` AND the on-disk block bytes are byte-identical (`cli/tests/sync_pass_integration.rs`).
- **bridge `sync_status`** — read-only projection of the per-vault `SyncState` CBOR + state-file mtime (no secrets); DTOs `SyncStatusDto`/`DeviceClockDto`.
- **bridge `sync_vault`** — the pause-on-conflict mutation: opens a core identity from a **re-prompted password** (caller passes it; never retained), holds the per-vault `LockfileGuard` (→ `SyncInProgress` if a daemon/2nd client holds it), runs the cli pass, persists `SyncState` **only on the advancing arms**, maps `SyncError`/`StateError` → `FfiVaultError`. Takes `now_ms` from the caller (the `MergedClean` commit's merge timestamp — D.1.14 supplies wall-clock). Returns `SyncOutcomeDto`. Identity + password are `ZeroizeOnDrop`, dropped at fn end, never stashed.
- **5 new `FfiVaultError` sync variants** (`SyncStateVaultMismatch`, `SyncStateCorrupt{detail}`, `SyncEvidenceStale`, `SyncInProgress`, `SyncFailed{detail}`) threaded through **every** exhaustive-match site: bridge enum, uniffi `VaultError` + `From` + UDL, pyo3 (exception + match + module registration), Swift + Kotlin `ConformanceErrors`, the core KAT helper, **and `desktop/src-tauri AppError` + `map_ffi_error`** (mandatory plumbing — the desktop won't compile otherwise; unused until D.1.14). `EvidenceStale`→typed `SyncEvidenceStale` (NOT folded), `LockfileHeld`→`SyncInProgress`.
- **cross-language `sync_pass` classification KAT** — `core/tests/data/sync_pass_kat/cases.json` (6 cases, all outcomes) replayed by an always-run Rust guard (`core/tests/sync_pass_kat.rs`) AND a stdlib-only `conformance.py` section that **reuses** the existing `py_clock_relation`/`py_merge_vector_clocks` (no duplicate codec). Mutation-tested: flipping an expected label fails BOTH sides.

**Architecture: Rust/FFI only — no UI, no `core` on-disk-format/crypto change.** The `.state.cbor` side-file is a client-local cache, not the frozen vault format. Sync **functions** stay bridge-only (the desktop consumes the bridge as a Rust crate); projecting them onto uniffi/pyo3 is deferred to **[#187](https://github.com/hherb/secretary/issues/187)** (mirrors #167).

Commits on `feature/d113-sync-primitive` (branched from `main` @ `4e80604`):

| Commit | What it landed |
|---|---|
| `8eb89f5` | D.1.13 design spec. |
| `58dfa7a` | 7-task TDD plan + spec scope-correction (functions bridge-only, errors threaded). |
| `eae4e32` | cli `daemon` feature-gate (lean lib surface; no notify/clap downstream). |
| `e6cf920` | `sync_pass_pause_on_conflict` + real pause-path veto test. |
| `d3867b9` | 5 `FfiVaultError` sync variants threaded through every binding (incl. desktop AppError + core KAT helper). |
| `ae45bee` | bridge `sync_status` read primitive + lean `secretary-cli` dep. |
| `e7d5d79` | bridge `sync_vault` pause-on-conflict mutation. |
| `a5fa6ec` | cross-language `sync_pass` classification KAT. |
| `dbb7253` | README + ROADMAP D.1.13 ✅; next → D.1.14; issue #187 filed. |
| `1d7d60d` | final-review nit: sync deferral doc refs → #187. |
| _(ship)_ | this handoff + symlink retarget. |
| _(/fixall)_ | post-review: `map_sync_error` made exhaustive (no `_` catch-all → a new `SyncError` variant now fails to compile here); two non-blocking follow-ons filed (#189 lean-binding CI guard, #190 bridge `MergedClean`-under-lock test). |

**Process note:** one worktree (`.worktrees/d113-sync-primitive`), one reviewed commit per task + inline review-fix amends. Every per-task spec + quality finding fixed before proceeding. Two plan-improvements applied during execution (both documented): the implementers found **2 exhaustive-match sites the plan missed** (`desktop AppError`, `core/tests/conformance_kat_helpers`) and threaded them; `sync_vault` gained a caller-supplied `now_ms` (vs the plan's hardcoded 0) so the `MergedClean` merge timestamp is real. Spec: [docs/superpowers/specs/2026-06-06-d113-sync-primitive-design.md](../superpowers/specs/2026-06-06-d113-sync-primitive-design.md); plan: [docs/superpowers/plans/2026-06-06-d113-sync-primitive.md](../superpowers/plans/2026-06-06-d113-sync-primitive.md).

### Automated gauntlet (re-run clean on `feature/d113-sync-primitive` @ HEAD by the final whole-branch reviewer)

```
cargo fmt --all --check                                   → clean
cargo test --release --workspace                          → every suite 0 failed (3 KATs ignored as designed)
cargo clippy --release --workspace --tests -- -D warnings → clean
cargo build -p secretary-desktop                          → compiles (new AppError variants)
uv run core/tests/python/conformance.py                   → PASS (incl. sync_pass_kat ×6)
uv run core/tests/python/spec_test_name_freshness.py      → PASS (101 resolved, 0 unresolved)
swift  run_conformance.sh                                 → 22/22
kotlin run_conformance.sh                                 → 22/22
cargo tree -p secretary-ffi-uniffi --no-default-features  → no notify/clap (lean binding confirmed)
```

## (2) What's next — D.1.14 (the desktop sync UI)

D.1.14 is the **pre-committed** follow-on (mirrors D.1.11): wire the D.1.13 bridge primitives into the desktop.

- **`commands/sync.rs`** IPC: `sync_status` (over `secretary_ffi_bridge::sync_status`, surfacing `SyncStatusDto`) + `sync_now` (over `sync_vault` — takes a **re-prompted password** + `now_ms`, returns the `SyncOutcomeDto`). Map outcomes to user messages via the already-threaded `AppError` sync variants.
- **Svelte:** a sync-status indicator (last-sync mtime + per-device clock from `SyncStatusDto`) + a "Sync now" button with a password re-prompt, rendering the outcome ("up to date" / "applied peer changes" / "**N conflicts need resolution — coming soon**" for `ConflictsPending` / "rollback rejected" / "another sync in progress").
- **`AppError::SyncFailed`'s user message** is currently the terse `"Sync failed"` (a deliberate D.1.14 UI-copy decision flagged in Task 3 review) — give it a proper user-facing string + recovery hint in the UI layer.

**Acceptance criteria:** author the D.1.14 plan via `superpowers:brainstorming` → `superpowers:writing-plans`. Pure D-phase desktop slice — **no `core`/`ffi`/`FfiVaultError`/UDL change** (the bridge surface + error variants already shipped), so **no cross-language conformance run is needed** (see [[project_secretary_ffivaulterror_workspace_match]]). The mutation path (`sync_now`) needs the confirm + strict typed-error-surfacing care D.1.11 used. Ends with a manual GUI smoke (the visual gate this headless slice didn't carry) — per [[feedback_smoke_test_temp_copy_golden_vault]], **`cp -R` the golden vault to a tempdir first**; do not open the tracked fixture.

**Deferred / parallel (not D.1.14):** **[#187](https://github.com/hherb/secretary/issues/187)** project `sync_vault`/`sync_status` + DTOs onto uniffi+pyo3 (mobile/Python; pairs with #167); **#186** dedup `copy_dir_recursive` + golden-staging helpers into a shared bridge `#[cfg(test)]` module. Interactive conflict resolution (the veto UX over `DraftMerge`) and background auto-sync (the `notify` daemon loop) remain deferred beyond D.1.14.

## (3) Open decisions and risks

- **No outstanding gate** — the gauntlet is fully green and the slice is headless, so there is no manual smoke for D.1.13. The PR is ready to open + merge.
- **`now_ms` for `MergedClean`** — `sync_vault` takes `now_ms` from the caller; D.1.14's IPC must pass real wall-clock (the desktop has it). A `0` only affects the merge timestamp on the rare concurrent-clean-merge arm.
- **`SyncInProgress` vs a running daemon** — if a user ever runs the headless `secretary-sync` daemon AND clicks "Sync now", the lockfile makes one of them return `SyncInProgress`. Correct behaviour; D.1.14's UI should surface it gracefully ("another sync is in progress").

### Verified non-issues (don't re-investigate)
- **Pause-on-conflict writes nothing:** disk-pinned (block bytes byte-identical) AND state-pinned (`state == state_before`) on the veto arm, at BOTH the cli level (`sync_pass_integration.rs`) and the bridge (`sync_vault_in` persists only on the 3 advancing arms).
- **Zeroize/identity:** the core identity is opened from the password, used by-ref, dropped (ZeroizeOnDrop) at fn end — never stashed/cloned/logged; password not retained; no `unsafe`.
- **No silent error fold:** `EvidenceStale`→typed `SyncEvidenceStale`, `LockfileHeld`→`SyncInProgress`; only the non-actionable internal `SyncError` guards fold to the documented `SyncFailed` catch-all.
- **Exhaustive-match completeness:** all 5 variants at every site; the cargo-invisible Swift/Kotlin sites are validated by the 22/22 conformance runs.
- **KAT bites:** mutation-tested on both Rust and Python; Python reuses the existing `py_clock_relation`/`py_merge_vector_clocks` (no duplicate codec).

## (4) Exact commands to resume (D.1.14)

```bash
# Open + merge the D.1.13 PR first (this session leaves the branch ready, PR not opened).
cd /Users/hherb/src/secretary
git fetch --prune origin
git checkout main
git pull --ff-only origin main
git log -3 --oneline           # confirm the D.1.13 PR landed

# Re-baseline the automated gauntlet on fresh main (pure desktop slice ahead — desktop subdir is enough):
cd desktop && pnpm install && pnpm test && pnpm typecheck && pnpm svelte-check && pnpm lint && cd ..
cd desktop/src-tauri && cargo fmt --check && cargo clippy --tests -- -D warnings && cargo test 2>&1 | grep "^test result:" && cd ../..
# (full core-workspace gauntlet NOT needed for D.1.14 — it touches no core/ffi/FfiVaultError/UDL.)

# Author the D.1.14 plan:
#   superpowers:brainstorming  → confirm the desktop sync-UI scope (status panel + Sync now; see §2)
#   superpowers:writing-plans  → mirror docs/superpowers/plans/2026-06-06-d113-sync-primitive.md

# Then the first implementation worktree:
git worktree add .worktrees/d114-<slug> -b feature/d114-<slug> main
cd .worktrees/d114-<slug>/desktop && pnpm install
```

### Housekeeping (after the D.1.13 PR merges)
```bash
cd /Users/hherb/src/secretary
git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/d113-sync-primitive 2>/dev/null && git branch -D feature/d113-sync-primitive 2>/dev/null
git worktree prune && git worktree list
```

## (5) Handoff file model

`NEXT_SESSION.md` at the repo root is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Author the handoff once; the symlink is a pointer. To open D.1.14: author `docs/handoffs/<date>-d114-*.md` and `ln -snf docs/handoffs/<new>.md NEXT_SESSION.md`, committing both on the feature branch (per [[feedback_next_session_in_pr]]).

## Closing inventory

- **Branch on close:** `main` @ `4e80604`. `feature/d113-sync-primitive` carries the spec + plan + 7 task commits + the doc-ref nit + the ship commit (this handoff + symlink). Squash-merge collapses to one commit on `main`.
- **Automated gauntlet:** green across the workspace (Rust test/clippy/fmt, desktop build, conformance.py incl. sync_pass_kat, freshness, Swift+Kotlin 22/22, lean-binding check).
- **Final whole-branch review:** **APPROVE TO MERGE** — zero Critical/Important; the sole Minor (doc refs → #187) fixed in `1d7d60d`.
- **PR:** [#188](https://github.com/hherb/secretary/pull/188) open. **No outstanding gate** (headless slice).
- **README.md / ROADMAP.md:** D.1.13 ✅ shipped 2026-06-06; "next" advanced to D.1.14.
- **CLAUDE.md / `docs/adr/`:** unchanged (no new architecture decision; no on-disk-format/crypto change).
- **Issues:** **#187** filed (project sync onto uniffi/pyo3, deferred); **#186** filed (dedup bridge test helpers); **#189** (lean-binding CI guard — no notify/clap in mobile bindings; awaits a CI workflow) + **#190** (bridge `MergedClean`-under-lock test) filed post-review. #161/#162/#167 stay open.
- **NEXT_SESSION.md:** symlink retargeted to this file.
- **This file:** the live D.1.13 ship baton. The next slice opens with `docs/handoffs/<date>-d114-*.md`.
