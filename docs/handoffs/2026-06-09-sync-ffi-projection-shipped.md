# NEXT_SESSION.md — #187 ✅ project the sync API onto uniffi + pyo3

**Session date:** 2026-06-09 (#187 — projects the D.1.13–D.1.15 sync surface from the `secretary-ffi-bridge` Rust crate onto the uniffi (Swift/Kotlin) + pyo3 (Python) bindings; the error variants already rode cross-language since D.1.13, this adds the **functions + DTOs**). Flow: `superpowers:brainstorming` (3 scope questions → design) → `superpowers:writing-plans` (10-task TDD plan) → `superpowers:subagent-driven-development` (fresh implementer per task + spec-compliance + code-quality review after each + a final whole-branch review).
**Status:** ✅ code-complete on branch `feature/sync-ffi-projection`. **PR: see §4.** Full automated gauntlet **green** (Rust workspace + Python conformance + pytest 74 + Swift/Kotlin smoke + Swift/Kotlin conformance 22/22). Final whole-branch review: **APPROVE TO MERGE**, zero Critical/Important.
**No outstanding manual gate** — this is **not** a UI slice (no desktop/GUI change). The Swift+Kotlin `SmokeSync` parity-smokes ran green locally (swiftc + kotlinc available on this host).

## (1) What we shipped this session

The **sync FFI projection** (#187). Three bridge functions — `sync_status`, `sync_vault`, `sync_commit_decisions` — plus the full DTO set (`SyncStatusDto`/`DeviceClockDto`/`SyncOutcomeDto` incl. `ConflictsPending{vetoes,collisions,manifest_hash}` + the conflict DTOs `VetoDto`/`CollisionDto`/`VetoDecisionDto`) are now callable from Swift, Kotlin, and Python.

**Key architecture decision — explicit `state_dir` parameter.** The param-free public bridge `sync_*` wrappers hardcode `default_state_dir()` (`dirs::data_dir()` — a desktop path). The bindings instead project the existing `sync_*_in` seams (which take an explicit `state_dir: &Path`), promoted `pub(crate)` → `pub`. So a sandboxed/non-desktop consumer passes its own path, and every cross-language test is hermetic (tempdir state). Desktop's param-free wrappers are untouched.

**Binding consumers per [ADR 0007]:** Sub-project D's first-party UI is a single **Tauri** universal client (consumes the bridge directly, not via uniffi). The bindings serve **third-party / alternate consumers** (Python automation; Swift/Kotlin host integrations — Shortcuts/AutoFill/scripts) + keep the binding surface at parity with the bridge + give the cross-language differential value. See §3 — there's an open question worth confirming.

**Six layers touched:**
- **bridge** (`secretary-ffi-bridge`) — visibility-only: `sync_status_in`/`sync_vault_in`/`sync_commit_decisions_in` promoted to `pub` + re-exported at crate root; param-free wrappers unchanged. A new integration test (`tests/sync_public_api.rs`) pins the public reachability (a downstream-crate test that won't compile against `pub(crate)`).
- **uniffi** (`secretary-ffi-uniffi`) — UDL fns + dictionaries + `[Enum] interface SyncOutcomeDto`; new `wrappers/sync.rs` value types; `namespace.rs` split into a `namespace/` dir module with the sync fns + bridge→uniffi converters in `namespace/sync.rs`; password wrapped in `SecretBytes` immediately.
- **pyo3** (`secretary-ffi-py`) — new `src/sync.rs`: 6 DTO pyclasses (`SyncOutcomeDto` exposes a `kind`-string discriminant + payload getters, matching the TS tagged-union shape) + 3 pyfunctions + registration. `#[pyo3(get)]` on the input `VetoDecisionDto` so Python can read its fields back (pyo3 0.28: `get_all`+`from_py_object` don't combine).
- **Python pytest** — `tests/test_sync.py`: status (empty→no state), wrong-length uuid→ValueError, clean `sync_vault`→`AppliedAutomatically`→`NothingToDo`, bad manifest_hash→`VaultSyncFailed`, **full `ConflictsPending → commit_decisions → MergedClean` round-trip** + `VaultSyncDecisionsIncomplete`.
- **fixture** — a committed, deterministic two-device divergence at `core/tests/data/sync_conflict_fixture/` (`vault/` canonical + sibling manifest + blocks; `state/<uuid>.state.cbor` seeded Concurrent SyncState). Produced by an `#[ignore]` generator inside `cli/tests/sync_pass_integration.rs` that reuses `stage_concurrent_veto_vault` and self-validates `ConflictsPending` before writing. Secret-free (encrypted vault bytes + clock-only state).
- **Swift/Kotlin** — `SmokeSync.{swift,kt}` parity-smokes (status + clean sync_vault + DTO round-trip) wired into the smoke `run.sh` + `main.swift`/`Main.kt`. The conflict round-trip is proven once in Python (shared Rust logic; uniffi generates Swift+Kotlin from one definition).

Commits on `feature/sync-ffi-projection` (branched from `main` @ `1a22e96`):

| Commit | What it landed |
|---|---|
| `dc26d93` | design spec |
| `9ea2d8e` | 10-task TDD plan |
| `71ce4ab` | Task 1 — bridge `sync_*_in` → `pub` + reachability test |
| `7de91b4` | Task 1 fmt fixup |
| `66d8414` | Task 2 — uniffi projection (UDL + wrappers/sync.rs + namespace fns) |
| `67f0146` | Task 2 review — split `namespace/sync.rs`, doc the password-zeroize reasoning |
| `a06f27f` | Task 3 — pyo3 projection (`src/sync.rs` + registration) |
| `25f5366` | Task 3 review — expose `VetoDecisionDto` fields + doc the pyfunctions |
| `f7e73a9` / `e0385d9` | Task 4 — Python status/clean-sync/error pytest (+ drop unused import) |
| `db5f36d` / `163e945` | Task 5 — generated divergence fixture (+ ignore-reason) |
| `172d0f2` | Task 6 — Python ConflictsPending→commit→MergedClean round-trip |
| `3c97a0e` | Task 7 — Swift `SmokeSync` |
| `8fec59a` | Task 8 — Kotlin `SmokeSync` |
| `58c34cd` | Task 9 — README + ROADMAP #187 ✅ |
| `75ccd7f` | final-review nit — reframe design motivation to match ADR 0007 |
| _(ship)_ | this handoff + symlink retarget |

**Process notes:**
- The pyo3 plan code assumed an older pyo3; the crate is on **0.28.3** where auto-`FromPyObject` on `#[pyclass]+Clone` is deprecated (breaks `-D warnings`). Implementer adapted to the existing `save.rs` attribute convention (`from_py_object` / `skip_from_py_object`, `Clone` only where `get_all` Vec getters need it). Worth remembering for any future pyo3 DTO work.
- Two cosmetic review nits were carried as no-ops with rationale (orphan-rule blocks a `From` impl for the uniffi→bridge `VetoDecisionDto`; the pyo3 `outcome_from_bridge` `_` payload arm is exhaustive-by-design and commented).

### Automated gauntlet (re-run clean @ HEAD `75ccd7f`)
```
cargo fmt --all --check                                          → clean
cargo clippy --release --workspace --tests -- -D warnings        → clean
cargo test --release --workspace                                 → 0 failed
uv run core/tests/python/conformance.py                          → PASS (incl. sync_pass KATs)
uv run --directory ffi/secretary-ffi-py pytest                   → 74 passed (incl. test_sync.py 6)
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh                 → OK (sync smoke green)
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh     → 22/22
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh                → OK (sync smoke green)
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh    → 22/22
```

## (2) What's next

No slice is pre-committed. Honest next-deferred (pick one → brainstorm → plan → execute):

- **Resolve the ADR 0007 question first (see §3)** — it determines whether more binding investment is even wanted. Cheap to settle.
- **Background auto-sync** — the `notify`-driven daemon loop (C.2 `secretary-sync run`) surfaced in-app so sync happens without a manual click; the pill reflects live status (the D.1.14/D.1.15 deferred "live polling"). Acceptance: a vault syncs on file-change with a debounce; the pill updates; must coordinate with `SyncInProgress` (lockfile) so a daemon + a manual click / open resolution modal don't fight; a background pass that hits a veto must surface it without stomping an open modal. **Tauri-desktop slice — consumes the bridge directly, no binding work.**
- **Reveal-to-decide** — let the user inspect actual winner/loser field values (reveal-gated) to decide a veto/collision. `FieldCollision` already preserves both values. Separate reveal-gated desktop feature; out of D.1.15 scope.
- **#192** — the collision-population path is still unasserted end-to-end (the veto fixture is tombstone-based → no field collision). Needs a non-tombstone concurrent-edit fixture; now reproducible cross-language via the generator pattern this slice added.

**Acceptance criteria for whichever is chosen:** author via `superpowers:brainstorming` → `superpowers:writing-plans`. A pure Tauri-desktop slice consumes the bridge directly and does NOT need the cross-language gauntlet. Anything touching `core`/`ffi`/`FfiVaultError`/UDL re-triggers the full workspace gauntlet **and** the Swift+Kotlin conformance runs ([[project_secretary_ffivaulterror_workspace_match]]). Any mutation path needs the confirm + strict typed-error-surfacing care; a UI slice needs a manual GUI smoke on a `cp -R` temp copy ([[feedback_smoke_test_temp_copy_golden_vault]]).

**Open follow-up issues:** **#192** (collision-population test), **#193** (pipeline.rs refactor/real-race/orphaned-pass), plus carried **#186/#189/#190/#161/#162/#167**. #187 closes with this PR.

## (3) Open decisions and risks

- **⚠️ Strategic: ADR 0007 vs "native mobile apps".** Mid-session the architecture (bindings vs all-Rust+Tauri) was re-examined; I researched Tauri-v2-mobile and you concluded "go ahead with the bindings, mobile apps are needed." **But the repo already has [ADR 0007] (May 2026): Sub-project D pivoted to a single Tauri universal client for desktop AND mobile, and the README states the uniffi/pyo3 bindings are "third-party-consumer paths … no longer the UI path."** This slice is valid + valuable under ADR 0007 (third-party consumers + binding parity + cross-language differential testing), and the design doc was reframed to say so (`75ccd7f`). **Decision to confirm next session:** is ADR 0007 still the direction (bindings = third-party; Tauri = mobile UI), or do you want to revisit it toward native SwiftUI/Compose apps? Either answer keeps this slice's code correct — it only changes how much further binding investment is warranted. (Tauri-v2-mobile research summary from this session: viable but the hardware-key-storage plugin ecosystem is immature — Secure Enclave/Keystore only via <10-star alpha plugins or a small hand-written Swift/Kotlin shim; biometric plugin is a yes/no gate not a key binding; an Android-relevant IPC origin-confusion CVE was fixed in Tauri 2.11.1.)
- **pyo3 0.28 DTO attribute discipline** — auto-`FromPyObject` is deprecated; use the `save.rs`/`sync.rs` convention (`from_py_object` for input DTOs, `skip_from_py_object` + `Clone` for nested-in-`get_all`-Vec output DTOs) for any future pyclass.
- **`namespace/mod.rs` is 501 lines** (one over the soft guideline after extracting `namespace/sync.rs`). Acceptable; flag if the next uniffi fn would grow it further.

### Verified non-issues (don't re-investigate)
- **Secret hygiene (HIGH confidence):** `password` wrapped in `SecretBytes` immediately on every projected fn (both bindings), never copied/logged; no secret VALUE crosses any DTO — `VetoDto`/`CollisionDto` carry field *names* (`.keys()`) only, confirmed at the bridge `project_veto` source; the committed fixture is encrypted-bytes + clock-only state.
- **Error surface:** all six sync `FfiVaultError` variants map explicitly through `VaultError::from` (uniffi) and `ffi_vault_error_to_pyerr` (pyo3) with **no `_` wildcard**; the sync-outcome converters name all six variants.
- **Wire consistency:** field names/types + `SyncOutcomeDto` variants line up across bridge ↔ UDL ↔ uniffi Rust ↔ pyo3 ↔ Python/Swift/Kotlin; `manifest_hash` is bytes/32-byte everywhere; `keep_local`↔`keepLocal`; pyo3 `kind` strings == bridge variant names.
- **Fixture determinism:** regenerating produces byte-identical output (fixed seeds/nonces/timestamps) — verified by re-run + empty `git status`.

## (4) Exact commands to resume

```bash
# 1) PR (opened this session — confirm / review):
cd /Users/hherb/src/secretary && gh pr list --head feature/sync-ffi-projection

# 2) Merge (squash) once reviewed, then housekeeping:
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/sync-ffi-projection && git branch -D feature/sync-ffi-projection
git worktree prune && git worktree list

# 3) Next slice: settle the ADR 0007 question (§3), then brainstorm → plan → execute (§2):
git worktree add .worktrees/<slug> -b feature/<slug> main

# Re-run the gauntlet on the branch if needed (from the worktree):
cd /Users/hherb/src/secretary/.worktrees/sync-ffi-projection
cargo test --release --workspace && cargo clippy --release --workspace --tests -- -D warnings
uv run core/tests/python/conformance.py
uv run --directory ffi/secretary-ffi-py maturin develop --release && uv run --directory ffi/secretary-ffi-py pytest
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh && bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh
```

## (5) Handoff file model

`NEXT_SESSION.md` at the repo root is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Author the handoff once; the symlink is a pointer. main did NOT move during this session (branch point == origin/main == `1a22e96`), so the symlink retarget merges cleanly. Next slice: author `docs/handoffs/<date>-<slug>-shipped.md` + `ln -snf docs/handoffs/<new>.md NEXT_SESSION.md`, both committed on the feature branch ([[feedback_next_session_in_pr]]).

## Closing inventory

- **Branch on close:** `main` @ `1a22e96`; `feature/sync-ffi-projection` carries design + plan + 16 task/review/doc commits + this ship commit. Squash-merge collapses to one commit on `main`.
- **Automated gauntlet:** green — Rust (fmt/clippy/workspace tests) + Python conformance + pytest 74 + Swift/Kotlin smoke + Swift/Kotlin conformance 22/22.
- **Final whole-branch review:** **APPROVE TO MERGE** — zero Critical/Important; one Minor doc-framing nit fixed in `75ccd7f`.
- **README.md / ROADMAP.md:** #187 ✅ 2026-06-09.
- **CLAUDE.md / `docs/adr/`:** unchanged (no new on-disk-format/crypto decision; ADR 0007 already governs the binding-consumer story).
- **Open decision for next session:** confirm ADR 0007 direction (§3).
- **NEXT_SESSION.md:** symlink retargeted to this file.

[ADR 0007]: ../adr/0007-d-row-tauri.md
