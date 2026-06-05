# D.1.13 — sync bridge primitive (`sync_vault` + `sync_status`, pause-on-conflict)

**Date:** 2026-06-06
**Status:** design — approved scope, pending plan
**Phase:** D (platform UIs), but the work is a B-phase bridge/FFI primitive + a C-phase orchestration addition. **No desktop UI in this slice.**

## Why this slice exists

The desktop is feature-complete for local vault management (browse / edit / delete / share / revoke / contacts), but has **zero** sync integration — `SessionState` covers lock/unlock only, and the desktop depends on `secretary-ffi-bridge` + `secretary-core`, never on the headless `secretary-sync` (`cli`) crate. The C-phase sync orchestration (`sync_once → prepare_merge → commit_with_decisions`, plus the `cli::pipeline::run_one` daemon seam) exists and is tested, but nothing above the CLI can reach it.

"Surface sync state in the desktop" is the next high-value step toward a genuinely usable app. It is **decomposed** into:

- **D.1.13 (this spec)** — the **sync bridge primitive**: a `sync_vault` mutation + a read-only `sync_status` read, projected through the full FFI surface (pyo3 + uniffi + Swift/Kotlin conformance). Mirrors **D.1.10** (the revoke primitive that preceded the D.1.11 revoke UI).
- **D.1.14 (next slice, not this spec)** — the **desktop sync UI**: a status panel + a manual "Sync now" button (password re-prompted), surfacing the structured outcome. Mirrors **D.1.11**.

Deferred beyond D.1.14: interactive conflict resolution (the veto UX over `DraftMerge` / `RecordTombstoneVeto`) and background auto-sync (the `notify`-driven daemon loop).

## Decisions locked in during brainstorming

| Decision | Choice | Rationale |
|---|---|---|
| Trigger interface | **Bridge-thick primitive** | House style (share/revoke/contacts/edit/delete all own their disk I/O inside a bridge primitive). Identity stays in the bridge's zeroize space; mobile/Python get sync via the same surface. Accepts the full conformance gauntlet. |
| Password source | **Re-prompted per sync** (D.1.14 UI) | The session never retains the human password; it is passed fresh into `sync_vault` and zeroized after. No widening of the in-memory secret surface. |
| Conflict behaviour | **Pause, don't auto-commit** | When a concurrent state carries tombstone vetoes (delete-vs-edit disputes needing human judgement), the pass reports `ConflictsPending { veto_count }` and writes **nothing** — no silent side-pick. Sets up D.1.14+ interactive resolution. |
| Status read | **`SyncState` CBOR + state-file mtime, no secrets** | A read-only `sync_status` that loads the per-vault `.state.cbor` and its mtime. No identity, no password. |
| Code layering | **Feature-gate `cli`** | Orchestration stays in the C-phase layer; state-file format single-sourced in `cli`; **no `core` change**; mobile bindings stay lean (no `notify`/`clap`). |

## Architecture

Three layers, bottom-up.

### Layer 1 — `secretary-cli`: a pause-on-conflict orchestration sibling to `run_one`

`run_one` (`cli/src/pipeline.rs`) always commits via a `VetoUx`. We need a variant that **never** drives a UX and **aborts on vetoes instead of committing**. New pure-orchestration entry point:

```rust
// cli/src/pipeline.rs (feature-available without `daemon`)
pub enum SyncPassOutcome {
    /// Disk clock == local highest-seen. No state mutation, no write.
    NothingToDo,
    /// Disk strictly dominates local. `state` advanced to disk clock. No vault write.
    AppliedAutomatically,
    /// Concurrent, but diverging_blocks empty → silent-merge clock. `state`
    /// advanced to the LUB. No vault write.
    SilentMerge,
    /// Concurrent, diverging_blocks non-empty, **zero** tombstone vetoes →
    /// `commit_with_decisions(.., [])` wrote the merged result. `state` advanced.
    MergedClean,
    /// Concurrent, diverging_blocks non-empty, **non-empty** tombstone vetoes →
    /// **NOT committed, `state` NOT advanced**. Caller surfaces the count and
    /// defers to interactive resolution.
    ConflictsPending { veto_count: usize },
    /// Disk clock strictly dominated by local (rollback). `state` unchanged.
    RollbackRejected,
}

/// Run one sync pass that auto-applies every safe arm and pauses (commits
/// nothing) the instant a tombstone veto requires human judgement.
pub fn sync_pass_pause_on_conflict(
    vault_folder: &Path,
    identity: &UnlockedIdentity,
    password: &SecretBytes,
    state: &mut SyncState,
    now_ms: u64,
) -> Result<SyncPassOutcome, SyncError>;
```

Outcome truth table (the whole contract):

| `sync_once` result | `diverging_blocks` | `draft.vetoes` | action | `SyncPassOutcome` | state advanced? | vault written? |
|---|---|---|---|---|---|---|
| `NothingToDo` | — | — | none | `NothingToDo` | no | no |
| `AppliedAutomatically` | — | — | adopt disk clock | `AppliedAutomatically` | **yes** | no |
| `RollbackRejected` | — | — | none | `RollbackRejected` | no | no |
| `ConcurrentDetected` | empty | — | silent-merge LUB | `SilentMerge` | **yes** | no |
| `ConcurrentDetected` | non-empty | **empty** | `commit_with_decisions(.., [])` | `MergedClean` | **yes** | **yes** |
| `ConcurrentDetected` | non-empty | **non-empty** | **abort** | `ConflictsPending { n }` | **no** | **no** |

This reuses `silent_merge_clock` (already in `pipeline.rs`, already unit-tested) for the `SilentMerge` arm. It does **not** depend on the `veto` module's interactive half — the abort path needs no `VetoUx`.

**Feature-gating.** Add a default feature `daemon` to `cli/Cargo.toml` that gates `clap` + `notify` + `ctrlc` + `tracing-subscriber`, the `[[bin]]` (`secretary-sync`), the daemon-loop module, and the interactive veto UX (`veto::interactive`, which reads a TTY). The feature-**off** lib surface exposes:

- `pipeline::{sync_pass_pause_on_conflict, SyncPassOutcome}` (and `run_one` — pure already);
- `state::{load, save, LockfileGuard, canonical_hex, state_file_path, default_state_dir, StateError}`;
- `veto::noninteractive::AutoKeepLocalVetoUx` (pure; harmless to keep available).

Acceptance: `cargo build -p secretary-cli --no-default-features` is green and pulls **neither** `clap` nor `notify`. `cargo test -p secretary-cli` (default features on) stays green — the existing `pipeline_integration.rs` + daemon tests are unaffected.

### Layer 2 — `secretary-ffi-bridge`: the two primitives

The bridge gains a `secretary-cli = { path = "../../cli", default-features = false }` dependency (lean — no `notify`/`clap`). New module `ffi/secretary-ffi-bridge/src/sync/` mirroring `revoke/`:

```rust
// Read-only — no secrets. Loads the per-vault SyncState CBOR + state-file mtime.
pub fn sync_status(vault_folder: &Path) -> Result<SyncStatusDto, FfiVaultError>;

// Mutation — opens a core identity from `password`, acquires the per-vault
// lockfile, runs sync_pass_pause_on_conflict, persists state, zeroizes,
// maps SyncError → FfiVaultError.
pub fn sync_vault(vault_folder: &Path, password: SecretBytes)
    -> Result<SyncOutcomeDto, FfiVaultError>;
```

DTOs (FFI-friendly, redacting — secrets never cross the boundary):

```rust
pub struct SyncStatusDto {
    /// Whether a .state.cbor exists for this vault yet (false ⇒ never synced).
    pub has_state: bool,
    /// Per-device vector-clock entries (device_uuid hex + counter). Public
    /// metadata, not secret.
    pub device_clocks: Vec<DeviceClockDto>,
    /// Unix-ms mtime of the state file, or None if has_state == false.
    pub last_state_write_ms: Option<u64>,
}

pub struct DeviceClockDto { pub device_uuid_hex: String, pub counter: u64 }

/// Tagged outcome of one sync pass.
pub enum SyncOutcomeDto {
    NothingToDo,
    AppliedAutomatically,
    SilentMerge,
    MergedClean,
    ConflictsPending { veto_count: u32 },
    RollbackRejected,
}
```

**State directory.** The public FFI functions resolve the state dir via `cli::state::default_state_dir()` (the same OS-data-dir path the daemon uses), so the desktop and a running `secretary-sync` share one state file. They delegate to internal `sync_status_in(state_dir, ..)` / `sync_vault_in(state_dir, ..)` helpers that take an explicit dir, so tests drive a `TempDir` without polluting `~/Library/Application Support/` — the same injection pattern the bridge/desktop already use (`settings::load_or_create_device_uuid_in`, `VaultSession::new(device_data_dir)`). The test-only dir is **not** part of the public uniffi/pyo3 surface.

**Lockfile.** `sync_vault` acquires `cli::state::LockfileGuard` before the pass. If a `secretary-sync` daemon (or another desktop call) holds it, return the typed `FfiVaultError::SyncLockHeld` rather than blocking — the UI surfaces "another sync is in progress."

**Identity.** `sync_vault` opens a fresh `core::UnlockedIdentity` from `password` for the duration of the pass (the bridge's existing `open_vault_with_password` path), then drops/zeroizes it. It does **not** borrow the desktop session's sealed handle — the session stays untouched, consistent with the re-prompt decision.

### Layer 3 — FFI propagation (the gauntlet)

New `FfiVaultError` variants in `ffi/secretary-ffi-bridge/src/error/vault/mod.rs`, with `SyncError → FfiVaultError` mapping. Proposed set (final set settled in implementation; **every** variant is a workspace-wide exhaustive-match obligation per [[project_secretary_ffivaulterror_workspace_match]]):

| `SyncError` | `FfiVaultError` | surfaced as |
|---|---|---|
| `VaultUuidMismatch` | `SyncVaultUuidMismatch` | the state file belongs to a different vault |
| `StateDecodeFailed` / `StateEncodeFailed` | `SyncStateCorrupt { #[serde(skip)] detail }` | local state cache is corrupt |
| `EvidenceStale` | `SyncEvidenceStale` | concurrent writer; retryable |
| `cli::state::StateError` (lock held) | `SyncLockHeld` | another sync process holds the lockfile |
| `Vault(VaultError)` | reuse existing `VaultError → FfiVaultError` mapping | — |
| `InvalidArgument` / `ConflictCopyScanIoFailed` / `Unknown`/`Missing`/`DraftRecordsEmpty` veto invariants | `SyncFailed { #[serde(skip)] detail }` | catch-all internal |

Then, threaded through **every** binding (functions propagated, not just errors — full bridge-thick surface, like D.1.10):

- `ffi/secretary-ffi-uniffi/src/secretary.udl` — the two functions + DTO records/enums + the new error variants.
- pyo3 (`ffi/secretary-ffi-py`) — exhaustive match over the new error variants + the function wrappers.
- uniffi (`ffi/secretary-ffi-uniffi`) — same.
- `ffi/secretary-ffi-uniffi/tests/{swift,kotlin}/Conformance*.{swift,kt}` — the conformance error harnesses (cargo/clippy **cannot** see these; only `run_conformance.sh` does — [[project_secretary_ffivaulterror_workspace_match]]).
- `core/tests/...` KAT-helper exhaustive matches over `FfiVaultError`, if any.

**Clean-room conformance KAT.** Add a scoped `sync_pass` KAT to `core/tests/python/conformance.py` proving the **outcome classification + post-merge clock** cross-language: a JSON fixture of `(disk_clock, local_highest_seen, copy_clocks, has_vetoes)` cases → expected `(SyncPassOutcome, post_clock)`, asserted by a Rust always-run guard (à la `revoke_kat_after_block_matches_inputs`) **and** by a stdlib-only Python replay. This pins the truth-table above without a full crypto replay (the merge math itself is already covered by the 11 `conflict_kat` vectors + the `revoke_kat`).

## What this slice is NOT

- **No desktop UI** — no `commands/sync.rs`, no Svelte, no `AppError` mapping. That is D.1.14.
- **No interactive conflict resolution** — `ConflictsPending` is terminal here; resolving it is D.1.14+.
- **No background auto-sync** — the `notify` daemon loop stays in the (feature-gated-out) CLI.
- **No session password retention** — the session is untouched; the password is a `sync_vault` parameter (used by D.1.14's re-prompt).
- **No vault on-disk-format or crypto change** — `docs/vault-format.md` and `docs/crypto-design.md` are untouched. The `.state.cbor` side-file is a client-local cache, not part of the frozen format. The bridge sync surface + the pause-on-conflict semantics are documented in the C.2 spec (`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`) or a short B-phase addendum.

## Testing

- **`cli`**: unit tests for `sync_pass_pause_on_conflict` outcome classification (extend the existing `pipeline.rs` tests + `pipeline_integration.rs` golden-vault fixtures with a veto-bearing concurrent case proving **no write + no state advance** on `ConflictsPending`); a `--no-default-features` build job proving the lean surface.
- **bridge**: `sync_status` (no-state, has-state, foreign-vault) + `sync_vault` (every outcome arm, lockfile-held, wrong-password, zeroize discipline) unit tests against a `TempDir` state dir + golden-vault copy.
- **pyo3**: pytest over the function wrappers + the new error variants.
- **uniffi**: Swift + Kotlin conformance (`run_conformance.sh`) over the new errors + a `sync_pass` KAT replay.
- **conformance.py**: the stdlib-only `sync_pass` classification KAT.
- **Full workspace gauntlet** (because this touches `core`-adjacent + bridge + FFI): `cargo test --release --workspace`, `cargo clippy --release --workspace --tests -- -D warnings`, `cargo fmt --all --check`, `uv run core/tests/python/conformance.py`, `bash ffi/secretary-ffi-uniffi/tests/{swift,kotlin}/run_conformance.sh`, plus `uv run core/tests/python/spec_test_name_freshness.py`.

## Risks & open items

- **`cli` feature-gating fragility.** The feature-off build must compile cleanly and the feature-on tests must stay green. Risk: a module accidentally references a gated dep on the lean path. Mitigation: a CI `--no-default-features` build check (file #135-adjacent if no CI yet — but at minimum a local gate command in the plan).
- **State-file format single-sourcing.** The desktop and the daemon MUST agree on `.state.cbor`. This holds **only** because both go through `cli::state` — no duplicate codec. Any change to `SyncState` serialization is a cross-consumer change.
- **`FfiVaultError` variant count.** Each new variant is the documented multi-site exhaustive-match obligation across pyo3 + uniffi + Swift/Kotlin harnesses that cargo/clippy can't see. Keep the set minimal; prefer the `SyncFailed { detail }` catch-all for internal/unreachable `SyncError` arms.
- **Conformance-KAT scope.** The `sync_pass` KAT proves classification + clock, not a full crypto replay — deliberately, to avoid re-implementing AEAD/merge in Python a second time (already covered). Reviewers should confirm this scoping is acceptable.
- **`ConflictsPending` is a success return, not an error.** It is an `Ok(SyncOutcomeDto::ConflictsPending)`, not an `Err`. The vault is provably unchanged on this arm — the test suite must pin "no write, no state advance."

## Build sequence (for the plan)

1. `cli` feature-gate (`daemon` default feature) + `sync_pass_pause_on_conflict` + `SyncPassOutcome` + tests + lean-build gate.
2. bridge `sync/` module: `sync_status` + DTOs + tests (read path first — no secrets).
3. bridge `sync_vault` + `LockfileGuard` + identity-open/zeroize + `SyncError → FfiVaultError` mapping + new variants + tests.
4. FFI propagation: UDL + pyo3 + uniffi + Swift/Kotlin conformance harnesses + the `sync_pass` clean-room KAT.
5. README / ROADMAP: D.1.13 ✅; "next" → D.1.14 (desktop sync UI).
