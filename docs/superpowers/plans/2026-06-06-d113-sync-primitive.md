# D.1.13 — Sync Bridge Primitive Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a bridge-thick sync surface — `sync_vault` (a manual, pause-on-conflict sync pass) and `sync_status` (a read-only state read) — to `secretary-ffi-bridge`, backed by a new feature-gated `secretary-cli` orchestration entry point, with the new `FfiVaultError` sync variants threaded through every FFI binding.

**Architecture:** Three layers. (1) `secretary-cli` gains a default `daemon` feature so its lean lib surface (`pipeline` + `state`) is reachable without dragging `notify`/`clap` into the mobile bindings, plus a new pure orchestration fn `sync_pass_pause_on_conflict` that auto-applies every safe sync arm but commits **nothing** when a tombstone veto needs human judgement. (2) `secretary-ffi-bridge` wraps it in `sync_vault` (mutation, opens an identity from a re-prompted password, owns the `.state.cbor` + lockfile) + `sync_status` (no secrets). (3) The new `FfiVaultError` sync error variants are threaded through the bridge enum, the uniffi-side `VaultError` enum + UDL, pyo3, and the Swift/Kotlin conformance harnesses. The sync **functions** stay bridge-only (the desktop consumes the bridge as a Rust crate); projecting them onto uniffi/pyo3 is deferred to a new #167-sibling issue.

**Tech Stack:** Rust (stable, `#![forbid(unsafe_code)]`), `secretary-core::sync`, `secretary-cli` (`fs4` lockfile, `tempfile` atomic write, CBOR `SyncState`), uniffi + pyo3 bindings, Swift/Kotlin conformance harnesses, `uv`-run `conformance.py`.

**Spec:** [docs/superpowers/specs/2026-06-06-d113-sync-primitive-design.md](../specs/2026-06-06-d113-sync-primitive-design.md)

**Worktree:** `.worktrees/d113-sync-primitive` on branch `feature/d113-sync-primitive`. All commands below assume you are in that worktree root. Per CLAUDE.md, verify with `pwd && git branch --show-current` before any `cargo`/`git` command.

---

## File Structure

| File | Responsibility | Task |
|---|---|---|
| `cli/Cargo.toml` | add `[features] default=["daemon"]`; make daemon-only deps optional | 1 |
| `cli/src/lib.rs` | `#[cfg(feature="daemon")]`-gate the daemon-only modules | 1 |
| `cli/src/veto/mod.rs` | gate `pub mod interactive` | 1 |
| `cli/src/pipeline.rs` | add `SyncPassOutcome` + `sync_pass_pause_on_conflict` | 2 |
| `cli/tests/sync_pass_integration.rs` | end-to-end pass tests against the golden vault | 2 |
| `ffi/secretary-ffi-bridge/src/error/vault/mod.rs` | add 5 `FfiVaultError` sync variants | 3 |
| `ffi/secretary-ffi-uniffi/src/errors/vault.rs` | mirror variants in uniffi `VaultError` + `From` | 3 |
| `ffi/secretary-ffi-uniffi/src/secretary.udl` | add variants to `[Error] interface VaultError` | 3 |
| `ffi/secretary-ffi-py/src/errors.rs` | `create_exception!` + match arms | 3 |
| `ffi/secretary-ffi-uniffi/tests/{swift,kotlin}/ConformanceErrors.{swift,kt}` | exhaustive switch/when arms | 3 |
| `ffi/secretary-ffi-bridge/Cargo.toml` | add `secretary-cli` dep (default-features=false) | 4 |
| `ffi/secretary-ffi-bridge/src/sync/mod.rs` + `status.rs` | `sync_status` + `SyncStatusDto` + `DeviceClockDto` | 4 |
| `ffi/secretary-ffi-bridge/src/sync/orchestration.rs` | `sync_vault` + `SyncOutcomeDto` + error mapping | 5 |
| `ffi/secretary-ffi-bridge/src/lib.rs` | register + re-export the `sync` module | 4, 5 |
| `core/tests/data/sync_pass_kat/cases.json` | clock-classification KAT fixture | 6 |
| `core/tests/sync_pass_kat.rs` | always-run Rust guard | 6 |
| `core/tests/python/conformance.py` | `section_sync_pass_kat` | 6 |
| `README.md`, `ROADMAP.md` | mark D.1.13 ✅; next → D.1.14 | 7 |

---

## Task 1: Feature-gate `secretary-cli`

**Files:**
- Modify: `cli/Cargo.toml`
- Modify: `cli/src/lib.rs`
- Modify: `cli/src/veto/mod.rs`

**Context:** `cli` pulls `clap` + `notify` + `tracing-subscriber` + `rpassword` + `serde_json` — daemon/CLI deps. The bridge (Task 4) needs only `pipeline` + `state` from the lib. A default `daemon` feature gates the heavy deps + the bin + the daemon/TTY-only modules, so the bridge depends on `secretary-cli` with `default-features = false` and the mobile bindings stay lean. `signal-hook` stays a non-optional unix-only dep (tiny; gating it through a feature is awkward because it lives in `[target.'cfg(unix)'.dependencies]`).

> **Feature-unification note for the implementer/reviewer:** in a `cargo build --workspace`, Cargo unifies `secretary-cli`'s features across the graph, so the cli bin (which needs `daemon`) forces `daemon` on for everyone in that build — the bridge then transitively sees `notify`/`clap`. That is expected and harmless: the *shipped* mobile artifacts are built **standalone** (e.g. `cargo build -p secretary-ffi-uniffi --target aarch64-apple-ios`), where the cli subtree has no bin/test forcing `daemon`, so it stays lean. The acceptance check therefore builds the binding crate **standalone**, not via `--workspace`.

- [ ] **Step 1: Add the `daemon` feature + make daemon-only deps optional**

In `cli/Cargo.toml`, change the five daemon-only deps to `optional = true` and add a `[features]` table. Replace the existing dependency lines for `clap`, `notify`, `tracing-subscriber`, `rpassword`, `serde_json`:

```toml
[features]
default = ["daemon"]
# The headless `secretary-sync` binary + its file-watch daemon loop, arg
# parsing, TTY veto/password prompts, and structured logging. Gated so the
# `secretary-ffi-bridge` consumer (and the mobile bindings beneath it) can
# depend on `secretary-cli` with `default-features = false` and reach only
# the lean `pipeline` + `state` lib surface, without compiling `notify`
# (inotify/FSEvents/kqueue) or `clap` into the iOS/Android artifacts.
daemon = ["dep:clap", "dep:notify", "dep:tracing-subscriber", "dep:rpassword", "dep:serde_json"]

[dependencies]
secretary-core = { path = "../core" }
clap = { version = "4", features = ["derive"], optional = true }
notify = { version = "6", optional = true }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "fmt", "json"], optional = true }
dirs = "5"
tempfile = "=3.27.0"
rpassword = { version = "7", optional = true }
serde_json = { version = "1", optional = true }
fs4 = "1"
thiserror = "2"
```

Add `required-features` to the existing `[[bin]]` so the binary is only built when `daemon` is on:

```toml
[[bin]]
name = "secretary-sync"
path = "src/main.rs"
required-features = ["daemon"]
```

(Leave `[lib]`, `[target.'cfg(unix)'.dependencies] signal-hook`, `[dev-dependencies]`, `[lints]`, and the `tempfile` exact-pin comment unchanged.)

- [ ] **Step 2: Gate the daemon-only modules in `lib.rs`**

In `cli/src/lib.rs`, add `#[cfg(feature = "daemon")]` to every module that uses a now-optional dep (`args`→clap, `daemon`/`watcher`→notify, `logging`→tracing-subscriber, `signal`→signal-hook + daemon-only, `unlock`→rpassword). Keep `exit`, `pipeline`, `state`, and `veto` ungated:

```rust
pub mod exit;
pub mod pipeline;
pub mod state;
pub mod veto;

#[cfg(feature = "daemon")]
pub mod args;
#[cfg(feature = "daemon")]
pub mod daemon;
#[cfg(feature = "daemon")]
pub mod logging;
#[cfg(feature = "daemon")]
pub mod signal;
#[cfg(feature = "daemon")]
pub mod unlock;
#[cfg(feature = "daemon")]
pub mod watcher;
```

- [ ] **Step 3: Gate the interactive veto UX**

In `cli/src/veto/mod.rs`, gate the interactive submodule (it reads a TTY) while leaving the trait + the non-interactive impl ungated. Find the `pub mod interactive;` line and gate it:

```rust
#[cfg(feature = "daemon")]
pub mod interactive;
```

(Leave `pub mod noninteractive;`, the `VetoUx` trait, and any `pub mod test_util;` lines as they are. If `test_util` is `#[cfg(test)]`-gated and references `interactive`, also add `feature = "daemon"` to its cfg — fix whatever the compiler flags in Step 5.)

- [ ] **Step 4: Verify default-feature build + tests still pass**

Run: `cargo build -p secretary_cli && cargo test -p secretary_cli 2>&1 | grep "test result:"`
Expected: build succeeds; every `test result:` line says `ok`. (Default features include `daemon`, so nothing changed for the existing bin/daemon/integration tests.)

- [ ] **Step 5: Verify the lean (no-default-features) lib build excludes notify + clap**

Run: `cargo build -p secretary_cli --no-default-features 2>&1 | tail -5`
Expected: build succeeds (lib only; the bin is skipped via `required-features`). Fix any "cannot find module/function" by confirming the ungated modules (`pipeline`, `state`, `veto::{mod,noninteractive}`, `exit`) do not reference gated ones.

Run: `cargo tree -p secretary_cli --no-default-features -e normal 2>/dev/null | grep -E "^.*(notify|clap)" || echo "LEAN: no notify/clap"`
Expected: `LEAN: no notify/clap`

- [ ] **Step 6: Commit**

```bash
git add cli/Cargo.toml cli/src/lib.rs cli/src/veto/mod.rs
git commit -m "D.1.13(cli): feature-gate daemon deps so the lean lib surface excludes notify/clap

Add a default \`daemon\` feature gating clap/notify/tracing-subscriber/
rpassword/serde_json + the secretary-sync bin + the daemon/TTY-only
modules, so secretary-ffi-bridge can depend on secretary-cli with
default-features=false and the mobile bindings stay lean.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: `sync_pass_pause_on_conflict` orchestration

**Files:**
- Modify: `cli/src/pipeline.rs`
- Create: `cli/tests/sync_pass_integration.rs`

**Context:** `run_one` (already in `pipeline.rs`) always commits via a `VetoUx`. We need a variant that auto-applies every safe arm and **aborts (commits nothing, advances no state)** the instant a tombstone veto appears. The truth table (from the spec):

| `sync_once` result | `diverging_blocks` | `draft.vetoes` | outcome | state advanced? | vault written? |
|---|---|---|---|---|---|
| `NothingToDo` | — | — | `NothingToDo` | no | no |
| `AppliedAutomatically` | — | — | `AppliedAutomatically` | yes | no |
| `RollbackRejected` | — | — | `RollbackRejected` | no | no |
| `ConcurrentDetected` | empty | — | `SilentMerge` | yes | no |
| `ConcurrentDetected` | non-empty | empty | `MergedClean` | yes | yes |
| `ConcurrentDetected` | non-empty | non-empty | `ConflictsPending{n}` | **no** | **no** |

It reuses the existing private `silent_merge_clock` helper for the `SilentMerge` arm and never touches the `veto` module.

- [ ] **Step 1: Write the failing unit tests for `SyncPassOutcome`**

Append to the `#[cfg(test)] mod tests` block in `cli/src/pipeline.rs` (mirroring the existing `RunOutcome` variant tests):

```rust
    #[test]
    fn sync_pass_outcome_variants_are_self_equal() {
        assert_eq!(SyncPassOutcome::NothingToDo, SyncPassOutcome::NothingToDo);
        assert_eq!(
            SyncPassOutcome::AppliedAutomatically,
            SyncPassOutcome::AppliedAutomatically
        );
        assert_eq!(SyncPassOutcome::SilentMerge, SyncPassOutcome::SilentMerge);
        assert_eq!(SyncPassOutcome::MergedClean, SyncPassOutcome::MergedClean);
        assert_eq!(
            SyncPassOutcome::RollbackRejected,
            SyncPassOutcome::RollbackRejected
        );
        assert_eq!(
            SyncPassOutcome::ConflictsPending { veto_count: 3 },
            SyncPassOutcome::ConflictsPending { veto_count: 3 }
        );
    }

    #[test]
    fn sync_pass_outcome_conflicts_pending_discriminates_on_count() {
        assert_ne!(
            SyncPassOutcome::ConflictsPending { veto_count: 1 },
            SyncPassOutcome::ConflictsPending { veto_count: 2 }
        );
    }

    #[test]
    fn sync_pass_outcome_debug_includes_variant_name() {
        assert!(format!("{:?}", SyncPassOutcome::SilentMerge).contains("SilentMerge"));
        let c = SyncPassOutcome::ConflictsPending { veto_count: 7 };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("ConflictsPending"));
        assert!(dbg.contains('7'));
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p secretary_cli --lib pipeline::tests::sync_pass 2>&1 | tail -15`
Expected: FAIL — `cannot find type SyncPassOutcome in this scope`.

- [ ] **Step 3: Add the `SyncPassOutcome` enum**

In `cli/src/pipeline.rs`, after the `RunOutcome` enum definition, add:

```rust
/// Outcome of one [`sync_pass_pause_on_conflict`] pass. Mirrors
/// [`RunOutcome`] for the safe arms, but replaces the always-commit
/// `MergedAndCommitted` with two outcomes: [`Self::MergedClean`] (a
/// concurrent state that merged with zero tombstone vetoes, committed)
/// and [`Self::ConflictsPending`] (a concurrent state whose merge raised
/// tombstone vetoes — **not** committed; the caller surfaces the count and
/// defers to interactive resolution).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncPassOutcome {
    /// Disk clock == local highest-seen. No state mutation, no write.
    NothingToDo,
    /// Disk strictly dominates local. `state` advanced; no vault write.
    AppliedAutomatically,
    /// Concurrent, `diverging_blocks` empty → silent-merge clock advance.
    /// `state` advanced; no vault write.
    SilentMerge,
    /// Concurrent, `diverging_blocks` non-empty, **zero** vetoes →
    /// `commit_with_decisions(.., [])` wrote the merged result. `state`
    /// advanced.
    MergedClean,
    /// Concurrent, `diverging_blocks` non-empty, **non-empty** vetoes →
    /// nothing committed, `state` NOT advanced. `veto_count` is the number
    /// of tombstone disputes awaiting a human decision.
    ConflictsPending { veto_count: usize },
    /// Disk clock strictly dominated by local (rollback). `state` unchanged.
    RollbackRejected,
}
```

- [ ] **Step 4: Run to verify the unit tests pass**

Run: `cargo test -p secretary_cli --lib pipeline::tests::sync_pass 2>&1 | tail -8`
Expected: PASS (3 tests).

- [ ] **Step 5: Add the `sync_pass_pause_on_conflict` function**

In `cli/src/pipeline.rs`, after `run_one`, add the function (it reuses the same `sync_once`/`prepare_merge`/`commit_with_decisions`/`silent_merge_clock` already imported/defined in the file):

```rust
/// Run one sync pass that auto-applies every safe arm and **pauses**
/// (commits nothing, advances no state) the instant a tombstone veto needs
/// human judgement. Unlike [`run_one`], it drives no [`crate::veto::VetoUx`]:
/// the `ConcurrentDetected` arm commits only when the prepared draft has an
/// empty veto set, and otherwise returns [`SyncPassOutcome::ConflictsPending`]
/// without writing.
///
/// State-mutation contract is identical to [`run_one`] on the shared arms
/// (`NothingToDo`/`RollbackRejected` leave `state` byte-identical;
/// `AppliedAutomatically`/`SilentMerge`/`MergedClean` advance it). On the
/// `ConflictsPending` arm `state` is byte-identical and the vault is
/// unwritten — the caller may re-run after the user resolves the conflict.
///
/// # Errors
///
/// Any [`SyncError`] from the underlying `sync_once` / `prepare_merge` /
/// `commit_with_decisions` bubbles up verbatim.
pub fn sync_pass_pause_on_conflict(
    vault_folder: &Path,
    identity: &UnlockedIdentity,
    password: &SecretBytes,
    state: &mut SyncState,
    now_ms: u64,
) -> Result<SyncPassOutcome, SyncError> {
    let outcome = sync_once(vault_folder, identity, state, now_ms)?;
    match outcome {
        SyncOutcome::NothingToDo => Ok(SyncPassOutcome::NothingToDo),
        SyncOutcome::AppliedAutomatically { new_state } => {
            *state = new_state;
            Ok(SyncPassOutcome::AppliedAutomatically)
        }
        SyncOutcome::RollbackRejected(_evidence) => Ok(SyncPassOutcome::RollbackRejected),
        SyncOutcome::ConcurrentDetected {
            bundle,
            plan,
            manifest_hash: _,
            disk_vector_clock,
            local_highest_seen: _,
        } => {
            if plan.diverging_blocks.is_empty() {
                let copy_clocks: Vec<&[VectorClockEntry]> = bundle
                    .copies
                    .iter()
                    .map(|c| c.manifest.vector_clock.as_slice())
                    .collect();
                state.highest_vector_clock_seen = silent_merge_clock(
                    &disk_vector_clock,
                    &copy_clocks,
                    &state.highest_vector_clock_seen,
                );
                return Ok(SyncPassOutcome::SilentMerge);
            }
            let draft = prepare_merge(vault_folder, identity, &bundle, &plan)?;
            if !draft.vetoes.is_empty() {
                // Pause: a tombstone dispute needs a human decision. Commit
                // nothing, advance nothing — the vault and `state` are
                // byte-identical to pre-call.
                return Ok(SyncPassOutcome::ConflictsPending {
                    veto_count: draft.vetoes.len(),
                });
            }
            // Zero vetoes: a pure field-level merge. Safe to auto-commit with
            // an empty decision set.
            let new_state = commit_with_decisions(vault_folder, password, draft, Vec::new(), now_ms)?;
            *state = new_state;
            Ok(SyncPassOutcome::MergedClean)
        }
    }
}
```

- [ ] **Step 6: Verify the crate still compiles + lints clean**

Run: `cargo clippy -p secretary_cli --tests -- -D warnings 2>&1 | tail -5`
Expected: no warnings. (If `commit_with_decisions` wants `decisions: Vec<VetoDecision>`, the empty `Vec::new()` type-infers; if it wants a slice, adjust to `&[]` — follow the compiler.)

- [ ] **Step 7: Write the failing safe-arm integration tests**

Create `cli/tests/sync_pass_integration.rs`. Mirror the harness in `cli/tests/pipeline_integration.rs` (reuse its `stage_and_unlock_golden` pattern — copy the `core_test_data_dir`/`copy_dir_recursive`/`golden_vault_password`/`stage_and_unlock_golden` helper block verbatim from that file, or factor a shared `mod` if you prefer; the existing file keeps them local, so duplicating is consistent with the established per-test-isolation pattern). Then:

```rust
//! End-to-end tests for `secretary_cli::pipeline::sync_pass_pause_on_conflict`
//! against a staged copy of `golden_vault_001`. Proves the safe arms match
//! `run_one` and that the pause arm writes nothing.

use secretary_cli::pipeline::{sync_pass_pause_on_conflict, SyncPassOutcome};
use secretary_core::sync::SyncState;
// ... (paste the helper block from pipeline_integration.rs: stage_and_unlock_golden, etc.)

/// A fresh (empty) SyncState against the populated golden vault → the disk
/// clock strictly dominates, so the pass fast-forwards. Mirrors
/// `run_one_returns_applied_automatically_on_fresh_state`.
#[test]
fn sync_pass_returns_applied_automatically_on_fresh_state() {
    let (_tmp, vault_dir, identity, password, vault_uuid) = stage_and_unlock_golden();
    let mut state = SyncState::empty(vault_uuid);
    let outcome = sync_pass_pause_on_conflict(&vault_dir, &identity, &password, &mut state, 0)
        .expect("sync pass must succeed on golden vault");
    assert_eq!(outcome, SyncPassOutcome::AppliedAutomatically);
    assert!(
        !state.highest_vector_clock_seen.is_empty(),
        "fast-forward must advance the local clock to the non-empty disk clock"
    );
}

/// A second pass with the now-current state → nothing to do, no mutation.
/// Mirrors `run_one_returns_nothing_to_do_on_second_call`.
#[test]
fn sync_pass_returns_nothing_to_do_on_second_call() {
    let (_tmp, vault_dir, identity, password, vault_uuid) = stage_and_unlock_golden();
    let mut state = SyncState::empty(vault_uuid);
    sync_pass_pause_on_conflict(&vault_dir, &identity, &password, &mut state, 0).expect("first");
    let before = state.clone();
    let outcome = sync_pass_pause_on_conflict(&vault_dir, &identity, &password, &mut state, 0)
        .expect("second pass");
    assert_eq!(outcome, SyncPassOutcome::NothingToDo);
    assert_eq!(state, before, "NothingToDo must leave state byte-identical");
}
```

- [ ] **Step 8: Run the safe-arm tests**

Run: `cargo test -p secretary_cli --test sync_pass_integration 2>&1 | grep "test result:"`
Expected: PASS (2 tests).

- [ ] **Step 9: Add the pause-path integration test**

Append a test that forces a tombstone veto and asserts **no write + no state advance**. Construct the concurrent-veto scenario by mirroring the conflict-copy setup in `core/tests/sync_merge_vetoes.rs` (read it for the exact helper calls — it stages a vault, applies a local tombstone/edit, and writes a conflict-copy manifest+block whose record diverges; reuse the same `write_conflict_copy`-style helper from `core/tests/sync_helpers/mod.rs` adapted to the cli test, OR drive `save_block` + a hand-written conflict copy as that file does). The assertions are the contract:

```rust
/// A concurrent state whose merge raises a tombstone veto must return
/// ConflictsPending WITHOUT committing: the on-disk block bytes and the
/// caller's SyncState are both byte-identical to pre-call.
#[test]
fn sync_pass_pauses_and_writes_nothing_on_tombstone_veto() {
    // Arrange: stage golden, advance local (tombstone a record + commit),
    // then write a conflict copy that edits that same record so prepare_merge
    // yields a non-empty veto set. (Mirror core/tests/sync_merge_vetoes.rs.)
    let (_tmp, vault_dir, identity, password, vault_uuid, conflicting_block_path) =
        stage_with_tombstone_veto_conflict_copy();
    let mut state = SyncState::empty(vault_uuid);
    // Bring local up to its own post-tombstone clock first (fast-forward),
    // so the next pass sees the conflict copy as genuinely concurrent.
    sync_pass_pause_on_conflict(&vault_dir, &identity, &password, &mut state, 0).expect("prime");

    let state_before = state.clone();
    let block_bytes_before = std::fs::read(&conflicting_block_path).expect("read block before");

    // Act
    let outcome = sync_pass_pause_on_conflict(&vault_dir, &identity, &password, &mut state, 0)
        .expect("pass must not error on a veto — it pauses");

    // Assert: paused, with the right count; nothing written.
    match outcome {
        SyncPassOutcome::ConflictsPending { veto_count } => assert!(veto_count >= 1),
        other => panic!("expected ConflictsPending, got {other:?}"),
    }
    assert_eq!(state, state_before, "pause must not advance state");
    let block_bytes_after = std::fs::read(&conflicting_block_path).expect("read block after");
    assert_eq!(
        block_bytes_before, block_bytes_after,
        "pause must not rewrite the conflicting block"
    );
}
```

> If transcribing the conflict-copy fixture proves large, factor `stage_with_tombstone_veto_conflict_copy()` by lifting the relevant helper from `core/tests/sync_merge_vetoes.rs` + `core/tests/sync_helpers/mod.rs`. Do **not** weaken the assertions — the "no write, no state advance" guarantee is the whole point of pause-on-conflict.

- [ ] **Step 10: Run the pause-path test + full cli suite**

Run: `cargo test -p secretary_cli 2>&1 | grep "test result:"`
Expected: every line `ok`.

- [ ] **Step 11: Commit**

```bash
git add cli/src/pipeline.rs cli/tests/sync_pass_integration.rs
git commit -m "D.1.13(cli): sync_pass_pause_on_conflict — auto-apply safe arms, pause on veto

A run_one sibling that commits every safe arm (nothing-to-do, fast-forward,
silent-merge, concurrent-with-zero-vetoes) but returns ConflictsPending{n}
WITHOUT writing the moment a tombstone veto needs a human decision. No VetoUx.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Thread the new `FfiVaultError` sync variants through every binding

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/error/vault/mod.rs`
- Modify: `ffi/secretary-ffi-uniffi/src/errors/vault.rs`
- Modify: `ffi/secretary-ffi-uniffi/src/secretary.udl`
- Modify: `ffi/secretary-ffi-py/src/errors.rs`
- Modify: `ffi/secretary-ffi-uniffi/tests/swift/ConformanceErrors.swift`
- Modify: `ffi/secretary-ffi-uniffi/tests/kotlin/ConformanceErrors.kt`

**Context:** Five new sync variants. The cargo-visible exhaustive matches (uniffi `From<FfiVaultError>`, pyo3 `ffi_vault_error_to_pyerr`) won't compile until updated, so they move **with** the enum in this single task. The Swift/Kotlin harnesses are compiled only by `run_conformance.sh`, so they're updated here and verified at Step 7. Per [[project_secretary_ffivaulterror_workspace_match]] this is the multi-site obligation cargo/clippy cannot fully see. The five variants:

| variant | shape | meaning |
|---|---|---|
| `SyncStateVaultMismatch` | fieldless | the `.state.cbor` belongs to a different vault |
| `SyncStateCorrupt { detail: String }` | detail | `SyncState` CBOR decode/encode failed |
| `SyncEvidenceStale` | fieldless | a concurrent writer changed the manifest mid-pass; retryable |
| `SyncInProgress` | fieldless | another process holds the per-vault sync lockfile |
| `SyncFailed { detail: String }` | detail | catch-all for internal/unreachable sync errors |

- [ ] **Step 1: Add the variants to the bridge `FfiVaultError` enum**

In `ffi/secretary-ffi-bridge/src/error/vault/mod.rs`, inside `pub enum FfiVaultError`, after the last existing variant (`CannotDeleteOwnerContact` region), add:

```rust
    /// The on-disk `SyncState` cache (`<state-dir>/<vault_uuid>.state.cbor`)
    /// is for a different vault than the one being synced.
    #[error("sync state file belongs to a different vault")]
    SyncStateVaultMismatch,

    /// The `SyncState` CBOR could not be decoded or re-encoded — the local
    /// sync cache is corrupt. The vault itself is untouched.
    #[error("sync state cache is corrupt: {detail}")]
    SyncStateCorrupt {
        /// Diagnostic text. Not secret (clock metadata only), but kept off
        /// the wire for consistency with the other `detail` variants.
        detail: String,
    },

    /// A concurrent writer changed the canonical manifest between the read
    /// and the commit of a sync pass. No write occurred; retry the pass.
    #[error("vault changed on disk during sync; retry")]
    SyncEvidenceStale,

    /// Another process (a `secretary-sync` daemon, or a second client) holds
    /// the per-vault sync lockfile. No write occurred.
    #[error("another sync is already in progress for this vault")]
    SyncInProgress,

    /// A sync pass failed for an internal/unexpected reason (argument or
    /// invariant violation, conflict-copy scan I/O, etc.). The vault is
    /// unchanged.
    #[error("sync failed: {detail}")]
    SyncFailed {
        detail: String,
    },
```

- [ ] **Step 2: Mirror the variants in the uniffi-side `VaultError` + `From`**

In `ffi/secretary-ffi-uniffi/src/errors/vault.rs`, add the same five variants to the uniffi `pub enum VaultError` (after `CannotDeleteOwnerContact`):

```rust
    #[error("sync state file belongs to a different vault")]
    SyncStateVaultMismatch,
    #[error("sync state cache is corrupt: {detail}")]
    SyncStateCorrupt { detail: String },
    #[error("vault changed on disk during sync; retry")]
    SyncEvidenceStale,
    #[error("another sync is already in progress for this vault")]
    SyncInProgress,
    #[error("sync failed: {detail}")]
    SyncFailed { detail: String },
```

Then in the `impl From<FfiVaultError> for VaultError` match, add the arms (after `CannotDeleteOwnerContact`):

```rust
            FfiVaultError::SyncStateVaultMismatch => VaultError::SyncStateVaultMismatch,
            FfiVaultError::SyncStateCorrupt { detail } => VaultError::SyncStateCorrupt { detail },
            FfiVaultError::SyncEvidenceStale => VaultError::SyncEvidenceStale,
            FfiVaultError::SyncInProgress => VaultError::SyncInProgress,
            FfiVaultError::SyncFailed { detail } => VaultError::SyncFailed { detail },
```

- [ ] **Step 3: Add the variants to the UDL `[Error] interface VaultError`**

In `ffi/secretary-ffi-uniffi/src/secretary.udl`, inside `[Error] interface VaultError { ... }`, after `CannotDeleteOwnerContact();`, add:

```
    SyncStateVaultMismatch();
    SyncStateCorrupt(string detail);
    SyncEvidenceStale();
    SyncInProgress();
    SyncFailed(string detail);
```

- [ ] **Step 4: Add pyo3 exception classes + match arms**

In `ffi/secretary-ffi-py/src/errors.rs`, after the existing `create_exception!` block (near `VaultCannotRevokeOwner`), add:

```rust
create_exception!(secretary_ffi_py, VaultSyncStateVaultMismatch, PyException);
create_exception!(secretary_ffi_py, VaultSyncStateCorrupt, PyException);
create_exception!(secretary_ffi_py, VaultSyncEvidenceStale, PyException);
create_exception!(secretary_ffi_py, VaultSyncInProgress, PyException);
create_exception!(secretary_ffi_py, VaultSyncFailed, PyException);
```

Then in the `ffi_vault_error_to_pyerr` match, after the `CannotDeleteOwnerContact` arm, add:

```rust
        FfiVaultError::SyncStateVaultMismatch => VaultSyncStateVaultMismatch::new_err(e.to_string()),
        FfiVaultError::SyncStateCorrupt { .. } => VaultSyncStateCorrupt::new_err(e.to_string()),
        FfiVaultError::SyncEvidenceStale => VaultSyncEvidenceStale::new_err(e.to_string()),
        FfiVaultError::SyncInProgress => VaultSyncInProgress::new_err(e.to_string()),
        FfiVaultError::SyncFailed { .. } => VaultSyncFailed::new_err(e.to_string()),
```

(If the module registers exception classes into the Python module elsewhere, e.g. an `add_class`/`add("VaultSyncFailed", ...)` block, add the five there too — follow the existing `VaultCannotRevokeOwner` registration site.)

- [ ] **Step 5: Build the cargo-visible bindings to confirm exhaustiveness**

Run: `cargo build -p secretary-ffi-bridge -p secretary-ffi-uniffi -p secretary-ffi-py 2>&1 | tail -8`
Expected: build succeeds. A "non-exhaustive patterns" error here means a match arm was missed in Step 2 or 4 — add it.

- [ ] **Step 6: Add the Swift + Kotlin conformance arms**

In `ffi/secretary-ffi-uniffi/tests/swift/ConformanceErrors.swift`, in `vaultErrorName`, after the `case .CannotDeleteOwnerContact:` line, add:

```swift
    case .SyncStateVaultMismatch: return "SyncStateVaultMismatch"
    case .SyncStateCorrupt: return "SyncStateCorrupt"
    case .SyncEvidenceStale: return "SyncEvidenceStale"
    case .SyncInProgress: return "SyncInProgress"
    case .SyncFailed: return "SyncFailed"
```

And in `vaultErrorDetail`, add the two detail-bearing variants before `default: return nil`:

```swift
    case .SyncStateCorrupt(let d): return d
    case .SyncFailed(let d): return d
```

In `ffi/secretary-ffi-uniffi/tests/kotlin/ConformanceErrors.kt`, in `vaultExceptionVariantName`, after the `is VaultException.CannotDeleteOwnerContact ->` arm, add:

```kotlin
    is VaultException.SyncStateVaultMismatch -> "SyncStateVaultMismatch"
    is VaultException.SyncStateCorrupt -> "SyncStateCorrupt"
    is VaultException.SyncEvidenceStale -> "SyncEvidenceStale"
    is VaultException.SyncInProgress -> "SyncInProgress"
    is VaultException.SyncFailed -> "SyncFailed"
```

And in `vaultExceptionDetail`, add `SyncStateCorrupt`/`SyncFailed` to the detail-returning arms and the rest to the `-> null` group, mirroring the existing `RecipientNotPresent`/`InvalidMnemonic` split:

```kotlin
    is VaultException.SyncStateCorrupt -> e.detail
    is VaultException.SyncFailed -> e.detail
    is VaultException.SyncStateVaultMismatch,
    is VaultException.SyncEvidenceStale,
    is VaultException.SyncInProgress -> null
```

- [ ] **Step 7: Run the Swift + Kotlin conformance harnesses**

Run: `bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh 2>&1 | tail -5`
Run: `bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh 2>&1 | tail -5`
Expected: both report PASS / exit 0. A non-exhaustive `switch`/`when` compile error here means an arm was missed in Step 6.

- [ ] **Step 8: Commit**

```bash
git add ffi/secretary-ffi-bridge/src/error/vault/mod.rs \
        ffi/secretary-ffi-uniffi/src/errors/vault.rs \
        ffi/secretary-ffi-uniffi/src/secretary.udl \
        ffi/secretary-ffi-py/src/errors.rs \
        ffi/secretary-ffi-uniffi/tests/swift/ConformanceErrors.swift \
        ffi/secretary-ffi-uniffi/tests/kotlin/ConformanceErrors.kt
git commit -m "D.1.13(ffi): thread 5 FfiVaultError sync variants through every binding

SyncStateVaultMismatch / SyncStateCorrupt / SyncEvidenceStale /
SyncInProgress / SyncFailed — across the bridge enum, uniffi VaultError +
UDL, pyo3 exceptions, and the Swift/Kotlin conformance harnesses (the
exhaustive-match sites cargo can't all see). Functions stay bridge-only.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Bridge `sync_status` (read path, no secrets)

**Files:**
- Modify: `ffi/secretary-ffi-bridge/Cargo.toml`
- Create: `ffi/secretary-ffi-bridge/src/sync/mod.rs`
- Create: `ffi/secretary-ffi-bridge/src/sync/status.rs`
- Modify: `ffi/secretary-ffi-bridge/src/lib.rs`

**Context:** `sync_status` loads the per-vault `SyncState` CBOR + the state-file mtime via `cli::state`. No identity, no password. DTOs are plain Rust bridge types (not UDL records — the functions are bridge-only).

- [ ] **Step 1: Add the `secretary-cli` dependency (lean)**

In `ffi/secretary-ffi-bridge/Cargo.toml`, under `[dependencies]` after `secretary-core`, add:

```toml
# `secretary-cli` provides the sync orchestration (pipeline::sync_pass_*) and
# the single-source SyncState CBOR + lockfile persistence (state::*). Pulled
# with default-features=false so the daemon deps (notify/clap) are NOT compiled
# into this bridge or the mobile bindings beneath it. See the cli `daemon`
# feature (cli/Cargo.toml) + the D.1.13 spec §"Code layering".
secretary-cli = { path = "../../cli", default-features = false }
```

- [ ] **Step 2: Write the failing `sync_status` tests**

Create `ffi/secretary-ffi-bridge/src/sync/status.rs` with the test module first (TDD). The read path needs no vault unlock — `cli::state::save` lets us seed a state file under a `TempDir`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use secretary_cli::state::save;
    use secretary_core::sync::SyncState;
    use tempfile::TempDir;

    #[test]
    fn status_in_reports_no_state_when_file_absent() {
        let dir = TempDir::new().unwrap();
        let status = sync_status_in(dir.path(), [9u8; 16]).expect("status");
        assert!(!status.has_state);
        assert!(status.device_clocks.is_empty());
        assert!(status.last_state_write_ms.is_none());
    }

    #[test]
    fn status_in_reports_state_after_save() {
        let dir = TempDir::new().unwrap();
        let mut state = SyncState::empty([7u8; 16]);
        state
            .highest_vector_clock_seen
            .push(secretary_core::vault::block::VectorClockEntry {
                device_uuid: [0xAB; 16],
                counter: 5,
            });
        save(dir.path(), &state).unwrap();
        let status = sync_status_in(dir.path(), [7u8; 16]).expect("status");
        assert!(status.has_state);
        assert_eq!(status.device_clocks.len(), 1);
        assert_eq!(status.device_clocks[0].counter, 5);
        assert_eq!(
            status.device_clocks[0].device_uuid_hex,
            "abababababababababababababababab"
        );
        assert!(status.last_state_write_ms.is_some());
    }

    #[test]
    fn status_in_surfaces_vault_mismatch() {
        let dir = TempDir::new().unwrap();
        let state = SyncState::empty([7u8; 16]);
        save(dir.path(), &state).unwrap();
        // Load it under the wrong expected uuid → mismatch.
        let from = secretary_cli::state::state_file_path(dir.path(), [7u8; 16]);
        let to = secretary_cli::state::state_file_path(dir.path(), [9u8; 16]);
        std::fs::rename(from, to).unwrap();
        let err = sync_status_in(dir.path(), [9u8; 16]).unwrap_err();
        assert!(matches!(err, FfiVaultError::SyncStateVaultMismatch));
    }
}
```

- [ ] **Step 3: Run to verify failure**

Run: `cargo test -p secretary-ffi-bridge sync::status 2>&1 | tail -10`
Expected: FAIL — `cannot find function sync_status_in` / `SyncStatusDto`.

- [ ] **Step 4: Implement `sync_status` + DTOs**

At the top of `ffi/secretary-ffi-bridge/src/sync/status.rs`, add the implementation:

```rust
//! `sync_status` — read-only projection of the per-vault `SyncState` cache.
//! No secrets: loads `<state-dir>/<vault_uuid>.state.cbor` + its mtime.

use std::path::Path;
use std::time::UNIX_EPOCH;

use secretary_cli::state::{default_state_dir, load, state_file_path, StateError};

use crate::error::FfiVaultError;

/// One device's vector-clock entry — public metadata, never secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceClockDto {
    pub device_uuid_hex: String,
    pub counter: u64,
}

/// Read-only sync status for a vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncStatusDto {
    /// False ⇒ no `.state.cbor` exists yet (this vault has never synced here).
    pub has_state: bool,
    /// Per-device highest-seen vector clock.
    pub device_clocks: Vec<DeviceClockDto>,
    /// Unix-ms mtime of the state file, or None when `has_state` is false.
    pub last_state_write_ms: Option<u64>,
}

/// Load the sync status for `vault_uuid` from the default OS state dir.
///
/// # Errors
/// - [`FfiVaultError::SyncStateVaultMismatch`] — the state file is for a
///   different vault.
/// - [`FfiVaultError::SyncStateCorrupt`] — the CBOR failed to decode.
/// - [`FfiVaultError::SyncFailed`] — no platform state dir, or an I/O error.
pub fn sync_status(vault_uuid: [u8; 16]) -> Result<SyncStatusDto, FfiVaultError> {
    let state_dir = default_state_dir().ok_or_else(|| FfiVaultError::SyncFailed {
        detail: "no platform data directory available for the sync state cache".into(),
    })?;
    sync_status_in(&state_dir, vault_uuid)
}

/// Test/seam variant taking an explicit state dir (mirrors
/// `settings::load_or_create_device_uuid_in`). Not part of the public surface.
pub(crate) fn sync_status_in(
    state_dir: &Path,
    vault_uuid: [u8; 16],
) -> Result<SyncStatusDto, FfiVaultError> {
    let path = state_file_path(state_dir, vault_uuid);
    let has_state = path.exists();
    let state = load(state_dir, vault_uuid).map_err(map_state_error)?;
    let last_state_write_ms = if has_state {
        std::fs::metadata(&path)
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as u64)
    } else {
        None
    };
    let device_clocks = state
        .highest_vector_clock_seen
        .iter()
        .map(|e| DeviceClockDto {
            device_uuid_hex: secretary_cli::state::canonical_hex(e.device_uuid),
            counter: e.counter,
        })
        .collect();
    Ok(SyncStatusDto {
        has_state,
        device_clocks,
        last_state_write_ms,
    })
}

/// Map `cli::state::StateError` → `FfiVaultError`. Shared with `sync_vault`.
pub(crate) fn map_state_error(e: StateError) -> FfiVaultError {
    match e {
        StateError::VaultUuidMismatch { .. } => FfiVaultError::SyncStateVaultMismatch,
        StateError::Decode(_) | StateError::Encode(_) => FfiVaultError::SyncStateCorrupt {
            detail: e.to_string(),
        },
        StateError::LockfileHeld(_) => FfiVaultError::SyncInProgress,
        StateError::Io(_) => FfiVaultError::SyncFailed {
            detail: e.to_string(),
        },
    }
}
```

Create `ffi/secretary-ffi-bridge/src/sync/mod.rs`:

```rust
//! Bridge-thick sync surface (D.1.13). Read-only `sync_status` here;
//! the `sync_vault` mutation lands in `orchestration` (D.1.13 Task 5).
//! Functions are bridge-only — the desktop consumes them as a Rust crate;
//! uniffi/pyo3 projection is deferred (#167-sibling).

pub mod status;

pub use status::{sync_status, DeviceClockDto, SyncStatusDto};
```

- [ ] **Step 5: Register the module in `lib.rs`**

In `ffi/secretary-ffi-bridge/src/lib.rs`, add `pub mod sync;` next to the other `pub mod` declarations (alphabetical neighbourhood near `pub mod share;`), and add a re-export line near the other `pub use`:

```rust
pub mod sync;
```
```rust
pub use sync::{sync_status, DeviceClockDto, SyncStatusDto};
```

- [ ] **Step 6: Run the `sync_status` tests + lint**

Run: `cargo test -p secretary-ffi-bridge sync:: 2>&1 | grep "test result:"`
Expected: PASS (3 tests).
Run: `cargo clippy -p secretary-ffi-bridge --tests -- -D warnings 2>&1 | tail -5`
Expected: clean. (Cast `as u64` may warn under pedantic; the workspace lint set allows the plain `as` here as elsewhere — match the existing style. If `clippy::cast_possible_truncation` fires, the existing codebase pattern is the call site that already does ms casts; mirror it.)

- [ ] **Step 7: Verify the mobile binding stays lean (standalone build)**

Run: `cargo tree -p secretary-ffi-uniffi --no-default-features -e normal 2>/dev/null | grep -E "(notify|clap)" || echo "LEAN: uniffi binding excludes notify/clap"`
Expected: `LEAN: uniffi binding excludes notify/clap`. (Confirms the `default-features=false` cli dep didn't drag the daemon deps into the binding when built standalone.)

- [ ] **Step 8: Commit**

```bash
git add ffi/secretary-ffi-bridge/Cargo.toml ffi/secretary-ffi-bridge/src/sync/ ffi/secretary-ffi-bridge/src/lib.rs
git commit -m "D.1.13(bridge): sync_status read primitive + lean secretary-cli dep

Read-only projection of the per-vault SyncState CBOR + state-file mtime; no
secrets. Pulls secretary-cli with default-features=false so notify/clap stay
out of the mobile bindings. DTOs are bridge-only Rust types.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Bridge `sync_vault` (the pause-on-conflict mutation)

**Files:**
- Create: `ffi/secretary-ffi-bridge/src/sync/orchestration.rs`
- Modify: `ffi/secretary-ffi-bridge/src/sync/mod.rs`
- Modify: `ffi/secretary-ffi-bridge/src/lib.rs`

**Context:** `sync_vault` opens a fresh core identity from the re-prompted password, acquires the per-vault lockfile, loads the `SyncState`, runs `sync_pass_pause_on_conflict`, persists state on the advancing arms, and maps `SyncError`/`StateError` → `FfiVaultError`. It returns a `SyncOutcomeDto`. Look at `ffi/secretary-ffi-bridge/src/revoke/orchestration.rs` for the identity-open/zeroize discipline and the snapshot pattern; `sync_vault` is simpler because the cli pass owns the disk I/O — the bridge only opens the identity, holds the lock, and persists state.

- [ ] **Step 1: Write the failing `sync_vault` outcome test (fast-forward)**

Append a test module to `ffi/secretary-ffi-bridge/src/sync/orchestration.rs`. Reuse the bridge's existing golden-vault test helper (grep the bridge tests for how `share`/`revoke` orchestration tests stage a golden vault + open an identity from the password — e.g. a `stage_golden_and_open` helper in the bridge test support; mirror it). The first test drives the fast-forward arm against a fresh state dir:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    // (mirror the bridge's existing golden-vault staging helper used by
    //  revoke/share orchestration tests: stage a writable golden copy + the
    //  golden password bytes.)

    #[test]
    fn sync_vault_in_fast_forwards_fresh_state() {
        let (_vault_tmp, vault_folder, password) = stage_golden_vault_and_password();
        let state_dir = TempDir::new().unwrap();
        let outcome = sync_vault_in(state_dir.path(), &vault_folder, password)
            .expect("sync_vault must succeed on a fresh golden vault");
        assert_eq!(outcome, SyncOutcomeDto::AppliedAutomatically);
        // The state file now exists (state advanced + persisted).
        let status = crate::sync::status::sync_status_in(state_dir.path(), golden_vault_uuid())
            .expect("status after sync");
        assert!(status.has_state);
        assert!(!status.device_clocks.is_empty());
    }

    #[test]
    fn sync_vault_in_reports_in_progress_when_lock_held() {
        let (_vault_tmp, vault_folder, password) = stage_golden_vault_and_password();
        let state_dir = TempDir::new().unwrap();
        // Hold the lockfile, then a concurrent sync must report SyncInProgress.
        let _guard = secretary_cli::state::LockfileGuard::acquire(
            state_dir.path(),
            golden_vault_uuid(),
        )
        .expect("acquire lock");
        let err = sync_vault_in(state_dir.path(), &vault_folder, password).unwrap_err();
        assert!(matches!(err, FfiVaultError::SyncInProgress));
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p secretary-ffi-bridge sync::orchestration 2>&1 | tail -10`
Expected: FAIL — `cannot find function sync_vault_in` / `SyncOutcomeDto`.

- [ ] **Step 3: Implement `SyncOutcomeDto`, `sync_vault`, and the mapping**

Write the implementation at the top of `ffi/secretary-ffi-bridge/src/sync/orchestration.rs`:

```rust
//! `sync_vault` — one manual, pause-on-conflict sync pass. Opens a core
//! identity from the re-prompted password, holds the per-vault lockfile,
//! runs `secretary_cli::pipeline::sync_pass_pause_on_conflict`, persists
//! `SyncState` on the advancing arms, and maps errors. The cli pass owns all
//! vault disk I/O; the bridge owns identity lifetime + state persistence.

use std::path::Path;

use secretary_cli::pipeline::{sync_pass_pause_on_conflict, SyncPassOutcome};
use secretary_cli::state::{default_state_dir, load, save, LockfileGuard};
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::sync::SyncError;

use crate::error::FfiVaultError;
use crate::sync::status::map_state_error;

/// Result of one [`sync_vault`] pass. Mirrors
/// [`secretary_cli::pipeline::SyncPassOutcome`] as a bridge-owned DTO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncOutcomeDto {
    NothingToDo,
    AppliedAutomatically,
    SilentMerge,
    MergedClean,
    ConflictsPending { veto_count: u32 },
    RollbackRejected,
}

impl From<SyncPassOutcome> for SyncOutcomeDto {
    fn from(o: SyncPassOutcome) -> Self {
        match o {
            SyncPassOutcome::NothingToDo => SyncOutcomeDto::NothingToDo,
            SyncPassOutcome::AppliedAutomatically => SyncOutcomeDto::AppliedAutomatically,
            SyncPassOutcome::SilentMerge => SyncOutcomeDto::SilentMerge,
            SyncPassOutcome::MergedClean => SyncOutcomeDto::MergedClean,
            SyncPassOutcome::ConflictsPending { veto_count } => SyncOutcomeDto::ConflictsPending {
                veto_count: veto_count as u32,
            },
            SyncPassOutcome::RollbackRejected => SyncOutcomeDto::RollbackRejected,
        }
    }
}

/// Run one manual sync pass against `vault_folder`, unlocking with `password`.
///
/// On the advancing arms (`AppliedAutomatically`/`SilentMerge`/`MergedClean`)
/// the new `SyncState` is persisted before returning. On `ConflictsPending`
/// (and `NothingToDo`/`RollbackRejected`) nothing is written.
///
/// # Errors
/// - [`FfiVaultError::SyncInProgress`] — the per-vault lockfile is held.
/// - [`FfiVaultError::WrongPasswordOrCorrupt`] — `password` failed to unlock.
/// - [`FfiVaultError::SyncStateVaultMismatch`] / [`FfiVaultError::SyncStateCorrupt`]
///   — the local sync cache is for another vault / is corrupt.
/// - [`FfiVaultError::SyncEvidenceStale`] — a concurrent writer changed the
///   manifest mid-pass; retry.
/// - [`FfiVaultError::SyncFailed`] — any other sync error; vault unchanged.
pub fn sync_vault(
    vault_folder: &Path,
    password: SecretBytes,
) -> Result<SyncOutcomeDto, FfiVaultError> {
    let state_dir = default_state_dir().ok_or_else(|| FfiVaultError::SyncFailed {
        detail: "no platform data directory available for the sync state cache".into(),
    })?;
    sync_vault_in(&state_dir, vault_folder, password)
}

/// Test/seam variant taking an explicit state dir.
pub(crate) fn sync_vault_in(
    state_dir: &Path,
    vault_folder: &Path,
    password: SecretBytes,
) -> Result<SyncOutcomeDto, FfiVaultError> {
    // Open a fresh core identity from the password. Reuse the bridge's
    // existing password→UnlockedIdentity path so zeroize discipline is
    // unchanged; the identity drops (zeroizes) at function end.
    let (identity, vault_uuid) = open_core_identity_for_sync(vault_folder, &password)?;

    // Hold the per-vault lock for the whole pass so we never race a daemon
    // or a second client. Released on drop at function end.
    let _lock = LockfileGuard::acquire(state_dir, vault_uuid).map_err(map_state_error)?;

    let mut state = load(state_dir, vault_uuid).map_err(map_state_error)?;
    let password_bytes = SecretBytes::from(password); // pass-through; see note
    let outcome = sync_pass_pause_on_conflict(vault_folder, &identity, &password_bytes, &mut state, 0)
        .map_err(map_sync_error)?;

    // Persist only on the advancing arms.
    match outcome {
        SyncPassOutcome::AppliedAutomatically
        | SyncPassOutcome::SilentMerge
        | SyncPassOutcome::MergedClean => {
            save(state_dir, &state).map_err(map_state_error)?;
        }
        SyncPassOutcome::NothingToDo
        | SyncPassOutcome::RollbackRejected
        | SyncPassOutcome::ConflictsPending { .. } => {}
    }
    Ok(outcome.into())
}

/// Map `secretary_core::sync::SyncError` → `FfiVaultError`.
fn map_sync_error(e: SyncError) -> FfiVaultError {
    match e {
        SyncError::VaultUuidMismatch { .. } => FfiVaultError::SyncStateVaultMismatch,
        SyncError::StateDecodeFailed { .. } | SyncError::StateEncodeFailed { .. } => {
            FfiVaultError::SyncStateCorrupt {
                detail: e.to_string(),
            }
        }
        SyncError::EvidenceStale => FfiVaultError::SyncEvidenceStale,
        SyncError::Vault(ve) => ve.into(), // reuse the existing VaultError → FfiVaultError
        // InvalidArgument, ConflictCopyScanIoFailed, Unknown/MissingVetoDecision,
        // and the draft-records invariant are all internal/unreachable for the
        // pause-on-conflict pass (it supplies no decisions). Surface as the
        // catch-all rather than a typed variant.
        other => FfiVaultError::SyncFailed {
            detail: other.to_string(),
        },
    }
}
```

> **Two implementer notes (resolve with the compiler + the bridge's existing code):**
> 1. `open_core_identity_for_sync` — the bridge already has a password→identity path (`open_vault_with_password` returns an `UnlockedIdentity` bridge handle + manifest). `sync_pass_pause_on_conflict` needs a `&core::UnlockedIdentity`. Reuse `secretary_core::unlock::open_with_password` directly here (the bridge depends on core) to get an owned `core::UnlockedIdentity` + read the vault's `vault_uuid` from the manifest, mapping unlock failure → `FfiVaultError::WrongPasswordOrCorrupt` (mirror `unlock.rs`'s mapping). Drop the identity at function end (it's `ZeroizeOnDrop`).
> 2. The `SecretBytes::from(password)` line is a placeholder for "pass the same password bytes into the pass" — if `open_with_password` consumes `password`, clone the `SecretBytes` once up front (it's zeroize-typed) so both the unlock and the commit-side re-open get it, then let both drop. Do **not** retain it beyond the function.

- [ ] **Step 4: Update `sync/mod.rs` + `lib.rs` re-exports**

In `ffi/secretary-ffi-bridge/src/sync/mod.rs`:

```rust
pub mod orchestration;
pub mod status;

pub use orchestration::{sync_vault, SyncOutcomeDto};
pub use status::{sync_status, DeviceClockDto, SyncStatusDto};
```

In `ffi/secretary-ffi-bridge/src/lib.rs`, extend the sync re-export:

```rust
pub use sync::{sync_status, sync_vault, DeviceClockDto, SyncOutcomeDto, SyncStatusDto};
```

- [ ] **Step 5: Run the `sync_vault` tests + lint**

Run: `cargo test -p secretary-ffi-bridge sync:: 2>&1 | grep "test result:"`
Expected: PASS (fast-forward + lock-held + the 3 status tests).
Run: `cargo clippy -p secretary-ffi-bridge --tests -- -D warnings 2>&1 | tail -5`
Expected: clean.

- [ ] **Step 6: Add a pause-path bridge test (optional but recommended)**

If the bridge test support can stage a concurrent-veto golden copy (reuse the cli pause fixture from Task 2 Step 9, or a bridge equivalent), add:

```rust
    #[test]
    fn sync_vault_in_pauses_and_persists_nothing_on_conflict() {
        let (_vault_tmp, vault_folder, password, conflicting_block) =
            stage_golden_with_tombstone_veto_conflict_copy();
        let state_dir = TempDir::new().unwrap();
        // Prime local to its own clock first.
        sync_vault_in(state_dir.path(), &vault_folder, password.clone()).expect("prime");
        let block_before = std::fs::read(&conflicting_block).unwrap();
        let outcome = sync_vault_in(state_dir.path(), &vault_folder, password).expect("pass");
        assert!(matches!(outcome, SyncOutcomeDto::ConflictsPending { .. }));
        assert_eq!(std::fs::read(&conflicting_block).unwrap(), block_before);
    }
```

Run: `cargo test -p secretary-ffi-bridge sync:: 2>&1 | grep "test result:"` → PASS.

- [ ] **Step 7: Commit**

```bash
git add ffi/secretary-ffi-bridge/src/sync/ ffi/secretary-ffi-bridge/src/lib.rs
git commit -m "D.1.13(bridge): sync_vault pause-on-conflict mutation primitive

Opens a core identity from the re-prompted password, holds the per-vault
lockfile, runs cli::sync_pass_pause_on_conflict, persists SyncState on the
advancing arms only, and maps SyncError/StateError -> FfiVaultError. Returns
a bridge-owned SyncOutcomeDto. ConflictsPending writes nothing.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Cross-language `sync_pass` classification KAT

**Files:**
- Create: `core/tests/data/sync_pass_kat/cases.json`
- Create: `core/tests/sync_pass_kat.rs`
- Modify: `core/tests/python/conformance.py`

**Context:** A scoped clean-room KAT proving the pause-on-conflict **outcome classification + post-merge clock** cross-language, without a full crypto replay (the merge math is already covered by the 11 `conflict_kat` vectors). Each case is a pure clock scenario → expected outcome label + post-merge clock. The Rust guard pins the classification against the cli logic; the Python replay recomputes the LUB with stdlib only. Mirror the structure of `core/tests/revoke_kat.rs` + `conformance.py::section_revoke_kat`.

- [ ] **Step 1: Author the KAT fixture**

Create `core/tests/data/sync_pass_kat/cases.json`. Each case encodes a clock relation + flags, with the expected outcome label and (for merge arms) the expected post-merge clock as a list of `[device_uuid_hex, counter]`:

```json
{
  "schema": "sync_pass_kat/v1",
  "comment": "Pure clock-classification vectors for sync_pass_pause_on_conflict. No crypto; the merge math is covered by conflict_kat. Outcome labels: NothingToDo, AppliedAutomatically, SilentMerge, MergedClean, ConflictsPending, RollbackRejected.",
  "cases": [
    {
      "name": "equal_clocks_nothing_to_do",
      "disk_clock": [["aa", 5]],
      "local_seen": [["aa", 5]],
      "copy_clocks": [],
      "diverging_blocks": 0,
      "veto_count": 0,
      "expected_outcome": "NothingToDo",
      "expected_post_clock": [["aa", 5]]
    },
    {
      "name": "disk_dominates_fast_forward",
      "disk_clock": [["aa", 7]],
      "local_seen": [["aa", 5]],
      "copy_clocks": [],
      "diverging_blocks": 0,
      "veto_count": 0,
      "expected_outcome": "AppliedAutomatically",
      "expected_post_clock": [["aa", 7]]
    },
    {
      "name": "concurrent_no_diverging_silent_merge_folds_copy",
      "disk_clock": [["aa", 5]],
      "local_seen": [["bb", 2]],
      "copy_clocks": [[["aa", 7], ["cc", 2]]],
      "diverging_blocks": 0,
      "veto_count": 0,
      "expected_outcome": "SilentMerge",
      "expected_post_clock": [["aa", 7], ["bb", 2], ["cc", 2]]
    },
    {
      "name": "concurrent_diverging_zero_vetoes_merged_clean",
      "disk_clock": [["aa", 5], ["bb", 1]],
      "local_seen": [["bb", 3]],
      "copy_clocks": [],
      "diverging_blocks": 1,
      "veto_count": 0,
      "expected_outcome": "MergedClean",
      "expected_post_clock": [["aa", 5], ["bb", 3]]
    },
    {
      "name": "concurrent_diverging_with_vetoes_pauses",
      "disk_clock": [["aa", 5]],
      "local_seen": [["bb", 3]],
      "copy_clocks": [],
      "diverging_blocks": 1,
      "veto_count": 2,
      "expected_outcome": "ConflictsPending",
      "expected_post_clock": null
    },
    {
      "name": "disk_dominated_rollback_rejected",
      "disk_clock": [["aa", 3]],
      "local_seen": [["aa", 5]],
      "copy_clocks": [],
      "diverging_blocks": 0,
      "veto_count": 0,
      "expected_outcome": "RollbackRejected",
      "expected_post_clock": null
    }
  ]
}
```

- [ ] **Step 2: Write the always-run Rust guard (failing first)**

Create `core/tests/sync_pass_kat.rs`. It replays the **classification + post-clock** using the same public clock primitives the cli pass uses (`clock_relation` for the arm, `merge_vector_clocks` for the LUB). Pin each case:

```rust
//! Always-run clean-room guard for the sync_pass classification KAT.
//! Pure clock logic — no crypto. Mirrors `revoke_kat.rs`'s always-run
//! structure. The Python equivalent is `conformance.py::section_sync_pass_kat`.

use std::path::{Path, PathBuf};

use secretary_core::vault::block::VectorClockEntry;
use secretary_core::vault::merge_vector_clocks;

fn kat_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("sync_pass_kat")
}

fn vc(hex: &str, counter: u64) -> VectorClockEntry {
    let mut device_uuid = [0u8; 16];
    let b = hex.as_bytes();
    // single-byte fill convention used in the fixture ("aa" -> 0xAA fill).
    let fill = u8::from_str_radix(hex, 16).expect("hex byte");
    device_uuid.fill(fill);
    let _ = b;
    VectorClockEntry { device_uuid, counter }
}

#[test]
fn sync_pass_kat_classification_matches_fixture() {
    let raw = std::fs::read_to_string(kat_dir().join("cases.json")).expect("read cases.json");
    // Use core's already-available JSON helper, or serde_json if a dev-dep.
    // Assert, per case, that:
    //  - the computed outcome label equals expected_outcome, derived from
    //    clock_relation(disk, local) + diverging_blocks + veto_count via the
    //    same truth table sync_pass_pause_on_conflict uses;
    //  - for SilentMerge/MergedClean/AppliedAutomatically/NothingToDo the LUB
    //    (merge_vector_clocks folded over disk + copies + local) equals
    //    expected_post_clock.
    // (Full assertion code: load each case, build VectorClockEntry vecs via
    //  `vc`, compute, compare. Keep it stdlib-or-serde_json only.)
    let _ = (raw, merge_vector_clocks as fn(&[VectorClockEntry], &[VectorClockEntry]) -> Vec<VectorClockEntry>);
    // ... per-case asserts ...
}
```

> Fill in the per-case assertion loop completely. Confirmed APIs: `secretary_core::sync::clock_relation(a, b)` returns the `ClockRelation` enum the ingest layer uses (read `core/src/sync/ingest.rs` for the exact variant names — `Equal`/`Dominates`/`Dominated`/`Concurrent` or similar); `serde_json` IS a `core` dev-dep (`core/Cargo.toml` line ~73, `preserve_order`); `merge_vector_clocks` is re-exported at `secretary_core::vault`. The classification truth table is the one in Task 2.

- [ ] **Step 3: Run the Rust guard**

Run: `cargo test --release -p secretary-core --test sync_pass_kat 2>&1 | grep "test result:"`
Expected: PASS once the loop is filled in.

- [ ] **Step 4: Add the Python conformance section**

In `core/tests/python/conformance.py`, mirror `section_revoke_kat`. Add a `sync_pass_kat_dir()` helper and a `section_sync_pass_kat()` that loads `cases.json` via the existing `load_json_fixture`, recomputes the outcome label + LUB with a stdlib-only vector-clock merge, and compares to the expected fields. Register it in the same place the other `section_*` functions are dispatched (grep for `section_revoke_kat(` to find the runner list) so it runs in the default `uv run core/tests/python/conformance.py`.

```python
def sync_pass_kat_dir() -> Path:
    here = Path(__file__).resolve().parent
    return here.parent / "data" / "sync_pass_kat"


def _lub(clocks: list[list]) -> dict:
    """Element-wise max LUB over a list of [hex, counter] clock lists."""
    out: dict[str, int] = {}
    for clock in clocks:
        for dev_hex, counter in clock:
            out[dev_hex] = max(out.get(dev_hex, 0), counter)
    return out


def section_sync_pass_kat() -> tuple[bool, list[str]]:
    """Clean-room classification of sync_pass_pause_on_conflict outcomes."""
    lines: list[str] = []
    ok = True
    data = load_json_fixture(sync_pass_kat_dir() / "cases.json", "sync_pass_kat/cases.json")
    for case in data["cases"]:
        # Derive the outcome label from the clock relation + diverging + vetoes
        # using the Task-2 truth table; compare to case["expected_outcome"].
        # For the merge arms, compare _lub(disk + copies + local) to
        # case["expected_post_clock"]. Append a PASS/FAIL line per case.
        ...
    return ok, lines
```

> Fill the loop in completely (the clock-relation derivation is: equal → NothingToDo; disk dominates → AppliedAutomatically; local dominates → RollbackRejected; concurrent + diverging==0 → SilentMerge; concurrent + diverging>0 + veto==0 → MergedClean; concurrent + diverging>0 + veto>0 → ConflictsPending). Keep it stdlib-only.

- [ ] **Step 5: Run conformance.py**

Run: `uv run core/tests/python/conformance.py 2>&1 | tail -15`
Expected: all sections PASS, including the new `sync_pass_kat` section.

- [ ] **Step 6: Commit**

```bash
git add core/tests/data/sync_pass_kat/cases.json core/tests/sync_pass_kat.rs core/tests/python/conformance.py
git commit -m "D.1.13(kat): cross-language sync_pass classification KAT

Pure clock-classification vectors proving the pause-on-conflict outcome
labels + post-merge LUB agree across the Rust guard and the stdlib-only
conformance.py replay. No crypto replay (merge math is covered by conflict_kat).

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Docs + deferral issue + full gauntlet

**Files:**
- Modify: `README.md`
- Modify: `ROADMAP.md`

- [ ] **Step 1: Run the full workspace gauntlet**

Because this slice touches `cli` + `core` (tests) + bridge + every binding, run the whole thing:

```bash
cargo fmt --all --check
cargo test --release --workspace 2>&1 | grep "test result:" | tail -20
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -5
uv run core/tests/python/conformance.py 2>&1 | tail -5
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -5
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh 2>&1 | tail -3
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh 2>&1 | tail -3
```
Expected: fmt clean; every `test result:` ok; clippy clean; both conformance scripts PASS; freshness check clean (add an allowlist entry only if it flags a citation this slice legitimately introduced).

- [ ] **Step 2: Update ROADMAP.md**

In `ROADMAP.md`, in the Sub-project D progress line and the D.1.x detail line, append the D.1.13 entry after D.1.12 and advance "next" to D.1.14. Match the existing per-slice prose style (one sentence, issue links). Example phrasing:

> **D.1.13 ✅ shipped 2026-06-06 (sync bridge primitive — `sync_vault` pause-on-conflict pass + read-only `sync_status`; a feature-gated `secretary-cli` `sync_pass_pause_on_conflict` orchestration that auto-applies every safe arm and pauses (writes nothing) on a tombstone veto; five new `FfiVaultError` sync variants threaded through every binding + a cross-language classification KAT; sync functions stay bridge-only ([#NNN](…)))** → D.1.14 ⏳ (desktop sync UI).

Update the `[====...]` Sub-project D bar caption to include "+ D.1.13 sync primitive".

- [ ] **Step 3: Update README.md**

If `README.md` has a status/highlights section that lists the latest slice, add a brief D.1.13 dot point (keep it terse per [[feedback_readme_style]] — no test-count walls). If README only references the ROADMAP for status, no change is needed; verify with `grep -n "D.1.1" README.md`.

- [ ] **Step 4: File the #167-sibling deferral issue**

```bash
gh issue create --title "Project sync_vault / sync_status onto uniffi + pyo3 (mobile/Python consumers)" \
  --body "D.1.13 shipped the sync bridge primitive (\`sync_vault\` / \`sync_status\`) as bridge-only Rust functions — the desktop consumes the bridge as a Rust crate, so no uniffi/pyo3 projection was needed. The new \`FfiVaultError\` sync variants ARE threaded through every binding. Mirror #167: project the two sync functions + their DTOs (SyncStatusDto/SyncOutcomeDto/DeviceClockDto) onto the uniffi namespace + pyo3 when a mobile (D.3) or Python consumer needs sync. Pairs with #167.

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
```

Then replace `#NNN` in the ROADMAP D.1.13 entry (Step 2) with the issue number `gh issue create` printed, and amend the docs commit.

- [ ] **Step 5: Commit docs**

```bash
git add README.md ROADMAP.md
git commit -m "D.1.13: docs — ROADMAP/README mark sync primitive shipped; next -> D.1.14

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-review checklist (run before opening the PR)

- [ ] **Spec coverage:** Layer 1 (cli feature-gate + `sync_pass_pause_on_conflict`) = Tasks 1–2. Layer 2 (bridge `sync_status`/`sync_vault`) = Tasks 4–5. Layer 3 (FFI error threading) = Task 3. KAT = Task 6. Docs + deferral = Task 7. The "pause-don't-auto-commit" contract is pinned by Task 2 Step 9 + Task 5 Step 6. ✅
- [ ] **No silent FfiVaultError fold:** every `SyncError`/`StateError` arm maps to a typed variant or the explicit `SyncFailed` catch-all — no `_ => CorruptVault` swallowing. ([[feedback_security_no_assumptions]])
- [ ] **Lean bindings verified standalone** (Task 4 Step 7), not via `--workspace`.
- [ ] **Single-source state format:** the bridge uses `cli::state` only — no duplicated `.state.cbor` codec.
- [ ] **Zeroize discipline:** `sync_vault` opens + drops the core identity within the function; the password `SecretBytes` is not retained.
- [ ] **NEXT_SESSION handoff** authored + symlink retargeted on this branch before the PR (per [[feedback_next_session_in_pr]]).
