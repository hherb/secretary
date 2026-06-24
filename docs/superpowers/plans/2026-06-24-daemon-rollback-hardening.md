# Daemon rollback-detection hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close three confirmed gaps in the headless sync daemon's manifest-rollback defense (#207 observability, #208 crash-durability, #209 state-dir safety).

**Architecture:** All changes live in `cli/` (`pipeline.rs`, `daemon.rs`, `main.rs`, `state.rs`). No `core/` crypto change, no FFI surface, no on-disk vault/manifest/`SyncState` format change. Three commits, one per issue, on one branch/PR. Each fix code-aligns to the existing C.2 design spec (`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`); two small spec-text clarifications are folded into the relevant commits.

**Tech Stack:** Rust (stable, workspace toolchain), `tracing` for logs, `thiserror` for typed errors, `tempfile`/`fs4` (already in `state.rs`). Tests via `cargo test --release`.

## Global Constraints

- `#![forbid(unsafe_code)]` workspace-wide — no `unsafe`.
- Clippy must stay clean: `cargo clippy --release --workspace --tests -- -D warnings`.
- `cargo fmt --all -- --check` must pass — run `cargo fmt` before every commit.
- Tests run `--release` (crypto crates are slow in debug).
- No magic numbers — name constants (e.g. the `0o700` mode).
- Pure functions in reusable modules; push I/O to the edges; logging side effects live only at the daemon edge (keep `pipeline.rs` free of `tracing` calls).
- Design doc: `docs/superpowers/specs/2026-06-24-daemon-rollback-hardening-design.md`.
- Crate package name: `secretary-cli` (run task-scoped tests with `-p secretary-cli`).

---

### Task 1 — #207: surface `Ok(RunOutcome)` attack indicators in the daemon loop

**Files:**
- Modify: `cli/src/pipeline.rs` (enrich `RunOutcome::RollbackRejected`, fix `run_one`, fix unit tests)
- Modify: `cli/src/main.rs:336` (`outcome_to_exit_code` match arm)
- Modify: `cli/tests/pipeline_integration.rs:271` (construction in assertion)
- Modify: `cli/src/daemon.rs` (add `OutcomeLog` + `outcome_log` + `log_outcome`; rewrite the loop closure's `run_one` handling)

**Interfaces:**
- Produces: `RunOutcome::RollbackRejected(RollbackEvidence)` (was unit variant); `daemon::log_outcome(&RunOutcome)`; `daemon::outcome_log(&RunOutcome) -> Option<OutcomeLog>` with `enum OutcomeLog { RollbackRejected { disk: Vec<VectorClockEntry>, local: Vec<VectorClockEntry> }, VetoesResolved(usize) }`.
- Consumes: `secretary_core::sync::RollbackEvidence` (fields `disk_vector_clock: Vec<VectorClockEntry>`, `local_highest_seen: Vec<VectorClockEntry>`; derives `Debug, Clone, PartialEq, Eq`).

- [ ] **Step 1: Enrich the enum and fix `run_one`'s construction**

In `cli/src/pipeline.rs`, add `RollbackEvidence` to the `secretary_core::sync` use-list:

```rust
use secretary_core::sync::{
    commit_with_decisions, prepare_merge, sync_once, ManifestHash, RecordTombstoneVeto,
    RollbackEvidence, SyncError, SyncOutcome, SyncState, VetoDecision,
};
```

Change the `RunOutcome::RollbackRejected` variant (around line 84) to carry evidence:

```rust
    /// Disk vector clock is strictly dominated by the local
    /// `highest_vector_clock_seen` (rollback per
    /// `docs/crypto-design.md` §10). `state` is NOT advanced — caller
    /// surfaces [`crate::exit::ExitCode::RollbackRejected`] and the
    /// next attempt sees the same disk state. Carries the
    /// [`RollbackEvidence`] (disk clock + local clock) so the daemon
    /// loop can log the attack indicator with forensic detail (#207).
    RollbackRejected(RollbackEvidence),
```

Change the construction in `run_one` (line 226) to carry the evidence:

```rust
        SyncOutcome::RollbackRejected(evidence) => Ok(RunOutcome::RollbackRejected(evidence)),
```

- [ ] **Step 2: Fix the existing match/construction sites (compile-fix)**

`cli/src/main.rs:336` — match arm ignores the payload:

```rust
        RunOutcome::RollbackRejected(_) => ExitCode::RollbackRejected,
```

`cli/tests/pipeline_integration.rs:271` — the assertion now needs an evidence payload; assert on the variant shape instead of equality to a unit value:

```rust
    assert!(matches!(outcome, RunOutcome::RollbackRejected(_)));
```

`cli/src/pipeline.rs` unit tests — update each `RunOutcome::RollbackRejected` (lines ~581, 622, 623, 644, 783) to construct with an empty-clock evidence. Add a tiny helper at the top of the `tests` module and use it:

```rust
    fn sample_evidence() -> RollbackEvidence {
        RollbackEvidence {
            disk_vector_clock: Vec::new(),
            local_highest_seen: Vec::new(),
        }
    }
```

Then e.g. the self-equal test becomes:

```rust
    #[test]
    fn rollback_rejected_is_self_equal() {
        assert_eq!(
            RunOutcome::RollbackRejected(sample_evidence()),
            RunOutcome::RollbackRejected(sample_evidence())
        );
    }
```

Apply the same substitution at lines ~622, 623, 644, 783 (the `assert_ne!`, the `Debug`-contains check, and the `sync_pass`/inspect test that names the variant). `RollbackEvidence` is in scope via `use super::*;`.

- [ ] **Step 3: Write the failing test for `outcome_log`**

In `cli/src/daemon.rs`, inside the `#[cfg(test)] mod tests` block, add:

```rust
    use crate::pipeline::RunOutcome;
    use secretary_core::sync::RollbackEvidence;
    use secretary_core::vault::block::VectorClockEntry;

    #[test]
    fn outcome_log_rollback_carries_clocks() {
        let ev = RollbackEvidence {
            disk_vector_clock: Vec::new(),
            local_highest_seen: Vec::new(),
        };
        let log = outcome_log(&RunOutcome::RollbackRejected(ev));
        assert!(matches!(log, Some(OutcomeLog::RollbackRejected { .. })));
    }

    #[test]
    fn outcome_log_vetoes_only_when_nonzero() {
        assert_eq!(
            outcome_log(&RunOutcome::MergedAndCommitted { vetoes_resolved: 3 }),
            Some(OutcomeLog::VetoesResolved(3))
        );
        assert_eq!(
            outcome_log(&RunOutcome::MergedAndCommitted { vetoes_resolved: 0 }),
            None
        );
    }

    #[test]
    fn outcome_log_silent_arms_are_none() {
        assert_eq!(outcome_log(&RunOutcome::NothingToDo), None);
        assert_eq!(outcome_log(&RunOutcome::AppliedAutomatically), None);
        assert_eq!(outcome_log(&RunOutcome::SilentMerge), None);
    }
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `cargo test --release -p secretary-cli outcome_log`
Expected: FAIL — `outcome_log` / `OutcomeLog` not defined.

- [ ] **Step 5: Implement `OutcomeLog`, `outcome_log`, `log_outcome`**

In `cli/src/daemon.rs`, add the imports near the top (after the existing `secretary_core` uses):

```rust
use secretary_core::vault::block::VectorClockEntry;
```

Add these items at module scope (above `run_against_vault`):

```rust
/// What (if anything) a successful [`RunOutcome`] should announce to the
/// operator. Pure classification — the caller maps it to a `tracing`
/// call. Kept separate from the emission so the decision is unit-testable
/// without a subscriber, and so `pipeline.rs` stays free of logging.
#[derive(Debug, Clone, PartialEq, Eq)]
enum OutcomeLog {
    /// Manifest-rollback attack indicator (threat-model §3.1). Carries
    /// the two clocks an operator needs for forensics.
    RollbackRejected {
        disk: Vec<VectorClockEntry>,
        local: Vec<VectorClockEntry>,
    },
    /// `n > 0` tombstone vetoes were auto-resolved — a peer record
    /// deletion was overridden this pass.
    VetoesResolved(usize),
}

/// Classify an `Ok(RunOutcome)` into the operator-visible log event, if
/// any. The silent arms (`NothingToDo`, `AppliedAutomatically`,
/// `SilentMerge`, and `MergedAndCommitted { vetoes_resolved: 0 }`) return
/// `None`.
fn outcome_log(outcome: &RunOutcome) -> Option<OutcomeLog> {
    match outcome {
        RunOutcome::RollbackRejected(ev) => Some(OutcomeLog::RollbackRejected {
            disk: ev.disk_vector_clock.clone(),
            local: ev.local_highest_seen.clone(),
        }),
        RunOutcome::MergedAndCommitted { vetoes_resolved } if *vetoes_resolved > 0 => {
            Some(OutcomeLog::VetoesResolved(*vetoes_resolved))
        }
        RunOutcome::NothingToDo
        | RunOutcome::AppliedAutomatically
        | RunOutcome::SilentMerge
        | RunOutcome::MergedAndCommitted { .. } => None,
    }
}

/// Emit the operator-visible log line (if any) for a successful sync
/// outcome. The side-effecting edge over the pure [`outcome_log`].
fn log_outcome(outcome: &RunOutcome) {
    match outcome_log(outcome) {
        Some(OutcomeLog::RollbackRejected { disk, local }) => tracing::warn!(
            disk_clock = ?disk,
            local_clock = ?local,
            "manifest rollback rejected (threat-model §3.1 attack indicator); daemon continues",
        ),
        Some(OutcomeLog::VetoesResolved(n)) => tracing::warn!(
            vetoes_resolved = n,
            "auto-resolved {n} tombstone veto(es): a peer record deletion was overridden",
        ),
        None => {}
    }
}
```

Add `RunOutcome` to the daemon's imports (it currently imports only `run_one`):

```rust
use crate::pipeline::{run_one, RunOutcome};
```

- [ ] **Step 6: Wire the loop closure to log `Ok` outcomes**

In `run_against_vault`, replace the `if let Err(e) = run_one(...)` block (lines ~293-295) with:

```rust
            match run_one(vault_folder, identity, password, state, veto_ux, now_ms()) {
                Ok(outcome) => log_outcome(&outcome),
                Err(e) => tracing::warn!("pipeline error (continuing): {e}"),
            }
```

- [ ] **Step 7: Run the full CLI test suite + lint + fmt**

Run:
```bash
cargo test --release -p secretary-cli
cargo clippy --release -p secretary-cli --tests -- -D warnings
cargo fmt --all -- --check
```
Expected: all PASS / clean.

- [ ] **Step 8: Commit**

```bash
git add cli/src/pipeline.rs cli/src/main.rs cli/src/daemon.rs cli/tests/pipeline_integration.rs
git commit -m "fix(cli): log RollbackRejected + auto-resolved vetoes in daemon loop (#207)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2 — #208: persist `SyncState` after every state-advancing sync

**Files:**
- Modify: `cli/src/pipeline.rs` (add `RunOutcome::advanced_state`; spec-comment)
- Modify: `cli/src/daemon.rs` (add `after_sync`; thread `state_dir` into `run_against_vault`; rewire closure)
- Modify: `cli/src/main.rs` (pass `state_dir` to `dispatch_run_subcommand`/`run_against_vault`; downgrade exit on final-save failure)
- Modify: `docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md:313` (extend persist-list with `SilentMerge`)

**Interfaces:**
- Consumes: `daemon::log_outcome` (Task 1).
- Produces: `RunOutcome::advanced_state(&self) -> bool`; `daemon::after_sync(result: Result<RunOutcome, SyncError>, state: &SyncState, save: &mut dyn FnMut(&SyncState) -> Result<(), StateError>)`; `run_against_vault(..., state_dir: &Path, ...)` (new `state_dir: &Path` parameter, inserted before `config`).

- [ ] **Step 1: Write the failing test for `advanced_state`**

In `cli/src/pipeline.rs` `tests` module add (use `sample_evidence()` from Task 1):

```rust
    #[test]
    fn advanced_state_true_for_advancing_arms() {
        assert!(RunOutcome::AppliedAutomatically.advanced_state());
        assert!(RunOutcome::SilentMerge.advanced_state());
        assert!(RunOutcome::MergedAndCommitted { vetoes_resolved: 0 }.advanced_state());
        assert!(RunOutcome::MergedAndCommitted { vetoes_resolved: 5 }.advanced_state());
    }

    #[test]
    fn advanced_state_false_for_non_advancing_arms() {
        assert!(!RunOutcome::NothingToDo.advanced_state());
        assert!(!RunOutcome::RollbackRejected(sample_evidence()).advanced_state());
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --release -p secretary-cli advanced_state`
Expected: FAIL — no method `advanced_state`.

- [ ] **Step 3: Implement `advanced_state`**

In `cli/src/pipeline.rs`, add an `impl` block after the `RunOutcome` enum definition:

```rust
impl RunOutcome {
    /// `true` iff this outcome advanced `state.highest_vector_clock_seen`
    /// and therefore must be persisted before the next daemon iteration.
    /// Matches the C.2 spec §"State persistence" persist-list (extended
    /// to include `SilentMerge`, which post-dates the spec text but does
    /// advance the clock — see `run_one`'s state-mutation contract).
    #[must_use]
    pub fn advanced_state(&self) -> bool {
        matches!(
            self,
            Self::AppliedAutomatically | Self::SilentMerge | Self::MergedAndCommitted { .. }
        )
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test --release -p secretary-cli advanced_state`
Expected: PASS.

- [ ] **Step 5: Write the failing test for `after_sync`**

In `cli/src/daemon.rs` `tests` module add:

```rust
    use secretary_core::sync::{SyncError, SyncState};

    #[test]
    fn after_sync_saves_on_advancing_arms() {
        let state = SyncState::empty([1; 16]);
        for outcome in [
            RunOutcome::AppliedAutomatically,
            RunOutcome::SilentMerge,
            RunOutcome::MergedAndCommitted { vetoes_resolved: 0 },
        ] {
            let mut saves = 0u32;
            let mut sink = |_: &SyncState| {
                saves += 1;
                Ok(())
            };
            after_sync(Ok(outcome), &state, &mut sink);
            assert_eq!(saves, 1);
        }
    }

    #[test]
    fn after_sync_skips_save_on_non_advancing_arms() {
        let state = SyncState::empty([2; 16]);
        let ev = RollbackEvidence {
            disk_vector_clock: Vec::new(),
            local_highest_seen: Vec::new(),
        };
        for outcome in [RunOutcome::NothingToDo, RunOutcome::RollbackRejected(ev)] {
            let mut saves = 0u32;
            let mut sink = |_: &SyncState| {
                saves += 1;
                Ok(())
            };
            after_sync(Ok(outcome), &state, &mut sink);
            assert_eq!(saves, 0);
        }
    }

    #[test]
    fn after_sync_does_not_save_on_err() {
        let state = SyncState::empty([3; 16]);
        let mut saves = 0u32;
        let mut sink = |_: &SyncState| {
            saves += 1;
            Ok(())
        };
        let err = SyncError::Vault(secretary_core::vault::VaultError::Io {
            context: "test",
            source: std::io::Error::other("boom"),
        });
        after_sync(Err(err), &state, &mut sink);
        assert_eq!(saves, 0);
    }
```

- [ ] **Step 6: Run to verify failure**

Run: `cargo test --release -p secretary-cli after_sync`
Expected: FAIL — `after_sync` not defined.

- [ ] **Step 7: Implement `after_sync` and import `StateError`**

In `cli/src/daemon.rs` add to imports:

```rust
use crate::state::{self, StateError};
```

Add at module scope (near `log_outcome`):

```rust
/// Handle the result of one `run_one` pass: log the operator-visible
/// outcome (#207) and persist `state` (#208) whenever it advanced. `save`
/// is injected (not a direct `state::save` call) so the loop body is
/// unit-testable without a real watcher or filesystem. A save failure is
/// logged and swallowed — the in-memory clock has still advanced, and a
/// transient FS error must not kill a daemon that may run for weeks; the
/// next advancing pass retries the persist.
fn after_sync(
    result: Result<RunOutcome, SyncError>,
    state: &SyncState,
    save: &mut dyn FnMut(&SyncState) -> Result<(), StateError>,
) {
    match result {
        Ok(outcome) => {
            log_outcome(&outcome);
            if outcome.advanced_state() {
                if let Err(e) = save(state) {
                    tracing::warn!("state persist after sync failed (continuing): {e}");
                }
            }
        }
        Err(e) => tracing::warn!("pipeline error (continuing): {e}"),
    }
}
```

- [ ] **Step 8: Thread `state_dir` into `run_against_vault` and rewire the closure**

Add `state_dir: &Path` to `run_against_vault`'s signature (insert before `config: DaemonConfig`):

```rust
pub fn run_against_vault(
    vault_folder: &Path,
    identity: &UnlockedIdentity,
    password: &SecretBytes,
    state: &mut SyncState,
    veto_ux: &mut dyn VetoUx,
    state_dir: &Path,
    config: DaemonConfig,
    ready_window: Duration,
) -> Result<(), SyncError> {
```

Replace the `match run_one(...)` block from Task 1 (the closure body) with the injected-sink form:

```rust
            let result = run_one(vault_folder, identity, password, state, veto_ux, now_ms());
            let mut save = |s: &SyncState| state::save(state_dir, s);
            after_sync(result, state, &mut save);
```

- [ ] **Step 9: Update `main.rs` call sites to pass `state_dir`**

In `cli/src/main.rs`, `dispatch_run_subcommand` gains a `state_dir: &Path` parameter (add it to the signature) and forwards it to both `run_against_vault` calls (insert `state_dir,` before `config,`). At the `dispatch_run_subcommand(...)` call in `run` (line ~138), pass `&state_dir`:

```rust
        Some(run_args) => dispatch_run_subcommand(
            run_args,
            vault,
            &identity,
            &password,
            &mut state,
            &state_dir,
            interactive,
        ),
```

And in `dispatch_run_subcommand`'s body, both `daemon::run_against_vault(...)` calls insert `state_dir,` before `config,`.

- [ ] **Step 10: Downgrade exit code on final-save failure**

Replace the final-save block (`cli/src/main.rs:149-151`) with:

```rust
    let exit_code = match state::save(&state_dir, &state) {
        Ok(()) => exit_code,
        Err(e) => {
            error!("final state save failed: {e}");
            // Don't override a more specific non-success code (e.g.
            // RollbackRejected, LockfileHeld); only escalate a Success.
            if matches!(exit_code, ExitCode::Success) {
                ExitCode::GenericError
            } else {
                exit_code
            }
        }
    };

    exit_code
```

- [ ] **Step 11: Extend the spec persist-list**

In `docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`, line ~313, change:

> Persists ONLY after `AppliedAutomatically` or successful `commit_with_decisions`. NOT after `NothingToDo` ...

to:

> Persists after every state-advancing outcome: `AppliedAutomatically`, `SilentMerge`, and successful `commit_with_decisions` (`MergedAndCommitted`). NOT after `NothingToDo` (no change), NOT after `RollbackRejected` (intentionally unchanged), NOT after `ConcurrentDetected` before commit. (`SilentMerge` post-dates the original draft but advances `highest_vector_clock_seen`; see `cli/src/pipeline.rs` `run_one`.)

- [ ] **Step 12: Run full suite + lint + fmt**

Run:
```bash
cargo test --release -p secretary-cli
cargo clippy --release -p secretary-cli --tests -- -D warnings
cargo fmt --all -- --check
```
Expected: all PASS / clean.

- [ ] **Step 13: Commit**

```bash
git add cli/src/pipeline.rs cli/src/daemon.rs cli/src/main.rs docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md
git commit -m "fix(cli): persist SyncState after every advancing sync in daemon loop (#208)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3 — #209: state-dir safety (no silent cwd, never inside vault, 0700)

**Files:**
- Modify: `cli/src/state.rs` (add `StateDirError`, `resolve_state_dir`, `normalize_abs`, `is_within`, `create_dir_secure`, `STATE_DIR_MODE`; use `create_dir_secure` in `save` + `LockfileGuard::acquire`)
- Modify: `cli/src/main.rs` (call `state::resolve_state_dir`; delete `STATE_DIR_FALLBACK` + old `resolve_state_dir`)
- Modify: `docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md` (note: no cwd fallback — hard error)

**Interfaces:**
- Produces: `state::resolve_state_dir(explicit: Option<PathBuf>, os_default: Option<PathBuf>, vault_folder: &Path) -> Result<PathBuf, StateDirError>`; `pub enum StateDirError { Unresolvable, InsideVault { state_dir: String, vault: String } }` (derives `Debug`, `thiserror::Error`).
- Consumes: existing `state::default_state_dir() -> Option<PathBuf>`; `CommonArgs::state_dir: Option<PathBuf>`.

- [ ] **Step 1: Write failing tests for path helpers + resolution**

In `cli/src/state.rs` `tests` module add:

```rust
    #[test]
    fn is_within_detects_nested_and_rejects_sibling() {
        assert!(is_within(Path::new("/vault/sub/state"), Path::new("/vault")));
        assert!(is_within(Path::new("/vault"), Path::new("/vault")));
        assert!(!is_within(Path::new("/other/state"), Path::new("/vault")));
    }

    #[test]
    fn is_within_folds_parent_dir_escape() {
        // /vault/../else normalizes out of /vault.
        assert!(!is_within(Path::new("/vault/../else"), Path::new("/vault")));
    }

    #[test]
    fn resolve_explicit_wins_even_if_no_os_default() {
        let got = resolve_state_dir(
            Some(PathBuf::from("/etc/secretary")),
            None,
            Path::new("/vault"),
        )
        .unwrap();
        assert_eq!(got, PathBuf::from("/etc/secretary"));
    }

    #[test]
    fn resolve_falls_back_to_os_default() {
        let got =
            resolve_state_dir(None, Some(PathBuf::from("/home/u/.local")), Path::new("/vault"))
                .unwrap();
        assert_eq!(got, PathBuf::from("/home/u/.local"));
    }

    #[test]
    fn resolve_unresolvable_when_no_source() {
        let err = resolve_state_dir(None, None, Path::new("/vault")).unwrap_err();
        assert!(matches!(err, StateDirError::Unresolvable));
    }

    #[test]
    fn resolve_rejects_state_dir_inside_vault() {
        let err = resolve_state_dir(
            Some(PathBuf::from("/vault/state")),
            None,
            Path::new("/vault"),
        )
        .unwrap_err();
        assert!(matches!(err, StateDirError::InsideVault { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn create_dir_secure_sets_0700() {
        use std::os::unix::fs::PermissionsExt;
        let base = TempDir::new().unwrap();
        let dir = base.path().join("nested").join("sync");
        create_dir_secure(&dir).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, STATE_DIR_MODE);
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --release -p secretary-cli resolve_ is_within create_dir_secure`
Expected: FAIL — items not defined.

- [ ] **Step 3: Implement the error type, constants, and pure helpers**

In `cli/src/state.rs`, add the mode constant near the other consts:

```rust
/// Mode the state directory is created with on first run (Unix only).
/// C.2 spec §"State persistence": "Directory created on first run with
/// mode 0700 (Unix)." Non-secret metadata, but the spec/code divergence
/// is resolved in favour of the spec.
const STATE_DIR_MODE: u32 = 0o700;
```

Add the error enum (next to `StateError`):

```rust
/// Why a usable state directory could not be established. Distinct from
/// [`StateError`] (I/O / decode / lock): these are operator
/// misconfigurations caught before any vault work, mapped by `main` to
/// the usage exit code.
#[derive(Debug, Error)]
pub enum StateDirError {
    #[error(
        "could not resolve a state directory (no --state-dir given and no OS data dir available); \
         pass --state-dir to a host-local path outside the vault folder"
    )]
    Unresolvable,
    #[error(
        "refusing to place rollback-detection state inside the vault folder \
         (state dir {state_dir} is within {vault}); pass --state-dir to a host-local path \
         outside the vault"
    )]
    InsideVault { state_dir: String, vault: String },
}
```

Add the pure helpers + secure-create at module scope:

```rust
/// Absolute, lexically-normalized form of `p`: joins the current dir if
/// relative, then folds `.` and `..` components. Does NOT resolve
/// symlinks — this is a misconfiguration guard, not a defence against an
/// attacker who can plant symlinks on the operator's local filesystem
/// (the in-scope adversary controls the synced folder's *contents*, not
/// the host's FS layout).
fn normalize_abs(p: &Path) -> PathBuf {
    use std::path::Component;
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(p)
    };
    let mut out = PathBuf::new();
    for comp in abs.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// `true` iff `child` is `ancestor` or lives beneath it, compared over
/// the lexically-normalized absolute forms.
fn is_within(child: &Path, ancestor: &Path) -> bool {
    normalize_abs(child).starts_with(normalize_abs(ancestor))
}

/// Resolve the state directory. `explicit` is `--state-dir`; `os_default`
/// is [`default_state_dir`]. An explicit path always wins (even `.` —
/// an informed operator choice). Otherwise the OS data dir. If neither is
/// available the result is [`StateDirError::Unresolvable`] — there is
/// **no** silent current-working-directory fallback. The resolved path is
/// rejected with [`StateDirError::InsideVault`] if it lies within
/// `vault_folder`.
pub fn resolve_state_dir(
    explicit: Option<PathBuf>,
    os_default: Option<PathBuf>,
    vault_folder: &Path,
) -> Result<PathBuf, StateDirError> {
    let dir = explicit.or(os_default).ok_or(StateDirError::Unresolvable)?;
    if is_within(&dir, vault_folder) {
        return Err(StateDirError::InsideVault {
            state_dir: dir.display().to_string(),
            vault: vault_folder.display().to_string(),
        });
    }
    Ok(dir)
}

/// Create `path` and any missing parents. On Unix the directory is
/// created with mode [`STATE_DIR_MODE`] (0700); other platforms use a
/// plain recursive create. An already-existing directory is left as-is
/// (its mode is not changed), matching the spec wording "created on first
/// run with mode 0700".
fn create_dir_secure(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(STATE_DIR_MODE)
            .create(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)
    }
}
```

- [ ] **Step 4: Use `create_dir_secure` in the two create sites**

In `state::save` (line ~135) replace `fs::create_dir_all(state_dir)?;` with `create_dir_secure(state_dir)?;`.
In `LockfileGuard::acquire` (line ~159) replace `fs::create_dir_all(state_dir)?;` with `create_dir_secure(state_dir)?;`.

- [ ] **Step 5: Run the state tests**

Run: `cargo test --release -p secretary-cli resolve_ is_within create_dir_secure`
Expected: PASS.

- [ ] **Step 6: Wire `main.rs` to the fallible resolver; delete the old fallback**

In `cli/src/main.rs`: delete the `STATE_DIR_FALLBACK` const (line 56) and its doc comment, and delete the old `resolve_state_dir` fn (lines ~176-186) with its doc comment. Add `StateDirError` to the `state` import line:

```rust
use secretary_cli::state::{self, LockfileGuard, StateDirError, StateError};
```

Replace the `let state_dir = resolve_state_dir(common);` line (113) with:

```rust
    let state_dir = match state::resolve_state_dir(
        common.state_dir.clone(),
        state::default_state_dir(),
        vault,
    ) {
        Ok(d) => d,
        Err(e) => {
            error!("{e}");
            return ExitCode::UsageError;
        }
    };
```

(`StateDirError` is imported for clarity even though it is only named in the error path's `Display`; if clippy flags it as unused, drop it from the import.)

- [ ] **Step 7: Add the spec clarification on the fallback**

In `docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`, in the `--state-dir` flag-table row / state-persistence section, append a sentence:

> If neither `--state-dir` nor the OS data dir resolves, the binary exits with the usage error code rather than falling back to the current working directory — host-local state must never land inside the (attacker-controlled) vault folder. A state dir resolving inside the vault folder is likewise a hard error.

- [ ] **Step 8: Run full suite + lint + fmt**

Run:
```bash
cargo test --release -p secretary-cli
cargo clippy --release -p secretary-cli --tests -- -D warnings
cargo fmt --all -- --check
```
Expected: all PASS / clean.

- [ ] **Step 9: Commit**

```bash
git add cli/src/state.rs cli/src/main.rs docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md
git commit -m "fix(cli): state-dir safety — no cwd fallback, never inside vault, 0700 (#209)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4 — Whole-workspace verification + docs sweep

**Files:**
- Possibly modify: `README.md`, `ROADMAP.md` (only if a status line references the daemon rollback defense)

- [ ] **Step 1: Full workspace gates**

Run from the worktree root:
```bash
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
uv run core/tests/python/conformance.py
```
Expected: 0 FAILED; clippy clean; fmt clean; conformance PASS (unaffected — no format/semantics change).

- [ ] **Step 2: README/ROADMAP review**

Check whether `README.md` (C.2 / sync-daemon status) or `ROADMAP.md` references the rollback-detection behavior being changed. Grep:
```bash
grep -ni "rollback\|state-dir\|daemon\|C.2" README.md ROADMAP.md
```
If a line is now inaccurate or worth a one-line note (#207/#208/#209 closed), update it (keep README status terse per the project's README style). If nothing references it, make no change. Commit any edit:
```bash
git add README.md ROADMAP.md
git commit -m "docs: note daemon rollback-detection hardening (#207/#208/#209)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review notes

- **Spec coverage:** #207 → Task 1; #208 → Task 2 (advanced_state + after_sync + in-loop save + final-save downgrade + spec persist-list); #209 → Task 3 (resolve/containment/0700 + main wiring + spec fallback note). Whole-workspace verify + docs → Task 4.
- **Type consistency:** `RunOutcome::RollbackRejected(RollbackEvidence)` used consistently across pipeline.rs, main.rs (`outcome_to_exit_code`, `_` arm), daemon.rs (`outcome_log`), and integration test. `after_sync` sink type `&mut dyn FnMut(&SyncState) -> Result<(), StateError>` matches the production `|s| state::save(state_dir, s)` closure (returns `Result<(), StateError>`). `resolve_state_dir` 3-arg signature matches the `main.rs` call site.
- **No new FFI/format surface:** `RunOutcome` is `cli`-internal; `SyncState` CBOR unchanged; no `core/` change → `conformance.py` and Swift/Kotlin harnesses untouched.
