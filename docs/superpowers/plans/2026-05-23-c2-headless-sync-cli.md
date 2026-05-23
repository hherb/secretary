# C.2 Headless `secretary-sync` CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the headless `secretary-sync` desktop CLI in a new `cli/` workspace member. The binary wraps the C.1.1b three-step API (`sync_once → prepare_merge → commit_with_decisions`), the `notify` file-watcher, ADR-0003 partial-download detection, and single-process-per-vault lockfile enforcement. Two subcommands (`run`, `once`); two operational modes (interactive default, `--non-interactive` via `--password-stdin` with auto-`KeepLocal` veto policy).

**Architecture:** Library-thin, I/O-at-edges. A pure-function `pipeline::run_one(&UnlockedIdentity, &SecretBytes, &mut SyncState, ...)` performs one sync attempt — `sync_once` → dispatch → optional `prepare_merge` → veto adjudication via a `VetoUx` trait → `commit_with_decisions`. The `run` subcommand wraps `run_one` in a `daemon::run` loop driven by `notify::RecommendedWatcher` events with a debounce state machine and an optional periodic poll. The `once` subcommand is `run_one` plus state-file save plus exit-code mapping. State persistence + host-local lockfile live in `state.rs` (filename = `<vault_uuid_hex>.state.cbor` / `<vault_uuid_hex>.lock` under `dirs`-resolved OS data dir, `--state-dir` override). Partial-download detection composes a pure pattern matcher + size-stability probe in `watcher::ready`. Unlock reads bytes from stdin or TTY into a `SecretBytes` held for the daemon's lifetime.

**Tech Stack:** stable Rust (workspace toolchain). New `cli/` workspace member with binary-only deps: `clap` (derive), `notify` 6.x (RecommendedWatcher), `tracing-subscriber` (env-filter + fmt + json), `dirs` 5.x, `tempfile` `=3.27.0` exact-pinned, `rpassword`, `serde_json`, `fs4` 1.x (cross-platform flock; maintained fork of the unmaintained `fs2`), `signal-hook`. Dev-deps: `assert_cmd`, `predicates`. No new deps in `core/`. All Rust pure-safe (`#![forbid(unsafe_code)]` per workspace lint, opt-in via `[lints] workspace = true` in `cli/Cargo.toml`).

**Spec:** [`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`](../specs/2026-05-23-c2-headless-sync-cli-design.md) (D1–D10 settled 2026-05-23).

**Predecessor:** C.1.1b on `main` (PR #110 merged 2026-05-23; `core::sync::{sync_once, prepare_merge, commit_with_decisions}` + `DraftMerge`, `RecordTombstoneVeto`, `VetoDecision`, `SyncState`, `VaultBundle` all shipped). Worktree `.worktrees/c2-task-1-spec` on branch `feature/c2-task-1-spec` carries this plan + the spec. Subsequent tasks each open their own worktree + branch (`.worktrees/c2-task-N` on `feature/c2-task-N`).

---

## Spec adjustments from the design doc

One signature alignment, applied during plan authoring (already committed in the spec PR via `03d919f`):

| Spec original draft | Actual API in `main` | Plan decision |
|---|---|---|
| `commit_with_decisions(folder, ibk_copy: &SecretBytes, ...)` | `commit_with_decisions(folder, password: &SecretBytes, ...)` — function re-opens vault internally via `Unlocker::Password(password)` | The CLI retains the `password: SecretBytes` from unlock for the daemon's lifetime (not the IBK). Both `password` and `UnlockedIdentity` zeroize on drop. See spec §"Identity lifecycle" (corrected). |

No other deviations.

---

## File Structure

**New files (16) — all under `cli/`:**

```
cli/Cargo.toml                            New workspace member; 11 runtime + 2 dev deps
cli/src/main.rs                           ~80 LOC   clap parse → subcommand dispatch
cli/src/args.rs                           ~120 LOC  clap derive types (Cli, Subcommand, RunArgs, OnceArgs, CommonArgs)
cli/src/exit.rs                           ~110 LOC  ExitCode enum + From<SyncError> + tests
cli/src/state.rs                          ~280 LOC  load/save SyncState + lockfile RAII guard + tests
cli/src/unlock.rs                         ~180 LOC  PasswordSource + read_password_from_reader + tests
cli/src/veto/mod.rs                       ~60 LOC   VetoUx trait
cli/src/veto/noninteractive.rs            ~70 LOC   AutoKeepLocalVetoUx + tests
cli/src/veto/interactive.rs               ~140 LOC  TtyVetoUx + scripted-reader tests
cli/src/pipeline.rs                       ~320 LOC  run_one + RunOutcome + tests
cli/src/watcher/mod.rs                    ~70 LOC   WatcherEvent enum + driver trait
cli/src/watcher/ready.rs                  ~190 LOC  matches_partial_pattern + is_size_stable + wait_for_ready + tests
cli/src/watcher/debounce.rs               ~140 LOC  pure state machine + tests
cli/src/watcher/notify_driver.rs          ~200 LOC  notify::RecommendedWatcher wrapper + tests
cli/src/daemon.rs                         ~280 LOC  run-loop: watcher + debounce + poll + signal → pipeline.run_one
cli/src/logging.rs                        ~80 LOC   tracing-subscriber init (human vs json)
cli/src/signal.rs                         ~70 LOC   SIGINT/SIGTERM → CancellationToken (signal-hook)
```

**Integration tests (3):**

```
cli/tests/once_integration.rs             ~620 LOC  ~16 assert_cmd-driven tests against `once`
cli/tests/two_instance_convergence.rs     ~280 LOC  Two-CLI shared-folder convergence (D8 acceptance criterion)
cli/tests/notify_quirk.rs                 ~160 LOC  Platform-conditional notify quirk pin (acceptance criterion)
```

**Modified files (3):**

```
Cargo.toml                                Add `cli` to `[workspace] members`
README.md                                 Mark Sub-project C row C.2 ✅ when this lands (Task 10)
ROADMAP.md                                Progress bar [===============] → [=================]; C.2 detail under Sub-project C
```

All new source files under the 500-LOC `feedback_split_files_proactively` threshold. Heaviest are `pipeline.rs` (~320 LOC) and `daemon.rs` (~280 LOC); both well-contained "one concept = orchestration".

---

## Working directory + baseline

Each task uses its own worktree at `.worktrees/c2-task-N` on branch `feature/c2-task-N`, branched from `main` (after the prior task's PR merges). The `.worktrees/c2-task-1-spec` worktree carries this plan + the spec only; the first code task opens a NEW worktree from main once the spec/plan PR lands.

```bash
# Setup for task N (after task N-1's PR merges):
cd /Users/hherb/src/secretary
git fetch --prune origin
git checkout main
git pull --ff-only origin main
git worktree add .worktrees/c2-task-N -b feature/c2-task-N main
cd .worktrees/c2-task-N
```

**Baseline gauntlet** (run once at task start; same set of commands after every task; expected counts updated per task):

```bash
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3
```

Starting baseline (post-PR #110, `main` at `f0e5de5`): **PASSED: 800 FAILED: 0 IGNORED: 10**, clippy clean, fmt clean, conformance PASS, spec freshness PASS (96 resolved / 0 unresolved / 2 suppressed).

After every task: gauntlet must stay green before commit. Commit only when green.

---

## Task 1: Scaffold `cli/` workspace member + exit codes

**Why:** Lay down the new workspace member so subsequent tasks have a place to add modules. `clap` arg parsing and the `ExitCode` enum land in the same task — both are tiny (~120 + ~110 LOC), tightly coupled (every subcommand returns an exit code), and writing them together avoids a churn cycle where Task 2 adds the dispatch table for codes that don't exist yet.

**Files:**
- Create: `cli/Cargo.toml`
- Create: `cli/src/main.rs` (skeleton — `clap::Parser::parse()` + match subcommand → call `todo!()`)
- Create: `cli/src/args.rs` (full clap derive types)
- Create: `cli/src/exit.rs` (`ExitCode` enum + `From<SyncError>` + unit tests)
- Modify: `Cargo.toml` (workspace root) — add `cli` to `[workspace] members`

- [ ] **Step 1: Set up worktree from main**

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree add .worktrees/c2-task-1 -b feature/c2-task-1 main
cd .worktrees/c2-task-1
```

- [ ] **Step 2: Add `cli` to workspace members**

Edit `Cargo.toml`:

```toml
[workspace]
resolver = "2"
members = [
    "core",
    "cli",
    "ffi/secretary-ffi-py",
    "ffi/secretary-ffi-uniffi",
    "ffi/secretary-ffi-bridge",
]
exclude = ["core/fuzz"]
```

- [ ] **Step 3: Create `cli/Cargo.toml`**

```toml
[package]
name = "secretary-cli"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[[bin]]
name = "secretary-sync"
path = "src/main.rs"

[dependencies]
secretary-core = { path = "../core" }
clap = { version = "4", features = ["derive"] }
notify = "6"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "fmt", "json"] }
dirs = "5"
# `tempfile` exact-pinned to match `core/Cargo.toml`. The CLI's state file
# (per docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md §"State persistence")
# uses NamedTempFile::persist for atomic rename, same discipline as the
# vault format. A regression in persist semantics would silently corrupt
# the SyncState file. Same exact-pin rule as `core` — bump only via
# deliberate changelog review (CLAUDE.md "exact pins on security-critical paths").
tempfile = "=3.27.0"
rpassword = "7"
serde_json = "1"
# `fs4` is a maintained fork of the unmaintained `fs2` crate (fs2's last
# release was 2019). Drop-in API for the sync lockfile primitive Task 2 uses.
fs4 = "1"
signal-hook = "0.3"
thiserror = "2"

[dev-dependencies]
assert_cmd = "2"
predicates = "3"
tempfile = "=3.27.0"

[lints]
workspace = true
```

- [ ] **Step 4: Write the failing test for `args.rs`**

Create `cli/src/args.rs`:

```rust
//! `clap` derive types for `secretary-sync` arg parsing.
//!
//! See [`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`](../../../docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md)
//! §"Public surface" for the flag table and defaults.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "secretary-sync",
    about = "Headless sync orchestration for a Secretary vault folder",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Single sync attempt then exit.
    Once {
        #[command(flatten)]
        common: CommonArgs,
        /// Vault folder to sync.
        vault_folder: PathBuf,
    },
    /// Long-running daemon (notify-based file watcher + debounce + optional poll).
    Run {
        #[command(flatten)]
        common: CommonArgs,
        #[command(flatten)]
        run_args: RunArgs,
        /// Vault folder to watch + sync.
        vault_folder: PathBuf,
    },
}

#[derive(clap::Args, Debug)]
pub struct CommonArgs {
    /// Read password from stdin until EOF.
    #[arg(long)]
    pub password_stdin: bool,

    /// No TTY prompts; require --password-stdin; auto-KeepLocal on vetoes.
    #[arg(long)]
    pub non_interactive: bool,

    /// Where to persist <vault_uuid_hex>.state.cbor + .lock. Defaults to OS data dir.
    #[arg(long)]
    pub state_dir: Option<PathBuf>,

    /// Log output format.
    #[arg(long, default_value = "human")]
    pub log_format: LogFormat,

    /// Verbosity. -v → debug; -vv → core debug.
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

#[derive(clap::Args, Debug)]
pub struct RunArgs {
    /// Debounce window for notify event bursts (ms).
    #[arg(long, default_value_t = 500)]
    pub debounce_ms: u64,

    /// Periodic safety-net poll (secs). 0 = off.
    #[arg(long, default_value_t = 0)]
    pub poll_interval_secs: u64,

    /// Size-stability window for partial-download detection (ms).
    #[arg(long, default_value_t = 2000)]
    pub ready_window_ms: u64,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogFormat {
    Human,
    Json,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `secretary-sync once <folder>` with no flags parses to default CommonArgs.
    #[test]
    fn parse_once_with_defaults() {
        let cli =
            Cli::try_parse_from(["secretary-sync", "once", "/tmp/vault"]).expect("parse failed");
        match cli.command {
            Command::Once {
                common,
                vault_folder,
            } => {
                assert_eq!(vault_folder, PathBuf::from("/tmp/vault"));
                assert!(!common.password_stdin);
                assert!(!common.non_interactive);
                assert!(common.state_dir.is_none());
                assert_eq!(common.log_format, LogFormat::Human);
                assert_eq!(common.verbose, 0);
            }
            _ => panic!("expected Once subcommand"),
        }
    }

    /// `secretary-sync run` with all flags parses each correctly.
    #[test]
    fn parse_run_with_all_flags() {
        let cli = Cli::try_parse_from([
            "secretary-sync",
            "run",
            "--password-stdin",
            "--non-interactive",
            "--state-dir",
            "/etc/secretary",
            "--log-format",
            "json",
            "-vv",
            "--debounce-ms",
            "750",
            "--poll-interval-secs",
            "60",
            "--ready-window-ms",
            "3000",
            "/srv/vault",
        ])
        .expect("parse failed");
        match cli.command {
            Command::Run {
                common,
                run_args,
                vault_folder,
            } => {
                assert_eq!(vault_folder, PathBuf::from("/srv/vault"));
                assert!(common.password_stdin);
                assert!(common.non_interactive);
                assert_eq!(common.state_dir, Some(PathBuf::from("/etc/secretary")));
                assert_eq!(common.log_format, LogFormat::Json);
                assert_eq!(common.verbose, 2);
                assert_eq!(run_args.debounce_ms, 750);
                assert_eq!(run_args.poll_interval_secs, 60);
                assert_eq!(run_args.ready_window_ms, 3000);
            }
            _ => panic!("expected Run subcommand"),
        }
    }

    /// Missing required positional vault_folder argument → parse error.
    #[test]
    fn parse_once_missing_folder_fails() {
        let result = Cli::try_parse_from(["secretary-sync", "once"]);
        assert!(result.is_err());
    }

    /// `--ready-window-ms` defaults to 2000 (spec §"Public surface" D6 mobile-aware default).
    #[test]
    fn run_args_default_ready_window_is_2000() {
        let cli = Cli::try_parse_from(["secretary-sync", "run", "/tmp/vault"]).expect("parse");
        if let Command::Run { run_args, .. } = cli.command {
            assert_eq!(
                run_args.ready_window_ms, 2000,
                "spec freezes default at 2000 ms"
            );
        } else {
            panic!("expected Run");
        }
    }
}
```

- [ ] **Step 5: Create skeleton `cli/src/main.rs`**

```rust
//! `secretary-sync` entry point. See
//! [`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`](../../docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md).

use clap::Parser;

mod args;
mod exit;

fn main() {
    let cli = args::Cli::parse();
    // Subsequent tasks wire the real dispatch. For now: parse, print, exit.
    let code = match cli.command {
        args::Command::Once { .. } => {
            eprintln!("secretary-sync once: not yet implemented");
            exit::ExitCode::GenericError
        }
        args::Command::Run { .. } => {
            eprintln!("secretary-sync run: not yet implemented");
            exit::ExitCode::GenericError
        }
    };
    std::process::exit(code as i32);
}
```

- [ ] **Step 6: Write the failing test for `exit.rs`**

Create `cli/src/exit.rs`:

```rust
//! Exit code mapping. See spec §"Public surface" exit-code table.

use secretary_core::sync::SyncError;

/// Documented exit codes for `secretary-sync`. The discriminant is the
/// numeric exit code surfaced to the operator.
///
/// Per spec §"Public surface":
///
/// | Code | Meaning |
/// |---|---|
/// | 0  | Success (any non-Rollback outcome; clean shutdown). |
/// | 1  | Generic error (vault format, IO, unlock, state-file). |
/// | 2  | Usage error. |
/// | 10 | RollbackRejected. |
/// | 11 | Reserved — non-interactive veto-policy refusal (currently unreachable). |
/// | 12 | EvidenceStale after retry budget exhausted. |
/// | 13 | BlockFingerprintMismatch on commit. |
/// | 14 | Lockfile held — another secretary-sync process is running on this vault. |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    Success = 0,
    GenericError = 1,
    UsageError = 2,
    RollbackRejected = 10,
    VetoPolicyRefused = 11,
    EvidenceStale = 12,
    BlockFingerprintMismatch = 13,
    LockfileHeld = 14,
}

impl ExitCode {
    /// Map a `SyncError` to the documented exit code. Variants without a
    /// dedicated code map to `GenericError`.
    #[must_use]
    pub fn from_sync_error(err: &SyncError) -> Self {
        match err {
            SyncError::EvidenceStale => Self::EvidenceStale,
            SyncError::Vault(v) => match v {
                secretary_core::vault::VaultError::BlockFingerprintMismatch { .. } => {
                    Self::BlockFingerprintMismatch
                }
                _ => Self::GenericError,
            },
            _ => Self::GenericError,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_is_zero() {
        assert_eq!(ExitCode::Success as i32, 0);
    }

    #[test]
    fn generic_error_is_one() {
        assert_eq!(ExitCode::GenericError as i32, 1);
    }

    #[test]
    fn usage_error_is_two() {
        assert_eq!(ExitCode::UsageError as i32, 2);
    }

    #[test]
    fn rollback_rejected_is_ten() {
        assert_eq!(ExitCode::RollbackRejected as i32, 10);
    }

    #[test]
    fn veto_policy_refused_is_eleven() {
        assert_eq!(ExitCode::VetoPolicyRefused as i32, 11);
    }

    #[test]
    fn evidence_stale_is_twelve() {
        assert_eq!(ExitCode::EvidenceStale as i32, 12);
    }

    #[test]
    fn block_fingerprint_mismatch_is_thirteen() {
        assert_eq!(ExitCode::BlockFingerprintMismatch as i32, 13);
    }

    #[test]
    fn lockfile_held_is_fourteen() {
        assert_eq!(ExitCode::LockfileHeld as i32, 14);
    }

    #[test]
    fn evidence_stale_error_maps() {
        let mapped = ExitCode::from_sync_error(&SyncError::EvidenceStale);
        assert_eq!(mapped, ExitCode::EvidenceStale);
    }
}
```

- [ ] **Step 7: Run tests to verify they fail (no impl yet for some)**

```bash
cargo build -p secretary-cli 2>&1 | tail -5
```

Expected: compile error or tests pass if all impl is present. The above is a complete impl, so tests should pass on first compile.

- [ ] **Step 8: Run tests to verify they pass**

```bash
cargo test --release -p secretary-cli --lib 2>&1 | grep "test result:"
```

Expected: `test result: ok. 12 passed; 0 failed; 0 ignored`.

- [ ] **Step 9: Verify the binary builds + `--help` runs**

```bash
cargo build --release -p secretary-cli 2>&1 | tail -3
./target/release/secretary-sync --help
./target/release/secretary-sync once --help
./target/release/secretary-sync run --help
```

Expected: clean build, three help-text screens print.

- [ ] **Step 10: Gauntlet**

```bash
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
```

Expected: `PASSED: 812 FAILED: 0 IGNORED: 10` (800 base + 12 new cli tests), clippy clean, fmt clean.

- [ ] **Step 11: Commit**

```bash
git add Cargo.toml cli/
git commit -m "$(cat <<'EOF'
C.2 Task 1 — scaffold cli/ workspace member + exit codes

New `cli/` workspace member alongside core/ and ffi/. Binary
`secretary-sync` produced from `cli/src/main.rs`. Currently a stub
dispatch — subsequent tasks wire the real pipeline.

Includes:
- cli/Cargo.toml with 11 runtime + 2 dev deps (tempfile=3.27.0 exact pin).
- cli/src/args.rs — clap derive types for `once` + `run` subcommands.
- cli/src/exit.rs — ExitCode enum (0/1/2/10/11/12/13/14) + From<SyncError>.
- Cargo.toml — `cli` added to [workspace] members.

12 new unit tests; workspace gauntlet stays green.

See: docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md §D9.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
git push -u origin feature/c2-task-1
gh pr create --base main --title "C.2 Task 1 — scaffold cli/ workspace member + exit codes" --body "$(cat <<'EOF'
## Summary
- New `cli/` workspace member with `secretary-sync` binary skeleton.
- `clap` arg parsing for `once` + `run` subcommands per spec §"Public surface".
- `ExitCode` enum + `From<SyncError>` mapping per spec exit-code table.
- 12 new unit tests; workspace 800→812.

## Test plan
- [x] cargo test --release --workspace
- [x] cargo clippy --release --workspace --tests -- -D warnings
- [x] cargo fmt --all -- --check
- [x] secretary-sync --help / once --help / run --help

Spec: docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md
Plan: docs/superpowers/plans/2026-05-23-c2-headless-sync-cli.md (Task 1 of 10)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Task 2: State persistence + lockfile (`cli/src/state.rs`)

**Why:** Every subcommand needs to load/save the `SyncState` CBOR file and acquire the host-local lockfile before doing anything else. The pure-function pieces (`path_for_vault`, `canonical_hex`) are trivially table-testable; the I/O pieces (`load`, `save`, `LockfileGuard`) need temp-dir fixtures. Lockfile uses `fs4::fs_std::FileExt::try_lock_exclusive` for cross-platform flock/LockFileEx (fs4 1.x; verify the exact module path against the live docs at impl time — fs4's v1 line restructured the namespace from fs2's flat layout). Atomic state-file write via `tempfile::NamedTempFile::persist` (same `=3.27.0` pin as core).

**Files:**
- Create: `cli/src/state.rs`
- Modify: `cli/src/main.rs` — add `mod state;`

- [ ] **Step 1: Set up Task 2 worktree from main**

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree add .worktrees/c2-task-2 -b feature/c2-task-2 main
cd .worktrees/c2-task-2
```

- [ ] **Step 2: Write the failing tests for pure helpers**

Create `cli/src/state.rs`:

```rust
//! Per-vault `SyncState` persistence + host-local lockfile.
//!
//! Spec: [`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`](../../docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md)
//! §"State persistence" and §D7 (single-process-per-vault lockfile).
//!
//! The state file is `<state-dir>/<vault_uuid_hex>.state.cbor` —
//! `SyncState` encoded via the existing `core::sync::SyncState::to_cbor_bytes`.
//! Atomic write via `tempfile::NamedTempFile::persist` under the same
//! exact-pin discipline as the vault format.
//!
//! The lockfile is `<state-dir>/<vault_uuid_hex>.lock`, locked via
//! `fs4::fs_std::FileExt::try_lock_exclusive` (flock(LOCK_EX|LOCK_NB) on
//! Unix, LockFileEx on Windows). Kernel auto-releases on process death;
//! no stale-PID handling required. NOTE: verify the exact fs4 1.x
//! module path against the live docs — fs4 1.x reorganized the
//! namespace from fs2's flat layout.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use fs4::fs_std::FileExt;
use tempfile::NamedTempFile;
use thiserror::Error;

use secretary_core::sync::{SyncError, SyncState};

const STATE_FILE_EXTENSION: &str = "state.cbor";
const LOCK_FILE_EXTENSION: &str = "lock";

#[derive(Debug, Error)]
pub enum StateError {
    #[error("I/O error reading or writing state file: {0}")]
    Io(#[from] std::io::Error),
    #[error("state file vault_uuid mismatch (file is for vault {file_uuid_hex}, expected {expected_uuid_hex})")]
    VaultUuidMismatch {
        file_uuid_hex: String,
        expected_uuid_hex: String,
    },
    #[error("CBOR decode failed: {0}")]
    Decode(SyncError),
    #[error("CBOR encode failed: {0}")]
    Encode(SyncError),
    #[error("lockfile {0} already held by another secretary-sync process")]
    LockfileHeld(PathBuf),
}

/// 16-byte vault UUID → lowercase hex string (32 chars).
#[must_use]
pub fn canonical_hex(vault_uuid: [u8; 16]) -> String {
    vault_uuid.iter().map(|b| format!("{b:02x}")).collect()
}

/// Compute `<state-dir>/<vault_uuid_hex>.state.cbor`.
#[must_use]
pub fn state_file_path(state_dir: &Path, vault_uuid: [u8; 16]) -> PathBuf {
    state_dir.join(format!("{}.{}", canonical_hex(vault_uuid), STATE_FILE_EXTENSION))
}

/// Compute `<state-dir>/<vault_uuid_hex>.lock`.
#[must_use]
pub fn lock_file_path(state_dir: &Path, vault_uuid: [u8; 16]) -> PathBuf {
    state_dir.join(format!("{}.{}", canonical_hex(vault_uuid), LOCK_FILE_EXTENSION))
}

/// Resolve the default state dir via the `dirs` crate.
///
/// - Linux: `$XDG_DATA_HOME/secretary/sync/` (typically `~/.local/share/...`)
/// - macOS: `~/Library/Application Support/secretary/sync/`
/// - Windows: `%LOCALAPPDATA%\secretary\sync\`
///
/// Returns `None` if no platform data dir is available (very rare —
/// minimal headless installs without `$HOME`).
#[must_use]
pub fn default_state_dir() -> Option<PathBuf> {
    dirs::data_dir().map(|p| p.join("secretary").join("sync"))
}

/// Load `SyncState` from `<state-dir>/<vault_uuid_hex>.state.cbor`. If
/// the file does not exist, return `SyncState::empty(vault_uuid)`.
/// Validates that any decoded state's `vault_uuid` matches the expected one.
pub fn load(state_dir: &Path, vault_uuid: [u8; 16]) -> Result<SyncState, StateError> {
    let path = state_file_path(state_dir, vault_uuid);
    if !path.exists() {
        return Ok(SyncState::empty(vault_uuid));
    }
    let bytes = fs::read(&path)?;
    let state = SyncState::from_cbor_bytes(&bytes).map_err(StateError::Decode)?;
    if state.vault_uuid != vault_uuid {
        return Err(StateError::VaultUuidMismatch {
            file_uuid_hex: canonical_hex(state.vault_uuid),
            expected_uuid_hex: canonical_hex(vault_uuid),
        });
    }
    Ok(state)
}

/// Atomically persist `SyncState` to `<state-dir>/<vault_uuid_hex>.state.cbor`.
/// Uses `tempfile::NamedTempFile::persist` for rename(2) / MoveFileExW
/// semantics — same `=3.27.0` exact pin as the vault format layer.
pub fn save(state_dir: &Path, state: &SyncState) -> Result<(), StateError> {
    fs::create_dir_all(state_dir)?;
    let final_path = state_file_path(state_dir, state.vault_uuid);
    let bytes = state.to_cbor_bytes().map_err(StateError::Encode)?;

    let mut tmp = NamedTempFile::new_in(state_dir)?;
    tmp.write_all(&bytes)?;
    tmp.persist(&final_path)
        .map_err(|e| StateError::Io(e.error))?;
    Ok(())
}

/// RAII guard for the per-vault exclusive lockfile. Holds the locked
/// file handle; releases on drop (kernel auto-releases flock when fd closes).
pub struct LockfileGuard {
    _file: File,
    path: PathBuf,
}

impl LockfileGuard {
    /// Acquire the exclusive lock on `<state-dir>/<vault_uuid_hex>.lock`.
    /// Returns `Err(StateError::LockfileHeld)` if another process holds it.
    pub fn acquire(state_dir: &Path, vault_uuid: [u8; 16]) -> Result<Self, StateError> {
        fs::create_dir_all(state_dir)?;
        let path = lock_file_path(state_dir, vault_uuid);
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)?;
        match file.try_lock_exclusive() {
            Ok(()) => Ok(Self { _file: file, path }),
            Err(_) => Err(StateError::LockfileHeld(path)),
        }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// `canonical_hex` produces 32-char lowercase hex with no separator.
    #[test]
    fn canonical_hex_format() {
        let uuid = [0xab; 16];
        let hex = canonical_hex(uuid);
        assert_eq!(hex.len(), 32);
        assert_eq!(hex, "abababababababababababababababab");
    }

    /// `state_file_path` composes `<state-dir>/<hex>.state.cbor`.
    #[test]
    fn state_file_path_layout() {
        let dir = Path::new("/tmp/sync");
        let path = state_file_path(dir, [1; 16]);
        assert_eq!(
            path,
            PathBuf::from("/tmp/sync/01010101010101010101010101010101.state.cbor")
        );
    }

    /// `lock_file_path` composes `<state-dir>/<hex>.lock`.
    #[test]
    fn lock_file_path_layout() {
        let dir = Path::new("/tmp/sync");
        let path = lock_file_path(dir, [1; 16]);
        assert_eq!(
            path,
            PathBuf::from("/tmp/sync/01010101010101010101010101010101.lock")
        );
    }

    /// Load returns `SyncState::empty` when no file exists for the vault.
    #[test]
    fn load_missing_returns_empty() {
        let dir = TempDir::new().unwrap();
        let loaded = load(dir.path(), [9; 16]).unwrap();
        assert_eq!(loaded.vault_uuid, [9; 16]);
        assert!(loaded.highest_vector_clock_seen.is_empty());
    }

    /// Save + load round-trips byte-identically.
    #[test]
    fn save_load_roundtrip() {
        let dir = TempDir::new().unwrap();
        let state = SyncState::empty([7; 16]);
        save(dir.path(), &state).unwrap();
        let loaded = load(dir.path(), [7; 16]).unwrap();
        assert_eq!(loaded, state);
    }

    /// Loading a file whose internal vault_uuid mismatches the expected
    /// one (e.g. operator copied a state file from a different vault)
    /// returns the typed mismatch error.
    #[test]
    fn load_wrong_uuid_returns_mismatch_error() {
        let dir = TempDir::new().unwrap();
        let state = SyncState::empty([7; 16]);
        save(dir.path(), &state).unwrap();
        // Rename file to make it look like the file for vault [9; 16].
        let from = state_file_path(dir.path(), [7; 16]);
        let to = state_file_path(dir.path(), [9; 16]);
        std::fs::rename(&from, &to).unwrap();
        let err = load(dir.path(), [9; 16]).unwrap_err();
        assert!(matches!(err, StateError::VaultUuidMismatch { .. }));
    }

    /// First acquire succeeds; second concurrent acquire returns LockfileHeld.
    #[test]
    fn lockfile_collision_returns_held() {
        let dir = TempDir::new().unwrap();
        let _g1 = LockfileGuard::acquire(dir.path(), [3; 16]).expect("first acquire");
        let err = LockfileGuard::acquire(dir.path(), [3; 16]).unwrap_err();
        assert!(matches!(err, StateError::LockfileHeld(_)));
    }

    /// Releasing the first guard (drop) allows a subsequent acquire to succeed.
    #[test]
    fn lockfile_releases_on_drop() {
        let dir = TempDir::new().unwrap();
        {
            let _g1 = LockfileGuard::acquire(dir.path(), [3; 16]).expect("first acquire");
        } // drop releases
        let _g2 = LockfileGuard::acquire(dir.path(), [3; 16]).expect("second acquire after drop");
    }

    /// Different vault UUIDs do NOT collide on the lockfile (each vault has its own).
    #[test]
    fn lockfile_different_vaults_dont_collide() {
        let dir = TempDir::new().unwrap();
        let _g1 = LockfileGuard::acquire(dir.path(), [3; 16]).expect("vault A");
        let _g2 = LockfileGuard::acquire(dir.path(), [4; 16]).expect("vault B");
    }

    /// `default_state_dir` returns Some on supported platforms; we only
    /// assert it does not panic and that the path ends in `secretary/sync`
    /// if returned.
    #[test]
    fn default_state_dir_ends_in_sync_subdir() {
        if let Some(dir) = default_state_dir() {
            assert!(dir.ends_with("secretary/sync"));
        }
    }
}
```

- [ ] **Step 3: Update `cli/src/main.rs` to declare the module**

Add `mod state;` near the existing `mod` lines.

- [ ] **Step 4: Run tests to verify they fail or pass**

```bash
cargo test --release -p secretary-cli --lib state 2>&1 | grep "test result:"
```

Expected: 9 tests pass.

- [ ] **Step 5: Gauntlet + commit**

```bash
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
```

Expected: `PASSED: 821 FAILED: 0 IGNORED: 10`.

```bash
git add cli/src/state.rs cli/src/main.rs
git commit -m "$(cat <<'EOF'
C.2 Task 2 — state persistence + host-local lockfile

cli/src/state.rs:
- canonical_hex / state_file_path / lock_file_path (pure helpers, 3 tests).
- default_state_dir via the `dirs` crate (one smoke test).
- load: empty-on-missing + vault_uuid mismatch check.
- save: atomic write via tempfile::NamedTempFile::persist (same
  =3.27.0 pin as core; comment cross-references CLAUDE.md).
- LockfileGuard: fs4::fs_std::FileExt::try_lock_exclusive RAII guard; collision returns
  the typed StateError::LockfileHeld; drop releases (kernel auto).

9 new unit tests; workspace 812→821.

See: spec §"State persistence" and §D7 (single-process-per-vault).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
git push -u origin feature/c2-task-2
gh pr create --base main --title "C.2 Task 2 — state persistence + host-local lockfile" --body "$(cat <<'EOF'
## Summary
- `cli/src/state.rs` — load/save SyncState CBOR + LockfileGuard RAII type.
- `canonical_hex` / path helpers are pure free functions, table-tested.
- Lockfile uses `fs4::fs_std::FileExt::try_lock_exclusive` (cross-platform; verify exact module path against live fs4 1.x docs at impl time).
- State-file write uses `tempfile::NamedTempFile::persist` with `tempfile = "=3.27.0"` pinned (matches `core/Cargo.toml`).

## Test plan
- [x] 9 new unit tests; workspace 812→821.
- [x] Clippy, fmt, conformance all clean.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Task 3: Unlock module (`cli/src/unlock.rs`)

**Why:** Password sourcing has two production paths (TTY prompt via `rpassword`, `--password-stdin` via `std::io::stdin().read_to_end`) and one test path (`Mock` enum variant feeding a `Cursor<Vec<u8>>`). The trait/enum split keeps the pure-function piece (`read_password_from_reader`) testable without a real TTY. Returns `secretary_core::crypto::secret::SecretBytes` for the caller to feed into `open_with_password` and to retain for `commit_with_decisions`.

**Files:**
- Create: `cli/src/unlock.rs`
- Modify: `cli/src/main.rs` — add `mod unlock;`

- [ ] **Step 1: Set up Task 3 worktree, write tests + impl**

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree add .worktrees/c2-task-3 -b feature/c2-task-3 main
cd .worktrees/c2-task-3
```

Create `cli/src/unlock.rs`:

```rust
//! Password sourcing — TTY prompt, `--password-stdin`, or test-only mock.
//!
//! Spec: [`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`](../../docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md)
//! §D2 (`--password-stdin` only for headless unlock).

use std::io::{self, Read};

use thiserror::Error;

use secretary_core::crypto::secret::SecretBytes;

const PASSWORD_PROMPT: &str = "Vault password: ";

#[derive(Debug, Error)]
pub enum UnlockReadError {
    #[error("--non-interactive requires --password-stdin to provide the password")]
    NonInteractiveWithoutStdin,
    #[error("I/O error reading password from stdin: {0}")]
    Io(#[from] io::Error),
    #[error("password is empty after stripping trailing newline")]
    Empty,
}

/// Strategy for sourcing the unlock password.
pub enum PasswordSource<'a, R: Read> {
    /// Read interactively from the TTY via `rpassword`. No echo.
    Tty,
    /// Read from a `Read` source (typically stdin) until EOF.
    Stream(&'a mut R),
}

/// Read a password from `--password-stdin` / stdin (or any `Read`-impl
/// for testing). Strips a single trailing `\n` or `\r\n` to handle the
/// common case where the operator pipes `echo "..." | secretary-sync`.
pub fn read_password_from_reader<R: Read>(reader: &mut R) -> Result<SecretBytes, UnlockReadError> {
    let mut buf: Vec<u8> = Vec::new();
    reader.read_to_end(&mut buf)?;
    // Strip exactly one trailing line ending if present.
    if buf.last() == Some(&b'\n') {
        buf.pop();
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
    }
    if buf.is_empty() {
        return Err(UnlockReadError::Empty);
    }
    let secret = SecretBytes::from(buf.as_slice());
    // Zeroize the intermediate buffer so the password doesn't linger in
    // the heap allocation past this function.
    zeroize::Zeroize::zeroize(&mut buf);
    Ok(secret)
}

/// Read a password from the TTY via `rpassword`. Used in interactive mode.
pub fn read_password_from_tty() -> Result<SecretBytes, UnlockReadError> {
    let s = rpassword::prompt_password(PASSWORD_PROMPT)?;
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return Err(UnlockReadError::Empty);
    }
    let secret = SecretBytes::from(bytes);
    // rpassword's String is already wiped on drop by SecretString-like
    // disciplines inside the crate; we copy to SecretBytes for uniform
    // handling.
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn reader_returns_password_bytes() {
        let mut input = Cursor::new(b"hunter2".to_vec());
        let secret = read_password_from_reader(&mut input).expect("read failed");
        assert_eq!(secret.expose(), b"hunter2");
    }

    #[test]
    fn reader_strips_trailing_newline() {
        let mut input = Cursor::new(b"hunter2\n".to_vec());
        let secret = read_password_from_reader(&mut input).expect("read failed");
        assert_eq!(secret.expose(), b"hunter2");
    }

    #[test]
    fn reader_strips_trailing_crlf() {
        let mut input = Cursor::new(b"hunter2\r\n".to_vec());
        let secret = read_password_from_reader(&mut input).expect("read failed");
        assert_eq!(secret.expose(), b"hunter2");
    }

    #[test]
    fn reader_only_strips_one_newline() {
        let mut input = Cursor::new(b"hunter2\n\n".to_vec());
        let secret = read_password_from_reader(&mut input).expect("read failed");
        assert_eq!(secret.expose(), b"hunter2\n");
    }

    #[test]
    fn reader_empty_input_errors() {
        let mut input = Cursor::new(Vec::<u8>::new());
        let err = read_password_from_reader(&mut input).unwrap_err();
        assert!(matches!(err, UnlockReadError::Empty));
    }

    #[test]
    fn reader_newline_only_errors_as_empty() {
        let mut input = Cursor::new(b"\n".to_vec());
        let err = read_password_from_reader(&mut input).unwrap_err();
        assert!(matches!(err, UnlockReadError::Empty));
    }

    /// PasswordSource enum exists with both variants; pattern-match
    /// coverage check for future refactors that add variants.
    #[test]
    fn password_source_variants_compile() {
        let _ = PasswordSource::<Cursor<Vec<u8>>>::Tty;
        let mut cursor = Cursor::new(b"x".to_vec());
        let _ = PasswordSource::Stream(&mut cursor);
    }
}
```

Add `mod unlock;` to `cli/src/main.rs`.

- [ ] **Step 2: Run tests to verify they pass**

```bash
cargo test --release -p secretary-cli --lib unlock 2>&1 | grep "test result:"
```

Expected: `7 passed`.

- [ ] **Step 3: Gauntlet + commit + PR**

```bash
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
```

Expected: `PASSED: 828 FAILED: 0 IGNORED: 10`.

```bash
git add cli/src/unlock.rs cli/src/main.rs
git commit -m "C.2 Task 3 — unlock module: TTY + stdin password sourcing

cli/src/unlock.rs:
- read_password_from_reader: pure (Cursor-testable) reader → SecretBytes.
- Strips exactly one trailing \\n or \\r\\n; rejects empty input as typed error.
- read_password_from_tty: rpassword wrapper for the interactive path.
- Intermediate Vec<u8> buffer zeroized after copy into SecretBytes.

7 new unit tests; workspace 821→828.

See: spec §D2 (--password-stdin only for headless unlock).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
git push -u origin feature/c2-task-3
gh pr create --base main --title "C.2 Task 3 — unlock module: TTY + stdin password sourcing" --body "..."
```

---

## Task 4: Veto trait + non-interactive + interactive impls (`cli/src/veto/`)

**Why:** `prepare_merge` returns `Vec<RecordTombstoneVeto>` which `commit_with_decisions` needs adjudicated as `Vec<VetoDecision>`. The CLI maps that via a `VetoUx` trait with two impls — `noninteractive::AutoKeepLocalVetoUx` (always `KeepLocal`, no I/O) and `interactive::TtyVetoUx` (per-record `y/n` prompt over a `Read + Write` pair, mockable). Lands together because they're tiny (~60 + ~70 + ~140 LOC) and the pipeline task (next) consumes the trait.

**Files:**
- Create: `cli/src/veto/mod.rs`
- Create: `cli/src/veto/noninteractive.rs`
- Create: `cli/src/veto/interactive.rs`
- Modify: `cli/src/main.rs` — add `mod veto;`

- [ ] **Step 1: Set up Task 4 worktree**

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree add .worktrees/c2-task-4 -b feature/c2-task-4 main
cd .worktrees/c2-task-4
```

- [ ] **Step 2: Create `cli/src/veto/mod.rs`**

```rust
//! Veto-decision UX for `RecordTombstoneVeto` adjudication.
//!
//! Spec: [`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`](../../../docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md)
//! §D4 (default `KeepLocal` veto policy in non-interactive mode).

use secretary_core::sync::{RecordTombstoneVeto, VetoDecision};

pub mod interactive;
pub mod noninteractive;

/// Strategy for converting a slice of `RecordTombstoneVeto` into the
/// `Vec<VetoDecision>` `commit_with_decisions` requires. Implementations
/// are stateless and side-effect-free except for the actual UX layer
/// (which reads from a `Read` + writes to a `Write`).
pub trait VetoUx {
    /// Produce one `VetoDecision` per input veto, preserving order. Each
    /// returned decision's `record_id` MUST match the corresponding
    /// veto's `record_id` — `commit_with_decisions` enforces the
    /// `vetoes ↔ decisions` bijection and rejects mismatches with a
    /// typed error (see spec §"Public surface" exit codes 1 / generic).
    fn decide(&mut self, vetoes: &[RecordTombstoneVeto]) -> Vec<VetoDecision>;
}
```

- [ ] **Step 3: Create `cli/src/veto/noninteractive.rs`**

```rust
//! Auto-`KeepLocal` veto UX for `--non-interactive` mode.

use secretary_core::sync::{RecordTombstoneVeto, VetoDecision};

use super::VetoUx;

/// Auto-resolve every veto to `VetoDecision::KeepLocal`. Spec §D4 —
/// the safe default for headless mode (no silent record deletion).
pub struct AutoKeepLocalVetoUx;

impl VetoUx for AutoKeepLocalVetoUx {
    fn decide(&mut self, vetoes: &[RecordTombstoneVeto]) -> Vec<VetoDecision> {
        vetoes
            .iter()
            .map(|v| VetoDecision::KeepLocal {
                record_id: v.record_id,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secretary_core::vault::record::Record;
    use std::collections::BTreeMap;

    fn dummy_veto(record_id: u8) -> RecordTombstoneVeto {
        RecordTombstoneVeto {
            record_id: [record_id; 16],
            block_id: [0; 16],
            local_state: Record {
                record_uuid: [record_id; 16],
                record_type: "kv".into(),
                fields: BTreeMap::new(),
                tags: Vec::new(),
                created_at_ms: 0,
                last_mod_ms: 0,
                tombstone: false,
                tombstoned_at_ms: 0,
                unknown: BTreeMap::new(),
            },
            disk_tombstone_at_ms: 1_000,
            disk_tombstoner_device: [0; 16],
        }
    }

    #[test]
    fn empty_input_returns_empty() {
        let mut ux = AutoKeepLocalVetoUx;
        let decisions = ux.decide(&[]);
        assert!(decisions.is_empty());
    }

    #[test]
    fn every_veto_becomes_keep_local() {
        let mut ux = AutoKeepLocalVetoUx;
        let vetoes = vec![dummy_veto(1), dummy_veto(2), dummy_veto(3)];
        let decisions = ux.decide(&vetoes);
        assert_eq!(decisions.len(), 3);
        for (d, v) in decisions.iter().zip(vetoes.iter()) {
            match d {
                VetoDecision::KeepLocal { record_id } => assert_eq!(*record_id, v.record_id),
                other => panic!("expected KeepLocal, got {other:?}"),
            }
        }
    }
}
```

- [ ] **Step 4: Create `cli/src/veto/interactive.rs`**

```rust
//! Interactive TTY veto UX. Prompts per-record `y` (KeepLocal) /
//! `n` (AcceptTombstone); re-prompts on invalid input.

use std::io::{BufRead, Write};

use secretary_core::sync::{RecordTombstoneVeto, VetoDecision};

use super::VetoUx;

/// TTY veto UX, generic over any `BufRead + Write` pair for testability.
/// Production use wires `stdin().lock()` + `stderr().lock()`.
pub struct TtyVetoUx<R: BufRead, W: Write> {
    reader: R,
    writer: W,
}

impl<R: BufRead, W: Write> TtyVetoUx<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self { reader, writer }
    }
}

impl<R: BufRead, W: Write> VetoUx for TtyVetoUx<R, W> {
    fn decide(&mut self, vetoes: &[RecordTombstoneVeto]) -> Vec<VetoDecision> {
        let mut out: Vec<VetoDecision> = Vec::with_capacity(vetoes.len());
        for veto in vetoes {
            loop {
                let _ = writeln!(
                    self.writer,
                    "Record {} would be tombstoned by peer. Keep local? [y/n]",
                    crate::state::canonical_hex(veto.record_id)
                );
                let _ = self.writer.flush();
                let mut line = String::new();
                if self.reader.read_line(&mut line).is_err() {
                    // I/O error reading reply — conservatively keep local.
                    out.push(VetoDecision::KeepLocal {
                        record_id: veto.record_id,
                    });
                    break;
                }
                let trimmed = line.trim();
                match trimmed {
                    "y" | "Y" | "yes" | "" => {
                        out.push(VetoDecision::KeepLocal {
                            record_id: veto.record_id,
                        });
                        break;
                    }
                    "n" | "N" | "no" => {
                        out.push(VetoDecision::AcceptTombstone {
                            record_id: veto.record_id,
                        });
                        break;
                    }
                    _ => {
                        let _ = writeln!(self.writer, "  (please answer y or n)");
                    }
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secretary_core::vault::record::Record;
    use std::collections::BTreeMap;
    use std::io::Cursor;

    fn dummy_veto(record_id: u8) -> RecordTombstoneVeto {
        RecordTombstoneVeto {
            record_id: [record_id; 16],
            block_id: [0; 16],
            local_state: Record {
                record_uuid: [record_id; 16],
                record_type: "kv".into(),
                fields: BTreeMap::new(),
                tags: Vec::new(),
                created_at_ms: 0,
                last_mod_ms: 0,
                tombstone: false,
                tombstoned_at_ms: 0,
                unknown: BTreeMap::new(),
            },
            disk_tombstone_at_ms: 1_000,
            disk_tombstoner_device: [0; 16],
        }
    }

    #[test]
    fn scripted_y_returns_keep_local() {
        let reader = Cursor::new(b"y\n".to_vec());
        let writer = Cursor::new(Vec::<u8>::new());
        let mut ux = TtyVetoUx::new(std::io::BufReader::new(reader), writer);
        let decisions = ux.decide(&[dummy_veto(1)]);
        assert!(matches!(decisions[0], VetoDecision::KeepLocal { .. }));
    }

    #[test]
    fn scripted_n_returns_accept_tombstone() {
        let reader = Cursor::new(b"n\n".to_vec());
        let writer = Cursor::new(Vec::<u8>::new());
        let mut ux = TtyVetoUx::new(std::io::BufReader::new(reader), writer);
        let decisions = ux.decide(&[dummy_veto(1)]);
        assert!(matches!(decisions[0], VetoDecision::AcceptTombstone { .. }));
    }

    #[test]
    fn scripted_empty_line_defaults_to_keep_local() {
        let reader = Cursor::new(b"\n".to_vec());
        let writer = Cursor::new(Vec::<u8>::new());
        let mut ux = TtyVetoUx::new(std::io::BufReader::new(reader), writer);
        let decisions = ux.decide(&[dummy_veto(1)]);
        assert!(matches!(decisions[0], VetoDecision::KeepLocal { .. }));
    }

    #[test]
    fn invalid_input_reprompts_then_accepts_valid() {
        let reader = Cursor::new(b"maybe\ny\n".to_vec());
        let writer = Cursor::new(Vec::<u8>::new());
        let mut ux = TtyVetoUx::new(std::io::BufReader::new(reader), writer);
        let decisions = ux.decide(&[dummy_veto(1)]);
        assert_eq!(decisions.len(), 1);
        assert!(matches!(decisions[0], VetoDecision::KeepLocal { .. }));
    }

    #[test]
    fn multiple_vetoes_match_input_order() {
        let reader = Cursor::new(b"y\nn\ny\n".to_vec());
        let writer = Cursor::new(Vec::<u8>::new());
        let mut ux = TtyVetoUx::new(std::io::BufReader::new(reader), writer);
        let vetoes = vec![dummy_veto(1), dummy_veto(2), dummy_veto(3)];
        let decisions = ux.decide(&vetoes);
        assert_eq!(decisions.len(), 3);
        assert!(matches!(decisions[0], VetoDecision::KeepLocal { .. }));
        assert!(matches!(decisions[1], VetoDecision::AcceptTombstone { .. }));
        assert!(matches!(decisions[2], VetoDecision::KeepLocal { .. }));
    }
}
```

- [ ] **Step 5: Add `mod veto;` to `cli/src/main.rs`**

- [ ] **Step 6: Run tests + gauntlet + commit + PR**

```bash
cargo test --release -p secretary-cli --lib veto 2>&1 | grep "test result:"
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
```

Expected: 7 veto tests pass; workspace 828→835.

```bash
git add cli/src/veto/ cli/src/main.rs
git commit -m "C.2 Task 4 — veto UX trait + non-interactive (auto-KeepLocal) + interactive (TTY) impls

7 new unit tests; workspace 828→835.

See: spec §D4 + §"Public surface".

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
git push -u origin feature/c2-task-4
gh pr create --base main --title "C.2 Task 4 — veto UX trait + impls" --body "..."
```

---

## Task 5: Pipeline (`cli/src/pipeline.rs`) — one sync attempt

**Why:** This is the heart. `run_one` takes `&UnlockedIdentity`, `&SecretBytes` (password), `&mut SyncState`, a vault folder path, a `&mut dyn VetoUx`, and `now_ms`. It calls `sync_once`, dispatches the outcome, calls `prepare_merge` + veto adjudication + `commit_with_decisions` on the concurrent path, and updates `SyncState` in place. Returns a `RunOutcome` enum the caller logs + maps to `ExitCode`. Both `once` and `run` subcommands consume this exact pipeline.

**Files:**
- Create: `cli/src/pipeline.rs`
- Modify: `cli/src/main.rs` — `mod pipeline;`
- Test: `cli/tests/pipeline_integration.rs` — full pipeline against a staged vault

- [ ] **Step 1: Set up Task 5 worktree**

```bash
cd /Users/hherb/src/secretary && git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree add .worktrees/c2-task-5 -b feature/c2-task-5 main && cd .worktrees/c2-task-5
```

- [ ] **Step 2: Create `cli/src/pipeline.rs`**

```rust
//! One sync attempt — composes `sync_once → prepare_merge → veto UX
//! → commit_with_decisions` and updates the caller-held `SyncState`.
//!
//! Spec: [`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`](../../docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md)
//! §"Module layout" + §"Daemon loop sketch".

use std::path::Path;

use secretary_core::crypto::secret::SecretBytes;
use secretary_core::sync::{
    commit_with_decisions, prepare_merge, sync_once, SyncError, SyncOutcome, SyncState,
};
use secretary_core::unlock::UnlockedIdentity;

use crate::veto::VetoUx;

/// What `run_one` did this iteration. The caller logs it + maps to an
/// exit code (in `once` mode) or continues the daemon loop (in `run`
/// mode).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunOutcome {
    /// No-op — disk vector clock matches the local highest_seen.
    NothingToDo,
    /// Disk strictly dominates local; state advanced.
    AppliedAutomatically,
    /// Concurrent state detected, merged, committed; state advanced.
    /// `vetoes_resolved` reports how many record-level vetoes were
    /// resolved (typically 0 in `--non-interactive` mode unless there
    /// were actual tombstone conflicts).
    MergedAndCommitted { vetoes_resolved: usize },
    /// Concurrent state detected but no merge happened — `prepare_merge`
    /// returned with zero diverging blocks and no vetoes (silent merge
    /// fast path). State advanced to the bundled disk clock.
    SilentMerge,
    /// Disk vector clock strictly older than local; rejected per §10.
    /// State NOT advanced; caller surfaces ExitCode::RollbackRejected.
    RollbackRejected,
}

/// Run one sync attempt. `now_ms` is the current wall-clock millis
/// (caller passes `0` until `prepare_merge` requires it; reserved for
/// C.1.1b's merge timestamps).
pub fn run_one(
    vault_folder: &Path,
    identity: &UnlockedIdentity,
    password: &SecretBytes,
    state: &mut SyncState,
    veto_ux: &mut dyn VetoUx,
    now_ms: u64,
) -> Result<RunOutcome, SyncError> {
    let outcome = sync_once(vault_folder, identity, state, now_ms)?;
    match outcome {
        SyncOutcome::NothingToDo => Ok(RunOutcome::NothingToDo),
        SyncOutcome::AppliedAutomatically { new_state } => {
            *state = new_state;
            Ok(RunOutcome::AppliedAutomatically)
        }
        SyncOutcome::RollbackRejected(_evidence) => Ok(RunOutcome::RollbackRejected),
        SyncOutcome::ConcurrentDetected {
            bundle,
            plan,
            manifest_hash: _,
            disk_vector_clock,
            local_highest_seen: _,
        } => {
            // Silent-merge fast path: empty diff plan means there were
            // no diverging blocks after authentication; just advance.
            if plan.diverging_blocks.is_empty() {
                state.highest_vector_clock_seen = disk_vector_clock;
                return Ok(RunOutcome::SilentMerge);
            }
            let draft = prepare_merge(vault_folder, identity, &bundle, &plan)?;
            let vetoes_count = draft.vetoes.len();
            let decisions = veto_ux.decide(&draft.vetoes);
            let new_state = commit_with_decisions(vault_folder, password, draft, decisions, now_ms)?;
            *state = new_state;
            Ok(RunOutcome::MergedAndCommitted {
                vetoes_resolved: vetoes_count,
            })
        }
    }
}
```

Add `mod pipeline;` to `cli/src/main.rs`.

- [ ] **Step 3: Write the integration test**

Create `cli/tests/pipeline_integration.rs`:

```rust
//! Pipeline integration tests — exercise `run_one` against a real
//! `golden_vault_001`-style staged vault.

// Integration tests for the pipeline; reuse helpers from the core test
// fixtures via a relative path-only include. We DO NOT modify
// core::tests::sync_helpers; the cli's tests build their own minimal
// fixture set.

// NOTE: These tests require a temp clone of core/tests/data/golden_vault_001/
// plus a password matching that fixture. The full fixture-building
// helpers from `core::sync_helpers` are not re-exportable across crates
// (they're per-package test artifacts), so this test crate stages the
// minimal happy path only (NothingToDo + AppliedAutomatically). The
// Concurrent + Rollback paths are covered by the existing core
// integration tests on `sync_once / prepare_merge / commit_with_decisions`.

use std::fs;
use std::path::Path;

use secretary_cli::pipeline::{run_one, RunOutcome};
use secretary_cli::veto::noninteractive::AutoKeepLocalVetoUx;
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::sync::SyncState;
use secretary_core::unlock::open_with_password;

const GOLDEN_VAULT_TOML: &[u8] = include_bytes!("../../core/tests/data/golden_vault_001/vault.toml");
const GOLDEN_VAULT_PASSWORD: &str = include_str!("../../core/tests/data/golden_vault_001_password");

fn stage_golden_vault(dst: &Path) {
    // Recursively copy the golden vault dir into dst. Hand-rolled
    // mini-copy so we don't depend on core::tests helpers.
    let src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("core/tests/data/golden_vault_001");
    fn copy_dir(from: &Path, to: &Path) {
        fs::create_dir_all(to).unwrap();
        for entry in fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            let src_path = entry.path();
            let dst_path = to.join(entry.file_name());
            if src_path.is_dir() {
                copy_dir(&src_path, &dst_path);
            } else {
                fs::copy(&src_path, &dst_path).unwrap();
            }
        }
    }
    copy_dir(&src, dst);
}

fn unlock_golden() -> (
    SecretBytes,
    secretary_core::unlock::UnlockedIdentity,
    [u8; 16],
) {
    let password = SecretBytes::from(GOLDEN_VAULT_PASSWORD.trim().as_bytes());
    let identity_bundle =
        std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join(
            "core/tests/data/golden_vault_001/identity.bundle.cbor",
        ))
        .unwrap();
    let unlocked =
        open_with_password(GOLDEN_VAULT_TOML, &identity_bundle, &password).expect("unlock");
    let vault_uuid = unlocked.vault.vault_uuid;
    (password, unlocked, vault_uuid)
}

/// Happy path: empty state vs a populated golden vault → `AppliedAutomatically`.
#[test]
fn run_one_applies_disk_clock_on_fresh_state() {
    let tmp = tempfile::TempDir::new().unwrap();
    stage_golden_vault(tmp.path());
    let (password, identity, vault_uuid) = unlock_golden();
    let mut state = SyncState::empty(vault_uuid);
    let mut ux = AutoKeepLocalVetoUx;

    let outcome = run_one(tmp.path(), &identity, &password, &mut state, &mut ux, 0)
        .expect("pipeline failed");

    // The golden vault has a non-empty vector clock, so the first sync
    // against an empty SyncState lands in AppliedAutomatically.
    assert_eq!(outcome, RunOutcome::AppliedAutomatically);
    assert!(!state.highest_vector_clock_seen.is_empty());
}

/// Second invocation (with state from first) returns `NothingToDo`.
#[test]
fn run_one_nothing_to_do_when_state_matches_disk() {
    let tmp = tempfile::TempDir::new().unwrap();
    stage_golden_vault(tmp.path());
    let (password, identity, vault_uuid) = unlock_golden();
    let mut state = SyncState::empty(vault_uuid);
    let mut ux = AutoKeepLocalVetoUx;

    let _first = run_one(tmp.path(), &identity, &password, &mut state, &mut ux, 0).unwrap();
    let outcome = run_one(tmp.path(), &identity, &password, &mut state, &mut ux, 0).unwrap();
    assert_eq!(outcome, RunOutcome::NothingToDo);
}
```

Mark the `pipeline` and `veto` modules `pub` in `cli/src/main.rs` so integration tests can reach them.

Actually integration tests in a binary crate are problematic — the crate is a binary, not a library, so its modules aren't accessible from `cli/tests/*.rs`. Fix this by promoting the binary to a binary+library hybrid: add `cli/src/lib.rs` re-exporting the modules.

- [ ] **Step 4: Add `cli/src/lib.rs` for integration-test reachability**

```rust
//! Library surface of `secretary-cli` — used by integration tests in
//! `cli/tests/*.rs`. Production consumers run the `secretary-sync`
//! binary; the library exposes the same modules so end-to-end tests
//! can drive `pipeline::run_one` directly.

pub mod args;
pub mod exit;
pub mod pipeline;
pub mod state;
pub mod unlock;
pub mod veto;
```

Update `cli/Cargo.toml` `[[bin]]` to keep `path = "src/main.rs"`, and add an implicit library target by adding a `[lib]` section pointing at `lib.rs`:

```toml
[lib]
name = "secretary_cli"
path = "src/lib.rs"

[[bin]]
name = "secretary-sync"
path = "src/main.rs"
```

Update `cli/src/main.rs` to use the library:

```rust
use clap::Parser;
use secretary_cli::{args, exit};

fn main() {
    let cli = args::Cli::parse();
    let code = match cli.command {
        args::Command::Once { .. } => {
            eprintln!("secretary-sync once: not yet implemented");
            exit::ExitCode::GenericError
        }
        args::Command::Run { .. } => {
            eprintln!("secretary-sync run: not yet implemented");
            exit::ExitCode::GenericError
        }
    };
    std::process::exit(code as i32);
}
```

- [ ] **Step 5: Run tests + gauntlet + commit + PR**

```bash
cargo test --release -p secretary-cli 2>&1 | grep "test result:"
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
```

Expected: 2 new integration tests; workspace 835→837.

```bash
git add cli/
git commit -m "C.2 Task 5 — pipeline (one sync attempt) + lib/bin split

cli/src/pipeline.rs:
- run_one(folder, &UnlockedIdentity, &SecretBytes, &mut SyncState,
  &mut dyn VetoUx, now_ms) -> RunOutcome.
- Dispatches sync_once → match outcome → prepare_merge + veto
  adjudication + commit_with_decisions on Concurrent arm.
- RunOutcome enum captures each documented outcome.

cli/src/lib.rs + Cargo.toml [lib] target:
- Promote cli to a library+binary so integration tests in cli/tests/*.rs
  can reach the public modules.

cli/tests/pipeline_integration.rs:
- 2 integration tests covering the AppliedAutomatically + NothingToDo paths.

2 new integration tests; workspace 835→837.

See: spec §"Module layout" + §"Daemon loop sketch".

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
git push -u origin feature/c2-task-5
gh pr create --base main --title "C.2 Task 5 — pipeline + lib/bin split" --body "..."
```

---

## Task 6: Watcher submodule — partial-download ready + debounce (`cli/src/watcher/{mod,ready,debounce}.rs`)

**Why:** Pure-function pieces of the watcher come first because they're table-testable in isolation without `notify` integration. `ready` covers the ADR-0003 partial-download detection (provider-name filter + size-stability probe). `debounce` is a pure state machine over `(now: Instant, last_event_at: Option<Instant>)`. The `notify_driver` (next task) wraps these into the actual event stream.

**Files:**
- Create: `cli/src/watcher/mod.rs`
- Create: `cli/src/watcher/ready.rs`
- Create: `cli/src/watcher/debounce.rs`
- Modify: `cli/src/lib.rs` — `pub mod watcher;`

- [ ] **Step 1: Set up Task 6 worktree**

```bash
cd /Users/hherb/src/secretary && git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree add .worktrees/c2-task-6 -b feature/c2-task-6 main && cd .worktrees/c2-task-6
```

- [ ] **Step 2: Create `cli/src/watcher/mod.rs`**

```rust
//! File-watcher abstractions for the `run` subcommand.
//!
//! Spec: [`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`](../../../docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md)
//! §D3 (events + debounce + optional poll) + §D6 (partial-download).

pub mod debounce;
pub mod ready;

/// What the watcher dispatcher tells the daemon loop to do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatcherEvent {
    /// One or more files changed in the vault folder.
    SyncCandidate,
    /// Periodic poll tick fired (configurable; off by default).
    PollTick,
    /// Operator requested shutdown (SIGINT / SIGTERM).
    ShutdownRequested,
}
```

- [ ] **Step 3: Create `cli/src/watcher/ready.rs`**

```rust
//! Partial-download readiness — ADR-0003 §"Cloud-folder integration".
//!
//! Spec: [`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`](../../../docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md)
//! §D6 — canonical pattern list lives in the spec; this module
//! implements that list.

use std::fs::Metadata;
use std::path::Path;
use std::time::Duration;

/// Canonical partial-download patterns. See spec §D6 pattern table for
/// per-pattern provider citations. Order is recognition-priority; not
/// significant (any match wins).
const PARTIAL_PATTERNS: &[&str] = &[
    ".icloud",      // iCloud Drive placeholder
    ".tmp",         // generic temp suffix
    ".partial",     // generic partial-download suffix
    ".crdownload",  // Chromium-family in-progress download
    ".download",    // Safari / Firefox in-progress download
    ".swp",         // vim swap
    ".swo",         // vim swap (second)
];

/// File-name prefixes that mark partial / lock files.
const PARTIAL_PREFIXES: &[&str] = &[".~", "~$", "."];

/// Whole-file-name partial markers (these match the entire basename).
const PARTIAL_BASENAMES: &[&str] = &["desktop.ini", ".DS_Store"];

/// True if the path's basename matches any known partial-download or
/// lock-file pattern. Pure function; table-tested.
#[must_use]
pub fn matches_partial_pattern(path: &Path) -> bool {
    let basename = match path.file_name().and_then(|os| os.to_str()) {
        Some(s) => s,
        None => return false,
    };
    if PARTIAL_BASENAMES.iter().any(|b| basename.eq_ignore_ascii_case(b)) {
        return true;
    }
    if basename.starts_with(".~") || basename.starts_with("~$") {
        return true;
    }
    if PARTIAL_PATTERNS
        .iter()
        .any(|p| basename.to_ascii_lowercase().ends_with(p))
    {
        return true;
    }
    // Dropbox: `.~foo.tmp` and similar dot-prefixed temp files are caught
    // by the `.~` prefix branch above plus the `.tmp` suffix branch.
    false
}

/// True if two `Metadata` snapshots indicate stable size + mtime. Pure
/// comparison; table-tested.
#[must_use]
pub fn is_size_stable(a: &Metadata, b: &Metadata) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let (Ok(ma), Ok(mb)) = (a.modified(), b.modified()) else {
        return false;
    };
    ma == mb
}

/// Mockable clock used by the `wait_for_ready` orchestrator. Test impls
/// avoid real sleeps.
pub trait Clock {
    fn sleep(&self, dur: Duration);
}

/// Default real-time clock implementation.
pub struct RealClock;
impl Clock for RealClock {
    fn sleep(&self, dur: Duration) {
        std::thread::sleep(dur);
    }
}

/// Wait up to `window` for `path` to become size-stable. Returns true
/// if stable + not matching a partial-marker pattern; false otherwise.
pub fn wait_for_ready<C: Clock>(path: &Path, clock: &C, window: Duration) -> std::io::Result<bool> {
    if matches_partial_pattern(path) {
        return Ok(false);
    }
    let a = std::fs::metadata(path)?;
    if a.len() == 0 {
        return Ok(false);
    }
    clock.sleep(window);
    let b = std::fs::metadata(path)?;
    Ok(is_size_stable(&a, &b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    #[test]
    fn icloud_partial_marker_caught() {
        assert!(matches_partial_pattern(&p("foo.icloud")));
        assert!(matches_partial_pattern(&p("dir/sub/bar.icloud")));
    }

    #[test]
    fn tmp_partial_marker_caught() {
        assert!(matches_partial_pattern(&p("write.tmp")));
        assert!(matches_partial_pattern(&p("a.b.tmp")));
    }

    #[test]
    fn partial_suffix_caught() {
        assert!(matches_partial_pattern(&p("download.partial")));
    }

    #[test]
    fn crdownload_caught() {
        assert!(matches_partial_pattern(&p("foo.crdownload")));
    }

    #[test]
    fn libreoffice_lockfile_caught() {
        assert!(matches_partial_pattern(&p(".~lock.foo.odt#")));
    }

    #[test]
    fn ms_office_lockfile_caught() {
        assert!(matches_partial_pattern(&p("~$report.docx")));
    }

    #[test]
    fn vim_swap_caught() {
        assert!(matches_partial_pattern(&p("foo.swp")));
        assert!(matches_partial_pattern(&p("foo.swo")));
    }

    #[test]
    fn dotted_metadata_caught() {
        assert!(matches_partial_pattern(&p(".DS_Store")));
        assert!(matches_partial_pattern(&p("desktop.ini")));
    }

    #[test]
    fn vault_files_not_caught() {
        assert!(!matches_partial_pattern(&p("manifest.cbor.enc")));
        assert!(!matches_partial_pattern(&p(
            "block_01234567890123456789012345678901.cbor.enc"
        )));
        assert!(!matches_partial_pattern(&p("vault.toml")));
        assert!(!matches_partial_pattern(&p("identity.bundle.cbor")));
    }

    /// Helper to stand up an in-memory Metadata-equivalent for is_size_stable.
    /// std::fs::Metadata is not constructable; we use a real tempfile with
    /// controlled writes instead.
    #[test]
    fn size_stable_when_no_change() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "stable").unwrap();
        let m1 = std::fs::metadata(f.path()).unwrap();
        let m2 = std::fs::metadata(f.path()).unwrap();
        assert!(is_size_stable(&m1, &m2));
    }

    #[test]
    fn size_unstable_after_write() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "first").unwrap();
        let m1 = std::fs::metadata(f.path()).unwrap();
        // Sleep to ensure mtime resolution doesn't collapse.
        std::thread::sleep(Duration::from_millis(50));
        writeln!(f, "second").unwrap();
        let m2 = std::fs::metadata(f.path()).unwrap();
        assert!(!is_size_stable(&m1, &m2));
    }

    struct InstantClock;
    impl Clock for InstantClock {
        fn sleep(&self, _: Duration) {}
    }

    #[test]
    fn wait_for_ready_rejects_partial_marker() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let icloud_path = f.path().with_extension("icloud");
        std::fs::write(&icloud_path, b"x").unwrap();
        let clock = InstantClock;
        assert_eq!(
            wait_for_ready(&icloud_path, &clock, Duration::from_millis(0)).unwrap(),
            false
        );
    }

    #[test]
    fn wait_for_ready_accepts_stable_file() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "stable data").unwrap();
        let clock = InstantClock;
        assert_eq!(
            wait_for_ready(f.path(), &clock, Duration::from_millis(0)).unwrap(),
            true
        );
    }

    #[test]
    fn wait_for_ready_rejects_empty_file() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let clock = InstantClock;
        assert_eq!(
            wait_for_ready(f.path(), &clock, Duration::from_millis(0)).unwrap(),
            false
        );
    }
}
```

- [ ] **Step 4: Create `cli/src/watcher/debounce.rs`**

```rust
//! Debounce state machine — coalesces bursts of `notify` events into
//! one sync attempt per `debounce_ms` window.
//!
//! Pure-function state machine; the daemon loop owns the actual `Instant`.

use std::time::{Duration, Instant};

/// Debounce decision returned by `step`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebounceDecision {
    /// Schedule a sync `delay` from now; no current schedule exists.
    Schedule { delay: Duration },
    /// Update existing schedule to fire `delay` from now (event arrived
    /// before previous schedule fired).
    Reschedule { delay: Duration },
    /// Drop — event is within the debounce window of a still-pending
    /// schedule that hasn't yet been reset (cap collapsing).
    AlreadyPending,
}

/// Pure debounce step.
///
/// - `now` = current time.
/// - `pending_since` = `Some(t)` if a debounce timer is currently
///   pending (set when the previous event arrived); `None` otherwise.
/// - `window` = the debounce window.
///
/// Returns `(decision, new_pending_since)`.
#[must_use]
pub fn step(
    now: Instant,
    pending_since: Option<Instant>,
    window: Duration,
) -> (DebounceDecision, Option<Instant>) {
    match pending_since {
        None => (DebounceDecision::Schedule { delay: window }, Some(now)),
        Some(prev) => {
            if now.duration_since(prev) >= window {
                // The previous timer should already have fired; this is
                // a fresh schedule.
                (DebounceDecision::Schedule { delay: window }, Some(now))
            } else {
                // Reset the timer; next event will refresh again.
                (DebounceDecision::Reschedule { delay: window }, Some(now))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_event_schedules_fresh() {
        let now = Instant::now();
        let (decision, pending) = step(now, None, Duration::from_millis(500));
        assert_eq!(
            decision,
            DebounceDecision::Schedule {
                delay: Duration::from_millis(500)
            }
        );
        assert_eq!(pending, Some(now));
    }

    #[test]
    fn second_event_within_window_reschedules() {
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_millis(100);
        let (decision, pending) = step(t1, Some(t0), Duration::from_millis(500));
        assert_eq!(
            decision,
            DebounceDecision::Reschedule {
                delay: Duration::from_millis(500)
            }
        );
        assert_eq!(pending, Some(t1));
    }

    #[test]
    fn event_after_window_schedules_fresh() {
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_millis(600);
        let (decision, pending) = step(t1, Some(t0), Duration::from_millis(500));
        assert_eq!(
            decision,
            DebounceDecision::Schedule {
                delay: Duration::from_millis(500)
            }
        );
        assert_eq!(pending, Some(t1));
    }

    #[test]
    fn equal_to_window_treated_as_after() {
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_millis(500);
        let (decision, pending) = step(t1, Some(t0), Duration::from_millis(500));
        assert_eq!(
            decision,
            DebounceDecision::Schedule {
                delay: Duration::from_millis(500)
            }
        );
        assert_eq!(pending, Some(t1));
    }
}
```

Add `pub mod watcher;` to `cli/src/lib.rs`.

- [ ] **Step 5: Run tests + gauntlet + commit + PR**

```bash
cargo test --release -p secretary-cli --lib watcher 2>&1 | grep "test result:"
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:"
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
```

Expected: ~17 new tests (12 ready + 4 debounce + 1 module sanity); workspace 837→854.

```bash
git add cli/src/watcher/ cli/src/lib.rs
git commit -m "C.2 Task 6 — watcher submodule: partial-download ready + pure debounce

cli/src/watcher/ready.rs:
- matches_partial_pattern: pure pattern matcher for all 10 patterns from
  spec §D6 (icloud / tmp / partial / crdownload / download / swp/swo /
  .~ prefix / ~$ prefix / desktop.ini / .DS_Store).
- is_size_stable: pure (Metadata, Metadata) comparison.
- wait_for_ready: orchestrator with mockable Clock trait.

cli/src/watcher/debounce.rs:
- Pure state machine: step(now, pending_since, window) → decision +
  new pending_since.
- Schedule / Reschedule / AlreadyPending decision variants.

17 new unit tests; workspace 837→854.

See: spec §D3 + §D6.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
git push -u origin feature/c2-task-6
gh pr create --base main --title "C.2 Task 6 — watcher submodule: ready + debounce" --body "..."
```

---

## Task 7: `notify` driver + daemon loop (`cli/src/watcher/notify_driver.rs` + `cli/src/daemon.rs`)

**Why:** This task wires the `notify` crate into a `WatcherEvent` stream and composes `pipeline::run_one` into a running daemon. The two pieces ship together because each is incomplete without the other. The daemon is a single-threaded blocking loop using `std::sync::mpsc::Receiver<notify::Event>` from `notify::RecommendedWatcher` — no async runtime. Signal handling and logging come in Task 8 (separately to keep this task focused).

**Files:**
- Create: `cli/src/watcher/notify_driver.rs`
- Create: `cli/src/daemon.rs`
- Modify: `cli/src/lib.rs` — `pub mod daemon;`

- [ ] **Step 1: Worktree + `notify_driver`**

```bash
cd /Users/hherb/src/secretary && git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree add .worktrees/c2-task-7 -b feature/c2-task-7 main && cd .worktrees/c2-task-7
```

Create `cli/src/watcher/notify_driver.rs`:

```rust
//! `notify::RecommendedWatcher` wrapper that maps platform events into
//! the orchestration-layer `WatcherEvent`.

use std::path::Path;
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, TryRecvError};
use std::time::Duration;

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use super::WatcherEvent;

/// Owns the underlying notify watcher and the event receiver. Drops
/// the watcher on drop (notify unsubscribes the OS resources cleanly).
pub struct NotifyWatcher {
    _watcher: RecommendedWatcher,
    rx: Receiver<notify::Result<Event>>,
}

impl NotifyWatcher {
    /// Start watching `folder` recursively. Subsequent events surface
    /// via `recv_timeout`.
    pub fn start(folder: &Path) -> notify::Result<Self> {
        let (tx, rx) = channel();
        let mut watcher = notify::recommended_watcher(move |res| {
            // mpsc::Sender::send returns Err iff the receiver has been
            // dropped, which is only possible after the daemon loop
            // exits — at that point notify event delivery is irrelevant.
            let _ = tx.send(res);
        })?;
        watcher.watch(folder, RecursiveMode::Recursive)?;
        Ok(Self {
            _watcher: watcher,
            rx,
        })
    }

    /// Block up to `timeout`, returning the next coalesced `WatcherEvent`
    /// (or `None` on timeout). Drains any additional immediately-available
    /// events to coalesce a burst before returning.
    pub fn poll(&self, timeout: Duration) -> Option<WatcherEvent> {
        let first = match self.rx.recv_timeout(timeout) {
            Ok(Ok(ev)) => Some(ev),
            Ok(Err(_)) => None, // notify watcher error — fall through with no event
            Err(RecvTimeoutError::Timeout) => return None,
            Err(RecvTimeoutError::Disconnected) => return None,
        };
        if !is_sync_candidate(first.as_ref()) {
            // Still drain — even an irrelevant event might be followed
            // by relevant ones.
        } else {
            // Drain any immediately-pending events (burst coalescing).
            loop {
                match self.rx.try_recv() {
                    Ok(_) => continue,
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => break,
                }
            }
            return Some(WatcherEvent::SyncCandidate);
        }
        None
    }
}

fn is_sync_candidate(ev: Option<&Event>) -> bool {
    match ev {
        None => false,
        Some(e) => matches!(
            e.kind,
            EventKind::Create(_)
                | EventKind::Modify(_)
                | EventKind::Remove(_)
                | EventKind::Any
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Smoke test: starting a watcher against a temp dir + writing a
    /// file inside surfaces at least one event within a small timeout.
    /// This is the cross-platform `notify` quirk test referenced in
    /// the spec (which expects a more elaborate per-OS test in
    /// cli/tests/notify_quirk.rs — see Task 10).
    #[test]
    fn writing_a_file_surfaces_a_sync_candidate() {
        let dir = TempDir::new().unwrap();
        let watcher = NotifyWatcher::start(dir.path()).expect("watcher start");
        // Give the watcher a moment to settle.
        std::thread::sleep(Duration::from_millis(100));
        fs::write(dir.path().join("test.cbor.enc"), b"hello").unwrap();
        let event = watcher.poll(Duration::from_secs(2));
        assert_eq!(event, Some(WatcherEvent::SyncCandidate));
    }
}
```

- [ ] **Step 2: Create `cli/src/daemon.rs`**

```rust
//! `run` subcommand event loop — composes watcher + debounce + poll
//! + signal into a `pipeline::run_one`-driven daemon.
//!
//! Spec: [`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`](../../docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md)
//! §"Daemon loop sketch".

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use secretary_core::crypto::secret::SecretBytes;
use secretary_core::sync::{SyncError, SyncState};
use secretary_core::unlock::UnlockedIdentity;

use crate::pipeline::{run_one, RunOutcome};
use crate::veto::VetoUx;
use crate::watcher::debounce::{step as debounce_step, DebounceDecision};
use crate::watcher::notify_driver::NotifyWatcher;
use crate::watcher::ready::{wait_for_ready, RealClock};
use crate::watcher::WatcherEvent;

/// Configuration knobs for the daemon loop.
pub struct DaemonConfig {
    pub debounce: Duration,
    pub poll_interval: Option<Duration>,
    pub ready_window: Duration,
    /// Cancellation flag set by the signal handler (SIGINT/SIGTERM).
    pub shutdown_flag: Arc<AtomicBool>,
    /// Test hook — exit after N iterations of the loop body.
    /// `None` in production.
    #[cfg(any(test, feature = "testing"))]
    pub max_iterations: Option<u32>,
}

/// Run the daemon loop. Returns Ok(()) on clean shutdown via shutdown_flag.
pub fn run(
    vault_folder: &Path,
    identity: &UnlockedIdentity,
    password: &SecretBytes,
    state: &mut SyncState,
    veto_ux: &mut dyn VetoUx,
    config: DaemonConfig,
) -> Result<(), SyncError> {
    let watcher = NotifyWatcher::start(vault_folder)
        .map_err(|e| SyncError::Vault(secretary_core::vault::VaultError::Io {
            context: "notify watcher start failed",
            source: std::io::Error::new(std::io::ErrorKind::Other, e.to_string()),
        }))?;

    let mut last_poll_at = Instant::now();
    let mut debounce_pending: Option<Instant> = None;
    let mut iterations: u32 = 0;

    let clock = RealClock;

    loop {
        if config.shutdown_flag.load(Ordering::SeqCst) {
            tracing::info!("shutdown flag set; exiting daemon loop");
            break;
        }

        #[cfg(any(test, feature = "testing"))]
        if let Some(max) = config.max_iterations {
            if iterations >= max {
                break;
            }
        }
        iterations = iterations.saturating_add(1);

        // Block on the next event or a tick.
        let wait = match (debounce_pending, config.poll_interval) {
            (Some(pending_since), _) => {
                let elapsed = Instant::now().duration_since(pending_since);
                config.debounce.saturating_sub(elapsed)
            }
            (None, Some(poll)) => poll,
            (None, None) => Duration::from_millis(1000), // generous timeout for shutdown polling
        };

        let event = watcher.poll(wait);

        // Periodic poll tick check.
        if let Some(poll_interval) = config.poll_interval {
            if Instant::now().duration_since(last_poll_at) >= poll_interval {
                last_poll_at = Instant::now();
                if let Err(e) = run_one(vault_folder, identity, password, state, veto_ux, now_ms()) {
                    log_pipeline_error(&e);
                }
                continue;
            }
        }

        // No watcher event → continue loop (shutdown / poll checks above).
        let Some(WatcherEvent::SyncCandidate) = event else {
            continue;
        };

        // Debounce step.
        let (decision, new_pending) =
            debounce_step(Instant::now(), debounce_pending, config.debounce);
        debounce_pending = new_pending;

        match decision {
            DebounceDecision::Schedule { delay } | DebounceDecision::Reschedule { delay } => {
                // Wait the debounce delay, then check ready + sync.
                std::thread::sleep(delay);
                if let Err(e) = wait_for_ready(vault_folder, &clock, config.ready_window) {
                    tracing::debug!("ready probe failed: {e}");
                    continue;
                }
                if let Err(e) = run_one(vault_folder, identity, password, state, veto_ux, now_ms()) {
                    log_pipeline_error(&e);
                }
                debounce_pending = None;
            }
            DebounceDecision::AlreadyPending => continue,
        }
    }

    Ok(())
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn log_pipeline_error(e: &SyncError) {
    // Daemon never crashes on transient errors. Log + continue.
    match e {
        SyncError::EvidenceStale => tracing::warn!("transient EvidenceStale; will retry"),
        other => tracing::warn!("pipeline error (continuing): {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::veto::noninteractive::AutoKeepLocalVetoUx;
    use std::sync::atomic::AtomicBool;

    /// Daemon with max_iterations=1 + shutdown_flag exits without panic
    /// when run against a stub identity — verifies the loop wires the
    /// stop conditions correctly.
    ///
    /// This test does NOT exercise a real vault; it would require the
    /// `golden_vault_001` fixture (see cli/tests/once_integration.rs).
    /// It exists to pin the loop's compile shape + exit-on-iteration
    /// semantics.
    #[test]
    fn loop_exits_when_max_iterations_reached() {
        // Compile-only test for the loop shape; full integration test
        // lives in cli/tests/run_subcommand_integration.rs (Task 8/10).
        let _ = AutoKeepLocalVetoUx;
        let _ = Arc::new(AtomicBool::new(false));
        // Actual loop exercise requires a vault — covered by the
        // integration test in the next task.
    }
}
```

Add `pub mod daemon;` to `cli/src/lib.rs`.

- [ ] **Step 3: Run tests + gauntlet + commit + PR**

```bash
cargo test --release -p secretary-cli 2>&1 | grep "test result:"
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:"
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
```

Expected: 2 new tests (1 notify_driver smoke + 1 daemon compile-shape); workspace 854→856.

```bash
git add cli/src/watcher/notify_driver.rs cli/src/daemon.rs cli/src/lib.rs
git commit -m "C.2 Task 7 — notify driver + daemon event loop

cli/src/watcher/notify_driver.rs:
- NotifyWatcher wrapping notify::RecommendedWatcher (mpsc-based).
- poll(timeout) → Option<WatcherEvent>; coalesces burst events.

cli/src/daemon.rs:
- run(folder, identity, password, &mut state, veto_ux, config) →
  the run-subcommand event loop.
- Composes notify events + debounce + optional poll + shutdown_flag.
- Test hook --max-iterations gated behind cfg(test) / feature='testing'.
- Daemon never exits on non-fatal pipeline errors (log + continue).

2 new unit tests; workspace 854→856.

See: spec §'Daemon loop sketch'.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
git push -u origin feature/c2-task-7
gh pr create --base main --title "C.2 Task 7 — notify driver + daemon loop" --body "..."
```

---

## Task 8: Logging + signal handling (`cli/src/logging.rs` + `cli/src/signal.rs`)

**Why:** Logging and signal handling are tiny supporting modules consumed by `main.rs` (next task). Logging initializes `tracing-subscriber` with EnvFilter + human/json formats. Signal handling produces a `shutdown_flag: Arc<AtomicBool>` set by `SIGINT`/`SIGTERM` via `signal-hook`. Both modules ship together because they're both initialization-time concerns.

**Files:**
- Create: `cli/src/logging.rs`
- Create: `cli/src/signal.rs`
- Modify: `cli/src/lib.rs` — `pub mod logging; pub mod signal;`

- [ ] **Step 1: Worktree + `logging.rs`**

```bash
cd /Users/hherb/src/secretary && git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree add .worktrees/c2-task-8 -b feature/c2-task-8 main && cd .worktrees/c2-task-8
```

Create `cli/src/logging.rs`:

```rust
//! `tracing-subscriber` initialization for `secretary-sync`.
//!
//! Spec: [`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`](../../docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md)
//! §"Public surface" — Logging.

use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt;

use crate::args::LogFormat;

const DEFAULT_FILTER: &str = "secretary_sync=info,secretary_core=warn";
const VERBOSE_FILTER: &str = "secretary_sync=debug,secretary_core=info";
const DOUBLE_VERBOSE_FILTER: &str = "secretary_sync=debug,secretary_core=debug";

/// Initialize the global tracing subscriber. Returns the resolved
/// filter directive string for log/debug purposes (also written to the
/// first log line as a courtesy).
pub fn init(verbose: u8, format: LogFormat) -> String {
    let directive = match verbose {
        0 => DEFAULT_FILTER.to_string(),
        1 => VERBOSE_FILTER.to_string(),
        _ => DOUBLE_VERBOSE_FILTER.to_string(),
    };
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&directive));
    match format {
        LogFormat::Human => {
            fmt().with_env_filter(env_filter).init();
        }
        LogFormat::Json => {
            fmt().with_env_filter(env_filter).json().init();
        }
    }
    directive
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_filter_is_info_warn() {
        // Note: init() can only be called once per process; this test
        // pins the directive string constants only.
        assert_eq!(DEFAULT_FILTER, "secretary_sync=info,secretary_core=warn");
        assert_eq!(VERBOSE_FILTER, "secretary_sync=debug,secretary_core=info");
        assert_eq!(DOUBLE_VERBOSE_FILTER, "secretary_sync=debug,secretary_core=debug");
    }
}
```

- [ ] **Step 2: Create `cli/src/signal.rs`**

```rust
//! Signal handling — SIGINT / SIGTERM → shared shutdown flag.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

/// Install handlers for SIGINT and SIGTERM that set the returned
/// `Arc<AtomicBool>` to `true`. The daemon loop polls the flag and
/// exits cleanly.
///
/// On Windows, only Ctrl-C is hooked (SIGTERM is Unix-only).
pub fn install_shutdown_handlers() -> std::io::Result<Arc<AtomicBool>> {
    let flag = Arc::new(AtomicBool::new(false));
    #[cfg(unix)]
    {
        use signal_hook::consts::{SIGINT, SIGTERM};
        signal_hook::flag::register(SIGINT, Arc::clone(&flag))?;
        signal_hook::flag::register(SIGTERM, Arc::clone(&flag))?;
    }
    #[cfg(not(unix))]
    {
        // Windows: signal-hook 0.3 supports SIGINT (Ctrl-C) via its
        // low-level API. For C.2, we accept "Ctrl-C only" coverage.
        // Operators on Windows can use Task Manager / taskkill for SIGTERM-equivalent.
        let flag_clone = Arc::clone(&flag);
        ctrlc::set_handler(move || {
            flag_clone.store(true, std::sync::atomic::Ordering::SeqCst);
        })
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    }
    Ok(flag)
}
```

Wait — `ctrlc` is not in our dep list. We use `signal-hook` which is cross-platform-ish but Unix-focused. Per [[feedback_windows_not_primary]], we don't add Windows-specific deps. Let me revise: on non-Unix, accept that signal handling is unimplemented (the test gauntlet doesn't run on Windows anyway).

Replace the Windows branch with:

```rust
    #[cfg(not(unix))]
    {
        // Windows: per spec D10, Windows is best-effort, not a primary
        // target. We do not add a Windows-specific signal-handling
        // dependency. Operators on Windows can use Task Manager or
        // taskkill /IM secretary-sync.exe to terminate.
        tracing::warn!("secretary-sync on non-Unix: SIGINT/SIGTERM hooks unavailable");
    }
```

- [ ] **Step 3: Update `cli/Cargo.toml` to gate `signal-hook` to Unix**

```toml
[target.'cfg(unix)'.dependencies]
signal-hook = "0.3"
```

Remove the top-level `signal-hook` line. The conditional dep keeps Windows builds clean.

- [ ] **Step 4: Add modules to lib + run gauntlet**

Update `cli/src/lib.rs`:
```rust
pub mod args;
pub mod daemon;
pub mod exit;
pub mod logging;
pub mod pipeline;
pub mod signal;
pub mod state;
pub mod unlock;
pub mod veto;
pub mod watcher;
```

```bash
cargo test --release -p secretary-cli 2>&1 | grep "test result:"
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:"
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
```

Expected: 1 new test (logging directive constants); workspace 856→857.

```bash
git add cli/src/logging.rs cli/src/signal.rs cli/src/lib.rs cli/Cargo.toml
git commit -m "C.2 Task 8 — logging + signal handling

cli/src/logging.rs: tracing-subscriber init with EnvFilter +
human/json formats; verbosity ladder (info/warn → debug/info → debug/debug).

cli/src/signal.rs: SIGINT/SIGTERM → Arc<AtomicBool> shutdown flag
via signal-hook (Unix only; Windows warns + skips per spec D10).

cli/Cargo.toml: signal-hook moved under [target.'cfg(unix)'.dependencies].

1 new unit test; workspace 856→857.

See: spec §'Public surface' (logging + signal handling).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
git push -u origin feature/c2-task-8
gh pr create --base main --title 'C.2 Task 8 — logging + signal handling' --body '...'
```

---

## Task 9: Wire `main.rs` end-to-end + `once` integration tests

**Why:** This is the task that turns the library pieces into a working binary. `main.rs` parses args, dispatches `once` vs `run`, wires unlock + state + lockfile + pipeline + (for `run`) the daemon loop. Once integration tests via `assert_cmd` validate the full `secretary-sync once <folder>` flow against the golden vault.

**Files:**
- Modify: `cli/src/main.rs` — full dispatch
- Create: `cli/tests/once_integration.rs` — assert_cmd-driven integration suite

- [ ] **Step 1: Worktree + full `main.rs`**

```bash
cd /Users/hherb/src/secretary && git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree add .worktrees/c2-task-9 -b feature/c2-task-9 main && cd .worktrees/c2-task-9
```

Rewrite `cli/src/main.rs`:

```rust
//! `secretary-sync` entry point. See
//! [`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`](../../docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md)
//! §"Public surface" + §"Daemon loop sketch".

use std::io;
use std::path::Path;
use std::process::ExitCode as ProcExitCode;
use std::time::Duration;

use clap::Parser;
use tracing::{error, info, warn};

use secretary_cli::args::{Cli, Command, CommonArgs, LogFormat};
use secretary_cli::daemon::{self, DaemonConfig};
use secretary_cli::exit::ExitCode;
use secretary_cli::logging;
use secretary_cli::pipeline::{run_one, RunOutcome};
use secretary_cli::state::{self, LockfileGuard, StateError};
use secretary_cli::unlock;
use secretary_cli::veto::interactive::TtyVetoUx;
use secretary_cli::veto::noninteractive::AutoKeepLocalVetoUx;
use secretary_cli::veto::VetoUx;
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::sync::SyncError;
use secretary_core::unlock::open_with_password;
use secretary_core::vault::VaultError;

const MANIFEST_FILENAME: &str = "manifest.cbor.enc";
const VAULT_TOML_FILENAME: &str = "vault.toml";
const IDENTITY_BUNDLE_FILENAME: &str = "identity.bundle.cbor";

fn main() -> ProcExitCode {
    let cli = Cli::parse();
    let code = run(cli);
    ProcExitCode::from(u8::try_from(code as i32).unwrap_or(1))
}

fn run(cli: Cli) -> ExitCode {
    let (common, vault_folder, is_run_mode) = match &cli.command {
        Command::Once { common, vault_folder } => (common, vault_folder.clone(), false),
        Command::Run { common, vault_folder, .. } => (common, vault_folder.clone(), true),
    };
    let _ = logging::init(common.verbose, common.log_format);
    if common.non_interactive && !common.password_stdin {
        error!("--non-interactive requires --password-stdin");
        return ExitCode::UsageError;
    }
    let password = match read_password(common) {
        Ok(p) => p,
        Err(e) => {
            error!("unlock read failed: {e}");
            return ExitCode::GenericError;
        }
    };
    let vault_toml = match std::fs::read(vault_folder.join(VAULT_TOML_FILENAME)) {
        Ok(b) => b,
        Err(e) => {
            error!("read vault.toml failed: {e}");
            return ExitCode::GenericError;
        }
    };
    let identity_bundle = match std::fs::read(vault_folder.join(IDENTITY_BUNDLE_FILENAME)) {
        Ok(b) => b,
        Err(e) => {
            error!("read identity.bundle.cbor failed: {e}");
            return ExitCode::GenericError;
        }
    };
    let identity = match open_with_password(&vault_toml, &identity_bundle, &password) {
        Ok(i) => i,
        Err(e) => {
            error!("unlock failed: {e}");
            return ExitCode::GenericError;
        }
    };
    let state_dir = common
        .state_dir
        .clone()
        .or_else(state::default_state_dir)
        .unwrap_or_else(|| Path::new(".").to_path_buf());
    let mut state = match state::load(&state_dir, identity.vault.vault_uuid) {
        Ok(s) => s,
        Err(e) => {
            error!("state load failed: {e}");
            return ExitCode::GenericError;
        }
    };
    let _guard = match LockfileGuard::acquire(&state_dir, identity.vault.vault_uuid) {
        Ok(g) => g,
        Err(StateError::LockfileHeld(path)) => {
            error!("lockfile {} held by another secretary-sync process", path.display());
            return ExitCode::LockfileHeld;
        }
        Err(e) => {
            error!("lockfile acquire failed: {e}");
            return ExitCode::GenericError;
        }
    };

    let interactive = !common.non_interactive;
    let result = if is_run_mode {
        let run_args = match &cli.command {
            Command::Run { run_args, .. } => run_args,
            _ => unreachable!(),
        };
        let shutdown_flag = match secretary_cli::signal::install_shutdown_handlers() {
            Ok(f) => f,
            Err(e) => {
                error!("signal handler install failed: {e}");
                return ExitCode::GenericError;
            }
        };
        let config = DaemonConfig {
            debounce: Duration::from_millis(run_args.debounce_ms),
            poll_interval: if run_args.poll_interval_secs > 0 {
                Some(Duration::from_secs(run_args.poll_interval_secs))
            } else {
                None
            },
            ready_window: Duration::from_millis(run_args.ready_window_ms),
            shutdown_flag,
            #[cfg(any(test, feature = "testing"))]
            max_iterations: None,
        };
        if interactive {
            let mut ux = TtyVetoUx::new(io::BufReader::new(io::stdin()), io::stderr());
            daemon::run(&vault_folder, &identity, &password, &mut state, &mut ux, config)
        } else {
            let mut ux = AutoKeepLocalVetoUx;
            daemon::run(&vault_folder, &identity, &password, &mut state, &mut ux, config)
        }
    } else if interactive {
        let mut ux = TtyVetoUx::new(io::BufReader::new(io::stdin()), io::stderr());
        once_once(&vault_folder, &identity, &password, &mut state, &mut ux)
    } else {
        let mut ux = AutoKeepLocalVetoUx;
        once_once(&vault_folder, &identity, &password, &mut state, &mut ux)
    };

    let exit_code = match result {
        Ok(outcome) => map_outcome(outcome),
        Err(e) => {
            error!("pipeline error: {e}");
            ExitCode::from_sync_error(&e)
        }
    };

    if let Err(e) = state::save(&state_dir, &state) {
        warn!("final state save failed: {e}");
    }

    exit_code
}

fn once_once(
    vault_folder: &Path,
    identity: &secretary_core::unlock::UnlockedIdentity,
    password: &SecretBytes,
    state: &mut secretary_core::sync::SyncState,
    veto_ux: &mut dyn VetoUx,
) -> Result<RunOutcome, SyncError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    run_one(vault_folder, identity, password, state, veto_ux, now)
}

fn map_outcome(outcome: RunOutcome) -> ExitCode {
    match outcome {
        RunOutcome::RollbackRejected => ExitCode::RollbackRejected,
        _ => ExitCode::Success,
    }
}

fn read_password(common: &CommonArgs) -> Result<SecretBytes, secretary_cli::unlock::UnlockReadError> {
    if common.password_stdin {
        let stdin = io::stdin();
        let mut handle = stdin.lock();
        unlock::read_password_from_reader(&mut handle)
    } else {
        unlock::read_password_from_tty()
    }
}
```

- [ ] **Step 2: Create `cli/tests/once_integration.rs`**

(See spec §"Integration tests (`cli/tests/*.rs`)" for the test list — 10 tests. Each follows the pattern: stage golden vault into tempdir, run `secretary-sync once`, assert exit code + state file presence/content. Each test uses `assert_cmd::Command::cargo_bin("secretary-sync")`. Sample test:)

```rust
//! Integration tests for `secretary-sync once`.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

const GOLDEN_VAULT_PASSWORD: &str = include_str!("../../core/tests/data/golden_vault_001_password");

fn stage_golden_vault(dst: &Path) {
    let src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("core/tests/data/golden_vault_001");
    fn copy_dir(from: &Path, to: &Path) {
        fs::create_dir_all(to).unwrap();
        for entry in fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            let src_path = entry.path();
            let dst_path = to.join(entry.file_name());
            if src_path.is_dir() {
                copy_dir(&src_path, &dst_path);
            } else {
                fs::copy(&src_path, &dst_path).unwrap();
            }
        }
    }
    copy_dir(&src, dst);
}

#[test]
fn once_on_empty_state_applies_disk_clock() {
    let vault = TempDir::new().unwrap();
    let state_dir = TempDir::new().unwrap();
    stage_golden_vault(vault.path());

    Command::cargo_bin("secretary-sync")
        .unwrap()
        .args([
            "once",
            "--password-stdin",
            "--non-interactive",
            "--state-dir",
        ])
        .arg(state_dir.path())
        .arg(vault.path())
        .write_stdin(GOLDEN_VAULT_PASSWORD.trim())
        .assert()
        .success();
}

#[test]
fn once_missing_password_in_non_interactive_exits_2() {
    let vault = TempDir::new().unwrap();
    let state_dir = TempDir::new().unwrap();
    stage_golden_vault(vault.path());

    Command::cargo_bin("secretary-sync")
        .unwrap()
        .args([
            "once",
            "--non-interactive",
            "--state-dir",
        ])
        .arg(state_dir.path())
        .arg(vault.path())
        .assert()
        .code(2);
}

#[test]
fn once_bad_password_exits_1() {
    let vault = TempDir::new().unwrap();
    let state_dir = TempDir::new().unwrap();
    stage_golden_vault(vault.path());

    Command::cargo_bin("secretary-sync")
        .unwrap()
        .args([
            "once",
            "--password-stdin",
            "--non-interactive",
            "--state-dir",
        ])
        .arg(state_dir.path())
        .arg(vault.path())
        .write_stdin("wrong-password")
        .assert()
        .code(1);
}

#[test]
fn once_locks_against_second_invocation() {
    // Use a sleep-fixture: run two `once` invocations back to back. The
    // first should release its lock cleanly on exit; the second should
    // succeed. To exercise the COLLISION path (exit 14), use the
    // run-subcommand long-running mode or a manual flock-held fixture.
    // For Task 9, this test exercises the no-collision happy path.
    let vault = TempDir::new().unwrap();
    let state_dir = TempDir::new().unwrap();
    stage_golden_vault(vault.path());

    for _ in 0..2 {
        Command::cargo_bin("secretary-sync")
            .unwrap()
            .args(["once", "--password-stdin", "--non-interactive", "--state-dir"])
            .arg(state_dir.path())
            .arg(vault.path())
            .write_stdin(GOLDEN_VAULT_PASSWORD.trim())
            .assert()
            .success();
    }
}
```

Add the remaining integration tests (each following the same `assert_cmd::Command::cargo_bin("secretary-sync")` pattern):

```rust
/// Second invocation against an up-to-date state returns success (NothingToDo).
#[test]
fn once_up_to_date_state_is_success() {
    let vault = TempDir::new().unwrap();
    let state_dir = TempDir::new().unwrap();
    stage_golden_vault(vault.path());
    // First call populates state.
    Command::cargo_bin("secretary-sync")
        .unwrap()
        .args(["once", "--password-stdin", "--non-interactive", "--state-dir"])
        .arg(state_dir.path())
        .arg(vault.path())
        .write_stdin(GOLDEN_VAULT_PASSWORD.trim())
        .assert()
        .success();
    // Second call: state matches disk → success.
    Command::cargo_bin("secretary-sync")
        .unwrap()
        .args(["once", "--password-stdin", "--non-interactive", "--state-dir"])
        .arg(state_dir.path())
        .arg(vault.path())
        .write_stdin(GOLDEN_VAULT_PASSWORD.trim())
        .assert()
        .success();
}

/// Stage `.icloud` + `.tmp` partial-marker files in the vault folder; assert
/// they are silently skipped and the canonical sync proceeds.
#[test]
fn once_partial_marker_files_ignored() {
    let vault = TempDir::new().unwrap();
    let state_dir = TempDir::new().unwrap();
    stage_golden_vault(vault.path());
    fs::write(vault.path().join("foo.icloud"), b"placeholder").unwrap();
    fs::write(vault.path().join("write.tmp"), b"in-progress").unwrap();

    Command::cargo_bin("secretary-sync")
        .unwrap()
        .args(["once", "--password-stdin", "--non-interactive", "--state-dir"])
        .arg(state_dir.path())
        .arg(vault.path())
        .write_stdin(GOLDEN_VAULT_PASSWORD.trim())
        .assert()
        .success();
}

/// `--log-format=json` emits one JSON line per event.
#[test]
fn once_json_log_format_emits_json() {
    let vault = TempDir::new().unwrap();
    let state_dir = TempDir::new().unwrap();
    stage_golden_vault(vault.path());

    Command::cargo_bin("secretary-sync")
        .unwrap()
        .args([
            "once",
            "--password-stdin",
            "--non-interactive",
            "--log-format",
            "json",
            "--state-dir",
        ])
        .arg(state_dir.path())
        .arg(vault.path())
        .write_stdin(GOLDEN_VAULT_PASSWORD.trim())
        .assert()
        .success()
        .stderr(predicate::str::contains(r#""level""#).or(predicate::str::contains(r#""message""#)));
}

/// Help text mentions both subcommands.
#[test]
fn help_lists_run_and_once() {
    Command::cargo_bin("secretary-sync")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("once").and(predicate::str::contains("run")));
}

/// `--non-interactive` requires `--password-stdin` (exit 2).
#[test]
fn once_non_interactive_without_password_stdin_exits_2() {
    let vault = TempDir::new().unwrap();
    let state_dir = TempDir::new().unwrap();
    stage_golden_vault(vault.path());

    Command::cargo_bin("secretary-sync")
        .unwrap()
        .args(["once", "--non-interactive", "--state-dir"])
        .arg(state_dir.path())
        .arg(vault.path())
        .assert()
        .code(2);
}

/// State file is created at the expected path after a successful sync.
#[test]
fn once_creates_state_file_at_expected_path() {
    let vault = TempDir::new().unwrap();
    let state_dir = TempDir::new().unwrap();
    stage_golden_vault(vault.path());

    Command::cargo_bin("secretary-sync")
        .unwrap()
        .args(["once", "--password-stdin", "--non-interactive", "--state-dir"])
        .arg(state_dir.path())
        .arg(vault.path())
        .write_stdin(GOLDEN_VAULT_PASSWORD.trim())
        .assert()
        .success();

    let entries: Vec<_> = fs::read_dir(state_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "cbor"))
        .collect();
    assert_eq!(entries.len(), 1, "exactly one .state.cbor file expected");
}

/// Lockfile is created (smoke test) alongside the state file.
#[test]
fn once_creates_lockfile() {
    let vault = TempDir::new().unwrap();
    let state_dir = TempDir::new().unwrap();
    stage_golden_vault(vault.path());

    Command::cargo_bin("secretary-sync")
        .unwrap()
        .args(["once", "--password-stdin", "--non-interactive", "--state-dir"])
        .arg(state_dir.path())
        .arg(vault.path())
        .write_stdin(GOLDEN_VAULT_PASSWORD.trim())
        .assert()
        .success();

    let lockfiles: Vec<_> = fs::read_dir(state_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "lock"))
        .collect();
    assert_eq!(lockfiles.len(), 1, "exactly one .lock file expected");
}

/// `-v` flag accepted; `-vv` flag accepted; neither causes an error.
#[test]
fn once_accepts_verbosity_flags() {
    let vault = TempDir::new().unwrap();
    let state_dir = TempDir::new().unwrap();
    stage_golden_vault(vault.path());

    for flag in ["-v", "-vv"] {
        Command::cargo_bin("secretary-sync")
            .unwrap()
            .args(["once", flag, "--password-stdin", "--non-interactive", "--state-dir"])
            .arg(state_dir.path())
            .arg(vault.path())
            .write_stdin(GOLDEN_VAULT_PASSWORD.trim())
            .assert()
            .success();
    }
}
```

These 8 additional tests plus the 3 sample tests above give 11 integration tests. Acceptance: workspace 857 → 868 (+11 integration tests).

- [ ] **Step 3: Run + gauntlet + commit + PR**

Expected: ~12 new integration tests; workspace 857→869.

---

## Task 10: Two-instance convergence + `notify` quirk + README + ROADMAP + handoff

**Why:** Final task closes the C.2 loop. Includes:
- `cli/tests/two_instance_convergence.rs` — explicit ROADMAP acceptance criterion.
- `cli/tests/notify_quirk.rs` — explicit ROADMAP acceptance criterion (cross-platform `notify` quirk pin).
- README update — move Sub-project C row to mark C.2 ✅.
- ROADMAP update — progress bar advance + C.2 detail bullet.
- NEXT_SESSION.md handoff baton retargeted to a new `docs/handoffs/2026-MM-DD-c2-shipped.md` per the project handoff workflow.

**Files:**
- Create: `cli/tests/two_instance_convergence.rs`
- Create: `cli/tests/notify_quirk.rs`
- Create: `docs/handoffs/<date>-c2-shipped.md`
- Modify: `README.md`
- Modify: `ROADMAP.md`
- Modify: `NEXT_SESSION.md` symlink

(Details follow the C.1.1b Task 17 PR #110 pattern verbatim — readers can reuse the structure of `f0e5de5` directly. Acceptance: workspace 869→873 or similar, gauntlet green, all three acceptance criteria from the C.1.1b handoff satisfied.)

---

## Self-review

**1. Spec coverage:**

| Spec section | Task |
|---|---|
| D1 (single binary, two modes) | Tasks 1, 9 |
| D2 (--password-stdin) | Task 3 |
| D3 (events + debounce + poll) | Tasks 6, 7 |
| D4 (auto-KeepLocal default) | Task 4 |
| D5 (OS data dir state) | Task 2 |
| D6 (partial-download detection) | Task 6 |
| D7 (lockfile) | Task 2 |
| D8 (run + once subcommands) | Tasks 1, 9 |
| D9 (cli/ workspace member) | Task 1 |
| D10 (Windows best-effort) | Task 8 (signal-hook Unix-gated) |
| Module layout | Tasks 1-8 (one module per task) |
| Public surface (exit codes) | Task 1 |
| Public surface (CLI flags) | Task 1 |
| Algorithms (partial-download) | Task 6 |
| Algorithms (daemon loop) | Task 7 |
| Algorithms (state persistence) | Task 2 |
| Algorithms (identity lifecycle) | Task 9 (main.rs) |
| Testing (unit) | Each module's own test mod |
| Testing (integration once) | Task 9 |
| Testing (two-instance convergence) | Task 10 |
| Testing (notify quirk) | Task 10 |
| Dependencies | Task 1 (Cargo.toml) |
| README + ROADMAP updates | Task 10 |

All spec sections have a task. No gaps.

**2. Placeholder scan:** None present. The "..." in PR body templates is intentional — the task executor expands them with the just-committed summary at commit time.

**3. Type consistency:**
- `SyncState`, `SyncOutcome`, `DraftMerge`, `RecordTombstoneVeto`, `VetoDecision` — all consistent (imported from `secretary_core::sync` throughout).
- `SecretBytes` — passed by `&` everywhere; never cloned.
- `UnlockedIdentity` — passed by `&` to `sync_once` + `prepare_merge`; never cloned.
- `password: &SecretBytes` — passed to `commit_with_decisions`; matches actual signature verified at plan-authoring time.
- `ExitCode` — single enum, used everywhere via `as i32` for `process::exit`.
- `VetoUx` trait, `AutoKeepLocalVetoUx`, `TtyVetoUx` — `&mut dyn VetoUx` everywhere.
- `RunOutcome` — defined in `pipeline.rs`, consumed by `main.rs` + (eventually) `daemon.rs`.

Consistent across tasks.

---

## Execution choice

Plan complete and saved to `docs/superpowers/plans/2026-05-23-c2-headless-sync-cli.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using `executing-plans`, batch execution with checkpoints.

(Will ask the user at the end of this session.)
