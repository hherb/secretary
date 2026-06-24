# Daemon rollback-detection hardening (#207 / #208 / #209)

**Date:** 2026-06-24
**Status:** Design — approved, pre-implementation
**Scope:** `cli/` only. No FFI surface, no `core/` crypto change, no on-disk
vault/manifest format change. The per-vault `SyncState` CBOR file format is
**unchanged**.

## Problem

The headless sync daemon (`secretary-sync run`) implements the threat-model
§3.1 manifest-rollback defense, but three gaps weaken it in exactly the
long-running deployment it most matters for. All three are confirmed
spec/code divergences against the C.2 design
(`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`).

- **#207 (Medium, observability):** the daemon loop discards the entire
  `Ok(RunOutcome)`, logging only the `Err` arm
  (`cli/src/daemon.rs:293-295`). `RollbackRejected` — the CLI-visible
  attack indicator — and `MergedAndCommitted { vetoes_resolved > 0 }`
  (auto-resolved deletion conflicts) are never surfaced at any verbosity.
  A malicious cloud host can probe the daemon with replayed manifests at
  zero alerting cost. C.2 spec line 294 says "on RollbackRejected: log at
  warn, continue."

- **#208 (Medium, defense voided on crash):** the per-vault `SyncState`
  ("highest vector clock seen" — the sole anchor for rollback rejection)
  is mutated in memory throughout a run but persisted **exactly once**,
  after the loop exits (`cli/src/main.rs:149-151`). An unclean exit
  (SIGKILL/OOM/panic/power-loss) discards every clock advance of the
  session; on restart the stale clock lets the host replay any manifest
  from the elapsed window as a forward update — a silent rollback. C.2
  spec line 313 prescribes per-successful-sync persistence inside the loop.

- **#209 (Low–Medium, state can land in the attacker's folder):** when
  `dirs::data_dir()` returns `None` (headless, no `$HOME` — a stated
  systemd/Docker target) the state dir silently falls back to `"."`
  (`cli/src/main.rs:56`). If the working directory is the vault folder,
  rollback state is written **inside the attacker-controlled synced
  folder**, where the in-scope malicious host deletes it →
  `state::load` returns `SyncState::empty` → rollback detection disabled.
  Plus a spec/code divergence: the spec says the dir is created `0700`
  (line 106); the code uses plain `fs::create_dir_all` with no mode.

## Decisions (from brainstorming)

1. **Packaging:** one branch `feature/daemon-rollback-hardening`, one
   commit per issue, one PR. The fixes are coupled — #208 threads
   `state_dir` into `run_against_vault`, which #209's containment guard
   also consumes.
2. **#209 `"."` fallback:** **hard error** when the state dir would
   *implicitly* fall back to cwd (no `--state-dir`, no OS data dir). An
   *explicit* `--state-dir .` stays allowed (informed operator choice).
   The `"."` fallback was never in the C.2 spec, so this code-aligns to
   spec.
3. **#209 state-dir inside vault:** **hard error**. The C.2 rationale
   (lines 108/143) explicitly requires host-local placement NOT inside
   the vault folder.
4. **#207 detail:** enrich `RunOutcome::RollbackRejected` to carry
   `RollbackEvidence` (disk clock + local clock) and log the clocks at
   `warn!`. `RollbackEvidence` already derives `Debug, Clone, PartialEq,
   Eq`, so the shared enum keeps its derives; `once` mode ignores the
   payload.

## Design

### Commit 1 — #207: surface `Ok(RunOutcome)` attack indicators

**Enum change.** `RunOutcome::RollbackRejected` →
`RollbackRejected(RollbackEvidence)`. In `run_one`
(`cli/src/pipeline.rs:226`) stop discarding `_evidence`; carry it into the
returned outcome. `outcome_to_exit_code` (`cli/src/main.rs`) matches the
variant ignoring its payload — `once` mode still maps to exit code 10,
behaviour unchanged.

**Pure decision function.** A side-effect-free classifier that the daemon
closure consults before emitting any log line:

```rust
/// What (if anything) an Ok(RunOutcome) should announce to the operator.
enum OutcomeLog {
    /// Manifest-rollback attack indicator (threat-model §3.1). Carries the
    /// two clocks the operator needs for forensics.
    RollbackRejected { disk: Vec<VectorClockEntry>, local: Vec<VectorClockEntry> },
    /// Auto-resolved tombstone vetoes — a record deletion was overridden.
    VetoesResolved(usize),
}

fn outcome_log(outcome: &RunOutcome) -> Option<OutcomeLog>;
```

Returns `Some(RollbackRejected{..})` for the rollback arm,
`Some(VetoesResolved(n))` for `MergedAndCommitted { vetoes_resolved: n }`
**only when `n > 0`**, `None` otherwise. Unit-tested for every variant.
The daemon closure maps `Some(..)` to `tracing::warn!` with the clocks /
count as structured fields. `cli/src/pipeline.rs` stays free of any
`tracing` call — logging lives only at the daemon edge.

### Commit 2 — #208: persist `SyncState` after every state-advancing sync

**Pure predicate.**

```rust
impl RunOutcome {
    /// True iff this outcome advanced `state.highest_vector_clock_seen`
    /// and therefore must be persisted before the next iteration.
    #[must_use]
    fn advanced_state(&self) -> bool;  // Applied | SilentMerge | MergedAndCommitted
}
```

`NothingToDo` and `RollbackRejected` return `false` (state byte-unchanged).
Unit-tested per variant.

**Thread `state_dir` + a save sink into the loop.** `run_against_vault`
gains a `state_dir: &Path` parameter (plumbed from `dispatch_run_subcommand`
in `cli/src/main.rs`). The post-`run_one` handling is extracted into a
testable helper:

```rust
/// Log the outcome (#207) and persist `state` (#208) when it advanced.
/// `save` is injected so the loop body is unit-testable without a real
/// watcher or filesystem.
fn after_sync(
    result: Result<RunOutcome, SyncError>,
    state: &SyncState,
    save: &mut dyn FnMut(&SyncState) -> Result<(), StateError>,
);
```

On `Ok(outcome)`: emit `outcome_log(&outcome)`; if `outcome.advanced_state()`
call `save(state)`. A save error inside the loop is logged at `warn!` and
the loop **continues** — the in-memory clock has still advanced, and a
transient FS error must not kill a daemon that may run for weeks. On
`Err(e)`: `warn!("pipeline error (continuing): {e}")` (unchanged behaviour).

In production `run_against_vault` builds the sink as
`|s| state::save(state_dir, s)`.

**Final-save failure → non-success exit.** At `cli/src/main.rs:149`, on
`state::save` `Err`: log at `error!`, and if the pending `exit_code` was
`Success`, downgrade it to `GenericError`. Never override a more specific
non-success code (e.g. `RollbackRejected`, `LockfileHeld`).

**Teeth test (#208).** A unit test driving `after_sync` with an injected
recording sink proves `save` is called on each advancing arm
(`AppliedAutomatically`, `SilentMerge`, `MergedAndCommitted`) and **not**
on `NothingToDo` / `RollbackRejected`. This fails on `main` (no in-loop
save exists today).

### Commit 3 — #209: state-dir safety

**Fallible, injectable resolution.**

```rust
/// Resolve the state dir. `explicit` = `--state-dir`; `os_default` =
/// `state::default_state_dir()`. Explicit always wins (even `.`). Else the
/// OS data dir. Else an error — never a silent cwd fallback.
fn resolve_state_dir(
    explicit: Option<PathBuf>,
    os_default: Option<PathBuf>,
) -> Result<PathBuf, StateDirError>;
```

Injecting `os_default` makes the `None` branch unit-testable (the real
`dirs::data_dir()` is environment-dependent). `STATE_DIR_FALLBACK` is
deleted.

**Containment guard (lexical).**

```rust
/// Absolute, lexically-normalized form of `p` (joins cwd if relative,
/// folds `.` and `..`). Does NOT resolve symlinks.
fn normalize_abs(p: &Path) -> PathBuf;

/// True iff `child` is `ancestor` or lives beneath it, compared lexically.
fn is_within(child: &Path, ancestor: &Path) -> bool;
```

If `is_within(state_dir, vault_folder)` → error. Documented as a
**misconfiguration** guard, deliberately symlink-unaware: the in-scope
adversary (malicious cloud host) controls the *contents* of the synced
folder, not the operator's local-FS symlink layout, so a lexical check is
the right level. Both functions are pure and unit-tested, including `..`
escapes and relative inputs.

**Error surface.** A locally-typed `StateDirError` with two variants
(`Unresolvable`, `InsideVault { state_dir, vault }`), each `Display`ing a
one-line actionable message ("pass --state-dir to a host-local path
outside the vault folder"). Both map to `ExitCode::UsageError` (2) — this
is operator misconfiguration, caught before any vault work.

**0700 directory creation.**

```rust
/// Create `path` (and parents). On Unix the leaf is created with mode
/// 0700; other platforms use plain create_dir_all. Matches C.2 spec
/// line 106. Does not chmod an already-existing dir (spec wording:
/// "created on first run with mode 0700").
fn create_dir_secure(path: &Path) -> io::Result<()>;
```

Used by both `state::save` and `LockfileGuard::acquire` (the two
`create_dir_all` sites). Implemented with
`std::os::unix::fs::DirBuilderExt::mode(0o700)` + `.recursive(true)` under
`#[cfg(unix)]`. A `#[cfg(unix)]` test asserts the created dir's mode is
`0o700`.

## Testing strategy (TDD)

Every pure helper is written failing-first:

| Unit | Test focus |
|---|---|
| `outcome_log` | each `RunOutcome` variant → expected `Option<OutcomeLog>`; `vetoes_resolved == 0` → `None` |
| `RunOutcome::advanced_state` | `true`/`false` per variant |
| `after_sync` | save called on advancing arms, skipped on `NothingToDo`/`RollbackRejected` (injected recording sink) — **#208 teeth** |
| `resolve_state_dir` | explicit-wins, os-default, unresolvable→error |
| `normalize_abs` / `is_within` | relative join, `.`/`..` folding, escape cases |
| `create_dir_secure` | `#[cfg(unix)]` mode `0o700` on first creation |
| `outcome_to_exit_code` | `RollbackRejected(evidence)` still → exit 10 (payload ignored) |

Gates (run from the worktree):

```bash
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
uv run core/tests/python/conformance.py   # unaffected — sanity only
```

Each implementer runs `cargo fmt --check` before committing (carried
process note: last session's SDD implementers skipped it).

## Spec impact

The three fixes code-align to the existing C.2 spec; the spec stays the
source of truth. Two small clarifying edits to
`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`:

1. Note that an unresolvable state dir is a **hard error** (no cwd
   fallback), since the spec's flag table (line 219) lists "OS data dir"
   without ever sanctioning the `"."` fallback the code had silently added.
2. Extend the per-sync-persistence enumeration (line 313: "Persists ONLY
   after `AppliedAutomatically` or successful `commit_with_decisions`") to
   include the **`SilentMerge`** arm. That arm post-dates the spec text but
   `run_one` advances `state.highest_vector_clock_seen` on it
   (`cli/src/pipeline.rs:246-251`), so it must persist too. `advanced_state()`
   already reflects this; the spec line is brought into agreement rather
   than the code.

No `conformance.py` / Swift / Kotlin changes — no observable byte format or
merge semantics change.

## Risks / non-goals

- **No MAC on the state file** (explicitly out of scope per #209): an
  adversary who can substitute the file can also delete it, and absent-file
  must map to `SyncState::empty` for first-run semantics, so authentication
  cannot distinguish "fresh install" from "attacker wiped it". `load`
  already validates CBOR structure + `vault_uuid`, the right level.
- **Lexical (not canonical) containment guard:** symlink-unaware by design;
  matches the threat model (the cloud host controls folder contents, not
  the operator's local symlinks). Documented at the call site.
- **`#126` (capturing the save on dispatch `Err`)** is related but distinct
  and remains its own issue; not addressed here.
- The enum change to `RunOutcome::RollbackRejected` is `cli`-internal only
  — `RunOutcome` is not part of any FFI or on-disk surface.
