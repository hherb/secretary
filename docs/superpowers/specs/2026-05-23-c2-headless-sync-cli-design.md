# C.2 — Headless `secretary-sync` CLI (desktop)

**Date:** 2026-05-23
**Phase:** Sub-project C, phase C.2 (headless reference consumer of the C.1 merge layer)
**Status:** Design approved (D1–D10 settled in conversation 2026-05-23); implementation plan to follow
**Predecessor:** [`docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md`](2026-05-18-c1-1b-sync-merge-design.md) — the merge + commit layer whose three-step API this CLI consumes
**Root predecessor:** [`docs/superpowers/specs/2026-05-17-c1-sync-detection-design.md`](2026-05-17-c1-sync-detection-design.md)

---

## Context

C.1.1b shipped the three-function pure-Rust merge layer (`sync_once → prepare_merge → commit_with_decisions`) plus the supporting types (`SyncOutcome`, `DraftMerge`, `RecordTombstoneVeto`, `VetoDecision`, `SyncState`, `VaultBundle`). The API is the contract; C.2 turns it into a long-running binary that watches a vault folder and converges with peer devices over a user-controlled cloud folder per [ADR-0003](../../adr/0003-cloud-folder-sync.md).

C.2 is the first piece of Sub-project C that produces shippable software. A technically inclined user with a NAS can run a real multi-device vault on top of `secretary-sync` alone, without waiting for the platform UIs in Sub-project D.

The orchestration logic sits in `cli/` rather than `core/` so the cryptographic core stays minimal-dep and library-only. The CLI is the first reference consumer of the C.1 API; future Sub-project D platform UIs consume the same `core::sync` primitives through the FFI (Sub-project B), not through `cli/`.

## Goals

C.2 delivers `secretary-sync`, a single binary with two subcommands:

| Command | Purpose | Returns |
|---|---|---|
| `secretary-sync once <folder>` | Single sync attempt against the vault folder, then exit. Composable into cron jobs, scripts, and the two-instance convergence test. | Mapped exit code (see §"Public surface"). |
| `secretary-sync run <folder>` | Long-running daemon. `notify`-based file watcher + debounce + optional periodic poll. Drops to clean shutdown on SIGINT/SIGTERM. | Exit 0 on clean shutdown; non-zero only on fatal startup errors. |

Both modes share an identical "one sync attempt" pipeline (`sync_once` → dispatch → optional `prepare_merge` → veto adjudication → `commit_with_decisions`). The daemon adds the watcher + signal handling + retry policy on top.

The binary supports two operational modes selected by `--non-interactive`:

- **Interactive default** — TTY password prompt; TUI veto prompts (per-record yes/no).
- **`--non-interactive`** — `--password-stdin` required; vetoes auto-resolved to `KeepLocal` (safe; no silent record deletion).

Acceptance criteria (carried from the C.1.1b handoff):

- [x] `secretary-sync` CLI binary in a new `cli/` workspace member.
- [x] Wires `notify` file-watching into debounced merge invocations.
- [x] Surfaces `RecordTombstoneVeto` to the user (TUI in interactive mode; auto-`KeepLocal` in non-interactive).
- [x] Two-instance integration test: two CLIs against a shared temp directory converge on the same merged manifest fingerprint with no data loss.
- [x] At least one cross-platform `notify` quirk pinned in a test (FSEvents coalescing on macOS or inotify behaviour on Linux, whichever the host CI sees).
- [x] Cloud-folder partial-download detection per ADR-0003 (provider-name filter + size-stability window).

## Non-goals (for this slice)

- **FFI exposure of CLI primitives.** C.2 is Rust-only. Sub-project D platform UIs do NOT consume `cli/`; they consume `core::sync` through the existing PyO3 / uniffi bindings.
- **Mobile.** iOS / Android adapters (`NSFilePresenter`, Storage Access Framework) are C.3.
- **Cross-language conformance for the CLI.** C.2 sits on top of the already-clean-roomed `core::sync` API. Python clean-room replay of `sync_kat.json` is tracked under [#76](https://github.com/hherb/secretary/issues/76) (C.4 scope).
- **`--veto-policy=fail`, `--decisions-file`.** Deferred to a future C.2.x slice if a real deployment asks for stricter veto handling.
- **`status` / `init` subcommands.** YAGNI — no concrete observability requirement yet; init is a no-op given `sync_once` already handles empty `SyncState`.
- **`RollbackRejected` UX override** (e.g. "I'm restoring from backup, accept the older clock anyway"). C.1 deferred this; C.2 surfaces it as exit code 10 + a clear log line and stops there.
- **Daemonisation, `systemd` units, Windows service installer.** The binary is a foreground process; supervision is the operator's job.
- **Background-on-mobile.** Mobile platforms restrict background file-system watchers (ADR-0003 consequences); C.2 is desktop / NAS-only.
- **Multi-vault orchestration.** One `secretary-sync` invocation = one vault folder.
- **Daemon control plane (JSON-RPC / Unix socket).** Out of scope; future Sub-project D UIs talk to the core API directly through FFI.

## Design decisions and the rationale chain

Ten substantive decisions shape this design. Each follows from a stated user constraint and forecloses a class of alternatives. D1–D10 below mirror the brainstorming session's question order.

### D1 — Single binary, two modes via `--non-interactive`

One `secretary-sync` binary covers both deployment stories: terminal-launched on a user's desktop AND systemd / Docker / launchd-supervised on a NAS or server. A single `--non-interactive` flag flips veto handling, password sourcing, and TTY-dependent behaviour.

Rationale: a single binary keeps the install story trivial (one executable), and the modes share ~95% of code (the same pipeline runs underneath; only the unlock + veto adapters change).

Forecloses: separate `secretary-sync-daemon` / `secretary-sync-interactive` binaries; mode autodetection from `isatty()` (silent mode-flip is a footgun).

### D2 — `--password-stdin` only for headless unlock; no env var, no password file

In headless mode, the unlock secret arrives via stdin. The binary reads bytes until EOF, then closes stdin. Composes with `cat /run/secrets/secretary-password | secretary-sync ...`, systemd `LoadCredential=`, `pass`, `op run --env-file`, etc.

Rationale: matches the project's memory-hygiene posture (the password expands to `UnlockedIdentity` held for process lifetime). Stdin avoids `/proc/<pid>/environ` exposure that an env var would create; avoids the file-lifecycle / permission footguns that a password-file would create. The downstream secret-management story is the operator's (every modern supervisor has a "feed-secret-on-stdin" primitive).

Forecloses: `SECRETARY_PASSWORD` env var, `--password-file PATH`, OS-keyring integration in v1.

### D3 — Watcher loop = `notify` events + debounce + optional periodic poll

The daemon listens to `notify::RecommendedWatcher` events, coalesces bursts in a debounce window (default 500 ms), and runs one sync attempt per debounced burst. A periodic poll timer (default off; recommended 60 s for cloud-folder mounts) safety-nets against missed events on flaky filesystems (some WebDAV mounts, network drives without inotify, Dropbox's aggressive event coalescing).

Rationale: events alone are responsive but unreliable on cloud-folder mounts; polling alone is reliable but high-latency. Belt-and-suspenders matches ADR-0003's stated cloud-folder failure modes.

Forecloses: per-file event detail driving sync granularity (the core's `sync_once` reads the whole folder atomically anyway); poll-only design (loses the `notify` quirk acceptance criterion).

### D4 — Default `KeepLocal` veto policy in `--non-interactive` mode

When `prepare_merge` produces one or more `RecordTombstoneVeto` and there's no TTY to prompt, the headless mode auto-applies `VetoDecision::KeepLocal` to every veto. Records are NEVER silently tombstoned in headless mode; the deletion is deferred to the next interactive session.

Rationale: honours C.1.1b's D2 invariant — vetoes exist specifically to prevent silent data loss. `KeepLocal` is the strictly-safe default; the daemon makes forward progress (no operator-blocking halt on first veto in a multi-day cloud-folder partition) without ever losing user data. Operators wanting stricter semantics can opt into deferred `--veto-policy=fail` / `--decisions-file` flags.

Forecloses: `AcceptTombstone` as a non-interactive default (defeats D2); refusing to run unless an explicit veto policy is named (high friction for casual deployments).

### D5 — `SyncState` lives in the OS data dir, keyed by vault UUID

Per-vault `SyncState` CBOR persists at:

```
<state-dir>/<vault_uuid_hex>.state.cbor
```

Where `<state-dir>` resolves via the `dirs` crate:
- Linux: `$XDG_DATA_HOME/secretary/sync/` (typically `~/.local/share/secretary/sync/`)
- macOS: `~/Library/Application Support/secretary/sync/`
- Windows: `%LOCALAPPDATA%\secretary\sync\`

Override via `--state-dir PATH`. Filename uses 32-char lowercase hex of `vault_uuid` (mirrors core's block-UUID naming convention). Directory created on first run with mode 0700 (Unix).

Rationale: `SyncState` carries `vault_uuid` + `highest_vector_clock_seen` — public material, not secret. The OS keyring buys nothing. Per-vault filename allows multiple vaults to coexist on one host without collision. Host-local placement (not inside the vault folder) means each device's local state stays local; the two-instance convergence test uses one `--state-dir` per simulated device.

Forecloses: OS keychain (no security gain); sibling file inside vault folder (cross-device coupling); user-mandatory `--state-file` (high friction for casual users).

### D6 — Partial-download detection = provider-name filter + size-stability window

A file in the vault folder is "ready" for `sync_once` to read iff (a) its name does NOT match any known provider partial-download pattern AND (b) two `stat()` snapshots taken `--ready-window-ms` apart (default 2000 ms) return identical `(len, mtime)`.

The canonical pattern list (non-normative — extendable without a format change, but documented here so operators know which providers we've designed against):

| Pattern | Provider / Convention |
|---|---|
| `*.icloud` | iCloud Drive placeholder for not-yet-downloaded content |
| `*.tmp` | Generic temp suffix (rsync, rclone, many editors) |
| `*.partial` | Generic partial-download suffix |
| `*.crdownload` | Chromium-family in-progress download |
| `*.download` | Safari / Firefox-family in-progress download |
| `*.~*.tmp` | Dropbox transient files |
| `.~lock.*` | LibreOffice / OpenOffice lockfiles |
| `~$*` | Microsoft Office lockfiles |
| `*.swp`, `*.swo` | vim swap files |
| `desktop.ini`, `.DS_Store` | Windows / macOS filesystem-metadata droppings |

Default `--ready-window-ms` is **2000 ms** (not 1000): mobile networks have intermittent dropouts and low-bandwidth windows where a 1-second probe is too tight. 2s catches most "still arriving" scenarios on cellular without making local-disk sync feel sluggish.

The probe is pure-function-decomposable: `matches_partial_pattern(&Path) -> bool` is a table-tested string matcher; `is_size_stable(Metadata, Metadata) -> bool` is a struct comparison. Only the orchestrating `wait_for_ready` does I/O.

Rationale: this is the conservative, defensible interpretation of ADR-0003. Provider-name filter catches the cases each cloud provider explicitly signals; size-stability catches partial transfers without explicit markers (rclone, Syncthing in-progress, slow network mounts). If a file passes the readiness check but is still corrupted (silent truncation), the existing format-layer checks (BLAKE3 fingerprint mismatch, AEAD MAC failure) fire as `VaultError::BlockFingerprintMismatch` / `VaultError::Crypto`; the loop logs + retries on the next event.

Forecloses: O_EXLOCK / OpLock probing (weird cross-provider semantics, false positives); trusting the format layer alone (noisy logs on cloud-folder partial-download scenarios).

### D7 — Single-process-per-vault via host-local lockfile

Both `run` and `once` acquire an exclusive lock on `<state-dir>/<vault_uuid_hex>.lock` at startup via `fs2::FileExt::try_lock_exclusive` (`flock(LOCK_EX | LOCK_NB)` on Unix, `LockFileEx` on Windows). On lock-already-held: exit 14 with a one-line error naming the lockfile path. Lock auto-releases on process death (kernel-level `flock`/`LockFileEx` semantics).

Rationale: serialising the state-file write alone does NOT solve the underlying race — two processes calling `commit_with_decisions` against the same vault can still leave the vault with blocks from process A and a manifest from process B. Single-process-per-vault is the correct invariant. Host-local placement (in `<state-dir>`, NOT in the vault folder) means each host has its own lockfile; multi-device convergence is unaffected.

Forecloses: state-file-only locking (serialises the wrong resource); lockfile in vault folder (cross-device coupling — a powered-off device's stale lockfile would block other devices); PID files (stale-PID detection is OS-fiddly and unnecessary given flock's auto-release).

### D8 — Two subcommands: `run` and `once`; no `status` / `init`

`secretary-sync run <folder>` is the long-running daemon. `secretary-sync once <folder>` is single-attempt-then-exit. The two-instance convergence test composes `once` invocations (sequenced, no signal handling). Daemon mode is the user-facing main mode.

Rationale: two well-defined modes, both useful. `once` is testable without signal handling or async scheduling; `run` is the operational mode. `status` and `init` are YAGNI (no concrete need yet; `init` would be a no-op since `sync_once` already handles empty `SyncState`).

Forecloses: bare `secretary-sync <folder>` always-daemon (tests would have to drive the daemon and signal-shutdown for every assertion); `status` / `init` subcommands in v1.

### D9 — New `cli/` workspace member (not `core/src/bin/`)

A new top-level `cli/` workspace member alongside `core/` and `ffi/`. Has its own `Cargo.toml` with binary-only deps (`clap`, `notify`, `tracing-subscriber`, `dirs`, `fs2`, `rpassword`, `signal-hook`, `serde_json`, `assert_cmd` for tests). `core` stays library-only with its existing minimal dep surface intact.

Rationale: mirrors `ffi/secretary-ffi-py` / `ffi/secretary-ffi-uniffi` — each consumer of `core` lives in its own crate. Keeps `core`'s dep graph clean for FFI consumers and future platform UIs. Adds one workspace member.

Forecloses: `core/src/bin/secretary-sync.rs` + Cargo-feature gating (every downstream consumer of `secretary-core` pulls CLI deps transitively unless we gate them, which adds CI complexity).

### D10 — Windows is best-effort, not a primary target

`secretary-sync` is built and tested on Linux + macOS. Windows code paths exist (via cross-platform crates — `notify::RecommendedWatcher` covers `ReadDirectoryChangesW`; `fs2` covers `LockFileEx`; `dirs` covers `%LOCALAPPDATA%`) but Windows CI is NOT in this slice. The README will explicitly state that Windows is unsupported as a security-conscious target; users may compile + run, but the project does not vouch for the platform's underlying security model.

Rationale: per [[feedback_windows_not_primary]] in user memory — the user considers Windows insecure by design and effectively obsolete. We don't actively block porting (`#![forbid(unsafe_code)]` is the only platform-wide constraint, satisfied uniformly), but neither do we add Windows-specific shims, runners, or test coverage.

Forecloses: Windows-specific feature flags; per-platform installation guides; a CI matrix that includes Windows.

## Module layout

```
cli/
├── Cargo.toml                  # binary deps (see §"External dependencies")
└── src/
    ├── main.rs                 # entry point; clap parser dispatch
    ├── args.rs                 # clap derive types (RunArgs, OnceArgs, CommonArgs)
    ├── unlock.rs               # password sourcing (TTY prompt / --password-stdin)
    │                           # → SecretBytes, then open_with_password
    ├── state.rs                # SyncState load/save, default path resolution, lockfile
    ├── watcher/
    │   ├── mod.rs              # public WatcherEvent type + driver trait
    │   ├── notify_driver.rs    # notify::RecommendedWatcher backend
    │   ├── debounce.rs         # pure debounce state machine (table-tested)
    │   └── ready.rs            # partial-download filter + size-stability probe
    ├── pipeline.rs             # one sync attempt: sync_once → dispatch
    │                           # → prepare_merge → veto UX → commit_with_decisions
    ├── daemon.rs               # `run` subcommand loop: watcher + debounce
    │                           # + poll-tick + signal → pipeline.run_one
    ├── veto/
    │   ├── mod.rs              # VetoUx trait
    │   ├── interactive.rs      # TUI prompt impl (per-record yes/no)
    │   └── noninteractive.rs   # auto-KeepLocal impl
    ├── exit.rs                 # ExitCode enum + From<SyncError> mapping
    ├── logging.rs              # tracing-subscriber init (human vs JSON)
    └── signal.rs               # SIGINT/SIGTERM → CancellationToken
```

Per [[feedback_split_files_proactively]]: each file is one concept. `watcher/` and `veto/` are submodule directories with room to grow. The largest files projected are `pipeline.rs` (one sync attempt) and `daemon.rs` (the run-mode event loop), each at ~300-350 LOC. None should hit the 500-line soft limit.

Per [[feedback_pure_functions]]: `watcher::debounce`, `watcher::ready` matching, `state::path_for_vault`, and `exit::ExitCode::from_sync_error` are pure free functions. I/O is concentrated in `unlock`, `watcher::notify_driver`, `state` (file I/O), `pipeline` + `daemon` (orchestration), and `signal`.

## Public surface

### Subcommands

```
secretary-sync once [OPTIONS] <VAULT_FOLDER>
secretary-sync run  [OPTIONS] <VAULT_FOLDER>
```

### Common options

| Flag | Default | Purpose |
|---|---|---|
| `--password-stdin` | off | Read password from stdin until EOF; required in `--non-interactive`. |
| `--non-interactive` | off | No TTY prompts. Without `--password-stdin` → exit 2. Vetoes auto-`KeepLocal`. |
| `--state-dir <PATH>` | OS data dir | Where to persist `<vault_uuid_hex>.state.cbor` + `<vault_uuid_hex>.lock`. |
| `--log-format <human\|json>` | `human` | `tracing-subscriber` output format. |
| `-v, --verbose` | off | Repeatable. `-v` → `secretary_sync=debug,secretary_core=info`. `-vv` → `secretary_core=debug`. |

### `run`-only options

| Flag | Default | Purpose |
|---|---|---|
| `--debounce-ms <MS>` | `500` | Coalesce notify event bursts into one sync attempt. |
| `--poll-interval-secs <SECS>` | `0` (off) | Periodic safety-net poll. Recommended `60` for cloud-folder mounts. |
| `--ready-window-ms <MS>` | `2000` | Size-stability window for partial-download detection. |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | `once`: sync completed (any non-Rollback outcome). `run`: clean SIGTERM shutdown. |
| 1 | Generic error (vault format, IO, unlock failure, state-file I/O). |
| 2 | Usage error (missing argument, `--non-interactive` without `--password-stdin`). |
| 10 | `RollbackRejected` — disk vector clock strictly older than local state. |
| 11 | Reserved — non-interactive veto policy refused to proceed (currently unreachable; auto-`KeepLocal` default never refuses). |
| 12 | `EvidenceStale` after exhausted retry budget (3 attempts in a 5-minute window). |
| 13 | `BlockFingerprintMismatch` on commit (partial-commit recovery failure). |
| 14 | Lockfile held — another `secretary-sync` process is running on this vault. |

### Logging

`tracing` + `tracing-subscriber` with `EnvFilter`. Default filter: `secretary_sync=info,secretary_core=warn`. `RUST_LOG` overrides. `--log-format=json` emits one line of structured JSON per event for ingestion by journald / Datadog / Loki / etc.

The partial-download-filter rejection log line fires at `debug!` (not `info!`) so default-verbosity operators don't see noise from `*.icloud` placeholders.

### Signal handling

`SIGINT` / `SIGTERM` (Unix) and `Ctrl+C` (Windows, via `ctrlc` or `signal-hook`'s Windows backend) trigger graceful shutdown: stop the watcher, drain in-flight sync, drop the `UnlockedIdentity` (relies on `ZeroizeOnDrop`), exit 0. No second-signal force-quit — the merge layer is atomic-rename-safe at every step, so a graceful shutdown can always complete.

### Environment

- `RUST_LOG` — standard tracing override.
- `XDG_DATA_HOME` / equivalents — respected via the `dirs` crate.
- No `SECRETARY_PASSWORD` env var (per D2).

## Algorithms

### Partial-download detection (`watcher/ready.rs`)

```
fn is_ready(path: &Path, clock: &dyn Clock, window: Duration) -> Result<bool, IoError> {
    if matches_partial_pattern(path) { return Ok(false); }
    if !path.exists() { return Ok(false); }

    let snapshot_a = metadata(path)?;
    if snapshot_a.len() == 0 { return Ok(false); }

    clock.sleep(window);

    let snapshot_b = metadata(path)?;
    Ok(is_size_stable(&snapshot_a, &snapshot_b))
}
```

`matches_partial_pattern` is pure (table-tested against ~20 path fixtures). `is_size_stable` compares `(len, mtime)` pairs (pure). The orchestrating `is_ready` is tested via a `MockClock`. Code comments in `ready.rs` cross-reference this spec for the canonical pattern list.

### Daemon loop sketch (run subcommand)

```
unlock once (consume stdin if --password-stdin, else TTY prompt)
load SyncState (or empty)
acquire lockfile (exit 14 on collision)
start notify::RecommendedWatcher
loop:
    select:
        watcher event burst → debounce → wait_for_ready → pipeline.run_one
        poll tick (if --poll-interval-secs > 0) → pipeline.run_one
        shutdown signal → break
    on pipeline error: log + continue (do NOT crash the daemon on transient errors)
    on RollbackRejected: log at warn, continue (operator must intervene; daemon does not exit)
    on EvidenceStale: log + retry (bounded: 3 attempts in a 5-minute window, then back off)
on exit: drop UnlockedIdentity, flush logger, release lockfile (kernel auto on close)
```

The `once` subcommand reduces to: unlock → load state → acquire lockfile → `pipeline.run_one(...)` → save state → exit with mapped code.

### State persistence

```
state::load(state_dir: &Path, vault_uuid: [u8; 16]) -> Result<SyncState, _>
    if file missing → return SyncState::empty(vault_uuid)
    else            → read + SyncState::from_cbor_bytes + validate vault_uuid match

state::save(state_dir: &Path, state: &SyncState) -> Result<(), _>
    bytes = state.to_cbor_bytes()
    write atomically via tempfile::NamedTempFile + persist
```

Persists ONLY after `AppliedAutomatically` or successful `commit_with_decisions`. NOT after `NothingToDo` (no change), NOT after `RollbackRejected` (intentionally unchanged), NOT after `ConcurrentDetected` before commit.

`tempfile = "=3.27.0"` exact pin propagates from `core/Cargo.toml` to `cli/Cargo.toml` — same atomic-rename discipline applies to the state file as to the vault format.

### Identity lifecycle

```
main():
    args = parse()
    password = unlock::read_password(args)            // SecretBytes; zeroized on drop
    identity = open_with_password(folder, &password)  // UnlockedIdentity; owns IBK
    ibk_copy = identity.identity_block_key.clone()    // SecretBytes for commit path
    state = state::load(state_dir, identity.vault.vault_uuid)?
    _lockfile = state::acquire_lockfile(state_dir, identity.vault.vault_uuid)?  // RAII guard

    match args.subcommand:
        Once  => pipeline::run_one(&identity, &ibk_copy, &mut state, ...)?
        Run   => daemon::loop(&identity, &ibk_copy, &mut state, ...)?

    state::save(state_dir, &state)?  // final persist on clean shutdown
    // identity, ibk_copy, _lockfile drop here → ZeroizeOnDrop + lockfile release
```

`commit_with_decisions` takes `&SecretBytes` (the IBK), not `&UnlockedIdentity`. Since `IdentityBundle` deliberately does not `Clone` (past safety review), the IBK is extracted once at startup as `ibk_copy: SecretBytes`. Both halves zeroize on drop.

## Testing strategy

### Unit tests (`#[cfg(test)] mod tests`)

Pure-function pieces of `cli/`:

- `watcher::debounce::*` — deterministic state machine over `(now, last_event_at)` pairs.
- `watcher::ready::matches_partial_pattern` — table test against ~20 path fixtures (one positive case per pattern in the canonical list, plus negative cases for vault filenames).
- `watcher::ready::is_size_stable` — `(Metadata_a, Metadata_b)` pair table.
- `state::path_for_vault` — pure path resolution; verifies `<state-dir>/<vault_uuid_hex>.{state.cbor,lock}` layout.
- `state::canonical_hex` — vault-UUID hex encoding helper.
- `exit::ExitCode::from_sync_error` — table covering every `SyncError` variant → documented exit code.
- `veto::interactive::TtyVetoUx::decide` — feed a mocked TTY reader scripted with `y` / `n` responses.
- `veto::noninteractive::AutoKeepLocalVetoUx::decide` — every input yields `KeepLocal`.
- `unlock::read_password_from_reader` — `Cursor<Vec<u8>>` stdin substitute; password extracted + buffer zeroized.

Expected: ~30-40 unit tests.

### Integration tests (`cli/tests/*.rs`)

Drive the binary as a subprocess via `assert_cmd`. Each test owns a `tempfile::TempDir` for the vault folder + a separate `TempDir` for the state dir.

- `once_on_empty_state_applies_disk_clock` — first sync on fresh state → exit 0, state file written.
- `once_on_up_to_date_state_is_nothing_to_do` — state matches disk → exit 0, state file unchanged.
- `once_on_rollback_disk_exits_10` — local state ahead of disk → exit 10, no vault writes.
- `once_concurrent_no_vetoes_auto_merges` — two-device fork without tombstones → exit 0, merged blocks on disk.
- `once_concurrent_with_vetoes_non_interactive_keep_local` — tombstone-veto fork in `--non-interactive` → exit 0, records preserved.
- `once_concurrent_with_vetoes_interactive_prompts_user` — same fork in interactive mode, scripted stdin → exit 0, decisions applied per script.
- `once_locks_against_second_invocation` — second invocation while first holds lock → exit 14.
- `once_bad_password_exits_1` — `--password-stdin` fed garbage → exit 1.
- `once_missing_password_in_non_interactive_exits_2` — `--non-interactive` without `--password-stdin` → exit 2.
- `once_partial_marker_files_ignored` — stage `*.icloud` and `*.tmp` in vault folder → skipped without errors.

Expected: ~15-20 integration tests on `once` alone, plus a smaller `run`-mode integration test set (using a feature-gated `--max-iterations 1` debug flag — see "Daemon-mode testability" below).

### Two-instance convergence test (`cli/tests/two_instance_convergence.rs`)

Composes two `secretary-sync once` invocations against a shared temp vault folder. Each "device" has its own state dir; the test stages a known-good vault, has each device write a concurrent change via direct core-API calls, then runs `once` twice per device until both `SyncState`s converge. Assertions:

- Both devices' `state.cbor` files share the same `highest_vector_clock_seen`.
- On-disk canonical manifest fingerprint matches from both perspectives.
- Both devices' records are present in the merged blocks.
- No data loss; no spurious `RollbackRejected` outcomes.

This is the closest C.2 has to a real convergence proof. It exercises the full `sync_once → prepare_merge → commit_with_decisions` path through the binary, including the lockfile (sequenced invocations don't collide), state persistence, and partial-download detection (no partials produced but the code path runs).

### `notify` quirk pinned test (`cli/tests/notify_quirk.rs`)

Platform-conditional:

- **Linux (`cfg(target_os = "linux")`)**: write a file in the watched folder, assert `notify` produces at least one event within a bounded time window. Exercise the inotify watch-rotation edge case (unlink + recreate of watched folder leaves the watcher in a dead state) — assert the watcher either recovers or surfaces a clear error.
- **macOS (`cfg(target_os = "macos")`)**: write 5 files rapidly in the watched folder, assert FSEvents coalesces them to ≤ N events (N < 5), demonstrating the debounce layer's necessity.
- **Windows**: skip on first iteration; the test file documents this as a known coverage gap. Per D10, Windows is best-effort, not actively CI-tested.

Purpose: deliberately exercise the platform quirk so a future regression (e.g. `notify` upstream changing behaviour) surfaces in our suite, not in a user report.

### Daemon-mode testability

`run` subcommand integration tests use a `--max-iterations <N>` debug flag (gated behind a `testing` Cargo feature; NOT compiled into release binaries). The flag exits the daemon loop after N iterations. Without it, daemon tests would require driving via subprocess + SIGTERM, adding 1-2 s per test and flakiness around signal delivery.

### What we don't test

- No long-running daemon-mode soak tests in CI (flaky + slow).
- No KAT replay for the CLI surface (C.2 sits on top of the existing `sync_kat.json` vectors; Python clean-room replay is C.4 / issue [#76](https://github.com/hherb/secretary/issues/76)).

## External dependencies

### `cli/Cargo.toml` runtime deps

| Crate | Version | Why |
|---|---|---|
| `secretary-core` | workspace | The library we wrap. |
| `clap` | `4` (derive) | Arg parsing. Industry standard. |
| `notify` | `6` | File watching (`RecommendedWatcher` covers FSEvents / inotify / `ReadDirectoryChangesW`). |
| `tracing` | matches core | Logging facade. Core already uses this. |
| `tracing-subscriber` | `0.3` (env-filter + fmt + json) | Subscriber for the binary. |
| `dirs` | `5` | Platform-correct data dir resolution. |
| `tempfile` | `=3.27.0` (exact pin) | State-file atomic write. Same pin as core. |
| `rpassword` | `7` | TTY password prompt. Small, single-purpose. |
| `serde_json` | `1` | JSON log output + (future) JSON veto reporting. |
| `fs2` | `0.4` | Cross-platform `flock` / `LockFileEx` for lockfile. |
| `signal-hook` | `0.3` | Unix signal handling; Windows fallback. |

### `cli/Cargo.toml` dev-deps

| Crate | Version | Why |
|---|---|---|
| `assert_cmd` | `2` | Subprocess CLI testing. |
| `predicates` | `3` | Output assertions companion to `assert_cmd`. |
| `tempfile` | (already runtime) | Per-test temp dirs. |

### Pin discipline

- `tempfile = "=3.27.0"` — exact pin, matches `core/Cargo.toml`. Code comment in `cli/Cargo.toml` cross-references CLAUDE.md's "exact pins on security-critical paths" rule.
- Other deps use caret ranges. None are on the security-critical path (the binary's correctness derives from `core`'s correctness, which is the pinned-and-KAT-tested layer).

## Risks

### Risks carried from earlier phases

- **CRDT proptests must not weaken.** Same as C.1.1b. C.2 does not touch `core/src/vault/conflict.rs`. The two-instance test is meaningless without commutativity / associativity / idempotence / well-formedness holding.
- **`tempfile = "=3.27.0"` exact pin** propagates. State-file write atomicity relies on the same `tempfile::persist` semantics.
- **`#![forbid(unsafe_code)]` workspace-wide.** `cli/` must be pure-safe Rust.
- **AEAD nonce hygiene** already handled inside `commit_with_decisions`. The CLI passes records through; no new nonce-handling code.

### New risks introduced by C.2

- **`notify` cross-platform behaviour drift.** `notify` 6.x has had inconsistent semantics across backends (`PollWatcher` vs `RecommendedWatcher`, macOS FSEvents 10.13+ vs older). Mitigation: use `RecommendedWatcher` exclusively, pin to a caret range, test on every minor bump. The notify-quirk integration test is the regression backstop.
- **TTY interaction in tests.** `rpassword` requires a real TTY by default; CI may not have one. Mitigation: wrap the password source in a `PasswordSource` enum with `Tty` / `Stdin` / `Mock` variants (internal to `cli/`); tests use `Mock`.
- **Cloud-folder false-positives in `ready` probe.** A user with a flaky network sees a `*.icloud` placeholder linger for hours; daemon logs grow. Mitigation: partial-filter log line at `debug!` (not `info!`), so default verbosity stays quiet. Operator opts in with `-v` to investigate.
- **Single-process-per-vault enforcement bypass.** Operator deletes the lockfile under a running daemon; second instance starts. Mitigation: don't try — `flock` is advisory by design; spec documents "do not delete the lockfile under a running daemon" as a footgun.
- **State-file write perf cliff under a hot watcher.** Every successful sync writes the state file via `tempfile::persist`. Mitigation: debounce already coalesces watcher events to ≥ 500 ms apart, so worst case is ~2 state-file writes per second per device. Acceptable.

## Open decisions deferred to follow-up

- **`--veto-policy=fail`** — exit non-zero with JSON description of vetoes for explicit operator confirmation. Deferred until someone asks.
- **`--decisions-file <PATH>`** — pre-stage decisions in a JSON file for `--non-interactive`. Composes with `--veto-policy=fail`.
- **`--exit-on-error`** — preferring systemd-restart semantics over daemon self-healing. Deferred — per the C.2 design conversation, "daemon never exits on non-fatal errors" is the explicit choice.
- **Windows CI runner.** Adds `ReadDirectoryChangesW` coverage. Tracked but explicitly out of scope per D10.
- **Daemon-mode JSON-RPC control socket.** Lets an external UI talk to the daemon (pause sync, force sync, query last outcome). Out of scope — Sub-project D platform UIs plug in via the FFI to the core API directly, not via `cli/`.
- **`status` subcommand.** Per D8 — YAGNI until observability requirements crystallise.
- **Clean-room conformance harness for `cli/`.** Per the §"Conformance" section above — the surfaces a clean-room re-implementation would need are frozen by this spec, but the actual harness (analogous to `core/tests/python/conformance.py`) is deferred to a future C.2.x slice or absorbed into C.4. User explicitly stated this is on the eventual roadmap; not foreclosed.

## Conformance and clean-room property

### This slice

C.2 does NOT add a CLI-level clean-room conformance harness in this slice. The CLI is a Rust-only consumer of the already-clean-roomed `core::sync` API; the project's "spec is normative; clean-room implementation from `docs/` alone must be possible" property applies to `core` in this slice. No `conformance.py` updates are needed for C.2.

The C.2 spec IS normative for the CLI's *observable behaviour* — exit codes, file layouts, lockfile semantics, state-file CBOR shape, partial-download filter patterns — and explicitly freezes those surfaces so a future clean-room CLI can target them. The binary's internal architecture is NOT frozen.

### Future slice — clean-room CLI conformance

Per user direction (2026-05-23 brainstorm), a clean-room property for `cli/` is a planned future addition, not a foreclosed one. The eventual conformance harness for `secretary-sync` should target:

- **Exit code surface** — every documented exit code (0/1/2/10/11/12/13/14) must fire for the same input class in a clean-room reimplementation.
- **State-file CBOR shape** — `<vault_uuid_hex>.state.cbor` produced by the Rust binary must be byte-identical to the one produced by any clean-room CLI on the same input sequence (the file's bytes are already pinned by `SyncState::to_cbor_bytes` in `core`).
- **Lockfile semantics** — file location + exclusive-lock acquisition + auto-release on process death.
- **Partial-download filter pattern table** — the canonical 10-pattern list in D6 is the contract; a clean-room CLI must reject the same files.
- **Veto-policy behaviour in `--non-interactive`** — `KeepLocal` applied to all vetoes; no silent record deletion.
- **CLI flags + their defaults** — including the `--ready-window-ms=2000` mobile-network-aware default.

Tracked as a future C.2.x slice or as part of C.4 (cross-device convergence conformance), depending on which scope surfaces first. Until then, the spec freezes the surfaces a clean-room re-implementation will need; only the harness that actually proves the property is deferred.

## Spec self-review notes

- All decision points (D1–D10) have explicit rationale and explicit foreclosures.
- All non-goals are tagged with where they land (C.2.x / C.3 / C.4 / Sub-project D).
- Exit codes are numbered, contiguous-where-meaningful, and each maps to one and only one `SyncError` variant (or to `RollbackRejected` / lockfile collision).
- Module layout matches CLAUDE.md's "one concept per file" + 500-LOC guideline.
- Pure-function discipline preserved: every algorithm splits into pure-testable inner functions + a thin I/O orchestrator.
- No placeholders / TBDs / vague requirements.
- Pin discipline (`tempfile = "=3.27.0"`) carried into `cli/`.
- The `feedback_windows_not_primary` stance is captured in D10 + non-goals + risks.
- The "spec is normative" property is correctly scoped — applies to `core` in this slice; the CLI's observable surfaces are frozen by this spec so that a future clean-room CLI conformance harness (deferred, not foreclosed) has a contract to target.

## Approval

This spec is the contract for C.2. Implementation plan to follow at `docs/superpowers/plans/2026-05-23-c2-headless-sync-cli.md` via the `superpowers:writing-plans` skill, after user review of this document.
