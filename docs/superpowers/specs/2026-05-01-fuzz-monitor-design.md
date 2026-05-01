# `core/fuzz/monitor.py` fuzz monitor — design

**Date:** 2026-05-01
**Scope:** Operator quality-of-life dashboard for the Phase A.7 fuzz harness. Replaces the manual `cargo fuzz run | tail -f` workflow during Task 12 calibration and Task 13 bug-bash. Not part of the audit deliverable.
**Status:** approved design, awaiting implementation plan.

## Context

The fuzz harness committed in Tasks 1–11 (commits `96a76db` through `90804d9` on `feature/fuzz-harness`) is fully usable from the CLI: `cd core/fuzz && cargo fuzz run <target>`. Tasks 12 (calibration) and 13 (bug-bash) require running each of the six targets to plateau under both ASan and UBSan, observing libFuzzer's stderr telemetry to decide when to stop, and triaging any findings. On a typical workstation that's 1–4 hours of wall-clock time during which the operator stares at six terminal windows.

This monitor is a single-file NiceGUI dashboard that:
- Discovers the six fuzz targets from `core/fuzz/Cargo.toml`.
- Spawns `cargo fuzz run` subprocesses on demand with the correct PATH for the nightly toolchain.
- Parses libFuzzer's pulse lines to display live coverage / corpus / exec-rate stats.
- Auto-stops on coverage plateau (no `cov` or `corp` growth across the last K pulses).
- Surfaces crashes prominently with the artifact path and stderr tail.

The monitor is the durable **operator** artifact. The harness it drives is the durable **audit** artifact. They are deliberately separate: the harness must work standalone from the CLI for any future maintainer or auditor; the monitor is just a convenience over it.

## Goal

Single-file Python script that runs as `uv run core/fuzz/monitor.py`, opens a NiceGUI app on `http://localhost:8080`, and provides:
- A grid of six target cards.
- Per-card sanitizer toggle (ASan / UBSan / Both-sequential).
- Per-card runs-cap field (last value persisted per target).
- Live stats from libFuzzer pulse lines, scrolling log tail.
- Auto-stop on plateau detection (configurable K=10 default).
- Crash detection with badge, artifact path, and stack trace tail.
- Up to twelve concurrent runs (six targets × ASan + UBSan); operator manages resource use.

## Non-goals

- Auto-promote crashes to regression KATs (the `cargo fuzz tmin` + `cp` workflow stays in the shell).
- Run history or persistent log archives — just last-used config.
- Multi-host operation, authentication, or remote access.
- Replacing the CLI workflow — the harness must remain CLI-usable for auditors.

## UX shape

**Layout:** single-page grid, three cards per row × two rows on a typical 1280-wide window.

**Per card:**

```
┌─ vault_toml ─────────────────────────────────────┐
│ Sanitizer: (•) ASan ( ) UBSan ( ) Both           │
│ -runs cap: [____1000000____]    [START]          │
│                                                   │
│ Status: ● Running (plateau in 7 / 10)            │
│ Cov: 1247  Corp: 142  ft: 2891                   │
│ Exec/s: 58000  RSS: 124 MB                       │
│                                                   │
│ Log tail (last 20 lines):                        │
│ #1048576  pulse  cov: 1247 ft: 2891 corp: 142...│
│ #2097152  pulse  cov: 1247 ft: 2891 corp: 142...│
│ ...                                               │
└──────────────────────────────────────────────────┘
```

**Status badges:**
- ⚪ idle — never run or stopped cleanly
- 🟢 running — subprocess alive
- 🔵 plateau detected — auto-stopped after plateau
- 🟡 cap reached — stopped because `-runs` cap hit before plateau
- 🔴 CRASHED — non-zero exit and/or new file in `artifacts/<target>/`

**Top-of-page settings panel** (collapsible):
- Plateau window K (default 10)
- Stop timeout (SIGTERM grace period before SIGKILL, default 5 s)
- Log tail buffer size (default 20 lines)
- "Reset all to idle" button

**Top-of-page status banner:** if `cargo fuzz` is not on PATH, or rustup nightly toolchain not found, banner shows the problem and disables Start buttons.

## Plateau detection

`cargo fuzz run` writes pulse lines to stderr like:

```
#1048576  pulse  cov: 1247 ft: 2891 corp: 142/8.2k exec/s: 58000 rss: 124Mb
```

For each running `(target, sanitizer)` pair, maintain a ring buffer of the last K=10 parsed pulses. After every new pulse:

1. Parse the pulse line; extract `(exec_count, cov, ft, corp, exec_s, rss)`.
2. Push to the ring buffer; drop oldest if len > K.
3. If `len(buffer) == K` AND `all(p.cov == buffer[0].cov for p in buffer)` AND `all(p.corp == buffer[0].corp for p in buffer)` → **plateau detected**.
4. On plateau: send SIGTERM to the subprocess, status flips to 🔵 "plateau detected at exec N".

`corp` is the integer prefix of `corp: 142/8.2k` — the number of corpus entries (the second value is total bytes; we don't track it for plateau because it can vary slightly across pulses without representing real growth).

K=10 is the operator-visible default. libFuzzer's pulse intervals double over time (frequent early, sparser late), so 10 late-run pulses ≈ 1M+ execs ≈ 10+ minutes — about right for "we're done finding new things."

## Architecture

**Single Python file:** `core/fuzz/monitor.py` with PEP 723 inline deps:

```python
#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "nicegui>=2",
# ]
# ///
```

`tomllib` (CBOR/TOML parser for `Cargo.toml`) is stdlib in Python 3.11+, so no additional dep needed. NiceGUI is the only third-party.

### Module shape

The file is organized as a flat set of pure functions plus one `RunState` dataclass and one `MonitorApp` class. Per the project's "default to free functions, no side effects" convention:

**Pure functions** (no I/O, no global state — easy to unit-test):

- `parse_targets(cargo_toml_text: str) -> list[str]`
  Extract `[[bin]] name = "..."` entries from a `Cargo.toml` string.

- `parse_pulse_line(line: str) -> Pulse | None`
  Regex-parse one libFuzzer stderr line. Returns a `Pulse` dataclass on success, `None` on non-pulse lines.

- `check_plateau(window: list[Pulse], k: int) -> bool`
  Pure check on a sliding window: did we plateau?

- `find_nightly_toolchain(rustup_home: Path) -> str | None`
  Look for `~/.rustup/toolchains/nightly-*` directories, return the most recently modified one's name (e.g. `nightly-2026-04-29-aarch64-apple-darwin`).

- `build_subprocess_env(rustup_nightly_dir: Path, base_env: dict[str, str]) -> dict[str, str]`
  Return a copy of `base_env` with `nightly_dir/bin` prepended to PATH.

- `parse_runs_cap(text: str) -> int | None`
  Parse the runs-cap input (e.g. `"5_000_000"`, `"5000000"`, empty); return `None` for empty (open-ended), int for a number, raise `ValueError` for malformed.

**Dataclasses:**

- `Pulse` — frozen dataclass with `exec_count`, `cov`, `ft`, `corp`, `exec_s`, `rss`.
- `RunState` — mutable per-(target, sanitizer) state: `status` (enum), `pulses` (deque), `log_tail` (deque), `popen` (subprocess.Popen | None), `runs_cap` (int | None), `started_at` (timestamp), `stop_reason` (str | None), `crash_path` (Path | None).
- `Status` — IntEnum: IDLE, RUNNING, PLATEAU, CAP_REACHED, CRASHED, STOPPED.

**Stateful units:**

- `MonitorApp` — class owning the `dict[(target, sanitizer), RunState]`. Methods: `start(target, sanitizer, runs_cap)`, `stop(target, sanitizer)`, `tick()` (called periodically by NiceGUI to push reactive updates).
- Async stderr reader: per spawned subprocess, an `asyncio.create_task(_read_stderr(...))` reads `subprocess.stderr` line-by-line. For each line:
  - Try `parse_pulse_line(line)`; if success, push to RunState's pulses deque, then `check_plateau`; if plateau, schedule `stop(...)` on the event loop.
  - Always push raw line to `log_tail` deque.

**I/O at edges only:** subprocess spawn (`asyncio.create_subprocess_exec`), state-file read/write (`json.load/dump`), artifacts dir scan (`pathlib.Path.glob`), NiceGUI render via `ui.refreshable` decorators.

### Data flow

1. **Startup.** Parse `core/fuzz/Cargo.toml` to discover six target names. Find rustup nightly toolchain. Load persisted state (last-used runs caps, plateau K). Render UI with one card per target.
2. **User clicks Start.** `MonitorApp.start(target, sanitizer, runs_cap)`:
   - Build env via `build_subprocess_env`.
   - Translate sanitizer choice to flags: ASan → no flag; UBSan → `--sanitizer=undefined`; Both → ASan first, then UBSan after first stop.
   - Spawn `cargo fuzz run <target> [--sanitizer=undefined] -- -runs=N` from `core/fuzz/`.
   - Store Popen handle, mark status RUNNING, schedule async stderr reader.
   - Persist this `runs_cap` to `.monitor-state.json` for next time.
3. **Async stderr reader.** Reads subprocess stderr line by line. For each line, updates `RunState.log_tail` and (if it's a pulse) `RunState.pulses`. After each pulse: `check_plateau`. If True: `stop(target, sanitizer)` with reason "plateau".
4. **User clicks Stop.** `MonitorApp.stop(target, sanitizer)`:
   - SIGTERM to Popen.
   - Wait up to 5 s for exit.
   - SIGKILL fallback if still alive.
   - Update status (STOPPED, CAP_REACHED, PLATEAU depending on stop reason).
5. **Subprocess exits.** Async reader sees EOF or wait() returns:
   - Exit code 0 → status becomes whatever the stop reason was (or STOPPED if user-initiated, or CAP_REACHED if `-runs` exhausted naturally).
   - Exit code non-zero → check `artifacts/<target>/` for new `crash-*` files; if found, status becomes CRASHED with `crash_path` set; else show generic error.
6. **NiceGUI tick.** Every 0.5 s, NiceGUI re-renders cards from `RunState`. Reactive updates avoid full-page redraws.

### Sanitizer translation

| Sanitizer choice | cargo fuzz invocation                                          |
|------------------|----------------------------------------------------------------|
| ASan             | `cargo fuzz run <target> -- -runs=<N>`                         |
| UBSan            | `cargo fuzz run --sanitizer=undefined <target> -- -runs=<N>`   |
| Both-sequential  | ASan run; on stop (any reason except CRASHED), UBSan run automatically. |

For Both-sequential, two RunStates exist: `(target, "asan")` and `(target, "ubsan")`. The first runs to plateau/cap; on its `stop` callback, if reason was non-crash, schedule UBSan start. If user clicks Stop on the ASan run mid-flight, UBSan does NOT start automatically (treat user stop as "abandon the sequence").

### PATH handling

cargo-fuzz traditionally needs nightly Rust. The repo's main `rust-toolchain.toml` pins stable; `core/fuzz/rust-toolchain.toml` pins nightly path-scoped. But the path-scoped toolchain pin only works when `cargo` itself is rustup-managed. If the user has Homebrew's cargo on PATH (which doesn't honor rustup pins), `cargo fuzz` resolves to a stable cargo that fails to build the fuzz crate.

The monitor's PATH injection handles this:

1. Locate `~/.rustup/toolchains/nightly-*` (most recently modified).
2. Prepend that toolchain's `bin/` to subprocess PATH.
3. If no nightly toolchain found, show a startup banner with the problem and disable Start buttons.
4. Fallback: if `which rustup` succeeds AND `rustup run nightly cargo --version` succeeds, use `rustup run nightly cargo fuzz ...` form instead.

### Crash detection

Two signals must agree:

1. **Exit code.** libFuzzer exits non-zero on any sanitizer finding (or panic, OOM, etc.).
2. **Artifact file.** A new file appears in `core/fuzz/artifacts/<target>/crash-*` after the subprocess exits.

The monitor records the timestamp it started the subprocess and, on exit with non-zero, scans `artifacts/<target>/` for crash files newer than that timestamp. If found:
- Status flips to CRASHED.
- `crash_path` field set to the (newest) crash artifact.
- Card shows: "CRASHED at exec N", clickable file path (copies to clipboard via NiceGUI's clipboard helper), last 20 stderr lines (which usually contain the ASan/UBSan stack trace).

If non-zero exit but no crash artifact: probably a build failure or environment error. Show last 20 stderr lines and status flips to STOPPED with `stop_reason="exit code N, no crash artifact"`.

**No auto-promote** — the user runs `cargo fuzz tmin` and the rest of the regression-promotion workflow from the shell, as documented in `core/fuzz/README.md`.

## Persistence

`core/fuzz/.monitor-state.json` (gitignored — added to `core/fuzz/.gitignore`):

```json
{
  "runs_caps": {
    "vault_toml": 5000000,
    "record": 5000000,
    "contact_card": 5000000,
    "bundle_file": 2000000,
    "manifest_file": 2000000,
    "block_file": 1000000
  },
  "plateau_k": 10,
  "stop_timeout_seconds": 5,
  "log_tail_size": 20
}
```

Loaded once on startup; saved after each settings change or Start click. Schema migration: read with defaults; missing keys get filled in. No version field — additive-only changes.

## Error handling

| Failure mode                          | Behavior                                                                 |
|---------------------------------------|--------------------------------------------------------------------------|
| `cargo fuzz` not installed            | Startup banner; Start buttons disabled.                                  |
| Rustup nightly not found              | Startup banner; Start buttons disabled.                                  |
| Pulse line malformed                  | `parse_pulse_line` returns `None`; line still goes to log_tail; reader continues. |
| Subprocess fails to spawn             | Card shows inline error; status returns to IDLE.                         |
| Subprocess crashes (non-zero exit)    | Crash detection logic above.                                             |
| Subprocess hangs after SIGTERM        | SIGKILL after 5 s grace period.                                          |
| Monitor process exits mid-run         | Subprocesses orphan (acceptable for MVP; user can `pgrep cargo-fuzz`).   |
| Two monitor instances on port 8080    | Second instance fails to bind; user sees explicit error from NiceGUI.    |
| `.monitor-state.json` corrupt or missing | Use defaults silently; create file on first save.                     |
| Cargo.toml `[[bin]]` parse failure    | Fall back to hardcoded six target names (`vault_toml`, `record`, `contact_card`, `bundle_file`, `manifest_file`, `block_file`) and show a warning banner. Keeps the monitor usable if someone breaks the Cargo.toml structure. |

## Testing

Unit tests in a sibling file `core/fuzz/test_monitor.py`, runnable as `uv run --with pytest pytest core/fuzz/test_monitor.py`. Tests cover only the pure functions (no subprocess spawning, no NiceGUI integration tests).

| Function | Test cases |
|----------|------------|
| `parse_pulse_line` | 4 sample real libFuzzer pulse lines (early run, mid run, late run with large rss); 1 malformed line returns None; 1 non-pulse stderr line returns None. |
| `parse_targets` | Sample `Cargo.toml` with the six `[[bin]]` entries; minimal `Cargo.toml` with one entry; empty `Cargo.toml` returns `[]`. |
| `check_plateau` | Empty buffer returns False; partial buffer (len < K) returns False; full buffer with all-equal cov+corp returns True; full buffer with cov change at end returns False; full buffer with corp change in the middle returns False. |
| `find_nightly_toolchain` | Temp dir with `nightly-2026-04-29-x` and `nightly-2026-04-28-x` returns the more recent one; temp dir with no nightly returns None; missing `toolchains/` dir returns None. |
| `build_subprocess_env` | PATH prepended correctly; existing env preserved; missing PATH key handled. |
| `parse_runs_cap` | `""` → None; `"5000000"` → 5_000_000; `"5_000_000"` → 5_000_000; `"abc"` → ValueError; `"-1"` → ValueError. |

No integration tests against real `cargo fuzz` — too slow, depends on environment. The async stderr reader and subprocess management are exercised by manual operator use during Tasks 12-13.

## Build sequence

Implementation order, each step independently testable:

1. **Scaffold + `parse_targets` + static six-card layout** with hardcoded "idle" status. No subprocess yet. Verify `uv run core/fuzz/monitor.py` opens the page.
2. **`parse_pulse_line` + unit tests.** Pure function, fully unit-tested before any subprocess work.
3. **`check_plateau` + unit tests.** Same — pure, fully tested.
4. **`find_nightly_toolchain` + `build_subprocess_env` + unit tests.**
5. **`parse_runs_cap` + unit tests.**
6. **Subprocess management (start/stop) + async stderr reader.** First version: ASan only, no plateau detection. Verify start/stop button works on one target end-to-end.
7. **Plateau-triggered SIGTERM.** Wire `check_plateau` into the reader. Verify on a real target that finishes with plateau.
8. **UBSan and Both-sequential modes.**
9. **Crash detection.** Trigger by feeding a known crash input (a contrived seed) and verify status flips correctly.
10. **Persistence (`.monitor-state.json`).** Save on Start click, load on startup. Add to `core/fuzz/.gitignore`.
11. **Polish:** top-of-page settings panel, log tail formatting, click-to-copy crash path.
12. **Documentation:** add a "Monitor" section to `core/fuzz/README.md` describing how to launch and use the monitor.

The full implementation plan with task-by-task structure happens after spec sign-off via the writing-plans skill.

## Out of scope

- **Auto-promote crashes to regression KATs.** Manual `cargo fuzz tmin` + `cp` workflow stays in the shell.
- **Run history / persistent log archives.** Just last-used config in `.monitor-state.json`.
- **Multi-host operation, authentication, remote access.** localhost only.
- **Replacing the CLI workflow.** The harness must remain CLI-usable for any future maintainer or auditor; the monitor is a convenience over it.
- **Rich charts** (cov-over-time plots, etc.). Numeric live stats are sufficient for an MVP; charts are a (B)/(C) tier feature per the brainstorm scope discussion.
- **Differential replay launcher.** Out of MVP scope; users invoke `cargo test --features differential-replay` from the shell.
- **Calibration assistant** (auto-iterate to find the floor). Manual: user runs open-ended, observes plateau exec count, sets the floor manually.
