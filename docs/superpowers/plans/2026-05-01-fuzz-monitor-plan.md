# Fuzz Monitor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the single-file NiceGUI fuzz monitor at `core/fuzz/monitor.py` that lets the operator kick off `cargo fuzz run` campaigns across the six wire-format fuzz targets and auto-stops on coverage plateau detection.

**Architecture:** Single Python script with PEP 723 inline deps. Pure functions for parsing, plateau detection, and toolchain discovery (each independently unit-testable). One `MonitorApp` class owns subprocess Popen handles and per-(target, sanitizer) `RunState`s; an async stderr reader parses libFuzzer's pulse lines into reactive state that NiceGUI re-renders. PATH injection auto-locates the rustup nightly toolchain so cargo-fuzz runs even if Homebrew cargo is on PATH first.

**Tech Stack:** Python 3.11+, NiceGUI ≥ 2 (only third-party dep), stdlib `tomllib`/`asyncio`/`subprocess`/`json`/`pathlib`, pytest for unit tests via `uv run --with pytest`.

**Spec:** [docs/superpowers/specs/2026-05-01-fuzz-monitor-design.md](../specs/2026-05-01-fuzz-monitor-design.md).

**Pre-flight (one-time, before Task 1):**
- Working from worktree `/Users/hherb/src/secretary/.worktrees/fuzz-harness`, on branch `feature/fuzz-harness` (already on it).
- Confirm `uv` is installed (`uv --version`).
- Confirm rustup nightly is available (`ls ~/.rustup/toolchains/ | grep nightly`).
- Confirm `cargo fuzz list` from `core/fuzz/` returns the six target names.

---

## File Structure

| File | Responsibility |
|---|---|
| `core/fuzz/monitor.py` | The single-file monitor. Pure functions, dataclasses, `MonitorApp` class, `main()`. PEP 723 inline deps. |
| `core/fuzz/test_monitor.py` | Pytest unit tests. One test class per pure function. |
| `core/fuzz/.gitignore` | Modify: add `.monitor-state.json` to ignore list. |
| `core/fuzz/README.md` | Modify: add a "Monitor" section describing how to launch and use the monitor. |

The monitor is intentionally one file (per the spec). The test file is separate so pytest discovery is straightforward and unit tests don't pollute the runtime script.

---

## Task 1: PEP 723 scaffold + empty test file

Get a runnable shell in place: `uv run core/fuzz/monitor.py` exits 0, `uv run --with pytest pytest core/fuzz/test_monitor.py` runs zero tests cleanly. No real logic yet.

**Files:**
- Create: `core/fuzz/monitor.py`
- Create: `core/fuzz/test_monitor.py`

- [ ] **Step 1: Create `core/fuzz/monitor.py` with PEP 723 header and a no-op main**

```python
#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "nicegui>=2",
# ]
# ///
"""Fuzz monitor — single-file NiceGUI dashboard for the secretary fuzz harness.

See docs/superpowers/specs/2026-05-01-fuzz-monitor-design.md.
"""

from __future__ import annotations


def main() -> None:
    """Entry point. Real implementation arrives in Task 9."""
    print("monitor scaffold OK")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Create `core/fuzz/test_monitor.py` with empty test scaffold**

```python
"""Unit tests for `monitor.py` pure functions.

Run from the repo root:
    uv run --with pytest pytest core/fuzz/test_monitor.py -v
"""

from __future__ import annotations

# Imports populate as functions are added in later tasks.
```

- [ ] **Step 3: Verify monitor.py runs**

```bash
cd /Users/hherb/src/secretary/.worktrees/fuzz-harness
uv run core/fuzz/monitor.py
```

Expected output: `monitor scaffold OK`. Exit code 0. The first run downloads NiceGUI; subsequent runs are fast.

- [ ] **Step 4: Verify pytest collects zero tests cleanly**

```bash
cd /Users/hherb/src/secretary/.worktrees/fuzz-harness
uv run --with pytest pytest core/fuzz/test_monitor.py -v
```

Expected: `no tests ran` and exit code 5 (pytest's "no tests collected" code). Add `--exitfirst` flag if you want a non-zero exit to surface; either way, no errors.

- [ ] **Step 5: Commit**

```bash
git add core/fuzz/monitor.py core/fuzz/test_monitor.py
git commit -m "feat(monitor): scaffold core/fuzz/monitor.py + test_monitor.py

Single-file PEP 723 script with NiceGUI dep. Empty main() prints
'monitor scaffold OK' and exits. Companion test file ready for
unit tests of pure functions in subsequent tasks.

See docs/superpowers/specs/2026-05-01-fuzz-monitor-design.md."
```

---

## Task 2: `parse_pulse_line` + Pulse dataclass (TDD)

Parses libFuzzer's stderr pulse lines into structured `Pulse` records. The plateau detector consumes these.

Real libFuzzer pulse line shapes (verified against this project's smoke runs in Tasks 2-7 of the harness plan):

```
#1048576	pulse  cov: 1247 ft: 2891 corp: 142/8.2k exec/s: 58000 rss: 124Mb
#1000	DONE   cov: 714 ft: 978 corp: 61/147b lim: 4 exec/s: 0 rss: 46Mb
#2000000	NEW    cov: 80 ft: 80 corp: 4/15b exec/s: 60606 rss: 803Mb
#3	INITED cov: 234 ft: 234 corp: 1/3989b exec/s: 0 rss: 41Mb
```

Note variations:
- Event types: `pulse`, `NEW`, `REDUCE`, `INITED`, `DONE`, `RELOAD`.
- Optional `lim: N` field between `corp:` and `exec/s:`.
- `corp:` second value (total bytes) may have unit suffix `b`, `kb`, `Mb` or no suffix.
- `exec/s:` may be 0 (early in run).

We parse the *exec_count*, *cov*, *ft*, *corp* (entry count only — first integer), *exec_s*, *rss* fields. The corp size suffix is ignored; only the entry count matters for plateau.

**Files:**
- Modify: `core/fuzz/monitor.py` (add `Pulse` dataclass, `parse_pulse_line` function, regex)
- Modify: `core/fuzz/test_monitor.py` (add tests)

- [ ] **Step 1: Write failing tests in `core/fuzz/test_monitor.py`**

Append to the file:

```python
import pytest

from monitor import Pulse, parse_pulse_line


class TestParsePulseLine:
    def test_pulse_typical(self):
        line = "#1048576\tpulse  cov: 1247 ft: 2891 corp: 142/8.2k exec/s: 58000 rss: 124Mb"
        p = parse_pulse_line(line)
        assert p == Pulse(exec_count=1048576, cov=1247, ft=2891, corp=142, exec_s=58000, rss=124)

    def test_done_with_lim(self):
        line = "#1000\tDONE   cov: 714 ft: 978 corp: 61/147b lim: 4 exec/s: 0 rss: 46Mb"
        p = parse_pulse_line(line)
        assert p == Pulse(exec_count=1000, cov=714, ft=978, corp=61, exec_s=0, rss=46)

    def test_new_event(self):
        line = "#2000000\tNEW    cov: 80 ft: 80 corp: 4/15b exec/s: 60606 rss: 803Mb"
        p = parse_pulse_line(line)
        assert p == Pulse(exec_count=2000000, cov=80, ft=80, corp=4, exec_s=60606, rss=803)

    def test_inited(self):
        line = "#3\tINITED cov: 234 ft: 234 corp: 1/3989b exec/s: 0 rss: 41Mb"
        p = parse_pulse_line(line)
        assert p == Pulse(exec_count=3, cov=234, ft=234, corp=1, exec_s=0, rss=41)

    def test_corp_size_with_kilo_suffix(self):
        line = "#16777216\tpulse  cov: 8500 ft: 14200 corp: 350/1.2Mb exec/s: 12500 rss: 256Mb"
        p = parse_pulse_line(line)
        assert p.corp == 350
        assert p.exec_count == 16777216

    def test_non_pulse_line_returns_none(self):
        assert parse_pulse_line("Done 100000 runs in 1 second(s)") is None
        assert parse_pulse_line("INFO: Loaded 1 modules") is None
        assert parse_pulse_line("") is None

    def test_malformed_line_returns_none(self):
        assert parse_pulse_line("#abc\tpulse cov: bad") is None
        assert parse_pulse_line("#100\tpulse cov: 5 corp: badformat") is None
```

- [ ] **Step 2: Run the failing tests**

```bash
cd /Users/hherb/src/secretary/.worktrees/fuzz-harness
uv run --with pytest pytest core/fuzz/test_monitor.py -v
```

Expected: ImportError on `Pulse` and `parse_pulse_line` — they don't exist yet.

- [ ] **Step 3: Implement Pulse + parse_pulse_line in monitor.py**

Insert into `core/fuzz/monitor.py` between the docstring and `def main()`:

```python
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Pulse:
    """One libFuzzer telemetry record parsed from stderr.

    Captures only the fields the monitor needs:
    - exec_count: cumulative executions at this point.
    - cov: coverage edges hit.
    - ft: features hit (libFuzzer's coverage-with-cmp-args metric).
    - corp: corpus entry count (the first integer of `corp: N/Mb`).
    - exec_s: executions/second (averaged over recent interval).
    - rss: resident set size in megabytes.
    """

    exec_count: int
    cov: int
    ft: int
    corp: int
    exec_s: int
    rss: int


# Matches libFuzzer pulse-style stderr lines. Event types: pulse, NEW,
# REDUCE, INITED, DONE, RELOAD. The `lim: N` field is optional; corp's
# size component (after the slash) may be plain digits, a decimal, or
# carry a `b`/`kb`/`Mb` unit suffix — we ignore that part.
_PULSE_RE = re.compile(
    r"^#(?P<exec_count>\d+)\s+(?:pulse|NEW|REDUCE|INITED|DONE|RELOAD)\s+"
    r"cov:\s+(?P<cov>\d+)\s+"
    r"ft:\s+(?P<ft>\d+)\s+"
    r"corp:\s+(?P<corp>\d+)/[\d.]+(?:[KMGkmg])?b?\s+"
    r"(?:lim:\s+\d+\s+)?"
    r"exec/s:\s+(?P<exec_s>\d+)\s+"
    r"rss:\s+(?P<rss>\d+)Mb"
)


def parse_pulse_line(line: str) -> Pulse | None:
    """Parse one libFuzzer stderr line; return Pulse or None."""
    m = _PULSE_RE.match(line)
    if m is None:
        return None
    return Pulse(
        exec_count=int(m["exec_count"]),
        cov=int(m["cov"]),
        ft=int(m["ft"]),
        corp=int(m["corp"]),
        exec_s=int(m["exec_s"]),
        rss=int(m["rss"]),
    )
```

- [ ] **Step 4: Run tests, expect all pass**

```bash
cd /Users/hherb/src/secretary/.worktrees/fuzz-harness
uv run --with pytest pytest core/fuzz/test_monitor.py -v
```

Expected: 7 tests pass.

- [ ] **Step 5: Commit**

```bash
git add core/fuzz/monitor.py core/fuzz/test_monitor.py
git commit -m "feat(monitor): parse_pulse_line + Pulse dataclass

Regex-parses libFuzzer stderr pulse-style lines (pulse, NEW, REDUCE,
INITED, DONE, RELOAD events) into structured Pulse records. Captures
exec_count, cov, ft, corp (entry count), exec_s, rss. The corp size
suffix and lim field are tolerated but discarded.

7 unit tests covering typical pulse, DONE with lim, NEW event, INITED,
corp size with k/M suffix, non-pulse lines, and malformed inputs."
```

---

## Task 3: `parse_targets` + tests (TDD)

Reads `core/fuzz/Cargo.toml` and extracts the `[[bin]]` target names.

**Files:**
- Modify: `core/fuzz/monitor.py`
- Modify: `core/fuzz/test_monitor.py`

- [ ] **Step 1: Append failing tests to `test_monitor.py`**

```python
from monitor import parse_targets


class TestParseTargets:
    SAMPLE_CARGO_TOML = """\
[workspace]

[package]
name = "secretary-core-fuzz"

[[bin]]
name = "vault_toml"
path = "fuzz_targets/vault_toml.rs"
test = false

[[bin]]
name = "record"
path = "fuzz_targets/record.rs"
test = false
"""

    def test_extracts_two_targets(self):
        names = parse_targets(self.SAMPLE_CARGO_TOML)
        assert names == ["vault_toml", "record"]

    def test_empty_cargo_toml(self):
        assert parse_targets("[package]\nname = 'foo'\n") == []

    def test_six_targets_in_order(self):
        toml_text = "\n".join(
            f'[[bin]]\nname = "{n}"\npath = "fuzz_targets/{n}.rs"\n'
            for n in ["vault_toml", "record", "contact_card", "bundle_file", "manifest_file", "block_file"]
        )
        assert parse_targets(toml_text) == [
            "vault_toml", "record", "contact_card",
            "bundle_file", "manifest_file", "block_file",
        ]

    def test_malformed_toml_raises(self):
        with pytest.raises(Exception):  # tomllib.TOMLDecodeError
            parse_targets("[[bin\nname = 'unclosed")
```

- [ ] **Step 2: Run, see failure**

```bash
uv run --with pytest pytest core/fuzz/test_monitor.py -v
```

Expected: ImportError on `parse_targets`.

- [ ] **Step 3: Implement parse_targets in monitor.py**

Add after the `parse_pulse_line` definition:

```python
import tomllib


def parse_targets(cargo_toml_text: str) -> list[str]:
    """Extract [[bin]] target names from a Cargo.toml string.

    Returns the names in document order. Raises tomllib.TOMLDecodeError
    on malformed input.
    """
    parsed = tomllib.loads(cargo_toml_text)
    bins = parsed.get("bin", [])
    return [b["name"] for b in bins if "name" in b]
```

- [ ] **Step 4: Run, expect all pass**

```bash
uv run --with pytest pytest core/fuzz/test_monitor.py::TestParseTargets -v
```

Expected: 4 tests pass.

- [ ] **Step 5: Commit**

```bash
git add core/fuzz/monitor.py core/fuzz/test_monitor.py
git commit -m "feat(monitor): parse_targets reads Cargo.toml [[bin]] entries

Returns target names in document order. Raises on malformed TOML.
4 unit tests covering 2-target, empty, full 6-target, and malformed
inputs."
```

---

## Task 4: `check_plateau` + tests (TDD)

Pure plateau check on a sliding window of `Pulse` records.

**Files:**
- Modify: `core/fuzz/monitor.py`
- Modify: `core/fuzz/test_monitor.py`

- [ ] **Step 1: Append failing tests to `test_monitor.py`**

```python
from monitor import check_plateau


class TestCheckPlateau:
    @staticmethod
    def _pulse(cov: int, corp: int, exec_count: int = 1000) -> Pulse:
        return Pulse(exec_count=exec_count, cov=cov, ft=cov * 2, corp=corp, exec_s=50000, rss=128)

    def test_empty_window_returns_false(self):
        assert check_plateau([], k=10) is False

    def test_window_shorter_than_k_returns_false(self):
        window = [self._pulse(100, 5) for _ in range(5)]
        assert check_plateau(window, k=10) is False

    def test_full_window_all_equal_returns_true(self):
        window = [self._pulse(100, 5) for _ in range(10)]
        assert check_plateau(window, k=10) is True

    def test_full_window_cov_changed_at_end_returns_false(self):
        window = [self._pulse(100, 5) for _ in range(9)] + [self._pulse(101, 5)]
        assert check_plateau(window, k=10) is False

    def test_full_window_corp_changed_in_middle_returns_false(self):
        window = (
            [self._pulse(100, 5) for _ in range(4)]
            + [self._pulse(100, 6)]
            + [self._pulse(100, 6) for _ in range(5)]
        )
        assert check_plateau(window, k=10) is False

    def test_window_longer_than_k_uses_last_k(self):
        # First entry has different cov; last K=5 are all equal
        window = [self._pulse(99, 5)] + [self._pulse(100, 5) for _ in range(5)]
        assert check_plateau(window, k=5) is True

    def test_k_one_always_true_with_one_pulse(self):
        # Trivial case: K=1 means "no growth in last 1 pulse" — always trivially true.
        window = [self._pulse(100, 5)]
        assert check_plateau(window, k=1) is True
```

- [ ] **Step 2: Run, see failure**

```bash
uv run --with pytest pytest core/fuzz/test_monitor.py::TestCheckPlateau -v
```

Expected: ImportError.

- [ ] **Step 3: Implement check_plateau in monitor.py**

Add after `parse_targets`:

```python
def check_plateau(window: list[Pulse], k: int) -> bool:
    """True when the last `k` pulses all share the same cov AND corp.

    Returns False when len(window) < k. The plateau definition is
    "no growth in cov AND no growth in corp across the last k pulses",
    matching the spec's hardware-independent stop signal.
    """
    if len(window) < k:
        return False
    last_k = window[-k:]
    cov0 = last_k[0].cov
    corp0 = last_k[0].corp
    return all(p.cov == cov0 and p.corp == corp0 for p in last_k)
```

- [ ] **Step 4: Run, expect all pass**

```bash
uv run --with pytest pytest core/fuzz/test_monitor.py::TestCheckPlateau -v
```

Expected: 7 tests pass.

- [ ] **Step 5: Commit**

```bash
git add core/fuzz/monitor.py core/fuzz/test_monitor.py
git commit -m "feat(monitor): check_plateau over Pulse window

Returns True iff the last K pulses all share cov AND corp values.
7 unit tests covering empty, short, full-equal, cov-change-at-end,
corp-change-in-middle, longer-than-K, and K=1 cases."
```

---

## Task 5: `find_nightly_toolchain` + tests (TDD)

Locates the most recent rustup nightly toolchain. Used by Task 6's `build_subprocess_env`.

**Files:**
- Modify: `core/fuzz/monitor.py`
- Modify: `core/fuzz/test_monitor.py`

- [ ] **Step 1: Append failing tests**

```python
from pathlib import Path

from monitor import find_nightly_toolchain


class TestFindNightlyToolchain:
    def test_returns_most_recent_nightly(self, tmp_path: Path):
        rustup_home = tmp_path / "rustup"
        toolchains = rustup_home / "toolchains"
        toolchains.mkdir(parents=True)
        (toolchains / "stable-aarch64-apple-darwin").mkdir()
        older = toolchains / "nightly-2026-04-28-aarch64-apple-darwin"
        newer = toolchains / "nightly-2026-04-29-aarch64-apple-darwin"
        older.mkdir()
        newer.mkdir()
        # Set newer's mtime explicitly to a later moment.
        import os, time
        os.utime(older, (time.time() - 100, time.time() - 100))
        os.utime(newer, (time.time(), time.time()))

        result = find_nightly_toolchain(rustup_home)
        assert result is not None
        assert result.name == "nightly-2026-04-29-aarch64-apple-darwin"

    def test_returns_none_when_no_nightly(self, tmp_path: Path):
        rustup_home = tmp_path / "rustup"
        (rustup_home / "toolchains" / "stable-x").mkdir(parents=True)
        assert find_nightly_toolchain(rustup_home) is None

    def test_returns_none_when_toolchains_dir_missing(self, tmp_path: Path):
        rustup_home = tmp_path / "rustup"
        rustup_home.mkdir()  # no toolchains subdir
        assert find_nightly_toolchain(rustup_home) is None

    def test_returns_none_when_rustup_home_missing(self, tmp_path: Path):
        rustup_home = tmp_path / "does-not-exist"
        assert find_nightly_toolchain(rustup_home) is None
```

- [ ] **Step 2: Run, see failure**

```bash
uv run --with pytest pytest core/fuzz/test_monitor.py::TestFindNightlyToolchain -v
```

Expected: ImportError.

- [ ] **Step 3: Implement find_nightly_toolchain**

Add after `check_plateau`:

```python
from pathlib import Path


def find_nightly_toolchain(rustup_home: Path) -> Path | None:
    """Locate the most-recently-modified rustup nightly toolchain.

    Searches `rustup_home/toolchains/` for entries starting with
    `nightly-`. Returns the Path to the most recent one (by mtime),
    or None if no nightly is installed.
    """
    toolchains = rustup_home / "toolchains"
    if not toolchains.is_dir():
        return None
    nightlies = [p for p in toolchains.iterdir() if p.is_dir() and p.name.startswith("nightly-")]
    if not nightlies:
        return None
    return max(nightlies, key=lambda p: p.stat().st_mtime)
```

- [ ] **Step 4: Run, expect all pass**

```bash
uv run --with pytest pytest core/fuzz/test_monitor.py::TestFindNightlyToolchain -v
```

Expected: 4 tests pass.

- [ ] **Step 5: Commit**

```bash
git add core/fuzz/monitor.py core/fuzz/test_monitor.py
git commit -m "feat(monitor): find_nightly_toolchain locates rustup nightly

Returns the most-recently-modified ~/.rustup/toolchains/nightly-* dir.
4 unit tests covering the happy path (most recent wins), no nightlies
present, missing toolchains dir, and missing rustup home."
```

---

## Task 6: `build_subprocess_env` + tests (TDD)

Constructs the subprocess env with the rustup nightly's `bin/` prepended to PATH.

**Files:**
- Modify: `core/fuzz/monitor.py`
- Modify: `core/fuzz/test_monitor.py`

- [ ] **Step 1: Append failing tests**

```python
from monitor import build_subprocess_env


class TestBuildSubprocessEnv:
    def test_prepends_nightly_bin_to_path(self):
        nightly_dir = Path("/Users/me/.rustup/toolchains/nightly-2026-04-29-x")
        base_env = {"PATH": "/usr/local/bin:/usr/bin", "HOME": "/Users/me"}
        env = build_subprocess_env(nightly_dir, base_env)
        assert env["PATH"].startswith("/Users/me/.rustup/toolchains/nightly-2026-04-29-x/bin:")
        assert env["PATH"].endswith(":/usr/local/bin:/usr/bin")
        assert env["HOME"] == "/Users/me"

    def test_preserves_other_env_vars(self):
        nightly_dir = Path("/n")
        base_env = {"PATH": "/usr/bin", "RUSTFLAGS": "-Dwarnings", "FOO": "bar"}
        env = build_subprocess_env(nightly_dir, base_env)
        assert env["RUSTFLAGS"] == "-Dwarnings"
        assert env["FOO"] == "bar"

    def test_handles_missing_path(self):
        nightly_dir = Path("/n")
        base_env: dict[str, str] = {}  # no PATH key
        env = build_subprocess_env(nightly_dir, base_env)
        assert env["PATH"] == "/n/bin"

    def test_does_not_mutate_input(self):
        nightly_dir = Path("/n")
        base_env = {"PATH": "/usr/bin"}
        original = dict(base_env)
        build_subprocess_env(nightly_dir, base_env)
        assert base_env == original
```

- [ ] **Step 2: Run, see failure**

```bash
uv run --with pytest pytest core/fuzz/test_monitor.py::TestBuildSubprocessEnv -v
```

Expected: ImportError.

- [ ] **Step 3: Implement build_subprocess_env**

Add after `find_nightly_toolchain`:

```python
def build_subprocess_env(nightly_dir: Path, base_env: dict[str, str]) -> dict[str, str]:
    """Return a copy of base_env with `nightly_dir/bin` prepended to PATH.

    PATH may be absent from base_env (returns just `nightly_dir/bin`).
    The input dict is not mutated.
    """
    env = dict(base_env)
    nightly_bin = str(nightly_dir / "bin")
    existing_path = env.get("PATH")
    if existing_path:
        env["PATH"] = f"{nightly_bin}:{existing_path}"
    else:
        env["PATH"] = nightly_bin
    return env
```

- [ ] **Step 4: Run, expect all pass**

```bash
uv run --with pytest pytest core/fuzz/test_monitor.py::TestBuildSubprocessEnv -v
```

Expected: 4 tests pass.

- [ ] **Step 5: Commit**

```bash
git add core/fuzz/monitor.py core/fuzz/test_monitor.py
git commit -m "feat(monitor): build_subprocess_env injects nightly toolchain into PATH

Returns a copy of base_env with nightly_dir/bin prepended to PATH.
Handles missing PATH and never mutates the input dict.
4 unit tests covering prepend, preservation, missing-PATH, and
non-mutation properties."
```

---

## Task 7: `parse_runs_cap` + tests (TDD)

Parses the runs-cap text input from the UI: empty (open-ended), digit string, or underscore-separated digits (`5_000_000`).

**Files:**
- Modify: `core/fuzz/monitor.py`
- Modify: `core/fuzz/test_monitor.py`

- [ ] **Step 1: Append failing tests**

```python
from monitor import parse_runs_cap


class TestParseRunsCap:
    def test_empty_returns_none(self):
        assert parse_runs_cap("") is None
        assert parse_runs_cap("   ") is None

    def test_plain_integer(self):
        assert parse_runs_cap("5000000") == 5_000_000

    def test_underscore_separated(self):
        assert parse_runs_cap("5_000_000") == 5_000_000
        assert parse_runs_cap("1_000") == 1_000

    def test_with_surrounding_whitespace(self):
        assert parse_runs_cap("  5000000  ") == 5_000_000

    def test_negative_raises(self):
        with pytest.raises(ValueError):
            parse_runs_cap("-1")

    def test_zero_raises(self):
        with pytest.raises(ValueError):
            parse_runs_cap("0")

    def test_non_numeric_raises(self):
        with pytest.raises(ValueError):
            parse_runs_cap("abc")
        with pytest.raises(ValueError):
            parse_runs_cap("1.5")
```

- [ ] **Step 2: Run, see failure**

```bash
uv run --with pytest pytest core/fuzz/test_monitor.py::TestParseRunsCap -v
```

Expected: ImportError.

- [ ] **Step 3: Implement parse_runs_cap**

Add after `build_subprocess_env`:

```python
def parse_runs_cap(text: str) -> int | None:
    """Parse the UI runs-cap input.

    - Empty string (or whitespace) -> None (open-ended run).
    - Underscore-separated digits ('5_000_000') -> int.
    - Plain digits -> int.
    - Anything else -> ValueError.
    - Zero or negative -> ValueError.
    """
    stripped = text.strip()
    if not stripped:
        return None
    # int() accepts both '5000000' and '5_000_000' (PEP 515).
    n = int(stripped)
    if n <= 0:
        raise ValueError(f"runs cap must be positive, got {n}")
    return n
```

- [ ] **Step 4: Run, expect all pass**

```bash
uv run --with pytest pytest core/fuzz/test_monitor.py::TestParseRunsCap -v
```

Expected: 7 tests pass.

- [ ] **Step 5: Commit**

```bash
git add core/fuzz/monitor.py core/fuzz/test_monitor.py
git commit -m "feat(monitor): parse_runs_cap handles UI text input

Empty -> None (open-ended); '5_000_000' or '5000000' -> int.
Rejects zero, negative, or non-numeric. 7 unit tests."
```

---

## Task 8: `Status` enum + `RunState` dataclass

Per-(target, sanitizer) state container. Mostly definitions; one smoke test.

**Files:**
- Modify: `core/fuzz/monitor.py`
- Modify: `core/fuzz/test_monitor.py`

- [ ] **Step 1: Implement Status + RunState in monitor.py**

Add after `parse_runs_cap`:

```python
import enum
from collections import deque


class Status(enum.IntEnum):
    """RunState lifecycle status — drives card badge color."""

    IDLE = 0      # never run, or stopped cleanly with no telemetry
    RUNNING = 1   # subprocess alive
    PLATEAU = 2   # auto-stopped after plateau detection
    CAP_REACHED = 3  # stopped because -runs cap fired before plateau
    CRASHED = 4   # non-zero exit AND/OR new artifact in artifacts/<target>/
    STOPPED = 5   # user-clicked Stop


@dataclass
class RunState:
    """Per-(target, sanitizer) lifecycle state.

    Mutated by start_run / stop_run / async stderr reader. Read by NiceGUI
    rendering code via reactive bindings.
    """

    target: str
    sanitizer: str  # 'asan' | 'ubsan'
    status: Status = Status.IDLE
    pulses: deque[Pulse] = None  # type: ignore[assignment]
    log_tail: deque[str] = None  # type: ignore[assignment]
    runs_cap: int | None = None
    started_at: float = 0.0  # monotonic clock at subprocess spawn (for elapsed time)
    started_at_wall: float = 0.0  # wall clock (for comparing against artifact file mtimes)
    stop_reason: str | None = None
    crash_path: Path | None = None

    def __post_init__(self) -> None:
        if self.pulses is None:
            self.pulses = deque(maxlen=64)  # generous; actual K used by check_plateau is smaller
        if self.log_tail is None:
            self.log_tail = deque(maxlen=20)
```

- [ ] **Step 2: Append a smoke test**

```python
from monitor import RunState, Status


class TestRunState:
    def test_default_state(self):
        rs = RunState(target="vault_toml", sanitizer="asan")
        assert rs.status == Status.IDLE
        assert rs.runs_cap is None
        assert rs.crash_path is None
        assert len(rs.pulses) == 0
        assert len(rs.log_tail) == 0

    def test_pulses_bounded(self):
        rs = RunState(target="vault_toml", sanitizer="asan")
        for i in range(100):
            rs.pulses.append(Pulse(exec_count=i, cov=0, ft=0, corp=0, exec_s=0, rss=0))
        assert len(rs.pulses) == 64  # maxlen=64

    def test_log_tail_bounded(self):
        rs = RunState(target="vault_toml", sanitizer="asan")
        for i in range(50):
            rs.log_tail.append(f"line {i}")
        assert len(rs.log_tail) == 20  # maxlen=20
```

- [ ] **Step 3: Run, expect all pass**

```bash
uv run --with pytest pytest core/fuzz/test_monitor.py::TestRunState -v
```

Expected: 3 tests pass.

- [ ] **Step 4: Commit**

```bash
git add core/fuzz/monitor.py core/fuzz/test_monitor.py
git commit -m "feat(monitor): Status enum + RunState dataclass

Per-(target, sanitizer) lifecycle state with bounded pulses (deque
maxlen=64) and log_tail (deque maxlen=20) buffers. Status enum
drives card badge color: IDLE, RUNNING, PLATEAU, CAP_REACHED,
CRASHED, STOPPED."
```

---

## Task 9: Static UI scaffold

Wire NiceGUI to render six idle cards from parsed Cargo.toml. No subprocess yet — just verify the UI loads, layout works, and `parse_targets` is consumed correctly.

**Files:**
- Modify: `core/fuzz/monitor.py` (replace `def main`, add MonitorApp class skeleton)

- [ ] **Step 1: Replace `main()` with NiceGUI app skeleton**

In `core/fuzz/monitor.py`, replace the existing `def main()` and `if __name__ == "__main__"` block at the bottom with:

```python
from nicegui import ui

# Path constants (resolved at module import time so tests don't break).
_FUZZ_DIR = Path(__file__).parent  # core/fuzz/
_CARGO_TOML = _FUZZ_DIR / "Cargo.toml"


class MonitorApp:
    """Holds per-(target, sanitizer) RunState and orchestrates UI updates."""

    def __init__(self, targets: list[str]) -> None:
        self.targets = targets
        # Two RunStates per target (asan + ubsan). Even if the user only
        # runs one sanitizer at a time, the slots exist for both.
        self.runs: dict[tuple[str, str], RunState] = {
            (t, s): RunState(target=t, sanitizer=s)
            for t in targets
            for s in ("asan", "ubsan")
        }

    def render(self) -> None:
        """Build the full page UI."""
        ui.label("Secretary fuzz monitor").classes("text-h4")
        with ui.grid(columns=3).classes("gap-4"):
            for target in self.targets:
                self._render_card(target)

    def _render_card(self, target: str) -> None:
        with ui.card().classes("w-96"):
            ui.label(target).classes("text-h6")
            ui.label("Sanitizer toggle, runs-cap, status — added in Task 10")
            ui.label(f"asan: {self.runs[(target, 'asan')].status.name}")
            ui.label(f"ubsan: {self.runs[(target, 'ubsan')].status.name}")


def main() -> None:
    """Entry point — launch the NiceGUI app."""
    cargo_toml_text = _CARGO_TOML.read_text()
    targets = parse_targets(cargo_toml_text)
    if not targets:
        # Fallback per spec § "Cargo.toml fallback".
        targets = ["vault_toml", "record", "contact_card",
                   "bundle_file", "manifest_file", "block_file"]
    app = MonitorApp(targets)
    app.render()
    ui.run(port=8080, show=False, reload=False, title="Fuzz monitor")


if __name__ == "__main__" or __name__ == "__mp_main__":
    main()
```

(The `__mp_main__` check is NiceGUI's recommended pattern for non-reload mode.)

- [ ] **Step 2: Verify the page loads**

```bash
cd /Users/hherb/src/secretary/.worktrees/fuzz-harness
uv run core/fuzz/monitor.py
```

Expected output: NiceGUI starts and prints `NiceGUI ready to go on http://localhost:8080`. Open that URL in a browser. You should see:
- A page titled "Secretary fuzz monitor".
- Six cards in a 3×2 grid, each labeled with a target name.
- Each card shows "asan: IDLE" and "ubsan: IDLE".

Stop the server with `^C`.

- [ ] **Step 3: Verify pure-function tests still pass**

```bash
uv run --with pytest pytest core/fuzz/test_monitor.py -v
```

Expected: all tests pass (none should be affected by the UI additions).

- [ ] **Step 4: Commit**

```bash
git add core/fuzz/monitor.py
git commit -m "feat(monitor): static six-card UI scaffold

NiceGUI grid (3×2) renders one card per discovered target with
placeholder asan/ubsan IDLE labels. Cargo.toml parsed at startup
with hardcoded six-target fallback. No subprocess management yet."
```

---

## Task 10: Subprocess management — `start_run`, `stop_run`, async stderr reader

The first stateful task. Wires up `asyncio.create_subprocess_exec` to spawn `cargo fuzz run` and an async reader that parses pulse lines into the RunState. No plateau detection yet (Task 11) and no UBSan/Both yet (Task 12).

**Files:**
- Modify: `core/fuzz/monitor.py`

- [ ] **Step 1: Add subprocess + async imports at top of monitor.py**

After the existing imports, ensure these are present (some may already be there from earlier tasks):

```python
import asyncio
import os
import signal
import time
import subprocess
```

- [ ] **Step 2: Add `MonitorApp.start_run` and `stop_run`**

Add these methods to the `MonitorApp` class:

```python
    async def start_run(self, target: str, sanitizer: str, runs_cap: int | None) -> None:
        """Spawn cargo fuzz run for (target, sanitizer). Idempotent: refuses
        to start a second subprocess for the same key while one is alive."""
        rs = self.runs[(target, sanitizer)]
        if rs.status == Status.RUNNING:
            return  # already running

        # Locate nightly toolchain; bail if not found.
        rustup_home = Path.home() / ".rustup"
        nightly_dir = find_nightly_toolchain(rustup_home)
        if nightly_dir is None:
            rs.log_tail.append("ERROR: rustup nightly toolchain not found")
            rs.status = Status.STOPPED
            rs.stop_reason = "no nightly toolchain"
            return

        # Build argv. ASan is the default; UBSan needs --sanitizer=undefined.
        argv = ["cargo", "fuzz", "run"]
        if sanitizer == "ubsan":
            argv.append("--sanitizer=undefined")
        argv.append(target)
        argv.append("--")
        if runs_cap is not None:
            argv.append(f"-runs={runs_cap}")

        env = build_subprocess_env(nightly_dir, dict(os.environ))

        # Reset state for this run.
        rs.pulses.clear()
        rs.log_tail.clear()
        rs.runs_cap = runs_cap
        rs.crash_path = None
        rs.stop_reason = None
        rs.started_at = time.monotonic()
        rs.status = Status.RUNNING
        rs.log_tail.append(f"$ {' '.join(argv)}")

        proc = await asyncio.create_subprocess_exec(
            *argv,
            cwd=str(_FUZZ_DIR),
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        rs._popen = proc  # type: ignore[attr-defined]

        # Spawn async stderr reader.
        asyncio.create_task(self._read_stderr(target, sanitizer, proc))

    async def _read_stderr(
        self,
        target: str,
        sanitizer: str,
        proc: asyncio.subprocess.Process,
    ) -> None:
        rs = self.runs[(target, sanitizer)]
        assert proc.stderr is not None
        async for raw_line in proc.stderr:
            line = raw_line.decode("utf-8", errors="replace").rstrip()
            rs.log_tail.append(line)
            pulse = parse_pulse_line(line)
            if pulse is not None:
                rs.pulses.append(pulse)
        # stderr EOF → process is exiting. Wait for exit code.
        rc = await proc.wait()
        if rs.status == Status.RUNNING:
            # Not user-stopped; categorize by exit code.
            if rc == 0:
                rs.status = Status.CAP_REACHED  # natural exit on -runs
                rs.stop_reason = "exit 0 (cap reached)"
            else:
                # Crash detection in Task 13. For now: STOPPED with reason.
                rs.status = Status.STOPPED
                rs.stop_reason = f"exit code {rc}"

    async def stop_run(self, target: str, sanitizer: str) -> None:
        """SIGTERM the subprocess; SIGKILL fallback after grace period."""
        rs = self.runs[(target, sanitizer)]
        proc = getattr(rs, "_popen", None)
        if proc is None or proc.returncode is not None:
            return  # nothing to stop
        proc.send_signal(signal.SIGTERM)
        try:
            await asyncio.wait_for(proc.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
        rs.status = Status.STOPPED
        rs.stop_reason = "user stopped"
```

- [ ] **Step 3: Add Start/Stop buttons to `_render_card`**

Replace the `_render_card` method body with:

```python
    def _render_card(self, target: str) -> None:
        with ui.card().classes("w-96"):
            ui.label(target).classes("text-h6")
            sanitizer = ui.radio(["asan", "ubsan"], value="asan").props("inline")
            runs_cap_input = ui.input("runs cap (blank = open-ended)", value="").props("dense")
            status_label = ui.label("status: idle")

            async def on_start():
                try:
                    cap = parse_runs_cap(runs_cap_input.value)
                except ValueError as e:
                    ui.notify(f"invalid runs cap: {e}", type="negative")
                    return
                await self.start_run(target, sanitizer.value, cap)
                status_label.text = f"status: {self.runs[(target, sanitizer.value)].status.name}"

            async def on_stop():
                await self.stop_run(target, sanitizer.value)
                status_label.text = f"status: {self.runs[(target, sanitizer.value)].status.name}"

            with ui.row():
                ui.button("Start", on_click=on_start).props("color=primary")
                ui.button("Stop", on_click=on_stop).props("color=negative")
```

- [ ] **Step 4: Smoke-test by starting a real fuzz run from the UI**

```bash
cd /Users/hherb/src/secretary/.worktrees/fuzz-harness
uv run core/fuzz/monitor.py
```

Open http://localhost:8080. Click Start on the `vault_toml` card with runs cap `100000`. Wait for it to finish (~1 second on this workstation). The status label should update from idle → RUNNING → CAP_REACHED (when libFuzzer exits cleanly after 100k execs).

Verify by checking the running processes:

```bash
ps aux | grep "cargo-fuzz\|vault_toml"
```

Should be empty after the run completes. Stop the monitor with ^C.

- [ ] **Step 5: Verify pure-function tests still pass**

```bash
uv run --with pytest pytest core/fuzz/test_monitor.py -v
```

Expected: all earlier tests pass.

- [ ] **Step 6: Commit**

```bash
git add core/fuzz/monitor.py
git commit -m "feat(monitor): subprocess management + async stderr reader

start_run spawns cargo fuzz run with PATH-injected nightly toolchain.
stop_run SIGTERM with 5s SIGKILL fallback. Async stderr reader
populates RunState.pulses (parsed via parse_pulse_line) and log_tail
(raw lines). Card now has Start/Stop buttons with sanitizer radio
and runs-cap input. No plateau detection yet (Task 11)."
```

---

## Task 11: Plateau-triggered SIGTERM

Wire `check_plateau` into the stderr reader. When plateau fires, call `stop_run` and mark status as `PLATEAU`.

**Files:**
- Modify: `core/fuzz/monitor.py`

- [ ] **Step 1: Add a `plateau_k` field to MonitorApp and wire into `_read_stderr`**

In `MonitorApp.__init__`, add:

```python
        self.plateau_k = 10  # default; could be configurable later
```

Modify `_read_stderr` to call `check_plateau` after each new pulse:

```python
    async def _read_stderr(
        self,
        target: str,
        sanitizer: str,
        proc: asyncio.subprocess.Process,
    ) -> None:
        rs = self.runs[(target, sanitizer)]
        assert proc.stderr is not None
        async for raw_line in proc.stderr:
            line = raw_line.decode("utf-8", errors="replace").rstrip()
            rs.log_tail.append(line)
            pulse = parse_pulse_line(line)
            if pulse is not None:
                rs.pulses.append(pulse)
                # Plateau check: when fired, SIGTERM the subprocess. The
                # subsequent EOF on stderr will fall through to the wait()
                # logic below; mark stop_reason here so the post-exit
                # handler knows this was a plateau (not a cap-reached).
                if check_plateau(list(rs.pulses), self.plateau_k):
                    rs.stop_reason = f"plateau at exec {pulse.exec_count}"
                    proc.send_signal(signal.SIGTERM)
        rc = await proc.wait()
        if rs.status == Status.RUNNING:
            if rs.stop_reason and rs.stop_reason.startswith("plateau"):
                rs.status = Status.PLATEAU
            elif rc == 0:
                rs.status = Status.CAP_REACHED
                rs.stop_reason = "exit 0 (cap reached)"
            else:
                rs.status = Status.STOPPED
                rs.stop_reason = f"exit code {rc}"
```

- [ ] **Step 2: Smoke-test plateau detection**

```bash
cd /Users/hherb/src/secretary/.worktrees/fuzz-harness
uv run core/fuzz/monitor.py
```

Open http://localhost:8080. Click Start on `vault_toml` with `runs cap` = 5000000. Wait. The run should auto-stop before 5M execs once libFuzzer reports K=10 consecutive pulses with the same cov and corp. Status should flip to `PLATEAU` with a reason like "plateau at exec 1234567".

(If the run reaches 5M execs without plateauing, you'll see CAP_REACHED — increase the cap or decrease K to test the plateau path.)

Stop the monitor with ^C.

- [ ] **Step 3: Verify pure-function tests still pass**

```bash
uv run --with pytest pytest core/fuzz/test_monitor.py -v
```

- [ ] **Step 4: Commit**

```bash
git add core/fuzz/monitor.py
git commit -m "feat(monitor): plateau-triggered SIGTERM in stderr reader

After each parsed Pulse, check_plateau over the last K=10 entries.
On plateau, send SIGTERM and mark stop_reason='plateau at exec N'.
Post-exit handler distinguishes plateau, cap-reached, and crash
(crash classification still incomplete; Task 13)."
```

---

## Task 12: UBSan and Both-sequential modes

ASan and UBSan already work via the radio. "Both-sequential" runs ASan first, then UBSan when ASan stops cleanly.

**Files:**
- Modify: `core/fuzz/monitor.py`

- [ ] **Step 1: Update `_render_card` radio to add "both" option and chain logic**

Replace the radio line in `_render_card` and add a helper for the chained run:

```python
        sanitizer = ui.radio(["asan", "ubsan", "both"], value="asan").props("inline")
```

Replace `on_start` with a chain-aware version:

```python
            async def on_start():
                try:
                    cap = parse_runs_cap(runs_cap_input.value)
                except ValueError as e:
                    ui.notify(f"invalid runs cap: {e}", type="negative")
                    return
                if sanitizer.value == "both":
                    # Run ASan first; chain UBSan if ASan stops cleanly.
                    await self.start_run(target, "asan", cap)
                    # Wait for ASan to finish, then optionally launch UBSan.
                    asyncio.create_task(self._chain_ubsan(target, cap))
                else:
                    await self.start_run(target, sanitizer.value, cap)
                status_label.text = f"status: {self.runs[(target, sanitizer.value)].status.name}"
```

Add a new method to MonitorApp for the chain:

```python
    async def _chain_ubsan(self, target: str, runs_cap: int | None) -> None:
        """After ASan finishes (any reason except CRASHED or user-STOPPED),
        kick off UBSan automatically. Treat user-stop as 'abandon the chain'."""
        asan = self.runs[(target, "asan")]
        # Poll until ASan is no longer RUNNING.
        while asan.status == Status.RUNNING:
            await asyncio.sleep(1.0)
        if asan.status in (Status.PLATEAU, Status.CAP_REACHED):
            await self.start_run(target, "ubsan", runs_cap)
```

(Crash and STOPPED are intentionally NOT chained: a crash is something to triage; a manual stop is "abandon".)

- [ ] **Step 2: Smoke-test Both-sequential mode**

Run the monitor, click Start on `vault_toml` with sanitizer `both` and runs cap `100000` (small to keep the test fast). Watch:
1. The `asan` slot transitions IDLE → RUNNING → PLATEAU/CAP_REACHED.
2. After 1-2 seconds, the `ubsan` slot transitions IDLE → RUNNING → PLATEAU/CAP_REACHED.

Note the status display only shows the radio's current value; both slots are advancing in parallel (well, sequentially for the chain). Inspect with two browser tabs or refresh the page mid-run to see both slot statuses.

- [ ] **Step 3: Commit**

```bash
git add core/fuzz/monitor.py
git commit -m "feat(monitor): Both-sequential sanitizer mode

Radio gains 'both' option. _chain_ubsan polls the ASan slot until it
exits; on PLATEAU or CAP_REACHED, kicks off the UBSan slot with the
same runs cap. CRASHED or user-STOPPED outcomes abort the chain
(crash deserves triage; user stop means 'abandon')."
```

---

## Task 13: Crash detection

Two signals must combine: non-zero exit code AND a new file in `core/fuzz/artifacts/<target>/crash-*` newer than the run's start time.

**Files:**
- Modify: `core/fuzz/monitor.py`

- [ ] **Step 1: Add crash artifact scanning helper to MonitorApp**

Add a method:

```python
    def _find_new_crash(self, target: str, since: float) -> Path | None:
        """Look for crash-* files in artifacts/<target>/ modified after `since`."""
        artifacts_dir = _FUZZ_DIR / "artifacts" / target
        if not artifacts_dir.is_dir():
            return None
        crashes = [
            p for p in artifacts_dir.iterdir()
            if p.is_file() and p.name.startswith("crash-") and p.stat().st_mtime > since
        ]
        if not crashes:
            return None
        return max(crashes, key=lambda p: p.stat().st_mtime)
```

- [ ] **Step 2: Update `_read_stderr`'s post-exit logic**

Replace the post-exit handler in `_read_stderr` (the part starting with `rc = await proc.wait()`) with:

```python
        rc = await proc.wait()
        if rs.status == Status.RUNNING:
            if rs.stop_reason and rs.stop_reason.startswith("plateau"):
                rs.status = Status.PLATEAU
            elif rc == 0:
                rs.status = Status.CAP_REACHED
                rs.stop_reason = "exit 0 (cap reached)"
            else:
                # Non-zero exit. Check for a fresh crash artifact.
                crash = self._find_new_crash(target, since=rs.started_at_wall)
                if crash is not None:
                    rs.status = Status.CRASHED
                    rs.stop_reason = f"crash at exec {rs.pulses[-1].exec_count if rs.pulses else '?'}"
                    rs.crash_path = crash
                else:
                    rs.status = Status.STOPPED
                    rs.stop_reason = f"exit code {rc} (no crash artifact)"
```

Also, in `start_run`, store wall-clock start time alongside the monotonic one (we need wall time for file mtime comparison):

```python
        rs.started_at = time.monotonic()
        rs.started_at_wall = time.time()
```

- [ ] **Step 3: Show crash info in the card**

Update `_render_card` to display crash path when status is CRASHED:

```python
            crash_label = ui.label("")  # filled in by reactive update

            def update_crash_label():
                rs = self.runs[(target, sanitizer.value)]
                if rs.status == Status.CRASHED and rs.crash_path:
                    crash_label.text = f"CRASH: {rs.crash_path}"
                    crash_label.classes("text-red-600")
                else:
                    crash_label.text = ""

            ui.timer(1.0, update_crash_label)
```

- [ ] **Step 4: Smoke-test crash detection**

To force a crash: temporarily edit `core/fuzz/fuzz_targets/vault_toml.rs` to add a panic, e.g.:

```rust
fuzz_target!(|data: &[u8]| {
    if data.len() > 50 {
        panic!("forced crash for testing");
    }
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = vault_toml::decode(s);
    }
});
```

Run the monitor and start vault_toml. Within seconds, libFuzzer should hit the panic, write a crash artifact, and the monitor should flip status to CRASHED with the crash file path shown.

**Important:** revert the panic edit before committing:

```bash
cd /Users/hherb/src/secretary/.worktrees/fuzz-harness
git checkout core/fuzz/fuzz_targets/vault_toml.rs
```

- [ ] **Step 5: Verify pure-function tests still pass**

```bash
uv run --with pytest pytest core/fuzz/test_monitor.py -v
```

- [ ] **Step 6: Commit**

```bash
git add core/fuzz/monitor.py
git commit -m "feat(monitor): crash detection via artifact scan + non-zero exit

Two-signal combination: subprocess exit code != 0 AND a fresh
crash-* file in core/fuzz/artifacts/<target>/ since the run started.
Status flips to CRASHED with crash_path set; card shows the path
in red. Manual cargo-fuzz-tmin promotion stays in the shell per
the spec's no-auto-promote decision."
```

---

## Task 14: Persistence (`.monitor-state.json`)

Save last-used runs caps and plateau K across monitor restarts.

**Files:**
- Modify: `core/fuzz/monitor.py`
- Modify: `core/fuzz/.gitignore`

- [ ] **Step 1: Add load/save helpers and wire into MonitorApp**

Add module-level constant and helpers:

```python
import json

_STATE_FILE = _FUZZ_DIR / ".monitor-state.json"


def load_state() -> dict:
    """Load .monitor-state.json with defaults for missing keys."""
    defaults = {
        "runs_caps": {},  # target -> int
        "plateau_k": 10,
    }
    if not _STATE_FILE.is_file():
        return defaults
    try:
        loaded = json.loads(_STATE_FILE.read_text())
        return {**defaults, **loaded}
    except (json.JSONDecodeError, OSError):
        return defaults


def save_state(state: dict) -> None:
    """Write .monitor-state.json. Ignored failures (cosmetic feature)."""
    try:
        _STATE_FILE.write_text(json.dumps(state, indent=2))
    except OSError:
        pass
```

In `MonitorApp.__init__`, load and store state:

```python
        self.state = load_state()
        self.plateau_k = self.state.get("plateau_k", 10)
```

In `MonitorApp.start_run`, after `rs.runs_cap = runs_cap`, persist:

```python
        if runs_cap is not None:
            self.state["runs_caps"][target] = runs_cap
            save_state(self.state)
```

In `_render_card`, prefill the runs_cap input from state:

```python
        prefill = self.state.get("runs_caps", {}).get(target, "")
        runs_cap_input = ui.input(
            "runs cap (blank = open-ended)",
            value=str(prefill) if prefill else "",
        ).props("dense")
```

- [ ] **Step 2: Add `.monitor-state.json` to `core/fuzz/.gitignore`**

Add this line to `core/fuzz/.gitignore` (created in Task 1 of the harness plan):

```
.monitor-state.json
```

- [ ] **Step 3: Verify by restart**

Run the monitor, start a run on `vault_toml` with cap `1234567`, stop it. Quit the monitor (^C). Restart:

```bash
uv run core/fuzz/monitor.py
```

Open the page. The `vault_toml` card's runs-cap input should pre-populate with `1234567`.

- [ ] **Step 4: Verify state file is gitignored**

```bash
cd /Users/hherb/src/secretary/.worktrees/fuzz-harness
git status core/fuzz/.monitor-state.json 2>&1
git check-ignore -v core/fuzz/.monitor-state.json
```

Expected: `git status` should show no output (untracked file ignored). `git check-ignore` should report the matching `.gitignore` rule.

- [ ] **Step 5: Verify pure-function tests still pass**

```bash
uv run --with pytest pytest core/fuzz/test_monitor.py -v
```

- [ ] **Step 6: Commit**

```bash
git add core/fuzz/monitor.py core/fuzz/.gitignore
git commit -m "feat(monitor): persist last-used runs cap per target

.monitor-state.json holds {runs_caps: {target: int}, plateau_k: int}.
Loaded on startup, saved on each Start click. Pre-populates the
runs-cap input field. Schema migration via dict merge with defaults.
Added to core/fuzz/.gitignore."
```

---

## Task 15: README documentation

Add a "Monitor" section to `core/fuzz/README.md` describing how to launch and use the monitor.

**Files:**
- Modify: `core/fuzz/README.md`

- [ ] **Step 1: Append a "Monitor" section to `core/fuzz/README.md`**

Add this section between the existing "Promoting a crash to a regression" and "Differential replay (out-of-loop)" sections, or wherever fits best in the existing flow:

```markdown
## Monitor (NiceGUI dashboard)

A single-file NiceGUI dashboard at `core/fuzz/monitor.py` provides a
browser UI for kicking off fuzz campaigns and watching them auto-stop
on coverage plateau. Runs at `http://localhost:8080`.

```bash
uv run core/fuzz/monitor.py
```

Per-target card has:
- Sanitizer radio: `asan`, `ubsan`, or `both` (sequential).
- Runs cap input (last value persisted per target in `.monitor-state.json`).
- Start/Stop buttons.
- Live status, coverage, corpus, exec rate, RSS.
- Log tail (last 20 stderr lines).
- On crash: red badge with the crash file path.

Plateau detection: auto-SIGTERM after K=10 consecutive libFuzzer pulse
lines with no growth in `cov` or `corp`. Adjustable in the source if
needed; default works for the six fuzz targets in this repo.

The monitor is operator quality-of-life — the harness it drives stays
fully usable from the CLI (`cargo fuzz run <target>`) for any future
maintainer or auditor. See
[docs/superpowers/specs/2026-05-01-fuzz-monitor-design.md](../../docs/superpowers/specs/2026-05-01-fuzz-monitor-design.md)
for the design rationale.
```

- [ ] **Step 2: Commit**

```bash
git add core/fuzz/README.md
git commit -m "docs(fuzz): document monitor.py in core/fuzz/README.md

Brief 'Monitor (NiceGUI dashboard)' section explaining how to launch
the monitor, what the per-target card shows, plateau detection
defaults, and the intentional separation between operator UX and the
CLI-usable harness an external auditor will use."
```

---

## Self-review checklist

After completing all tasks, verify:

1. **Spec coverage:**
   - §2 UX shape → Tasks 9, 10, 13 ✓
   - §3 Plateau detection → Tasks 4, 11 ✓
   - §4 Architecture (pure functions) → Tasks 2-7 ✓
   - §4 Stateful units (RunState, MonitorApp) → Tasks 8, 10 ✓
   - §4 Sanitizer translation → Tasks 10 (asan/ubsan), 12 (both) ✓
   - §4 PATH handling → Tasks 5, 6, 10 ✓
   - §4 Crash detection → Task 13 ✓
   - §5 Persistence → Task 14 ✓
   - §6 Subprocess + PATH → Task 10 ✓
   - §7 Crash detection → Task 13 ✓
   - §8 Error handling → distributed across Tasks 5, 6, 10, 13 ✓
   - §9 Testing → Tasks 2-8 (TDD per pure function) ✓
   - §10 Build sequence → matches Tasks 1-15 order ✓

2. **Hardware-independence note:** plateau detection uses pulse-window K=10, hardware-independent ✓

3. **No placeholders:** every code block is concrete; no "TBD" except in legitimate design-time markers (none in the plan body).

4. **Type consistency:** `Pulse` (Task 2), `RunState` (Task 8), `Status` enum (Task 8), `MonitorApp` (Task 9). All consumed consistently in later tasks.

5. **TDD discipline:** Tasks 2-7 follow strict TDD (failing test → implementation → passing test). Tasks 8-15 mix smoke tests and manual verification because the units are I/O-stateful (subprocess, NiceGUI, filesystem) and pure-function TDD doesn't fit cleanly.
