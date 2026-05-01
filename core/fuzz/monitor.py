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

import enum
import re
from collections import deque
from dataclasses import dataclass
from pathlib import Path


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


import tomllib


def parse_targets(cargo_toml_text: str) -> list[str]:
    """Extract [[bin]] target names from a Cargo.toml string.

    Returns the names in document order. Raises tomllib.TOMLDecodeError
    on malformed input.
    """
    parsed = tomllib.loads(cargo_toml_text)
    bins = parsed.get("bin", [])
    return [b["name"] for b in bins if "name" in b]


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
