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

import asyncio
import enum
import os
import re
import signal
import subprocess
import time
from collections import deque
from dataclasses import dataclass, field
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
# REDUCE, INITED, DONE, RELOAD. The `lim: N` field is optional.
#
# libFuzzer's ScaleBytes() emits the corp size as exactly one of:
#   - "<int>b"      for sizes < 1 KiB                (e.g. "147b")
#   - "<float>k"    for sizes < 1 MiB, no trailing b (e.g. "8.2k")
#   - "<float>Mb"   for sizes >= 1 MiB               (e.g. "1.2Mb")
# We tolerate either an integer or a single-decimal float in the k/Mb
# variants for forward-compatibility with libFuzzer formatting changes,
# but reject ill-formed sizes (e.g. "1..5", "1234" with no unit, "Gb")
# so a corrupted log line can't silently masquerade as a valid pulse.
_PULSE_RE = re.compile(
    r"^#(?P<exec_count>\d+)\s+(?:pulse|NEW|REDUCE|INITED|DONE|RELOAD)\s+"
    r"cov:\s+(?P<cov>\d+)\s+"
    r"ft:\s+(?P<ft>\d+)\s+"
    r"corp:\s+(?P<corp>\d+)/(?:\d+b|\d+(?:\.\d+)?(?:k|Mb))\s+"
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
    # maxlen=64 is generous; actual K used by check_plateau is smaller.
    pulses: deque[Pulse] = field(default_factory=lambda: deque(maxlen=64))
    log_tail: deque[str] = field(default_factory=lambda: deque(maxlen=20))
    runs_cap: int | None = None
    started_at: float = 0.0  # monotonic clock at subprocess spawn (for elapsed time)
    started_at_wall: float = 0.0  # wall clock (for comparing against artifact file mtimes)
    stop_reason: str | None = None
    crash_path: Path | None = None


import json

from nicegui import ui

# Path constants (resolved at module import time so tests don't break).
_FUZZ_DIR = Path(__file__).parent  # core/fuzz/
_CARGO_TOML = _FUZZ_DIR / "Cargo.toml"
_STATE_FILE = _FUZZ_DIR / ".monitor-state.json"


def load_state() -> dict:
    """Load .monitor-state.json with defaults for missing keys."""
    defaults = {
        "runs_caps": {},
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
        self.state = load_state()
        self.plateau_k = self.state.get("plateau_k", 10)

    def render(self) -> None:
        """Build the full page UI."""
        ui.label("Secretary fuzz monitor").classes("text-h4")
        with ui.grid(columns=3).classes("gap-4"):
            for target in self.targets:
                self._render_card(target)

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
        if runs_cap is not None:
            self.state["runs_caps"][target] = runs_cap
            save_state(self.state)
        rs.crash_path = None
        rs.stop_reason = None
        rs.started_at = time.monotonic()
        rs.started_at_wall = time.time()
        rs.status = Status.RUNNING
        rs.log_tail.append(f"$ {' '.join(argv)}")

        # cargo-fuzz emits its telemetry on stderr; stdout is unused. Pipe it
        # to /dev/null rather than PIPE so the OS pipe buffer (~64 KB) cannot
        # fill and block the subprocess write — we never spawn a stdout reader.
        proc = await asyncio.create_subprocess_exec(
            *argv,
            cwd=str(_FUZZ_DIR),
            env=env,
            stdout=asyncio.subprocess.DEVNULL,
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
                # Non-zero exit. Check for a fresh crash artifact.
                crash = self._find_new_crash(target, since=rs.started_at_wall)
                if crash is not None:
                    rs.status = Status.CRASHED
                    rs.stop_reason = f"crash at exec {rs.pulses[-1].exec_count if rs.pulses else '?'}"
                    rs.crash_path = crash
                else:
                    rs.status = Status.STOPPED
                    rs.stop_reason = f"exit code {rc} (no crash artifact)"

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

    async def _chain_ubsan(self, target: str, runs_cap: int | None) -> None:
        """After ASan finishes (any reason except CRASHED or user-STOPPED),
        kick off UBSan automatically. Treat user-stop as 'abandon the chain'."""
        asan = self.runs[(target, "asan")]
        # Poll until ASan is no longer RUNNING.
        while asan.status == Status.RUNNING:
            await asyncio.sleep(1.0)
        if asan.status in (Status.PLATEAU, Status.CAP_REACHED):
            await self.start_run(target, "ubsan", runs_cap)

    def _render_card(self, target: str) -> None:
        with ui.card().classes("w-96"):
            ui.label(target).classes("text-h6")
            sanitizer = ui.radio(["asan", "ubsan", "both"], value="asan").props("inline")
            prefill = self.state.get("runs_caps", {}).get(target, "")
            runs_cap_input = ui.input(
                "runs cap (blank = open-ended)",
                value=str(prefill) if prefill else "",
            ).props("dense")
            status_label = ui.label("status: idle")
            crash_label = ui.label("")  # filled in by reactive update

            def update_crash_label():
                rs = self.runs[(target, sanitizer.value)]
                if rs.status == Status.CRASHED and rs.crash_path:
                    crash_label.text = f"CRASH: {rs.crash_path}"
                    crash_label.classes("text-red-600")
                else:
                    crash_label.text = ""

            ui.timer(1.0, update_crash_label)

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

            async def on_stop():
                await self.stop_run(target, sanitizer.value)
                status_label.text = f"status: {self.runs[(target, sanitizer.value)].status.name}"

            with ui.row():
                ui.button("Start", on_click=on_start).props("color=primary")
                ui.button("Stop", on_click=on_stop).props("color=negative")


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
