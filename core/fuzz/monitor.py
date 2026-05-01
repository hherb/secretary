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
import json
import os
import re
import signal
import time
import tomllib
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from nicegui import ui


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


class Status(enum.IntEnum):
    """RunState lifecycle status — drives card badge color."""

    IDLE = 0      # never run, or stopped cleanly with no telemetry
    RUNNING = 1   # subprocess alive
    PLATEAU = 2   # auto-stopped after plateau detection
    CAP_REACHED = 3  # stopped because -runs cap fired before plateau
    CRASHED = 4   # non-zero exit AND/OR new artifact in artifacts/<target>/
    STOPPED = 5   # user-clicked Stop


# Status -> Quasar text-color class. RUNNING is positive (green) so a healthy
# campaign reads as "go"; PLATEAU is warning (amber) because the auto-stop
# is informative but not an error; CAP_REACHED is info (blue) — the user
# requested the cap; CRASHED is negative (red); IDLE/STOPPED are grey-7
# (idle and "user stopped" are not states that warrant attention).
_STATUS_BADGE_CLASS: dict[Status, str] = {
    Status.IDLE: "text-grey-7",
    Status.RUNNING: "text-positive",
    Status.PLATEAU: "text-warning",
    Status.CAP_REACHED: "text-info",
    Status.CRASHED: "text-negative",
    Status.STOPPED: "text-grey-7",
}


def effective_sanitizer_key(selected: str, ubsan_status: Status) -> str:
    """Resolve the radio selection ('asan'/'ubsan'/'both') to the actual
    self.runs key. 'both' is a UI-only meta-option meaning 'run ASan, chain
    UBSan'; once UBSan has been started it becomes the live key, otherwise
    ASan does. Without this remap, 'both' would index a non-existent
    (target, 'both') slot and raise KeyError on every per-card tick."""
    if selected != "both":
        return selected
    return "ubsan" if ubsan_status != Status.IDLE else "asan"


def status_badge_class(status: Status) -> str:
    """Return the Quasar text-color class for a given Status."""
    return _STATUS_BADGE_CLASS[status]


def format_pulse_readout(pulse: Pulse | None) -> str:
    """Render the most recent libFuzzer pulse as a single readable line.

    `None` (no pulses yet — idle, or the subprocess has spawned but
    hasn't emitted INITED) renders as an em-dash so the user can tell
    "no telemetry yet" apart from "telemetry says zero".
    """
    if pulse is None:
        return "—"
    return (
        f"cov {pulse.cov} / ft {pulse.ft} / corp {pulse.corp} "
        f"/ {pulse.exec_s} exec/s / {pulse.rss} MB"
    )


def format_elapsed(seconds: float) -> str:
    """Render `time.monotonic()` differences as `mm:ss` or `h:mm:ss`.

    Truncates fractional seconds (sub-second monotonic noise should not
    show as flicker between `00:07` and `00:08`). Negative input is
    clamped to zero so a defensive `max(0, ...)` is unnecessary at the
    call site.
    """
    s = max(0, int(seconds))
    h, rest = divmod(s, 3600)
    m, sec = divmod(rest, 60)
    if h > 0:
        return f"{h}:{m:02d}:{sec:02d}"
    return f"{m:02d}:{sec:02d}"


def format_human_count(n: int) -> str:
    """SI-suffix decimal counter formatting (k = 1000, M = 1_000_000).

    Used for both `exec_count` and `runs_cap`. Trailing `.0` is stripped
    so round numbers read as `1k` not `1.0k`. Decimal SI is correct here
    (these are counts, not bytes); libFuzzer's `corp:` byte-formatter
    uses a different convention (k = 1024, Mb = 1024*1024) that we
    deliberately don't share.
    """
    if n < 1000:
        return str(n)
    if n < 1_000_000:
        return _trim_decimal(n / 1000) + "k"
    if n < 1_000_000_000:
        return _trim_decimal(n / 1_000_000) + "M"
    return _trim_decimal(n / 1_000_000_000) + "G"


def _trim_decimal(v: float) -> str:
    """Render `v` with one decimal (truncated, not rounded), then strip
    a trailing `.0`.

    Truncation rather than `:.1f`'s round-half-to-even avoids the
    boundary surprise where `format_human_count(999_999)` would render
    as `"1000k"`: `999_999/1000 = 999.999`, which `:.1f` rounds up to
    `"1000.0"`. The caller already chose the magnitude (kilo, mega,
    giga) based on the integer's actual range; the decimal part should
    not visually push the value into the next magnitude.
    """
    truncated = int(v * 10) / 10
    s = f"{truncated:.1f}"
    return s.removesuffix(".0")


def format_runs_progress(exec_count: int, runs_cap: int | None) -> str:
    """`exec_count / runs_cap` (e.g. '1.2M / 5M') when the campaign has
    a cap; just `exec_count` (open-ended) otherwise."""
    if runs_cap is None:
        return format_human_count(exec_count)
    return f"{format_human_count(exec_count)} / {format_human_count(runs_cap)}"


def format_card_elapsed(
    started_at: float,
    stopped_at: float,
    is_running: bool,
    now: float,
) -> str:
    """Render the per-card `elapsed: ...` label.

    Three regimes:

    * `started_at == 0.0` — card has never been started; `elapsed: —`.
    * `is_running == True` — live tick, `now - started_at`.
    * Terminal status with `stopped_at > 0.0` — frozen at the wall-clock
      moment the subprocess actually exited (or was SIGTERM'd), not the
      next 1 Hz tick after that. Closes the ~1 s lag the
      "skip-update-on-terminal" approach left, so the frozen value
      matches the actual run duration.

    Defensive fallback: terminal status with `stopped_at == 0.0`
    shouldn't happen with the current call sites, but the helper falls
    back to `now - started_at` rather than blowing up.
    """
    if started_at == 0.0:
        return "elapsed: —"
    if is_running:
        return f"elapsed: {format_elapsed(now - started_at)}"
    end = stopped_at if stopped_at > 0.0 else now
    return f"elapsed: {format_elapsed(end - started_at)}"


# libFuzzer artifact-prefix -> (singular, plural) display label. Order
# of iteration in summary output follows _KIND_ORDER below.
_ARTIFACT_KIND_LABELS: dict[str, tuple[str, str]] = {
    "oom": ("OOM", "OOMs"),
    "slow-unit": ("slow-unit", "slow-units"),
    "crash": ("crash", "crashes"),
}
_KIND_ORDER: tuple[str, ...] = ("oom", "slow-unit", "crash")


def categorize_artifact(filename: str) -> str | None:
    """Return the libFuzzer artifact kind for `filename`, or None.

    Recognises the three prefixes libFuzzer writes for findings —
    `oom-`, `slow-unit-`, `crash-` — and returns the prefix without
    the trailing dash. Anything else (`.gitkeep`, repo READMEs, leftover
    binaries) returns None and is ignored by the counter.
    """
    if not filename:
        return None
    for kind in _KIND_ORDER:
        if filename.startswith(f"{kind}-"):
            return kind
    return None


def aggregate_artifact_counts(filenames) -> dict[str, int]:
    """Fold a sequence of filenames into per-kind counts. Names that
    don't categorise (e.g. `.gitkeep`) are dropped silently."""
    counts: dict[str, int] = {}
    for name in filenames:
        kind = categorize_artifact(name)
        if kind is not None:
            counts[kind] = counts.get(kind, 0) + 1
    return counts


def format_findings_summary(counts: dict[str, int], target_count: int) -> str:
    """Render the global findings tally as a single line.

    Output shape (matching the spec):
      `Findings: 2 OOMs, 2 slow-units across 4 targets`

    Iteration order over kinds is fixed at `oom -> slow-unit -> crash`
    so the line doesn't shuffle as findings accumulate. Singular vs
    plural is per-kind (`1 OOM` / `2 OOMs`, `1 crash` / `2 crashes`).
    `target` itself is also pluralised so a single-target setup reads
    naturally.
    """
    parts: list[str] = []
    for kind in _KIND_ORDER:
        n = counts.get(kind, 0)
        if n == 0:
            continue
        singular, plural = _ARTIFACT_KIND_LABELS[kind]
        parts.append(f"{n} {singular if n == 1 else plural}")
    head = ", ".join(parts) if parts else "none"
    target_word = "target" if target_count == 1 else "targets"
    return f"Findings: {head} across {target_count} {target_word}"


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
    # monotonic clock at the instant the subprocess exits or is SIGTERM'd.
    # Captured so the per-card `elapsed:` label can freeze at the actual
    # stop time rather than at the next 1 Hz tick after that. 0.0 means
    # "still running, or never started".
    stopped_at: float = 0.0
    stop_reason: str | None = None
    crash_path: Path | None = None


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
        findings_label = ui.label(self._findings_summary()).classes("text-mono text-sm")

        def update_findings() -> None:
            findings_label.text = self._findings_summary()

        ui.timer(1.0, update_findings)
        with ui.grid(columns=3).classes("gap-4"):
            for target in self.targets:
                self._render_card(target)

    def _findings_summary(self) -> str:
        """Scan `artifacts/<target>/` for each target and render the
        aggregated tally.

        Failures (missing dir, transient OS error during a scan) are
        treated as 'no findings for that target' rather than propagated
        — the dashboard's findings line is informational, not a contract.
        """
        artifacts_root = _FUZZ_DIR / "artifacts"
        totals: dict[str, int] = {}
        for target in self.targets:
            target_dir = artifacts_root / target
            if not target_dir.is_dir():
                continue
            try:
                names = [p.name for p in target_dir.iterdir() if p.is_file()]
            except OSError:
                continue
            for kind, n in aggregate_artifact_counts(names).items():
                totals[kind] = totals.get(kind, 0) + n
        return format_findings_summary(totals, len(self.targets))

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
        rs.stopped_at = 0.0  # cleared so a re-run isn't frozen at the prior stop
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
                # Plateau check: when fired, SIGTERM the subprocess once.
                # libFuzzer may emit additional pulses between SIGTERM and
                # actual exit, and they may also satisfy check_plateau —
                # guarding on `returncode is None` (process still alive)
                # AND on stop_reason being unset (not already SIGTERM'd
                # this run) avoids redundant signals and overwriting the
                # original "plateau at exec N" reason.
                if (
                    proc.returncode is None
                    and rs.stop_reason is None
                    and check_plateau(list(rs.pulses), self.plateau_k)
                ):
                    rs.stop_reason = f"plateau at exec {pulse.exec_count}"
                    proc.send_signal(signal.SIGTERM)
        rc = await proc.wait()
        if rs.status == Status.RUNNING:
            # Capture the stop time before flipping status, so the moment
            # the next tick observes the new (terminal) status, stopped_at
            # is already set — keeps the frozen `elapsed:` label accurate
            # to the actual exit moment instead of ~1 s late.
            rs.stopped_at = time.monotonic()
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
        # Same ordering as _read_stderr: set stopped_at before status so
        # the per-card timer's first observation of STOPPED has a valid
        # frozen value to render.
        rs.stopped_at = time.monotonic()
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
            # Label shortened from "runs cap (blank = open-ended)" so it
            # fits the w-96 card column width without being clipped to
            # `runs cap (blank = open…`.
            runs_cap_input = ui.input(
                "runs cap (blank = ∞)",
                value=str(prefill) if prefill else "",
            ).props("dense")
            status_label = ui.label("status: IDLE").classes(status_badge_class(Status.IDLE))
            pulse_label = ui.label(format_pulse_readout(None)).classes("text-mono text-sm")
            elapsed_label = ui.label("elapsed: —").classes("text-mono text-sm")
            progress_label = ui.label("runs: —").classes("text-mono text-sm")
            crash_label = ui.label("")  # filled in by reactive update

            # Single per-card 1 Hz tick that owns every reactive label on the
            # card. status_label was previously imperative in on_start /
            # on_stop and never reflected the lifecycle transitions
            # (PLATEAU / CAP_REACHED / CRASHED) the stderr reader drives on
            # RunState.status; folding it into the timer plus the reset of
            # the badge class on each tick fixes that.
            def update_card():
                key = effective_sanitizer_key(
                    sanitizer.value, self.runs[(target, "ubsan")].status
                )
                rs = self.runs[(target, key)]
                status_label.text = f"status: {rs.status.name}"
                # Replace, don't append — repeated appends would accumulate
                # stale classes across status transitions.
                status_label.classes(replace=status_badge_class(rs.status))
                pulse_label.text = format_pulse_readout(
                    rs.pulses[-1] if rs.pulses else None
                )
                # Elapsed: tick live while RUNNING, freeze at the
                # subprocess's actual stop time (rs.stopped_at, captured
                # in _read_stderr / stop_run before the status flip), or
                # show '—' when the card has never been started.
                elapsed_label.text = format_card_elapsed(
                    rs.started_at,
                    rs.stopped_at,
                    rs.status == Status.RUNNING,
                    time.monotonic(),
                )
                progress_label.text = "runs: " + (
                    format_runs_progress(rs.pulses[-1].exec_count, rs.runs_cap)
                    if rs.pulses
                    else "—"
                )
                # Mirror the status_label pattern: replace, not append. The
                # crash_label is now reached every tick (not only on Stop),
                # so an append-only `.classes("text-red-600")` would stack
                # `text-red-600 text-red-600 ...` across consecutive CRASHED
                # ticks. Idempotent for CSS, but it makes the rendered
                # element ugly to inspect and obscures real class drift.
                if rs.status == Status.CRASHED and rs.crash_path:
                    crash_label.text = f"CRASH: {rs.crash_path}"
                    crash_label.classes(replace="text-red-600")
                else:
                    crash_label.text = ""
                    crash_label.classes(replace="")

            ui.timer(1.0, update_card)

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

            async def on_stop():
                key = effective_sanitizer_key(
                    sanitizer.value, self.runs[(target, "ubsan")].status
                )
                await self.stop_run(target, key)

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

    # Build UI per-session so ui.timer's lifecycle is bound to the page slot;
    # on the auto-index page timers outlive client disconnect and crash.
    @ui.page("/")
    def index() -> None:
        app.render()

    ui.run(port=8080, show=False, reload=False, title="Fuzz monitor")


if __name__ == "__main__" or __name__ == "__mp_main__":
    main()
