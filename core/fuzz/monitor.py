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

import re
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


def main() -> None:
    """Entry point. Real implementation arrives in Task 9."""
    print("monitor scaffold OK")


if __name__ == "__main__":
    main()
