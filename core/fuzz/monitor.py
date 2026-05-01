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


def main() -> None:
    """Entry point. Real implementation arrives in Task 9."""
    print("monitor scaffold OK")


if __name__ == "__main__":
    main()
