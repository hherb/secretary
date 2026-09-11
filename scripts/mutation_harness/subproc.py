"""Bounded subprocess execution, shared by the gate and both liveness probes.

Three properties every child this harness spawns needs, in ONE place so the
three call sites cannot drift (PR #652 review):

* **A timeout kills the whole PROCESS GROUP.** `subprocess.run(timeout=)`
  kills only the direct child. A gate is a shell, and `cargo test` under it
  spawns `rustc` and test binaries; killing the shell alone left those
  running while `runner.py` restored the tree underneath them. Every child
  starts in its own session, so its pgid is its pid and one `killpg` reaches
  every descendant.
* **Output is captured as BYTES and decoded with `errors="replace"`.**
  `text=True` decodes strictly, so one invalid UTF-8 byte in gate output — a
  Rust test printing raw bytes on failure, i.e. precisely when the gate is
  red — raised `UnicodeDecodeError` out of the run with no table rendered.
* **A timeout is `returncode is None`**, distinct from every real exit code,
  and whatever the child printed before the kill is still returned: for a
  hung gate that partial output is the only evidence the caller gets.
* **ANY exception kills the group too** — a `SystemExit` raised by
  `journal._on_signal` on Ctrl-C included. `subprocess.run` does this
  (`except: process.kill(); raise`) and the first version of this module
  dropped it, so an interrupted `cargo test` kept running against a tree the
  signal handler was restoring underneath it — the exact hazard the first
  bullet claims to close, reintroduced on the signal path (fix-wave review).
"""

from __future__ import annotations

import dataclasses
import os
import signal
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path


@dataclasses.dataclass(frozen=True)
class BoundedRun:
    returncode: int | None
    stdout: str
    stderr: str

    @property
    def timed_out(self) -> bool:
        return self.returncode is None


def _decode(chunk: bytes | None) -> str:
    return "" if chunk is None else chunk.decode(errors="replace")


def _kill_group(proc: subprocess.Popen) -> None:
    """SIGKILL the child's whole process group; fall back to the child alone
    where process groups do not exist."""
    if hasattr(os, "killpg"):
        try:
            os.killpg(proc.pid, signal.SIGKILL)
            return
        except ProcessLookupError:
            return
    proc.kill()


def run_bounded(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str] | None,
    timeout: int,
) -> BoundedRun:
    """Run `argv` in its own session; return its output, or the partial
    output plus `returncode=None` if it outlived `timeout` seconds."""
    with subprocess.Popen(
        list(argv),
        cwd=str(cwd),
        env=None if env is None else dict(env),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    ) as proc:
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill_group(proc)
            out, err = proc.communicate()
            return BoundedRun(None, _decode(out), _decode(err))
        except BaseException:
            # Includes KeyboardInterrupt and the SystemExit the journal's
            # signal handler raises; the context manager then closes the
            # pipes and reaps.
            _kill_group(proc)
            raise
    return BoundedRun(proc.returncode, _decode(out), _decode(err))
