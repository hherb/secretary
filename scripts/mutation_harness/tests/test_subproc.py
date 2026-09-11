"""`subproc.run_bounded`'s two kill paths (fix-wave review, I1).

The timeout path is also covered end to end in `test_gate.py`; the INTERRUPT
path had no test and had regressed: `subprocess.run` kills its child on any
exception (`except: process.kill(); raise`), and the first `run_bounded`
handled `TimeoutExpired` only, so the `SystemExit` the journal's signal
handler raises on Ctrl-C left a `cargo test` running against a tree the
handler was restoring underneath it.
"""

import os
import signal
import time
from pathlib import Path

import pytest

from mutation_harness.subproc import run_bounded


def _wait_for_death(pid: int, seconds: float = 3.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.05)
    return False


def _pid_recorded(pid_file: Path) -> int:
    for _ in range(100):
        if pid_file.exists() and pid_file.read_text().strip():
            return int(pid_file.read_text())
        time.sleep(0.02)
    raise AssertionError("the gate never recorded its child's pid")


class _Interrupted(BaseException):
    """Stands in for the `SystemExit` `journal._on_signal` raises."""


def test_an_exception_raised_while_waiting_kills_the_whole_group(tmp_path):
    pid_file = tmp_path / "child.pid"

    def interrupt(_signum, _frame):
        raise _Interrupted

    previous = signal.signal(signal.SIGALRM, interrupt)
    try:
        signal.setitimer(signal.ITIMER_REAL, 0.5)
        with pytest.raises(_Interrupted):
            run_bounded(
                ["bash", "-c", f"sleep 30 & echo $! > {pid_file}; wait"],
                cwd=tmp_path, env=None, timeout=60,
            )
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)

    child = _pid_recorded(pid_file)
    if not _wait_for_death(child):
        os.kill(child, signal.SIGKILL)
        pytest.fail(f"grandchild {child} survived the interrupt")


def test_a_timeout_reports_partial_output_and_returncode_none(tmp_path):
    run = run_bounded(
        ["bash", "-c", "echo partial; sleep 30"], cwd=tmp_path, env=None, timeout=1
    )
    assert run.timed_out and run.returncode is None
    assert "partial" in run.stdout


def test_invalid_utf8_is_replaced_not_raised(tmp_path):
    run = run_bounded(["bash", "-c", "printf '\\xff'"], cwd=tmp_path, env=None, timeout=5)
    assert run.returncode == 0
    assert run.stdout == "�"
