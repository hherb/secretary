"""Fix-round-1 coverage for `liveness.py` (Findings 1 and 2, PR review).

Deliberately three tests, no more: Task 3's own design leaves both proofs
uncovered by unit tests because they need a real interpreter / a real `cargo
build` (Task 6 exercises them as integration controls instead). Findings 1
and 2 added real behaviour that needs neither, so it gets pinned here rather
than left, per this project's own standard, as untested behaviour.
"""

import pytest

from mutation_harness import liveness
from mutation_harness.types import PythonProbe


def test_clear_pycache_removes_a_directory_and_counts_it(tmp_path):
    cache = tmp_path / "pkg" / "__pycache__"
    cache.mkdir(parents=True)
    (cache / "mod.cpython-313.pyc").write_bytes(b"stale bytecode")

    removed = liveness.clear_pycache(tmp_path)

    assert removed == 1
    assert not cache.exists()


def test_clear_pycache_raises_when_a_cache_survives_removal(tmp_path, monkeypatch):
    """Pins Finding 1: `clear_pycache`'s job is defeating false-green
    mechanism 1 (stale bytecode served under a `(mtime, size)` cache key a
    size-preserving mutation can satisfy), so a cache that fails to go away
    must never be silently reported as cleared.

    `shutil.rmtree` is monkeypatched to a no-op so the EXISTENCE CHECK, not
    `rmtree`'s return, is what fires — verified by execution that reverting
    Finding 1's fix (dropping the `cache.exists()` check and the
    unconditional `removed += 1`) turns this from a pass into a failure; see
    the fix report for the exact command and output.
    """
    cache = tmp_path / "pkg" / "__pycache__"
    cache.mkdir(parents=True)
    (cache / "mod.cpython-313.pyc").write_bytes(b"stale bytecode")

    monkeypatch.setattr(liveness.shutil, "rmtree", lambda *args, **kwargs: None)

    with pytest.raises(liveness.PycacheNotCleared):
        liveness.clear_pycache(tmp_path)


def test_probe_python_rejects_a_non_identifier_module(tmp_path):
    probe = PythonProbe(module="os; import sys", expr="1", equals="1", syspath=".")

    result = liveness.probe_python(probe, tmp_path)

    assert result.live is False
    assert result.mechanism == liveness.MECHANISM_INTERPRETER
    assert "os; import sys" in result.detail
