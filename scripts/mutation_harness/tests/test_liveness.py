"""Fix-round-1 coverage for `liveness.py` (Findings 1 and 2, PR review), plus
the final whole-branch review's Findings 1 and 6.

Task 3's own design leaves both PROOFS largely uncovered by unit tests because
they need a real interpreter / a real `cargo build` (Task 6 exercises them as
integration controls instead). What CAN be pinned without either is the
comparison logic each proof ends in, and after the final review that is where
the load-bearing behaviour lives: both proofs are now before/after
comparisons, and a reading that did not MOVE is `NOT_LIVE` whatever it equals.
"""

import pytest

from mutation_harness import liveness
from mutation_harness.types import PythonObservation, PythonProbe

PROBE = PythonProbe(module="m", expr="TOKEN", equals="mutated", syspath=".")


def _seen(value: str) -> PythonObservation:
    return PythonObservation(ok=True, value=repr(value), error="")


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


def test_observe_python_rejects_a_non_identifier_module(tmp_path):
    observation = liveness.observe_python(
        PythonProbe(module="os; import sys", expr="1", equals="1", syspath="."), tmp_path
    )

    assert observation.ok is False
    assert "os; import sys" in observation.error


# --- Final whole-branch review, Finding 1: the Python proof is a DIFF ------


def test_an_unchanged_python_value_is_not_live_even_when_it_equals_the_spec():
    """THE regression for the finding, and the harness committing #644's own
    sin: a no-op mutation (`TOKEN = "real"` -> `TOKEN = "real"  # edited`)
    whose `equals` was copied from the spec's `old` side satisfies the
    post-condition `observed == probe.equals` while proving nothing. The
    check used to be that post-condition alone, so it reported
    `GREEN_AS_EXPECTED, live=True (interpreter)`.
    """
    probe = PythonProbe(module="m", expr="TOKEN", equals="real", syspath=".")

    result = liveness.compare_python_probe(probe, _seen("real"), _seen("real"))

    assert result.live is False
    assert "did NOT change" in result.detail


def test_a_python_value_that_moved_to_the_declared_value_is_live():
    result = liveness.compare_python_probe(PROBE, _seen("real"), _seen("mutated"))

    assert result.live is True
    assert "'real'" in result.detail and "'mutated'" in result.detail


def test_a_python_value_that_moved_to_the_WRONG_value_is_not_live():
    """The other half of the conjunction: changed, but not to what the spec
    declared, so the harness has not established that THIS mutation is what
    moved it. `detail` must name this condition, not the first one."""
    result = liveness.compare_python_probe(PROBE, _seen("real"), _seen("something-else"))

    assert result.live is False
    assert "declared it would become" in result.detail
    assert "did NOT change" not in result.detail


@pytest.mark.parametrize(
    "before, after, wanted",
    [
        (PythonObservation(False, "", "boom"), _seen("mutated"), "no baseline"),
        (_seen("real"), PythonObservation(False, "", "boom"), "post-mutation probe"),
    ],
    ids=["before-failed", "after-failed"],
)
def test_a_probe_that_could_not_be_taken_is_not_live(before, after, wanted):
    result = liveness.compare_python_probe(PROBE, before, after)

    assert result.live is False
    assert wanted in result.detail


# --- Final whole-branch review, Finding 6: an absent side fails CLOSED -----


def test_an_empty_before_side_is_not_live():
    """The one fail-OPEN path found in the whole harness: an empty `before`
    with a non-empty `after` fell through to the "changed" arm and reported
    the mutation live, having compared a measurement against the absence of
    one."""
    result = liveness.compare_rust_artifacts({}, {"lib.rlib": "aaa"})

    assert result.live is False
    assert "no baseline" in result.detail


def test_an_empty_after_side_is_not_live():
    result = liveness.compare_rust_artifacts({"lib.rlib": "aaa"}, {})

    assert result.live is False


def test_a_timed_out_build_on_either_side_is_not_live():
    timed_out = {liveness.BUILD_TIMED_OUT: "build did not finish within 1s"}

    before_side = liveness.compare_rust_artifacts(timed_out, {"lib.rlib": "aaa"})
    after_side = liveness.compare_rust_artifacts({"lib.rlib": "aaa"}, timed_out)

    assert before_side.live is False and "pre-mutation" in before_side.detail
    assert after_side.live is False and "post-mutation" in after_side.detail


def test_differing_rust_artifacts_are_live():
    result = liveness.compare_rust_artifacts({"lib.rlib": "aaa"}, {"lib.rlib": "bbb"})

    assert result.live is True
    assert "lib.rlib" in result.detail


# --- Fix-round-3, Finding B: the timeout PLUMBING, not just its handling ---
#
# Everything above pins what happens once a timeout is REPORTED (a
# `TimeoutExpired`, a `BUILD_TIMED_OUT` sentinel). Nothing pinned that the
# `timeout` kwarg each function receives is actually the one handed to
# `subprocess.run` -- deleting `timeout=timeout` at either call site left
# 108/108 unit tests and 19/19 `--self-test` green (measured). These two
# tests monkeypatch `subprocess.run` in this module's own namespace with a
# fake that records the kwargs it was called with, so they pin the PLUMBING
# rather than exercising a timeout path.


class _FakeCompletedProcess:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_observe_python_passes_its_timeout_argument_to_subprocess_run(tmp_path, monkeypatch):
    captured = {}

    def fake_run(*args, **kwargs):
        captured.update(kwargs)
        return _FakeCompletedProcess(returncode=0, stdout="'ok'", stderr="")

    monkeypatch.setattr(liveness.subprocess, "run", fake_run)

    liveness.observe_python(PROBE, tmp_path, timeout=123)

    assert captured.get("timeout") == 123


def test_rust_artifact_hashes_passes_its_timeout_argument_to_subprocess_run(tmp_path, monkeypatch):
    captured = {}

    def fake_run(*args, **kwargs):
        captured.update(kwargs)
        return _FakeCompletedProcess(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(liveness.subprocess, "run", fake_run)

    liveness.rust_artifact_hashes("secretary-core", tmp_path, timeout=456)

    assert captured.get("timeout") == 456
