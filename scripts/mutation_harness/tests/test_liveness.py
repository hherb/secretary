"""Fix-round-1 coverage for `liveness.py` (Findings 1 and 2, PR review), the
final whole-branch review's Findings 1 and 6, and the PR #652 review's typed
Rust readings.

Task 3's own design leaves both PROOFS largely uncovered by unit tests because
they need a real interpreter / a real `cargo build` (Task 6 exercises them as
integration controls instead). What CAN be pinned without either is the
comparison logic each proof ends in — and, since the PR #652 review, cargo's
JSON parsing through a faked `run_bounded`, which had ZERO unit tests before
(the one fake returned empty stdout, so the artifact filter, the package-id
match, the hashing and the failure sentinel were unexecuted under pytest).
"""

import json
import sys

import pytest

from mutation_harness import liveness
from mutation_harness.subproc import BoundedRun
from mutation_harness.types import (
    PythonObservation, PythonProbe, RustObservation, RustReadingKind,
)

PROBE = PythonProbe(module="m", expr="TOKEN", equals="mutated", syspath=".")


def _seen(value: str) -> PythonObservation:
    return PythonObservation(ok=True, value=repr(value), error="")


def _artifacts(**hashes: str) -> RustObservation:
    return RustObservation(RustReadingKind.ARTIFACTS, dict(hashes))


FAILED = RustObservation(RustReadingKind.BUILD_FAILED, detail="failed (cargo exited 101)")
TIMED_OUT = RustObservation(RustReadingKind.BUILD_TIMED_OUT, detail="did not finish within 1s")
MISSING = RustObservation(RustReadingKind.ARTIFACT_MISSING, detail="named x but it could not be read")


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


def test_python_env_forbids_bytecode_writes_and_out_of_tree_bytecode_reads(monkeypatch):
    """With `PYTHONPYCACHEPREFIX` inherited, CPython reads bytecode from a
    mirror tree OUTSIDE the repo that `clear_pycache` never sweeps, so a
    stale `.pyc` there brought false-green mechanism 1 back for anyone who
    sets that variable."""
    monkeypatch.setenv("PYTHONPYCACHEPREFIX", "/somewhere/else")
    env = liveness.python_env()
    assert env["PYTHONDONTWRITEBYTECODE"] == "1"
    assert "PYTHONPYCACHEPREFIX" not in env


def test_observe_python_rejects_a_non_identifier_module(tmp_path):
    observation = liveness.observe_python(
        PythonProbe(module="os; import sys", expr="1", equals="1", syspath="."), tmp_path
    )

    assert observation.ok is False
    assert "os; import sys" in observation.error


def test_observe_python_runs_the_harness_interpreter_not_whatever_python3_is_on_path(
    tmp_path, monkeypatch
):
    captured = {}

    def fake_run_bounded(argv, **kwargs):
        captured["argv"] = list(argv)
        return BoundedRun(0, "'ok'", "")

    monkeypatch.setattr(liveness, "run_bounded", fake_run_bounded)
    liveness.observe_python(PROBE, tmp_path)
    assert captured["argv"][0] == sys.executable


@pytest.mark.parametrize(
    "run, wanted",
    [
        (BoundedRun(None, "", ""), "did not finish"),
        (BoundedRun(1, "", "Traceback: ImportError"), "failed to run"),
        (BoundedRun(0, "", ""), "printed no value"),
        (BoundedRun(0, "   \n", ""), "printed no value"),
    ],
    ids=["timeout", "non-zero-exit", "empty-stdout", "whitespace-stdout"],
)
def test_observe_python_reports_every_way_a_reading_can_fail(tmp_path, monkeypatch, run, wanted):
    """An empty stdout used to be `ok=True, value=""` — a baseline any later
    value "moved away from" (PR #652 review)."""
    monkeypatch.setattr(liveness, "run_bounded", lambda argv, **kw: run)
    observation = liveness.observe_python(PROBE, tmp_path)
    assert observation.ok is False
    assert wanted in observation.error


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
    """Including a module the mutation made UNIMPORTABLE — the Python ruling
    is `NOT_LIVE` (no value to compare), the OPPOSITE of the Rust ruling on
    a build the mutation broke; both are pinned, see the module docstring."""
    result = liveness.compare_python_probe(PROBE, before, after)

    assert result.live is False
    assert wanted in result.detail


# --- Final whole-branch review, Finding 6 + PR #652 Critical: absent sides --


def test_an_empty_before_side_is_not_live():
    """The one fail-OPEN path found in the whole-branch review: an empty
    `before` with a non-empty `after` fell through to the "changed" arm and
    reported the mutation live, having compared a measurement against the
    absence of one."""
    result = liveness.compare_rust_artifacts(_artifacts(), _artifacts(lib="aaa"))

    assert result.live is False
    assert "no baseline" in result.detail


def test_an_empty_after_side_is_not_live():
    assert liveness.compare_rust_artifacts(_artifacts(lib="aaa"), _artifacts()).live is False


def test_a_timed_out_build_on_either_side_is_not_live():
    before_side = liveness.compare_rust_artifacts(TIMED_OUT, _artifacts(lib="aaa"))
    after_side = liveness.compare_rust_artifacts(_artifacts(lib="aaa"), TIMED_OUT)

    assert before_side.live is False and "pre-mutation" in before_side.detail
    assert after_side.live is False and "post-mutation" in after_side.detail


@pytest.mark.parametrize("after", [FAILED, _artifacts(lib="bbb"), TIMED_OUT, MISSING],
                         ids=["failed", "artifacts", "timed-out", "missing"])
def test_a_failed_baseline_build_is_an_absent_baseline_whatever_the_mutated_build_does(after):
    """THE Critical of the PR #652 review: `BUILD_FAILED` was a sentinel KEY
    the comparison never looked for, so two failed builds whose stderr
    differed — a shifted line number, a "Blocking waiting for file lock" line
    from a parallel session — scored `live=True` with no artifact ever
    produced. A `before` that is not a measurement is `live=False` regardless
    of `after`."""
    result = liveness.compare_rust_artifacts(FAILED, after)

    assert result.live is False
    assert "pre-mutation" in result.detail and "no baseline" in result.detail


def test_two_identically_failing_builds_are_not_live_either():
    assert liveness.compare_rust_artifacts(FAILED, FAILED).live is False


def test_a_build_the_mutation_broke_is_live():
    """The deliberate asymmetry with the Python proof: the compiler
    demonstrably saw the change, and there is no declared value to miss."""
    result = liveness.compare_rust_artifacts(_artifacts(lib="aaa"), FAILED)

    assert result.live is True
    assert "no longer builds" in result.detail


def test_a_post_mutation_reading_that_lost_an_artifact_is_not_live():
    """A cargo-named artifact missing at hash time used to be silently
    dropped from the map, and the set difference then read as "changed"."""
    result = liveness.compare_rust_artifacts(_artifacts(lib="aaa"), MISSING)

    assert result.live is False
    assert "post-mutation" in result.detail


def test_a_changed_artifact_set_is_not_a_measurement():
    result = liveness.compare_rust_artifacts(
        _artifacts(lib="aaa", rmeta="bbb"), _artifacts(lib="aaa")
    )

    assert result.live is False
    assert "SET changed" in result.detail and "rmeta" in result.detail


def test_differing_rust_artifacts_are_live():
    result = liveness.compare_rust_artifacts(_artifacts(lib="aaa"), _artifacts(lib="bbb"))

    assert result.live is True
    assert "lib" in result.detail


def test_identical_rust_artifacts_are_not_live():
    result = liveness.compare_rust_artifacts(_artifacts(lib="aaa"), _artifacts(lib="aaa"))

    assert result.live is False
    assert "unchanged" in result.detail


# --- PR #652 review: cargo's JSON, through a faked `run_bounded` -------------


@pytest.mark.parametrize(
    "package_id, package, wanted",
    [
        ("path+file:///w/core#secretary-core@0.1.0", "secretary-core", True),
        ("path+file:///w/core#secretary-core@0.1.0", "core", False),
        ("path+file:///w/fuzz#secretary-core-fuzz@0.1.0", "secretary-core", False),
        ("path+file:///tmp/x/mutdemo#0.0.0", "mutdemo", True),
        ("path+file:///tmp/x/mutdemo#0.0.0", "demo", False),
        ("secretary-core 0.1.0 (path+file:///w/core)", "secretary-core", True),
        ("secretary-core-fuzz 0.1.0 (path+file:///w/fuzz)", "secretary-core", False),
    ],
    ids=["url-name", "url-substring", "url-prefix", "url-implicit", "url-implicit-substring",
         "legacy", "legacy-prefix"],
)
def test_package_id_matching_is_exact_in_both_cargo_spellings(package_id, package, wanted):
    """`package in package_id` matched `secretary-core-fuzz` for
    `secretary-core` and everything for `core`."""
    assert liveness.package_id_names(package_id, package) is wanted


def _artifact_line(package_id: str, *filenames: str) -> str:
    return json.dumps(
        {"reason": "compiler-artifact", "package_id": package_id, "filenames": list(filenames)}
    )


def test_rust_artifact_hashes_hashes_only_the_named_packages_artifacts(tmp_path, monkeypatch):
    mine = tmp_path / "libmine.rlib"
    mine.write_bytes(b"mine")
    theirs = tmp_path / "libtheirs.rlib"
    theirs.write_bytes(b"theirs")
    stdout = "\n".join([
        "not json at all",
        json.dumps({"reason": "compiler-message", "message": "warning"}),
        _artifact_line("path+file:///w/theirs#theirs@0.1.0", str(theirs)),
        _artifact_line("path+file:///w/mine#mine@0.1.0", str(mine)),
    ])
    monkeypatch.setattr(liveness, "run_bounded", lambda argv, **kw: BoundedRun(0, stdout, ""))

    reading = liveness.rust_artifact_hashes("mine", tmp_path)

    assert reading.kind is RustReadingKind.ARTIFACTS
    assert set(reading.hashes) == {str(mine)}


def test_a_failed_build_is_build_failed_even_when_cargo_named_an_artifact(tmp_path, monkeypatch):
    """The exit code was consulted only when the artifact map was EMPTY, so a
    build that failed after emitting a build-script binary read as a
    successful measurement."""
    early = tmp_path / "build_script"
    early.write_bytes(b"x")
    stdout = _artifact_line("path+file:///w/mine#mine@0.1.0", str(early))
    monkeypatch.setattr(
        liveness, "run_bounded", lambda argv, **kw: BoundedRun(101, stdout, "error[E0308]")
    )

    reading = liveness.rust_artifact_hashes("mine", tmp_path)

    assert reading.kind is RustReadingKind.BUILD_FAILED
    assert "101" in reading.detail


def test_a_named_artifact_that_cannot_be_read_is_artifact_missing(tmp_path, monkeypatch):
    stdout = _artifact_line("path+file:///w/mine#mine@0.1.0", str(tmp_path / "gone.rlib"))
    monkeypatch.setattr(liveness, "run_bounded", lambda argv, **kw: BoundedRun(0, stdout, ""))

    reading = liveness.rust_artifact_hashes("mine", tmp_path)

    assert reading.kind is RustReadingKind.ARTIFACT_MISSING
    assert "gone.rlib" in reading.detail


def test_a_build_that_outlives_its_timeout_is_build_timed_out(tmp_path, monkeypatch):
    monkeypatch.setattr(liveness, "run_bounded", lambda argv, **kw: BoundedRun(None, "", ""))

    reading = liveness.rust_artifact_hashes("mine", tmp_path, timeout=7)

    assert reading.kind is RustReadingKind.BUILD_TIMED_OUT
    assert "7s" in reading.detail


# --- Fix-round-3, Finding B: the timeout PLUMBING, not just its handling ---
#
# Everything above pins what happens once a timeout is REPORTED. Nothing
# pinned that the `timeout` kwarg each function receives is actually the one
# handed to the subprocess layer -- deleting it at either call site left the
# whole suite green (measured). These two fake `run_bounded` in this module's
# own namespace and record the kwargs it was called with.


def test_observe_python_passes_its_timeout_argument_to_run_bounded(tmp_path, monkeypatch):
    captured = {}

    def fake(argv, **kwargs):
        captured.update(kwargs)
        return BoundedRun(0, "'ok'", "")

    monkeypatch.setattr(liveness, "run_bounded", fake)

    liveness.observe_python(PROBE, tmp_path, timeout=123)

    assert captured.get("timeout") == 123


def test_rust_artifact_hashes_passes_its_timeout_argument_to_run_bounded(tmp_path, monkeypatch):
    captured = {}

    def fake(argv, **kwargs):
        captured.update(kwargs)
        return BoundedRun(0, "", "")

    monkeypatch.setattr(liveness, "run_bounded", fake)

    liveness.rust_artifact_hashes("secretary-core", tmp_path, timeout=456)

    assert captured.get("timeout") == 456


# --- fix-wave review, S3 and S4 ---------------------------------------------


@pytest.mark.parametrize(
    "package_id, package, wanted",
    [
        ("git+https://github.com/serde-rs/serde?branch=master#1.0.0", "serde", True),
        ("git+https://github.com/serde-rs/serde.git?rev=abc#1.0.0", "serde", True),
        ("path+file:///w/my%20crate#0.1.0", "my crate", True),
        ("registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0", "serde", True),
        ("sparse+https://index.crates.io/#serde@1.0.0", "serde", True),
    ],
    ids=["git-query", "git-dotgit-query", "percent-encoded", "registry", "sparse"],
)
def test_package_id_matching_handles_the_query_string_and_percent_encoding(
    package_id, package, wanted
):
    assert liveness.package_id_names(package_id, package) is wanted


def test_an_empty_after_side_is_blamed_on_the_post_mutation_build():
    """The first message said "there is no baseline" for BOTH sides."""
    result = liveness.compare_rust_artifacts(_artifacts(lib="aaa"), _artifacts())
    assert result.live is False
    assert "post-mutation" in result.detail and "no baseline" not in result.detail
