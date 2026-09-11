"""The control table, as DATA. Spec §6.

Consumed by BOTH `selftest.run_self_test` and pytest's `test_controls.py`, so
the two cannot drift onto different ideas of what a control asserts — the
"one implementation, called by both directions" move #600 and #602 made.

Every fixture is built under a caller-supplied temp dir. Nothing is ever
written into the source tree (#516).

`C12` was added after the brief for this task was written: a review found a
timed-out gate being credited as a catch (`GateResult.exit_code == 124`
satisfies the same "gate failed" test a genuine catch does), so `Outcome`
gained a TENTH member, `GATE_TIMEOUT`, and `GateResult` gained a `timed_out`
flag set only by `run_gate`'s own `TimeoutExpired` handler — never inferred
from the exit code. Spec §9 criterion 1 requires every outcome in §5.5 to
have a control; `C12` is that control, and its own docstring explains how it
drives the real `run_gate` timeout path without constructing a `GateResult`
by hand.
"""

from __future__ import annotations

import dataclasses
import py_compile
import shlex
import sys
import textwrap
from collections.abc import Callable
from pathlib import Path

from mutation_harness.types import (
    Expect, Lang, MutationSpec, Outcome, PythonProbe, RustProbe,
)


@dataclasses.dataclass(frozen=True)
class Control:
    label: str
    why: str
    build: Callable[[Path], MutationSpec]
    expect: Outcome


# The interpreter a control's GATE runs under: the same one the harness and
# its probes run under (`liveness.observe_python` uses `sys.executable` for
# exactly this reason), not whatever `python3` is first on PATH — the two
# coincide under `uv run` and do not have to (fix-wave review).
PY = shlex.quote(sys.executable)


def _write(root: Path, rel: str, body: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(body).lstrip())
    return path


def _py_spec(**kw) -> MutationSpec:
    defaults = dict(
        id="C", lang=Lang.PYTHON, path="m.py", gate="true", expect=Expect.RED,
        probe=PythonProbe(module="m", expr="TOKEN", equals="mutated", syspath="."),
    )
    defaults.update(kw)
    return MutationSpec(**defaults)


# --- C1: a stale .pyc must not be served (false green 1) -------------------
def _build_c1(root: Path) -> MutationSpec:
    """Pre-create bytecode that would answer with the PRE-mutation value.

    The real-world trap was TIMESTAMP-based: CPython invalidates a `.pyc` on
    `(source_mtime, size)` with the mtime in whole SECONDS, so a
    size-preserving edit applied inside one second is served from cache. That
    is racy to reproduce — it needs two writes in the same whole second — so
    this control uses an UNCHECKED_HASH `.pyc` (PEP 552) instead, which is
    served regardless of the source's content, size AND mtime. Verified by
    execution.

    Without the pre-created `.pyc` this control is VACUOUS — a fresh temp dir
    has no bytecode, so it would pass with `clear_pycache` deleted.

    **What this pins, stated precisely (fix round 2, Finding 2).** `runner.py`
    has TWO `clear_pycache` call sites: a BASELINE sweep of the whole
    `repo_root`, fired once per distinct gate command before any spec
    touching it runs; and a PRE-PROBE sweep inside `_observe`, scoped to the
    mutated file's directory, fired for every Python spec right before each of
    its two readings. An earlier version of this docstring said the harness
    clears `__pycache__` "before probing" as if that named the pre-probe call
    specifically. Measured false: deleting EITHER call site alone still
    leaves this single-spec control PASSING; only deleting BOTH reds it —
    re-measured after the Python proof became a before/after comparison,
    where a surviving stale `.pyc` answers BOTH readings with the
    pre-mutation value and the row lands on `NOT_LIVE` rather than
    `GREEN_AS_EXPECTED`. So C1 pins "at least one of the two calls runs
    before each reading", not that the pre-probe call individually matters
    here.

    That is not a gap in this control so much as a structural fact about the
    pipeline it exercises, and it does not go away for any single-spec
    fixture: the baseline sweep is UNSCOPED (the whole `repo_root`, not the
    one file this spec will touch) and runs before ANY spec's probe, and
    nothing this harness spawns as a subprocess ever WRITES a `.pyc` in the
    first place (every subprocess runs under `python_env()`'s
    `PYTHONDONTWRITEBYTECODE=1`, checked separately below) — so once the
    baseline sweep has fired even once, there is nothing left under
    `repo_root` for a later pre-probe sweep to ever need to clean up. Making
    the pre-probe call INDIVIDUALLY load-bearing would need a spec sharing a
    gate with an EARLIER spec (so the baseline sweep is skipped for it) whose
    stale `.pyc` is created AFTER the baseline sweep already ran — and this
    harness has no mechanism that creates one mid-run to arrange that with.
    Scoping the baseline sweep, or a `Control` shape that supports more than
    one `MutationSpec`, would each be a `runner.py`/Task-5-design change out
    of proportion to this finding; the docstring is corrected instead, per
    the design's own "an accurate weaker claim beats an inaccurate stronger
    one" guidance.
    """
    _write(root, "m.py", 'TOKEN = "aaaaaaa"\n')
    py_compile.compile(
        str(root / "m.py"),
        invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
        doraise=True,
    )
    return _py_spec(
        id="C1", old='TOKEN = "aaaaaaa"', new='TOKEN = "mutated"',
        gate="true", expect=Expect.GREEN,
        probe=PythonProbe("m", "TOKEN", "mutated", "."),
    )


# --- C2: a splice overridden by a later assignment (false green 2) ----------
def _build_c2(root: Path) -> MutationSpec:
    _write(
        root, "m.py",
        '''
        class Rejection:
            """A docstring, exactly as in conformance_lib."""

            TOKEN = "real"
        ''',
    )
    # Splices immediately after the class header, where the REAL assignment
    # below the docstring silently overrides it. The file changes; the
    # interpreter binds "real". This is the control the harness exists for.
    return _py_spec(
        id="C2",
        old="class Rejection:",
        new='class Rejection:\n    TOKEN = "mutated"',
        probe=PythonProbe("m", "Rejection.TOKEN", "mutated", "."),
    )


# --- C4 / C5: ambiguous and absent anchors ---------------------------------
def _build_c4(root: Path) -> MutationSpec:
    _write(root, "m.py", 'TOKEN = "x"\nOTHER = "x"\n')
    return _py_spec(id="C4", old='"x"', new='"y"')


def _build_c5(root: Path) -> MutationSpec:
    _write(root, "m.py", 'TOKEN = "x"\n')
    return _py_spec(id="C5", old="not-present-anywhere", new="y")


# --- C6: the gate is already red on the clean tree --------------------------
def _build_c6(root: Path) -> MutationSpec:
    _write(root, "m.py", 'TOKEN = "real"\n')
    return _py_spec(
        id="C6", old='"real"', new='"mutated"', gate="exit 1",
        probe=PythonProbe("m", "TOKEN", "mutated", "."),
    )


# --- C8: live, gate green, declared red ------------------------------------
def _build_c8(root: Path) -> MutationSpec:
    _write(root, "m.py", 'TOKEN = "real"\n')
    return _py_spec(
        id="C8", old='"real"', new='"mutated"', gate="true", expect=Expect.RED,
        probe=PythonProbe("m", "TOKEN", "mutated", "."),
    )


# --- C9: red, but not the test the row claims ------------------------------
def _build_c9(root: Path) -> MutationSpec:
    """The gate must be CONDITIONAL on the mutation, not unconditionally red.

    An earlier version of this control used `gate="echo ...; exit 1"` —
    always red, regardless of TOKEN's value. `run_mutations` baselines the
    SAME gate command on the clean tree BEFORE applying the mutation (spec
    §5.6 step 1), so an unconditionally-red gate makes the baseline itself
    red and the control never reaches the WRONG_TESTS_RED path at all —
    verified by execution: it reported BASELINE_DIRTY instead. `gate.py`
    mirrors N1's pattern (baseline green, post-mutation red) so the
    "gate goes red but never names the test" property is exercised for
    real, on the SAME live/dead distinction every other control here goes
    through, rather than being hidden behind a baseline failure.
    """
    _write(root, "m.py", 'TOKEN = "real"\n')
    _write(
        root, "gate.py",
        '''
        import m, sys
        if m.TOKEN == "real":
            sys.exit(0)
        print("something_else_failed")
        sys.exit(1)
        ''',
    )
    return _py_spec(
        id="C9", old='"real"', new='"mutated"',
        gate=f"{PY} gate.py", expect=Expect.RED,
        expect_red=("the_test_this_row_claims",),
        probe=PythonProbe("m", "TOKEN", "mutated", "."),
    )


# --- C14: the named test PASSES while another fails --------------------------
def _build_c14(root: Path) -> MutationSpec:
    """`expect_red` must be satisfied only by a test reported RED.

    `C9`'s gate never prints the claimed name at all; this one prints it on a
    PASSING line, exactly as libtest does for every test it runs (`test
    answer_is_42 ... ok`), while a DIFFERENT test fails. A substring match
    over the whole output — the first version of `classify` — found the name
    and reported `RED_AS_EXPECTED`: "caught by the test this row claims"
    with the claimed test green. That could not be seen by any `cargo test`
    gate, the repo's primary gate, because libtest always names passing
    tests (PR #652 review). The gate is conditional on the mutation, as C9's
    is, so the baseline stays green.
    """
    _write(root, "m.py", 'TOKEN = "real"\n')
    _write(
        root, "gate.py",
        '''
        import m, sys
        print("test the_test_this_row_claims ... ok")
        if m.TOKEN == "real":
            sys.exit(0)
        print("test some_other_test ... FAILED")
        sys.exit(1)
        ''',
    )
    return _py_spec(
        id="C14", old='"real"', new='"mutated"',
        gate=f"{PY} gate.py", expect=Expect.RED,
        expect_red=("the_test_this_row_claims",),
        probe=PythonProbe("m", "TOKEN", "mutated", "."),
    )


# --- C11: live, declared green, gate goes red ------------------------------
def _build_c11(root: Path) -> MutationSpec:
    """Same fix as `C9`, same reason: `gate="exit 1"` is unconditionally red,
    so the BASELINE run (on the clean tree, before the mutation) was already
    red and the control reported `BASELINE_DIRTY` instead of `UNEXPECTED_RED`
    — verified by execution. `gate.py` is byte-identical to N1's: baseline
    (TOKEN == "real") exits 0, post-mutation (TOKEN == "mutated") exits 1.
    Only `expect` differs from N1 — "green" here, "red" there — which is
    what turns a live mutation's real gate failure into a FINDING
    (`UNEXPECTED_RED`) rather than the expected outcome (`RED_AS_EXPECTED`).
    """
    _write(root, "m.py", 'TOKEN = "real"\n')
    _write(
        root, "gate.py",
        'import m, sys\nsys.exit(0 if m.TOKEN == "real" else 1)\n',
    )
    return _py_spec(
        id="C11", old='"real"', new='"mutated"', gate=f"{PY} gate.py", expect=Expect.GREEN,
        probe=PythonProbe("m", "TOKEN", "mutated", "."),
    )


# --- C12: a gate that outlives its timeout ---------------------------------
def _build_c12(root: Path) -> MutationSpec:
    """A gate that does not finish must be `GATE_TIMEOUT`, never a catch.

    `GateResult.exit_code` is 124 for BOTH a real caught mutation that
    happens to exit 124 on its own and a gate `run_gate` killed on timeout —
    `GateResult.timed_out` is the only thing that tells them apart, and it is
    set ONLY by `run_gate`'s own `TimeoutExpired` handler. This control must
    therefore go through the real `run_gate` timeout plumbing rather than
    constructing a `GateResult(timed_out=True)` by hand — a hand-built result
    would prove nothing about the pipeline `run_mutations` actually runs.

    The mechanism: the gate command's sleep DURATION is read from the same
    file the mutation touches (`sleep $(cat delay.txt)`), so:

    - the BASELINE run (delay.txt == "0", read before the mutation is
      applied — see runner.py's ordering) finishes instantly and the
      baseline is reported clean;
    - the POST-MUTATION run (delay.txt == "5") genuinely outlives the
      1-second `MutationSpec.timeout` this control sets, so `run_gate`'s
      `subproc.run_bounded` genuinely hits its `communicate(timeout=1)`
      expiry, kills the process group, and reports `returncode=None`.

    `m.py` exists only so a `PythonProbe` can observe the mutation the same
    way every other Python control does — it re-reads delay.txt at IMPORT
    time in a fresh interpreter, so there is no bytecode-staleness question
    here (delay.txt is data, not a .py source file `clear_pycache` needs to
    account for).
    """
    _write(root, "delay.txt", "0")
    _write(
        root, "m.py",
        '''
        from pathlib import Path
        DELAY = (Path(__file__).parent / "delay.txt").read_text().strip()
        ''',
    )
    return _py_spec(
        id="C12", path="delay.txt", old="0", new="5",
        gate="sleep $(cat delay.txt)", expect=Expect.RED, timeout=1,
        probe=PythonProbe("m", "DELAY", "5", "."),
    )


# --- C13: the BASELINE gate outlives its timeout ---------------------------
def _build_c13(root: Path) -> MutationSpec:
    """A baseline that did not FINISH is not a baseline that FAILED.

    `C12`'s twin, one step earlier in `run_mutations`. `C12` times out the
    POST-mutation gate; this one times out the gate on the CLEAN tree, before
    any mutation is applied. Until the final whole-branch review the runner
    cached the baseline as `not run_gate(...).is_red`, discarding
    `GateResult.timed_out` — so a baseline that never finished was reported
    `BASELINE_DIRTY`, which reads as "your tests are already failing" and
    sends a reader to fix tests that may be perfectly green. That is the exact
    collapse `C12` exists to prevent, at the other end of the same loop.

    The gate is unconditionally slow (`sleep 5` against a 1-second
    `timeout`), which is the OPPOSITE of what `C9`/`C11` needed: those want
    the baseline to pass so the post-mutation run is the thing under test,
    while this control's whole subject IS the baseline run. Nothing is ever
    applied, so `m.py` and the probe exist only to make this a well-formed
    spec — neither is ever read.
    """
    _write(root, "m.py", 'TOKEN = "real"\n')
    return _py_spec(
        id="C13", old='"real"', new='"mutated"', gate="sleep 5", expect=Expect.RED,
        timeout=1, probe=PythonProbe("m", "TOKEN", "mutated", "."),
    )


# --- Rust fixture: a standalone crate, deliberately outside any workspace ---
def _build_rust_crate(root: Path, lib_body: str) -> None:
    _write(
        root, "Cargo.toml",
        """
        [package]
        name = "mutdemo"
        version = "0.0.0"
        edition = "2021"

        [workspace]
        """,
    )
    _write(root, "src/lib.rs", lib_body)


# --- C10: a Rust edit the compiler cannot see ------------------------------
def _build_c10(root: Path) -> MutationSpec:
    """An edit genuinely invisible to codegen must be `NOT_LIVE`.

    The FIRST version of this fixture inserted a comment line BEFORE
    `pub fn answer()`, on the theory that a comment carries no bytes into
    the compiled artifact. Verified false by execution: `rustc` embeds
    per-item SPAN (source line/column) information into crate metadata
    (`.rmeta`) regardless of release/debug profile — used for cross-crate
    diagnostics and inlining — so shifting `answer()`'s start line by one
    changed the `.rmeta` bytes, and the control reported `UNEXPECTED_GREEN`
    (live, gate passed) instead of `NOT_LIVE`. Exactly the failure mode
    the design doc's Task 6 Step 5 warned about ("release builds can embed
    source paths or line tables") and told the implementer to fix by
    construction rather than by weakening the control.

    A SECOND version moved the comment to the file's LAST line, after every
    item, on the theory that a line shifting no other item's span would
    leave nothing for cross-crate metadata to reference differently.
    Verified false too, by a controlled experiment outside the harness (two
    back-to-back `cargo build`s of the identical file reproduce the
    identical `.rlib`/`.rmeta` bytes — ruling out build-time
    non-determinism — and reverting a byte-for-byte-identical file after a
    trailing-comment edit reproduces the ORIGINAL hash exactly): `rustc`
    embeds a whole-file content checksum into `.rmeta` for every
    `SourceFile` that contributes to the crate (used to validate debuginfo
    against source), independent of whether any exported item's span
    changed. That checksum makes a byte-identical artifact UNREACHABLE for
    *any* textual edit to a file the crate's build graph actually reads —
    not a fixture-placement problem `--release` or comment-placement can
    route around.

    This version therefore mutates a file the build graph does not read at
    all: `README.md`, never `mod`-declared and never opened by `cargo
    build`/`cargo test`. That is `NOT_LIVE`'s literal claim — "a Rust edit
    the compiler cannot see" — made true by construction rather than by
    hoping a comment goes unhashed. `cargo build`'s liveness probe
    (`rust_artifact_hashes`) sees byte-identical `.rlib`/`.rmeta` before and
    after, verified by execution.
    """
    _build_rust_crate(
        root,
        """
        pub fn answer() -> u32 {
            42
        }

        #[test]
        fn answer_is_42() {
            assert_eq!(answer(), 42);
        }
        """,
    )
    _write(root, "README.md", "notes: unchanged\n")
    return MutationSpec(
        id="C10", lang=Lang.RUST, path="README.md",
        old="notes: unchanged",
        new="notes: mutated, but cargo never reads this file",
        gate="cargo test --release", expect=Expect.RED, probe=RustProbe("mutdemo"),
    )


# --- N4: a Rust edit the compiler DOES see ---------------------------------
def _build_n4(root: Path) -> MutationSpec:
    _build_rust_crate(
        root,
        """
        pub fn answer() -> u32 {
            42
        }

        #[test]
        fn answer_is_42() {
            assert_eq!(answer(), 42);
        }
        """,
    )
    return MutationSpec(
        id="N4", lang=Lang.RUST, path="src/lib.rs", old="    42", new="    43",
        gate="cargo test --release", expect=Expect.RED,
        expect_red=("answer_is_42",), probe=RustProbe("mutdemo"),
    )


# --- N1 / N2: the harness must stay silent (N3 is `selftest.check_clean_baseline`) ---
def _build_n1(root: Path) -> MutationSpec:
    _write(root, "m.py", 'TOKEN = "real"\n')
    _write(root, "gate.py", 'import m, sys; sys.exit(0 if m.TOKEN == "real" else 1)\n')
    return _py_spec(
        id="N1", old='"real"', new='"mutated"',
        gate=f"{PY} gate.py", expect=Expect.RED,
        probe=PythonProbe("m", "TOKEN", "mutated", "."),
    )


def _build_n2(root: Path) -> MutationSpec:
    _write(root, "m.py", 'TOKEN = "real"\n')
    return _py_spec(
        id="N2", old='"real"', new='"mutated"', gate="true", expect=Expect.GREEN,
        probe=PythonProbe("m", "TOKEN", "mutated", "."),
    )


POSITIVE_CONTROLS: tuple[Control, ...] = (
    Control("C1", "size-preserving edit must still be observed (false green 1)",
            _build_c1, Outcome.GREEN_AS_EXPECTED),
    Control("C2", "splice overridden by a later assignment (false green 2)",
            _build_c2, Outcome.NOT_LIVE),
    Control("C4", "an anchor matching twice is ambiguous", _build_c4, Outcome.NOT_APPLIED),
    Control("C5", "an anchor matching zero times", _build_c5, Outcome.NOT_APPLIED),
    Control("C6", "the gate is red before any mutation", _build_c6, Outcome.BASELINE_DIRTY),
    Control("C8", "live, gate green, declared red", _build_c8, Outcome.UNEXPECTED_GREEN),
    Control("C9", "red, but not the test the row claims", _build_c9, Outcome.WRONG_TESTS_RED),
    Control("C14", "the claimed test PASSES (`... ok`) while another fails",
            _build_c14, Outcome.WRONG_TESTS_RED),
    Control("C10", "a Rust edit that emits identical artifacts", _build_c10, Outcome.NOT_LIVE),
    Control("C11", "live, declared green, gate goes red", _build_c11, Outcome.UNEXPECTED_RED),
    Control("C12", "the gate outlives its timeout — never credited as a catch",
            _build_c12, Outcome.GATE_TIMEOUT),
    Control("C13", "the BASELINE gate outlives its timeout — not a dirty baseline",
            _build_c13, Outcome.GATE_TIMEOUT),
)

NEGATIVE_CONTROLS: tuple[Control, ...] = (
    Control("N1", "a genuinely live Python mutation reddens its gate",
            _build_n1, Outcome.RED_AS_EXPECTED),
    Control("N2", "a by-design green, proven live", _build_n2, Outcome.GREEN_AS_EXPECTED),
    Control("N4", "a genuinely live Rust mutation", _build_n4, Outcome.RED_AS_EXPECTED),
)
