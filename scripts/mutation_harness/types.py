"""Value types for the mutation harness (#644).

`Outcome` is the load-bearing one. Spec §5.5: "did not red" and "did not run"
are opposite conclusions and the pre-#644 workflow rendered them identically.
They are `UNEXPECTED_GREEN` and `NOT_LIVE` here and can never collapse onto
one row.
"""

from __future__ import annotations

import dataclasses
import enum


class Outcome(enum.Enum):
    """What a single mutation row concluded. See spec §5.5."""

    RED_AS_EXPECTED = "RED_AS_EXPECTED"
    GREEN_AS_EXPECTED = "GREEN_AS_EXPECTED"
    UNEXPECTED_GREEN = "UNEXPECTED_GREEN"
    UNEXPECTED_RED = "UNEXPECTED_RED"
    WRONG_TESTS_RED = "WRONG_TESTS_RED"
    NOT_APPLIED = "NOT_APPLIED"
    NOT_LIVE = "NOT_LIVE"
    BASELINE_DIRTY = "BASELINE_DIRTY"
    RESTORE_FAILED = "RESTORE_FAILED"
    GATE_TIMEOUT = "GATE_TIMEOUT"

    @property
    def is_success(self) -> bool:
        """True iff the row concluded what its spec declared it would."""
        return self in (Outcome.RED_AS_EXPECTED, Outcome.GREEN_AS_EXPECTED)


class Lang(enum.Enum):
    PYTHON = "python"
    RUST = "rust"


@dataclasses.dataclass(frozen=True)
class PythonProbe:
    """Introspect the value a FRESH interpreter sees. Spec §5.1.

    `syspath` is repo-root-relative and is prepended to `sys.path` in the
    child, because `conformance_lib` resolves off the entrypoint's directory
    rather than off the working directory.
    """

    module: str
    expr: str
    equals: str
    syspath: str


@dataclasses.dataclass(frozen=True)
class PythonObservation:
    """ONE reading of a `PythonProbe`, taken before AND after the mutation.

    The Python proof is a before/after COMPARISON, exactly like the Rust one
    (`rust_artifact_hashes` twice, then `compare_rust_artifacts`). This type
    is the Python analogue of one of those hash dicts: a single reading, with
    no verdict attached. The verdict is `liveness.compare_python_probe`'s.

    `ok=False` means the reading could not be taken at all (the module is not
    a dotted identifier, the child exited non-zero, or it outlived its
    timeout) and `value` is then meaningless — a missing reading is never
    evidence of a change, in either direction.
    """

    ok: bool
    value: str
    error: str


@dataclasses.dataclass(frozen=True)
class RustProbe:
    """Compare the CONTENT hash of the artifacts cargo names. Spec §5.1."""

    package: str


@dataclasses.dataclass(frozen=True)
class MutationSpec:
    id: str
    lang: Lang
    path: str
    old: str
    new: str
    gate: str
    expect: str
    probe: PythonProbe | RustProbe
    expect_red: tuple[str, ...] = ()
    note: str = ""
    # Seconds before `run_gate` gives up on THIS spec's gate command, for
    # both the baseline run and the post-mutation run (runner.py threads it
    # to both `run_gate` calls it makes for this spec). Default matches
    # `run_gate`'s own prior hardcoded default, so an existing spec that
    # never mentions `timeout` behaves exactly as before this field existed.
    timeout: int = 3600

    @property
    def expects_red(self) -> bool:
        return self.expect == "red"


@dataclasses.dataclass(frozen=True)
class GateResult:
    exit_code: int
    output: str
    # Set ONLY by `run_gate`'s own `TimeoutExpired` handler — never inferred
    # from `exit_code == 124`. A real gate command is free to exit 124 on its
    # own (it is an ordinary shell exit code, not reserved), and inferring a
    # timeout from it would collapse "the gate finished and reported 124" and
    # "the gate never finished" onto the same signal — the exact collapse
    # this field exists to keep apart.
    timed_out: bool = False

    @property
    def is_red(self) -> bool:
        return self.exit_code != 0


@dataclasses.dataclass(frozen=True)
class LivenessResult:
    """`mechanism` is reported, never flattened: the Python and Rust proofs
    are not of equal strength and spec §8 refuses to imply they are."""

    live: bool
    mechanism: str
    detail: str


@dataclasses.dataclass(frozen=True)
class MutationResult:
    spec: MutationSpec
    outcome: Outcome
    liveness: LivenessResult | None = None
    gate: GateResult | None = None
    missing_reds: tuple[str, ...] = ()
