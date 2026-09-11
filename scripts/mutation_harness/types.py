"""Value types for the mutation harness (#644).

`Outcome` is the load-bearing one. Spec §5.5: "did not red" and "did not run"
are opposite conclusions and the pre-#644 workflow rendered them identically.
They are `UNEXPECTED_GREEN` and `NOT_LIVE` here and can never collapse onto
one row.

**The types REFUSE the states the design calls impossible** (PR #652 review).
Until that review the guarantee that `NOT_LIVE` and `UNEXPECTED_GREEN` never
share a row was a property of `runner.py`'s control flow alone:
`MutationResult` had no `__post_init__`, so a `NO | UNEXPECTED_GREEN` row was
representable and `render_markdown` printed it; `MutationSpec.expect` was a
free string, so `expect="Red"` built a spec whose `expects_red` was False and a
live green classified `GREEN_AS_EXPECTED` — exit 0, the fail-open direction —
reachable by every control and test that builds the dataclass directly and so
never passes through `spec.py`; `GateResult(exit_code=0, timed_out=True)`
constructed, and `is_red` read `exit_code` without consulting the flag. This is
the shape CLAUDE.md records for the Rust side ("`Verdict` is one enum, not a
`bool` plus two `Option`s — the old shape made two invalid states representable
and both were silent"), applied here.
"""

from __future__ import annotations

import dataclasses
import enum

# ONE declaration of the gate timeout default, read by `spec.py`, `gate.py`
# and `runner.py`. It was declared four times, once per module, and the
# runner's docstring had to explain that they happened to match.
DEFAULT_GATE_TIMEOUT_SECONDS = 3600

# The exit code `run_gate` records for a gate it killed on timeout. The
# VALUE is conventional (GNU `timeout(1)` uses it) and carries no meaning of
# its own — `GateResult.timed_out` is the only signal, and a real gate is
# free to exit 124 on its own. Pinned here so `GateResult.__post_init__` and
# `gate.run_gate` cannot drift onto two numbers.
TIMEOUT_EXIT_CODE = 124


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


# The five outcomes a FINISHED gate on a LIVE row decides between. Everything
# else is decided earlier in the pipeline and carries no gate verdict.
_GATE_DECIDED = frozenset(
    {
        Outcome.RED_AS_EXPECTED, Outcome.GREEN_AS_EXPECTED, Outcome.UNEXPECTED_GREEN,
        Outcome.UNEXPECTED_RED, Outcome.WRONG_TESTS_RED,
    }
)


class Lang(enum.Enum):
    PYTHON = "python"
    RUST = "rust"


class Expect(enum.Enum):
    """What the spec declares the gate will do once the mutation is live."""

    RED = "red"
    GREEN = "green"


@dataclasses.dataclass(frozen=True)
class PythonProbe:
    """Introspect the value a FRESH interpreter sees. Spec §5.1.

    `syspath` is repo-root-relative and is prepended to `sys.path` in the
    child, because `conformance_lib` resolves off the entrypoint's directory
    rather than off the working directory.

    `equals` is compared against the `repr()` of what `expr` evaluates to, so
    **only a string-valued expression can satisfy it as written**: for
    `MAX_LEN = 2`, `expr = "MAX_LEN"` with `equals = "2"` observes `2` and
    compares it against `'2'`, and the row is `NOT_LIVE` every time. Probe a
    non-string value through `expr = "str(MAX_LEN)"` (or `repr(...)`).
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
    is the Python analogue of one `RustObservation`: a single reading, with
    no verdict attached. The verdict is `liveness.compare_python_probe`'s.

    `ok=False` means the reading could not be taken at all (the module is not
    a dotted identifier, the child exited non-zero, printed nothing, or
    outlived its timeout) and `value` is then meaningless — a missing reading
    is never evidence of a change, in either direction.
    """

    ok: bool
    value: str
    error: str


@dataclasses.dataclass(frozen=True)
class RustProbe:
    """Compare the CONTENT hash of the artifacts cargo names. Spec §5.1."""

    package: str


class RustReadingKind(enum.Enum):
    """What ONE `cargo build` reading is. Only `ARTIFACTS` is a measurement.

    A closed sum rather than sentinel KEYS inside the hash map, which is what
    the first version used — and `compare_rust_artifacts` recognised one of
    the two sentinels and not the other, so a `BUILD_FAILED` baseline fell
    through to the set comparison and two differently-failing builds scored
    `live=True` (PR #652 review, the one Critical). With a sum, the comparison
    must dispatch on the kind before it can reach the hashes at all.
    """

    ARTIFACTS = "artifacts"
    BUILD_FAILED = "build-failed"
    BUILD_TIMED_OUT = "build-timed-out"
    ARTIFACT_MISSING = "artifact-missing"


@dataclasses.dataclass(frozen=True)
class RustObservation:
    """ONE reading of a `RustProbe`: the artifact content hashes cargo named,
    or the reason no measurement was taken. `hashes` is populated iff `kind`
    is `ARTIFACTS`; `detail` is populated iff it is not."""

    kind: RustReadingKind
    # `hash=False`: a frozen dataclass synthesises `__hash__` over every
    # field, and a dict field would make that RAISE at the first `set` or
    # dict key rather than fail to type-check (fix-wave review).
    hashes: dict[str, str] = dataclasses.field(default_factory=dict, hash=False)
    detail: str = ""

    def __post_init__(self) -> None:
        if self.is_measurement:
            if self.detail:
                raise ValueError("an ARTIFACTS reading carries hashes, not a detail")
        else:
            if self.hashes:
                raise ValueError(f"a {self.kind.value} reading cannot carry artifact hashes")
            if not self.detail:
                raise ValueError(f"a {self.kind.value} reading must say why")

    @property
    def is_measurement(self) -> bool:
        return self.kind is RustReadingKind.ARTIFACTS


@dataclasses.dataclass(frozen=True)
class MutationSpec:
    id: str
    lang: Lang
    path: str
    old: str
    new: str
    gate: str
    expect: Expect
    probe: PythonProbe | RustProbe
    expect_red: tuple[str, ...] = ()
    note: str = ""
    # Seconds before `run_gate` gives up on THIS spec's gate command, for
    # both the baseline run and the post-mutation run (`runner.py` threads it
    # to both `run_gate` calls it makes for this spec).
    timeout: int = DEFAULT_GATE_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        """`spec.py` checks all of this first with a per-field message; this
        is the guard for every OTHER constructor — the control table, the
        self-test checks and the tests all build a spec directly."""
        if not isinstance(self.expect, Expect):
            raise ValueError(f"expect must be an Expect member, got {self.expect!r}")
        wanted = PythonProbe if self.lang is Lang.PYTHON else RustProbe
        if not isinstance(self.probe, wanted):
            raise ValueError(
                f"a lang={self.lang.value} row needs a {wanted.__name__} probe, "
                f"got {type(self.probe).__name__}"
            )
        if self.expect_red and self.expect is not Expect.RED:
            raise ValueError("expect_red is meaningless unless expect is RED")
        if (
            isinstance(self.timeout, bool)
            or not isinstance(self.timeout, int)
            or self.timeout <= 0
        ):
            raise ValueError(f"timeout must be a positive integer, got {self.timeout!r}")

    @property
    def expects_red(self) -> bool:
        return self.expect is Expect.RED


@dataclasses.dataclass(frozen=True)
class GateResult:
    exit_code: int
    output: str
    # Set ONLY by `run_gate`'s own timeout handler — never inferred from
    # `exit_code == 124`. A real gate command is free to exit 124 on its own
    # (it is an ordinary shell exit code, not reserved), and inferring a
    # timeout from it would collapse "the gate finished and reported 124" and
    # "the gate never finished" onto the same signal — the exact collapse
    # this field exists to keep apart.
    timed_out: bool = False

    def __post_init__(self) -> None:
        if self.timed_out and self.exit_code != TIMEOUT_EXIT_CODE:
            raise ValueError(
                f"a timed_out gate records exit_code {TIMEOUT_EXIT_CODE}, got {self.exit_code}"
            )

    @property
    def is_red(self) -> bool:
        """A VERDICT — and a gate that never finished has none. Reading it
        on a timed-out result is a programming error, not `True`: the first
        version returned `exit_code != 0`, which a timeout's 124 satisfied,
        and that is how a hung gate got credited as a catch (`C12`)."""
        if self.timed_out:
            raise ValueError("a timed_out gate has no verdict; check timed_out first")
        return self.exit_code != 0


@dataclasses.dataclass(frozen=True)
class LivenessResult:
    """Which PROOF produced this is not stored here: it is a function of
    `MutationSpec.lang` and the report derives it from there. The first
    version carried a free-string `mechanism` beside `lang`, two sources for
    one fact."""

    live: bool
    detail: str


@dataclasses.dataclass(frozen=True)
class MutationResult:
    spec: MutationSpec
    outcome: Outcome
    liveness: LivenessResult | None = None
    gate: GateResult | None = None
    missing_reds: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        problem = _row_shape_problem(self)
        if problem is not None:
            raise ValueError(f"{self.outcome.value}: {problem}")


def _row_shape_problem(row: MutationResult) -> str | None:
    """The table of what each outcome MUST carry, as one function.

    Stated as the row shape `run_mutations` builds for each outcome, so a
    row that could only arise from a different pipeline ordering — a green
    verdict on a dead row, a gate result on a `NOT_LIVE` row — is refused at
    construction rather than rendered.
    """
    outcome, liveness, gate = row.outcome, row.liveness, row.gate
    if outcome in _GATE_DECIDED:
        if liveness is None or not liveness.live:
            return "a gate-decided outcome needs a liveness result with live=True"
        if gate is None or gate.timed_out:
            return "a gate-decided outcome needs a gate that finished"
    elif outcome is Outcome.NOT_LIVE:
        if liveness is None or liveness.live:
            return "needs a liveness result with live=False"
        if gate is not None:
            return "never runs the gate, so carries no gate result"
    elif outcome is Outcome.GATE_TIMEOUT:
        if gate is None or not gate.timed_out:
            return "needs a gate result with timed_out=True"
    elif outcome is Outcome.BASELINE_DIRTY:
        if gate is None or gate.timed_out or not gate.is_red:
            return "needs a finished, red gate result"
        if liveness is not None:
            return "is decided before any probe runs, so carries no liveness result"
    elif liveness is not None or gate is not None:
        return "carries neither a liveness result nor a gate result"
    if bool(row.missing_reds) != (outcome is Outcome.WRONG_TESTS_RED):
        return "missing_reds is non-empty iff the outcome is WRONG_TESTS_RED"
    return None
