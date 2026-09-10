# Verified Mutation Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a harness in `scripts/` that makes a mutation's effect checked rather than assumed, so mutation results cited as evidence in `CLAUDE.md` and handoffs are founded.

**Architecture:** A thin entrypoint (`scripts/mutate.py`) over a package (`scripts/mutation_harness/`), matching the existing `check-error-payload-hygiene.py` / `payload_guard/` pattern. A slice declares mutations as TOML data in its scratchpad; the harness owns all control flow, proves each mutation live before believing any gate result, restores from a durable journal rather than a `finally`, and emits the markdown result table the handoff pastes.

**Tech Stack:** Python 3.11+ (measured 3.13.14 available), stdlib only — `tomllib`, `hashlib`, `subprocess`, `signal`, `atexit`, `dataclasses`, `enum`. Run via `uv run`, never `pip`. `pytest` via `uv run --with pytest` for unit TDD (precedent: `core/fuzz/test_monitor.py`).

**Spec:** [docs/superpowers/specs/2026-09-11-mutation-harness-design.md](../specs/2026-09-11-mutation-harness-design.md)

## Global Constraints

- **`uv` exclusively.** Never `pip` / `pip3` / `python -m pip`.
- **PEP 723 header on the entrypoint**, `requires-python = ">=3.11"`, `dependencies = []`. Copy the shape from `scripts/check-test-support-placement.py:1-5`.
- **Every file under 500 lines.** Split before exceeding it, not after.
- **Stdlib only.** No third-party runtime dependency. `pytest` is a dev-time tool invoked with `--with`, never declared as a dependency.
- **No source-tree probe residue.** Every fixture goes to `tempfile.mkdtemp()`. Writing probe files into the live tree is #516.
- **Fail closed.** An unknown TOML key, an unrecognised value, a missing file, or an ambiguous match is an ERROR, never a skip. A skip is how `Path.rglob` silently contributed zero files in #496.
- **The control table is one source of truth**, consumed by both pytest and `--self-test`. Two copies of a control table is how two directions drift (#600, #602).
- **Attribution.** Every commit ends with `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`.
- **Work in the worktree** `/Users/hherb/src/secretary/.worktrees/mutation-harness` on branch `feature/mutation-harness`. Verify with `pwd && git branch --show-current` before any `git` or `cargo` command.

---

## File Structure

| File | Responsibility | Est. lines |
|---|---|---|
| `scripts/mutate.py` | Entrypoint: PEP 723 header, argument parsing, exit codes | 130 |
| `scripts/mutation_harness/__init__.py` | Package marker; no logic | 10 |
| `scripts/mutation_harness/types.py` | `Outcome`, `Lang`, `PythonProbe`, `RustProbe`, `MutationSpec`, `GateResult`, `LivenessResult`, `MutationResult` | 170 |
| `scripts/mutation_harness/spec.py` | `tomllib` parse + structural validation, fail-closed | 180 |
| `scripts/mutation_harness/journal.py` | Durable original-bytes journal; record / restore / drain / handlers | 210 |
| `scripts/mutation_harness/liveness.py` | The two liveness proofs; `__pycache__` discipline | 220 |
| `scripts/mutation_harness/gate.py` | Run a gate command; classify against `expect` / `expect_red` | 150 |
| `scripts/mutation_harness/runner.py` | The per-mutation state machine (spec §5.6) | 190 |
| `scripts/mutation_harness/report.py` | Markdown table and `--json` | 130 |
| `scripts/mutation_harness/controls.py` | The control table as DATA: fixture builders + expected outcome | 400 |
| `scripts/mutation_harness/selftest.py` | Drives `controls.py` through the real pipeline; the journal-refusal check | 200 |
| `scripts/mutation_harness/tests/conftest.py` | Puts `scripts/` on `sys.path` for pytest | 15 |
| `scripts/mutation_harness/tests/test_spec.py` | Unit tests for parsing/validation | 150 |
| `scripts/mutation_harness/tests/test_journal.py` | Unit tests for the journal | 130 |
| `scripts/mutation_harness/tests/test_gate.py` | Unit tests for classification | 140 |
| `scripts/mutation_harness/tests/test_report.py` | Unit tests for rendering | 80 |
| `scripts/mutation_harness/tests/test_controls.py` | Runs the shared control table through the pipeline | 60 |

**Why `controls.py` is data, not tests:** `--self-test` and pytest both consume it. That is the "one implementation called by both directions" move #600 and #602 made, and the reason is the same — a control table copied into two consumers drifts, and the drift is silent.

---

## Task 1: Spec types and TOML parsing

**Files:**
- Create: `scripts/mutation_harness/__init__.py`
- Create: `scripts/mutation_harness/types.py`
- Create: `scripts/mutation_harness/spec.py`
- Create: `scripts/mutation_harness/tests/conftest.py`
- Test: `scripts/mutation_harness/tests/test_spec.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `Outcome`, `Lang`, `PythonProbe`, `RustProbe`, `MutationSpec`, `GateResult`, `LivenessResult`, `MutationResult` from `mutation_harness.types`; `parse_spec(text: str, repo_root: Path) -> tuple[MutationSpec, ...]` and `SpecError` from `mutation_harness.spec`.

**Design note carried from the spec review:** the "`old` occurs exactly once" check is a RUNTIME check in the runner producing `Outcome.NOT_APPLIED`, not a parse error. Spec §5.5 makes `NOT_APPLIED` an outcome, so it must be reportable per-row rather than aborting the whole file. `parse_spec` validates STRUCTURE only.

- [ ] **Step 1: Write the failing tests**

Create `scripts/mutation_harness/tests/conftest.py`:

```python
"""Put `scripts/` on sys.path so `import mutation_harness` resolves under pytest."""

import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parents[2]
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))
```

Create `scripts/mutation_harness/tests/test_spec.py`:

```python
import pytest

from mutation_harness.spec import SpecError, parse_spec
from mutation_harness.types import Lang, PythonProbe, RustProbe

MINIMAL_PY = """
[[mutation]]
id = "M1"
lang = "python"
path = "a.py"
old = "x = 1"
new = "x = 2"
gate = "true"
expect = "red"
probe = { module = "a", expr = "x", equals = "2", syspath = "." }
"""


def test_parses_a_minimal_python_mutation(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    specs = parse_spec(MINIMAL_PY, tmp_path)
    assert len(specs) == 1
    s = specs[0]
    assert s.id == "M1"
    assert s.lang is Lang.PYTHON
    assert isinstance(s.probe, PythonProbe)
    assert s.probe.equals == "2"
    assert s.expect_red == ()


def test_parses_a_rust_mutation(tmp_path):
    (tmp_path / "a.rs").write_text("fn f() {}\n")
    text = """
[[mutation]]
id = "R1"
lang = "rust"
path = "a.rs"
old = "fn f"
new = "fn g"
gate = "true"
expect = "red"
expect_red = ["some_test"]
probe = { package = "demo" }
"""
    (s,) = parse_spec(text, tmp_path)
    assert s.lang is Lang.RUST
    assert isinstance(s.probe, RustProbe)
    assert s.probe.package == "demo"
    assert s.expect_red == ("some_test",)


def test_unknown_top_level_key_is_an_error(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    bad = MINIMAL_PY + '\nnote_typo = "oops"\n'
    with pytest.raises(SpecError, match="unknown key"):
        parse_spec(bad, tmp_path)


def test_unknown_probe_key_is_an_error(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    bad = MINIMAL_PY.replace('syspath = "."', 'syspath = ".", typo = 1')
    with pytest.raises(SpecError, match="unknown probe key"):
        parse_spec(bad, tmp_path)


def test_missing_required_key_is_an_error(tmp_path):
    bad = MINIMAL_PY.replace('gate = "true"\n', "")
    with pytest.raises(SpecError, match="missing required key"):
        parse_spec(bad, tmp_path)


def test_expect_must_be_red_or_green(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    bad = MINIMAL_PY.replace('expect = "red"', 'expect = "maybe"')
    with pytest.raises(SpecError, match="expect"):
        parse_spec(bad, tmp_path)


def test_path_escaping_the_repo_root_is_an_error(tmp_path):
    bad = MINIMAL_PY.replace('path = "a.py"', 'path = "../outside.py"')
    with pytest.raises(SpecError, match="outside the repository"):
        parse_spec(bad, tmp_path)


def test_duplicate_ids_are_an_error(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    with pytest.raises(SpecError, match="duplicate id"):
        parse_spec(MINIMAL_PY + MINIMAL_PY, tmp_path)


def test_a_python_mutation_may_not_carry_a_rust_probe(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    bad = MINIMAL_PY.replace(
        'probe = { module = "a", expr = "x", equals = "2", syspath = "." }',
        'probe = { package = "demo" }',
    )
    with pytest.raises(SpecError, match="unknown probe key"):
        parse_spec(bad, tmp_path)


def test_empty_spec_is_an_error(tmp_path):
    with pytest.raises(SpecError, match="no .mutation. blocks"):
        parse_spec("", tmp_path)
```

- [ ] **Step 2: Run the tests and verify they fail**

```bash
cd /Users/hherb/src/secretary/.worktrees/mutation-harness
uv run --with pytest pytest scripts/mutation_harness/tests/test_spec.py -q
```

Expected: collection error, `ModuleNotFoundError: No module named 'mutation_harness'`.

- [ ] **Step 3: Write `types.py`**

```python
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

    @property
    def expects_red(self) -> bool:
        return self.expect == "red"


@dataclasses.dataclass(frozen=True)
class GateResult:
    exit_code: int
    output: str

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
```

Create `scripts/mutation_harness/__init__.py`:

```python
"""A verified mutation harness (#644).

Read `docs/superpowers/specs/2026-09-11-mutation-harness-design.md` first.
Nothing here imports `selftest` or `controls`; those sit at the top of the
dependency order, consuming everything below.
"""
```

- [ ] **Step 4: Write `spec.py`**

```python
"""Parse and STRUCTURALLY validate a mutation spec. Fail-closed throughout.

An unknown key is an ERROR, never ignored. A typo'd key that silently
degrades a check is the failure mode `payload_guard`'s `ControlExpectation`
already records; the same ruling applies here.

Deliberately NOT checked here: whether `old` occurs exactly once in `path`.
Spec §5.5 makes that `Outcome.NOT_APPLIED`, a per-row outcome, so the runner
owns it. Parse-time validation is structure only.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from mutation_harness.types import Lang, MutationSpec, PythonProbe, RustProbe

TOP_LEVEL_KEYS = frozenset(
    {"id", "lang", "path", "old", "new", "gate", "expect", "expect_red", "note", "probe"}
)
REQUIRED_KEYS = frozenset({"id", "lang", "path", "old", "new", "gate", "expect", "probe"})
PYTHON_PROBE_KEYS = frozenset({"module", "expr", "equals", "syspath"})
RUST_PROBE_KEYS = frozenset({"package"})
VALID_EXPECT = frozenset({"red", "green"})


class SpecError(ValueError):
    """A structurally invalid spec. Always fatal — never degraded to a skip."""


def parse_spec(text: str, repo_root: Path) -> tuple[MutationSpec, ...]:
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise SpecError(f"spec is not valid TOML: {exc}") from None

    raw_rows = doc.get("mutation")
    if not raw_rows:
        raise SpecError("spec contains no [[mutation]] blocks")

    seen: set[str] = set()
    specs: list[MutationSpec] = []
    for index, raw in enumerate(raw_rows):
        spec = _validate_one(raw, repo_root, index)
        if spec.id in seen:
            raise SpecError(f"duplicate id {spec.id!r}")
        seen.add(spec.id)
        specs.append(spec)
    return tuple(specs)


def _validate_one(raw: dict, repo_root: Path, index: int) -> MutationSpec:
    where = f"[[mutation]] #{index + 1}"

    unknown = sorted(set(raw) - TOP_LEVEL_KEYS)
    if unknown:
        raise SpecError(f"{where}: unknown key(s) {unknown}")
    missing = sorted(REQUIRED_KEYS - set(raw))
    if missing:
        raise SpecError(f"{where}: missing required key(s) {missing}")

    try:
        lang = Lang(raw["lang"])
    except ValueError:
        raise SpecError(f"{where}: lang must be 'python' or 'rust'") from None

    expect = raw["expect"]
    if expect not in VALID_EXPECT:
        raise SpecError(f"{where}: expect must be one of {sorted(VALID_EXPECT)}")

    _require_path_inside_repo(raw["path"], repo_root, where)

    expect_red = raw.get("expect_red", [])
    if not isinstance(expect_red, list) or not all(isinstance(s, str) for s in expect_red):
        raise SpecError(f"{where}: expect_red must be a list of strings")

    return MutationSpec(
        id=str(raw["id"]),
        lang=lang,
        path=str(raw["path"]),
        old=str(raw["old"]),
        new=str(raw["new"]),
        gate=str(raw["gate"]),
        expect=expect,
        probe=_validate_probe(raw["probe"], lang, where),
        expect_red=tuple(expect_red),
        note=str(raw.get("note", "")),
    )


def _require_path_inside_repo(rel: str, repo_root: Path, where: str) -> None:
    """`..` and absolute paths are rejected. The harness mutates tracked
    source files; escaping the repo is never a legitimate spec."""
    resolved = (repo_root / rel).resolve()
    root = repo_root.resolve()
    if not resolved.is_relative_to(root):
        raise SpecError(f"{where}: path {rel!r} resolves outside the repository root")


def _validate_probe(raw: object, lang: Lang, where: str) -> PythonProbe | RustProbe:
    if not isinstance(raw, dict):
        raise SpecError(f"{where}: probe must be a table")
    allowed = PYTHON_PROBE_KEYS if lang is Lang.PYTHON else RUST_PROBE_KEYS
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise SpecError(f"{where}: unknown probe key(s) {unknown} for lang={lang.value}")
    missing = sorted(allowed - set(raw))
    if missing:
        raise SpecError(f"{where}: probe missing key(s) {missing} for lang={lang.value}")
    if lang is Lang.PYTHON:
        return PythonProbe(
            module=str(raw["module"]),
            expr=str(raw["expr"]),
            equals=str(raw["equals"]),
            syspath=str(raw["syspath"]),
        )
    return RustProbe(package=str(raw["package"]))
```

- [ ] **Step 5: Run the tests and verify they pass**

```bash
uv run --with pytest pytest scripts/mutation_harness/tests/test_spec.py -q
```

Expected: `11 passed`.

- [ ] **Step 6: Confirm every file is under 500 lines**

```bash
wc -l scripts/mutation_harness/*.py scripts/mutation_harness/tests/*.py
```

- [ ] **Step 7: Commit**

```bash
git add scripts/mutation_harness/
git commit -m "feat(mutate): spec types and fail-closed TOML parsing (#644)

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: The durable journal

**Files:**
- Create: `scripts/mutation_harness/journal.py`
- Test: `scripts/mutation_harness/tests/test_journal.py`

**Interfaces:**
- Consumes: nothing from Task 1 (deliberately independent).
- Produces: `Journal` with `record(path) -> JournalEntry`, `restore(entry) -> None`, `drain() -> list[str]`, `is_dirty() -> bool`, `dirty_paths() -> list[str]`, `install_handlers() -> None`; `JournalEntry`; `RestoreFailed`.

**Why a journal and not a `finally`:** spec §5.4. A `finally` is skipped by a kill. This is the structural fix for false-green mechanism 3 — a mutation left applied by a stalled worker, which was caught by a routine `git status` rather than by anything in the procedure.

- [ ] **Step 1: Write the failing tests**

Create `scripts/mutation_harness/tests/test_journal.py`:

```python
import hashlib
import json

import pytest

from mutation_harness.journal import Journal, RestoreFailed


def test_record_then_restore_round_trips(tmp_path):
    target = tmp_path / "f.txt"
    target.write_text("original\n")
    j = Journal(tmp_path / "jdir")
    entry = j.record(target)
    target.write_text("mutated\n")
    j.restore(entry)
    assert target.read_text() == "original\n"
    assert not j.is_dirty()


def test_journal_is_written_before_the_mutation(tmp_path):
    """A kill immediately after record() must leave a recoverable journal."""
    target = tmp_path / "f.txt"
    target.write_text("original\n")
    j = Journal(tmp_path / "jdir")
    j.record(target)
    on_disk = json.loads((tmp_path / "jdir" / "mutation-journal.json").read_text())
    assert on_disk["entries"][0]["path"] == str(target.resolve())
    assert on_disk["entries"][0]["sha256"] == hashlib.sha256(b"original\n").hexdigest()


def test_a_fresh_journal_in_the_same_dir_sees_the_dirty_entry(tmp_path):
    """This is the refusal path: a SIGKILL leaves the journal, and the NEXT
    invocation must see it rather than the run being lost."""
    target = tmp_path / "f.txt"
    target.write_text("original\n")
    Journal(tmp_path / "jdir").record(target)
    target.write_text("mutated\n")

    reopened = Journal(tmp_path / "jdir")
    assert reopened.is_dirty()
    assert reopened.dirty_paths() == [str(target.resolve())]
    assert reopened.drain() == [str(target.resolve())]
    assert target.read_text() == "original\n"
    assert not reopened.is_dirty()


def test_restore_verifies_sha256_and_raises_on_mismatch(tmp_path, monkeypatch):
    target = tmp_path / "f.txt"
    target.write_text("original\n")
    j = Journal(tmp_path / "jdir")
    entry = j.record(target)
    # Corrupt the backup so the restored bytes will not match the recorded hash.
    (tmp_path / "jdir" / entry.backup_name).write_text("tampered\n")
    target.write_text("mutated\n")
    with pytest.raises(RestoreFailed, match="sha256"):
        j.restore(entry)


def test_drain_on_a_clean_journal_is_a_no_op(tmp_path):
    j = Journal(tmp_path / "jdir")
    assert j.drain() == []
    assert not j.is_dirty()


def test_binary_files_round_trip(tmp_path):
    target = tmp_path / "f.bin"
    target.write_bytes(bytes(range(256)))
    j = Journal(tmp_path / "jdir")
    entry = j.record(target)
    target.write_bytes(b"\x00")
    j.restore(entry)
    assert target.read_bytes() == bytes(range(256))
```

- [ ] **Step 2: Run the tests and verify they fail**

```bash
uv run --with pytest pytest scripts/mutation_harness/tests/test_journal.py -q
```

Expected: `ModuleNotFoundError: No module named 'mutation_harness.journal'`.

- [ ] **Step 3: Write `journal.py`**

```python
"""A durable record of original bytes, so a restore survives an abnormal exit.

Spec §5.4. A `finally` block is skipped by a kill; a journal on disk is not.
The ordering is the whole mechanism: the backup and the index are written and
fsynced BEFORE the first byte of the target changes, so there is no window in
which a file is mutated and unrecorded.

An undrained journal makes the NEXT invocation refuse to run (see
`selftest`/`mutate`), which is the structural fix for a mutation left applied
by a stalled worker.
"""

from __future__ import annotations

import atexit
import dataclasses
import hashlib
import json
import os
import signal
import sys
from pathlib import Path

JOURNAL_NAME = "mutation-journal.json"


class RestoreFailed(RuntimeError):
    """A restored file did not match its recorded sha256. Always fatal —
    continuing would run the next mutation against a poisoned tree."""


@dataclasses.dataclass(frozen=True)
class JournalEntry:
    path: str
    sha256: str
    backup_name: str


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fsync_write(path: Path, data: bytes) -> None:
    """Write and fsync, so a kill immediately afterwards cannot lose it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())


class Journal:
    def __init__(self, directory: Path) -> None:
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.index_path = self.dir / JOURNAL_NAME
        self._entries: list[JournalEntry] = self._load()

    def _load(self) -> list[JournalEntry]:
        if not self.index_path.exists():
            return []
        raw = json.loads(self.index_path.read_text())
        return [JournalEntry(**e) for e in raw.get("entries", [])]

    def _flush(self) -> None:
        payload = {"entries": [dataclasses.asdict(e) for e in self._entries]}
        _fsync_write(self.index_path, json.dumps(payload, indent=2).encode())

    def is_dirty(self) -> bool:
        return bool(self._entries)

    def dirty_paths(self) -> list[str]:
        return [e.path for e in self._entries]

    def record(self, target: Path) -> JournalEntry:
        """Copy the original bytes aside and index them, BEFORE any mutation."""
        target = Path(target).resolve()
        data = target.read_bytes()
        digest = _sha256(data)
        backup_name = f"{digest[:16]}-{target.name}.orig"
        _fsync_write(self.dir / backup_name, data)
        entry = JournalEntry(path=str(target), sha256=digest, backup_name=backup_name)
        self._entries.append(entry)
        self._flush()
        return entry

    def restore(self, entry: JournalEntry) -> None:
        """Restore, then VERIFY. A mismatch aborts rather than continuing."""
        data = (self.dir / entry.backup_name).read_bytes()
        Path(entry.path).write_bytes(data)
        actual = _sha256(Path(entry.path).read_bytes())
        if actual != entry.sha256:
            raise RestoreFailed(
                f"restore of {entry.path} failed sha256 verification: "
                f"expected {entry.sha256}, got {actual}"
            )
        self._entries = [e for e in self._entries if e.backup_name != entry.backup_name]
        self._flush()

    def drain(self) -> list[str]:
        """Restore every outstanding entry. Returns the paths restored."""
        restored = []
        for entry in list(self._entries):
            self.restore(entry)
            restored.append(entry.path)
        return restored

    def install_handlers(self) -> None:
        """Drain on normal exit AND on SIGINT/SIGTERM. A SIGKILL cannot be
        trapped, which is exactly why the on-disk journal exists."""
        atexit.register(self._drain_quietly)
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, self._on_signal)

    def _drain_quietly(self) -> None:
        try:
            self.drain()
        except Exception as exc:  # noqa: BLE001 - last-ditch; must not mask exit
            print(f"mutate: JOURNAL DRAIN FAILED: {exc}", file=sys.stderr)

    def _on_signal(self, signum, _frame) -> None:
        self._drain_quietly()
        sys.exit(128 + signum)
```

- [ ] **Step 4: Run the tests and verify they pass**

```bash
uv run --with pytest pytest scripts/mutation_harness/tests/test_journal.py -q
```

Expected: `6 passed`.

- [ ] **Step 5: Commit**

```bash
git add scripts/mutation_harness/
git commit -m "feat(mutate): durable restore journal that survives a kill (#644)

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: The two liveness proofs

**Files:**
- Create: `scripts/mutation_harness/liveness.py`
- Test: covered by Task 6's control table (`C1`, `C2`, `C10`, `N1`, `N4`) — these need real interpreters and a real cargo build, so they are integration controls rather than unit tests.

**Interfaces:**
- Consumes: `PythonProbe`, `RustProbe`, `LivenessResult` from `mutation_harness.types`.
- Produces: `clear_pycache(root: Path) -> int`, `python_env() -> dict[str, str]`, `probe_python(probe, repo_root) -> LivenessResult`, `rust_artifact_hashes(package, repo_root) -> dict[str, str]`, `compare_rust_artifacts(before, after) -> LivenessResult`.

**The asymmetry is deliberate and must survive into the code comments:** the Python proof observes the value the interpreter actually binds; the Rust proof observes that the compiler emitted different bytes. Spec §8 refuses to flatten them.

- [ ] **Step 1: Write `liveness.py`**

```python
"""The two liveness proofs. Spec §5.1.

They are NOT of equal strength and the harness reports which one it used:

* Python — strong. A fresh interpreter imports the module and evaluates the
  probe expression. This observes the value the interpreter BINDS, not the
  bytes in the file, which is what false-green mechanism 2 defeated: a
  `token = ''` splice after a `class X:` header, silently overridden by the
  real assignment below the docstring.

* Rust — weaker. `cargo build --message-format=json` names the artifacts it
  produced; their CONTENT hash must change. This proves the compiler emitted
  different bytes. It does not prove the mutated expression is reached at
  runtime.

Never a source hash and never an mtime. mtime is the mechanism behind
false-green mechanism 1.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

from mutation_harness.types import LivenessResult, PythonProbe, RustProbe

MECHANISM_INTERPRETER = "interpreter"
MECHANISM_ARTIFACT = "artifact"

# Spec §5.2: applied uniformly, never a per-mutation judgement call. The
# mutation whose green must not be believed is precisely the size-preserving
# one that nobody flags as risky.
_NO_BYTECODE = {"PYTHONDONTWRITEBYTECODE": "1"}


def python_env() -> dict[str, str]:
    """The environment every Python subprocess runs under."""
    env = dict(os.environ)
    env.update(_NO_BYTECODE)
    return env


def clear_pycache(root: Path) -> int:
    """Remove every `__pycache__` under `root`. Returns how many were removed.

    CPython invalidates a `.pyc` on `(source_mtime, size)` with the mtime
    stored in whole SECONDS, so a size-preserving mutation applied and
    reverted inside one second is served from cache and never runs.
    """
    removed = 0
    for cache in Path(root).rglob("__pycache__"):
        if cache.is_dir():
            shutil.rmtree(cache, ignore_errors=True)
            removed += 1
    return removed


_PROBE_SOURCE = """\
import sys
sys.path.insert(0, {syspath!r})
import {module} as _m
print(repr(eval({expr!r}, {{"__builtins__": __builtins__}}, vars(_m))))
"""


def probe_python(probe: PythonProbe, repo_root: Path) -> LivenessResult:
    """Assert a FRESH interpreter observes the mutated value."""
    syspath = str((Path(repo_root) / probe.syspath).resolve())
    source = _PROBE_SOURCE.format(syspath=syspath, module=probe.module, expr=probe.expr)
    proc = subprocess.run(
        ["python3", "-c", source],
        capture_output=True,
        text=True,
        cwd=str(repo_root),
        env=python_env(),
    )
    if proc.returncode != 0:
        return LivenessResult(
            live=False,
            mechanism=MECHANISM_INTERPRETER,
            detail=f"probe failed to run: {proc.stderr.strip()[:400]}",
        )
    observed = proc.stdout.strip()
    if observed == repr(probe.equals):
        return LivenessResult(True, MECHANISM_INTERPRETER, f"observed {observed}")
    return LivenessResult(
        live=False,
        mechanism=MECHANISM_INTERPRETER,
        detail=f"expected {probe.equals!r}, interpreter observed {observed}",
    )


def rust_artifact_hashes(package: str, repo_root: Path) -> dict[str, str]:
    """Build `package` and hash the CONTENTS of every artifact cargo names.

    Cargo's JSON gives absolute paths, so no globbing against the ~13,000
    files in `target/release/deps/` is needed. Verified during design: for
    `-p secretary-core` the set is `target/release/libsecretary_core.rlib`
    plus a hash-suffixed `.rmeta`.
    """
    proc = subprocess.run(
        ["cargo", "build", "--release", "-p", package, "--message-format=json"],
        capture_output=True,
        text=True,
        cwd=str(repo_root),
    )
    hashes: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("reason") != "compiler-artifact":
            continue
        if package not in msg.get("package_id", ""):
            continue
        for filename in msg.get("filenames", []):
            path = Path(filename)
            if path.exists():
                hashes[filename] = hashlib.sha256(path.read_bytes()).hexdigest()
    if not hashes and proc.returncode != 0:
        # A build failure IS a live mutation signal, but a caller cannot tell
        # it apart from "cargo produced nothing", so say which happened.
        hashes["<build-failed>"] = hashlib.sha256(proc.stderr.encode()).hexdigest()
    return hashes


def compare_rust_artifacts(before: dict[str, str], after: dict[str, str]) -> LivenessResult:
    """The artifact set must differ. Identical bytes mean the mutation never
    reached the compiler."""
    if not before and not after:
        return LivenessResult(
            False, MECHANISM_ARTIFACT, "cargo named no artifacts in either build"
        )
    if before == after:
        return LivenessResult(
            False,
            MECHANISM_ARTIFACT,
            f"artifact contents unchanged across {len(after)} file(s)",
        )
    changed = sorted(
        Path(k).name for k in set(before) | set(after) if before.get(k) != after.get(k)
    )
    return LivenessResult(True, MECHANISM_ARTIFACT, f"changed: {', '.join(changed)}")
```

- [ ] **Step 2: Smoke the Python probe against the real tree**

```bash
cd /Users/hherb/src/secretary/.worktrees/mutation-harness
uv run --with pytest python3 -c "
import sys; sys.path.insert(0,'scripts')
from pathlib import Path
from mutation_harness.liveness import probe_python
from mutation_harness.types import PythonProbe
p = PythonProbe(module='conformance_lib.codec.manifest_rules',
                expr='ArraySortOrderViolation.token',
                equals='array_sort_order', syspath='core/tests/python')
print(probe_python(p, Path('.')))
"
```

Expected: `LivenessResult(live=True, mechanism='interpreter', detail=\"observed 'array_sort_order'\")`.

If `live=False`, read the `detail` — it names the real token, and the spec's example value may simply differ from the tree. Adjust the smoke command's `equals`, not the code.

- [ ] **Step 3: Commit**

```bash
git add scripts/mutation_harness/liveness.py
git commit -m "feat(mutate): interpreter and artifact liveness proofs (#644)

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Gate execution and classification

**Files:**
- Create: `scripts/mutation_harness/gate.py`
- Test: `scripts/mutation_harness/tests/test_gate.py`

**Interfaces:**
- Consumes: `MutationSpec`, `GateResult`, `LivenessResult`, `Outcome` from `mutation_harness.types`; `python_env` from `mutation_harness.liveness`.
- Produces: `run_gate(cmd: str, repo_root: Path, timeout: int = 3600) -> GateResult`, `classify(spec, gate, liveness) -> tuple[Outcome, tuple[str, ...]]`.

**`expect_red` matching semantics (spec §4):** a plain substring test over combined stdout+stderr. `cargo test` prints failing test names; `conformance.py` prints one `FAIL: <reason>` line per failed section. A substring is the only predicate spanning both without the spec declaring which parser to use.

- [ ] **Step 1: Write the failing tests**

Create `scripts/mutation_harness/tests/test_gate.py`:

```python
from mutation_harness.gate import classify, run_gate
from mutation_harness.types import (
    GateResult, Lang, LivenessResult, MutationSpec, Outcome, RustProbe,
)

LIVE = LivenessResult(True, "interpreter", "observed")
DEAD = LivenessResult(False, "interpreter", "unchanged")


def _spec(expect="red", expect_red=()):
    return MutationSpec(
        id="M1", lang=Lang.RUST, path="a.rs", old="a", new="b",
        gate="true", expect=expect, probe=RustProbe(package="p"),
        expect_red=tuple(expect_red),
    )


def test_a_dead_mutation_is_not_live_regardless_of_the_gate():
    """The pair that matters: NOT_LIVE must never render as UNEXPECTED_GREEN."""
    outcome, _ = classify(_spec(), GateResult(0, ""), DEAD)
    assert outcome is Outcome.NOT_LIVE
    outcome, _ = classify(_spec(), GateResult(1, ""), DEAD)
    assert outcome is Outcome.NOT_LIVE


def test_expected_red_that_goes_red_passes():
    outcome, missing = classify(_spec(), GateResult(1, "boom"), LIVE)
    assert outcome is Outcome.RED_AS_EXPECTED
    assert missing == ()


def test_expected_red_that_stays_green_is_a_finding():
    outcome, _ = classify(_spec(), GateResult(0, ""), LIVE)
    assert outcome is Outcome.UNEXPECTED_GREEN


def test_expected_green_that_stays_green_passes():
    outcome, _ = classify(_spec(expect="green"), GateResult(0, ""), LIVE)
    assert outcome is Outcome.GREEN_AS_EXPECTED


def test_expected_green_that_goes_red_is_reported():
    outcome, _ = classify(_spec(expect="green"), GateResult(1, ""), LIVE)
    assert outcome is Outcome.UNEXPECTED_RED


def test_red_with_a_missing_expected_test_name_is_wrong_tests_red():
    """Passing on 'something red' is not the claim a mutation table makes."""
    spec = _spec(expect_red=["wanted_test", "other_test"])
    outcome, missing = classify(spec, GateResult(1, "... other_test ... FAILED"), LIVE)
    assert outcome is Outcome.WRONG_TESTS_RED
    assert missing == ("wanted_test",)


def test_red_with_every_expected_test_name_present_passes():
    spec = _spec(expect_red=["wanted_test"])
    outcome, missing = classify(spec, GateResult(1, "wanted_test FAILED"), LIVE)
    assert outcome is Outcome.RED_AS_EXPECTED
    assert missing == ()


def test_run_gate_captures_exit_code_and_combined_output(tmp_path):
    ok = run_gate("echo hello", tmp_path)
    assert ok.exit_code == 0 and "hello" in ok.output
    bad = run_gate("echo oops >&2; exit 3", tmp_path)
    assert bad.exit_code == 3 and "oops" in bad.output and bad.is_red
```

- [ ] **Step 2: Run the tests and verify they fail**

```bash
uv run --with pytest pytest scripts/mutation_harness/tests/test_gate.py -q
```

Expected: `ModuleNotFoundError: No module named 'mutation_harness.gate'`.

- [ ] **Step 3: Write `gate.py`**

```python
"""Run a gate command and classify the result. Spec §5.5.

`classify` checks LIVENESS FIRST. That ordering is the whole point of #644:
a mutation that did not run and a mutation that ran without reddening any
test produce the same gate output, and reporting them identically is what
converted "this test is non-vacuous" into an unfounded claim.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from mutation_harness.liveness import python_env
from mutation_harness.types import GateResult, LivenessResult, MutationSpec, Outcome


def run_gate(cmd: str, repo_root: Path, timeout: int = 3600) -> GateResult:
    """Run `cmd` through a shell, capturing stdout and stderr TOGETHER.

    Combined because `expect_red` matches by substring across both: cargo
    writes test names to stdout, and a failing `conformance.py` section can
    surface on either stream depending on the caller.
    """
    try:
        proc = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            cwd=str(repo_root),
            env=python_env(),
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return GateResult(exit_code=124, output=f"gate timed out after {timeout}s")
    return GateResult(exit_code=proc.returncode, output=proc.stdout + proc.stderr)


def classify(
    spec: MutationSpec, gate: GateResult, liveness: LivenessResult
) -> tuple[Outcome, tuple[str, ...]]:
    """Return the row's outcome and any `expect_red` names that were absent."""
    if not liveness.live:
        # Deliberately BEFORE any gate reasoning. A row that measured nothing
        # must never be reported as a row that measured a green.
        return Outcome.NOT_LIVE, ()

    if spec.expects_red:
        if not gate.is_red:
            return Outcome.UNEXPECTED_GREEN, ()
        missing = tuple(name for name in spec.expect_red if name not in gate.output)
        if missing:
            return Outcome.WRONG_TESTS_RED, missing
        return Outcome.RED_AS_EXPECTED, ()

    if gate.is_red:
        return Outcome.UNEXPECTED_RED, ()
    return Outcome.GREEN_AS_EXPECTED, ()
```

- [ ] **Step 4: Run the tests and verify they pass**

```bash
uv run --with pytest pytest scripts/mutation_harness/tests/test_gate.py -q
```

Expected: `8 passed`.

- [ ] **Step 5: Commit**

```bash
git add scripts/mutation_harness/
git commit -m "feat(mutate): gate execution and liveness-first classification (#644)

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: The runner state machine and the report

**Files:**
- Create: `scripts/mutation_harness/runner.py`
- Create: `scripts/mutation_harness/report.py`
- Test: `scripts/mutation_harness/tests/test_report.py`

**Interfaces:**
- Consumes: everything from Tasks 1-4.
- Produces: `run_mutations(specs, repo_root, journal_dir) -> list[MutationResult]`, `apply_substitution(path, old, new) -> bool` from `mutation_harness.runner`; `render_markdown(results) -> str`, `render_json(results) -> str` from `mutation_harness.report`.

- [ ] **Step 1: Write the failing report tests**

Create `scripts/mutation_harness/tests/test_report.py`:

```python
import json

from mutation_harness.report import render_json, render_markdown
from mutation_harness.types import (
    GateResult, Lang, LivenessResult, MutationResult, MutationSpec, Outcome, RustProbe,
)


def _result(outcome, mechanism="artifact", note=""):
    spec = MutationSpec(
        id="M1", lang=Lang.RUST, path="a.rs", old="a", new="b", gate="true",
        expect="red", probe=RustProbe(package="p"), note=note,
    )
    return MutationResult(
        spec=spec,
        outcome=outcome,
        liveness=LivenessResult(True, mechanism, "changed: lib.rlib"),
        gate=GateResult(1, "boom"),
    )


def test_markdown_names_the_liveness_mechanism():
    """The Rust and Python proofs differ in strength; the table must say which."""
    out = render_markdown([_result(Outcome.RED_AS_EXPECTED)])
    assert "| M1 |" in out
    assert "artifact" in out
    assert "RED_AS_EXPECTED" in out


def test_markdown_marks_a_row_that_measured_nothing():
    out = render_markdown([_result(Outcome.NOT_LIVE, mechanism="interpreter")])
    assert "NOT_LIVE" in out
    assert "no" in out.lower()


def test_json_round_trips_every_field():
    payload = json.loads(render_json([_result(Outcome.UNEXPECTED_GREEN, note="why")]))
    assert payload[0]["id"] == "M1"
    assert payload[0]["outcome"] == "UNEXPECTED_GREEN"
    assert payload[0]["live"] is True
    assert payload[0]["note"] == "why"
```

- [ ] **Step 2: Run and verify failure**

```bash
uv run --with pytest pytest scripts/mutation_harness/tests/test_report.py -q
```

Expected: `ModuleNotFoundError: No module named 'mutation_harness.report'`.

- [ ] **Step 3: Write `report.py`**

```python
"""Render results. Spec §7.

The table is emitted so a handoff pastes GENERATED evidence. Every mutation
table in every handoff before #644 was hand-transcribed from scrollback — an
unverified step between the measurement and the published claim, invisible to
review because the scrollback is gone by the time anyone reads the table.
"""

from __future__ import annotations

import json

from mutation_harness.types import MutationResult

_HEADER = "| # | Mutation | Live | Outcome | Reds |\n|---|---|---|---|---|"


def _live_cell(result: MutationResult) -> str:
    if result.liveness is None:
        return "not probed"
    return f"yes ({result.liveness.mechanism})" if result.liveness.live else "NO"


def _reds_cell(result: MutationResult) -> str:
    if result.missing_reds:
        return "missing: " + ", ".join(result.missing_reds)
    if result.spec.expect_red:
        return ", ".join(result.spec.expect_red)
    return "—"


def _describe(result: MutationResult) -> str:
    if result.spec.note:
        return result.spec.note
    return f"`{result.spec.old}` -> `{result.spec.new}`"


def render_markdown(results: list[MutationResult]) -> str:
    rows = [
        f"| {r.spec.id} | {_describe(r)} | {_live_cell(r)} "
        f"| {r.outcome.value} | {_reds_cell(r)} |"
        for r in results
    ]
    return "\n".join([_HEADER, *rows])


def render_json(results: list[MutationResult]) -> str:
    payload = [
        {
            "id": r.spec.id,
            "lang": r.spec.lang.value,
            "path": r.spec.path,
            "expect": r.spec.expect,
            "note": r.spec.note,
            "outcome": r.outcome.value,
            "success": r.outcome.is_success,
            "live": None if r.liveness is None else r.liveness.live,
            "mechanism": None if r.liveness is None else r.liveness.mechanism,
            "liveness_detail": None if r.liveness is None else r.liveness.detail,
            "exit_code": None if r.gate is None else r.gate.exit_code,
            "missing_reds": list(r.missing_reds),
        }
        for r in results
    ]
    return json.dumps(payload, indent=2)
```

- [ ] **Step 4: Write `runner.py`**

```python
"""The per-mutation state machine. Spec §5.6.

Step ordering is load-bearing:

1. Baseline the gate on the CLEAN tree. A baseline that is already red and a
   mutation that did not run produce the same gate output; separating them is
   half of requirement 5.
2. Journal, then apply.
3. Probe liveness. A row that fails here measured NOTHING and says so.
4. Run the gate.
5. Classify.
6. Restore and sha256-verify.
"""

from __future__ import annotations

from pathlib import Path

from mutation_harness.gate import classify, run_gate
from mutation_harness.journal import Journal, RestoreFailed
from mutation_harness.liveness import (
    clear_pycache, compare_rust_artifacts, probe_python, rust_artifact_hashes,
)
from mutation_harness.types import (
    Lang, LivenessResult, MutationResult, MutationSpec, Outcome,
)


def apply_substitution(path: Path, old: str, new: str) -> bool:
    """Replace `old` with `new` iff it occurs EXACTLY once.

    Zero and two-or-more are both refusals. There is no first-wins guess: an
    ambiguous mutation is precisely the shape that produced false green 2.
    """
    text = path.read_text()
    if text.count(old) != 1:
        return False
    path.write_text(text.replace(old, new, 1))
    return True


def _probe(spec: MutationSpec, repo_root: Path, rust_before: dict) -> LivenessResult:
    if spec.lang is Lang.PYTHON:
        clear_pycache(repo_root / Path(spec.path).parent)
        return probe_python(spec.probe, repo_root)
    after = rust_artifact_hashes(spec.probe.package, repo_root)
    return compare_rust_artifacts(rust_before, after)


def run_mutations(
    specs: tuple[MutationSpec, ...], repo_root: Path, journal_dir: Path
) -> list[MutationResult]:
    journal = Journal(journal_dir)
    journal.install_handlers()
    results: list[MutationResult] = []
    baselines: dict[str, bool] = {}

    for spec in specs:
        target = (repo_root / spec.path).resolve()

        if spec.gate not in baselines:
            clear_pycache(repo_root)
            baselines[spec.gate] = not run_gate(spec.gate, repo_root).is_red
        if not baselines[spec.gate]:
            results.append(MutationResult(spec=spec, outcome=Outcome.BASELINE_DIRTY))
            continue

        rust_before: dict[str, str] = {}
        if spec.lang is Lang.RUST:
            rust_before = rust_artifact_hashes(spec.probe.package, repo_root)

        entry = journal.record(target)
        try:
            if not apply_substitution(target, spec.old, spec.new):
                results.append(MutationResult(spec=spec, outcome=Outcome.NOT_APPLIED))
                continue

            liveness = _probe(spec, repo_root, rust_before)
            if not liveness.live:
                results.append(
                    MutationResult(spec=spec, outcome=Outcome.NOT_LIVE, liveness=liveness)
                )
                continue

            gate = run_gate(spec.gate, repo_root)
            outcome, missing = classify(spec, gate, liveness)
            results.append(
                MutationResult(
                    spec=spec, outcome=outcome, liveness=liveness,
                    gate=gate, missing_reds=missing,
                )
            )
        finally:
            try:
                journal.restore(entry)
            except RestoreFailed:
                results.append(
                    MutationResult(spec=spec, outcome=Outcome.RESTORE_FAILED)
                )
                raise

    return results
```

- [ ] **Step 5: Run the report tests and verify they pass**

```bash
uv run --with pytest pytest scripts/mutation_harness/tests/ -q
```

Expected: `28 passed` (11 spec + 6 journal + 8 gate + 3 report).

- [ ] **Step 6: Commit**

```bash
git add scripts/mutation_harness/
git commit -m "feat(mutate): the per-mutation state machine and result rendering (#644)

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: The control table, `--self-test`, and the entrypoint

**Files:**
- Create: `scripts/mutation_harness/controls.py`
- Create: `scripts/mutation_harness/selftest.py`
- Create: `scripts/mutate.py`
- Test: `scripts/mutation_harness/tests/test_controls.py`

**Interfaces:**
- Consumes: everything from Tasks 1-5.
- Produces: `Control`, `POSITIVE_CONTROLS`, `NEGATIVE_CONTROLS` from `mutation_harness.controls`; `run_self_test() -> int` from `mutation_harness.selftest`.

**This is the task that earns the harness its trust.** A harness whose whole claim is detection must be proven to detect the three mechanisms that actually fooled this project. `C2` is the one it exists for.

- [ ] **Step 1: Write `controls.py`**

Each control builds a fixture in a caller-supplied temp dir and returns a `MutationSpec` plus the outcome the harness MUST reach. `C3` is not an `Outcome` and is checked separately in `selftest.py`.

```python
"""The control table, as DATA. Spec §6.

Consumed by BOTH `selftest.run_self_test` and pytest's `test_controls.py`, so
the two cannot drift onto different ideas of what a control asserts — the
"one implementation, called by both directions" move #600 and #602 made.

Every fixture is built under a caller-supplied temp dir. Nothing is ever
written into the source tree (#516).
"""

from __future__ import annotations

import dataclasses
import textwrap
from collections.abc import Callable
from pathlib import Path

from mutation_harness.types import Lang, MutationSpec, Outcome, PythonProbe, RustProbe


@dataclasses.dataclass(frozen=True)
class Control:
    label: str
    why: str
    build: Callable[[Path], MutationSpec]
    expect: Outcome


def _write(root: Path, rel: str, body: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(body).lstrip())
    return path


def _py_spec(root: Path, **kw) -> MutationSpec:
    defaults = dict(
        id="C", lang=Lang.PYTHON, path="m.py", gate="true", expect="red",
        probe=PythonProbe(module="m", expr="TOKEN", equals="mutated", syspath="."),
    )
    defaults.update(kw)
    return MutationSpec(**defaults)


# --- C1: a size-preserving mutation must still be seen (false green 1) ------
def _build_c1(root: Path) -> MutationSpec:
    _write(root, "m.py", 'TOKEN = "aaaaaaa"\n')
    # Same length, so (mtime, size) bytecode invalidation cannot see it.
    return _py_spec(
        root, id="C1", old='TOKEN = "aaaaaaa"', new='TOKEN = "mutated"',
        gate="true", expect="green",
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
        root, id="C2",
        old="class Rejection:",
        new='class Rejection:\n    TOKEN = "mutated"',
        probe=PythonProbe("m", "Rejection.TOKEN", "mutated", "."),
    )


# --- C4 / C5: ambiguous and absent anchors ---------------------------------
def _build_c4(root: Path) -> MutationSpec:
    _write(root, "m.py", 'TOKEN = "x"\nOTHER = "x"\n')
    return _py_spec(root, id="C4", old='"x"', new='"y"')


def _build_c5(root: Path) -> MutationSpec:
    _write(root, "m.py", 'TOKEN = "x"\n')
    return _py_spec(root, id="C5", old="not-present-anywhere", new="y")


# --- C6: the gate is already red on the clean tree --------------------------
def _build_c6(root: Path) -> MutationSpec:
    _write(root, "m.py", 'TOKEN = "real"\n')
    return _py_spec(
        root, id="C6", old='"real"', new='"mutated"', gate="exit 1",
        probe=PythonProbe("m", "TOKEN", "mutated", "."),
    )


# --- C8: live, gate green, declared red ------------------------------------
def _build_c8(root: Path) -> MutationSpec:
    _write(root, "m.py", 'TOKEN = "real"\n')
    return _py_spec(
        root, id="C8", old='"real"', new='"mutated"', gate="true", expect="red",
        probe=PythonProbe("m", "TOKEN", "mutated", "."),
    )


# --- C9: red, but not the test the row claims ------------------------------
def _build_c9(root: Path) -> MutationSpec:
    _write(root, "m.py", 'TOKEN = "real"\n')
    return _py_spec(
        root, id="C9", old='"real"', new='"mutated"',
        gate="echo something_else_failed; exit 1", expect="red",
        expect_red=("the_test_this_row_claims",),
        probe=PythonProbe("m", "TOKEN", "mutated", "."),
    )


# --- C11: live, declared green, gate goes red ------------------------------
def _build_c11(root: Path) -> MutationSpec:
    _write(root, "m.py", 'TOKEN = "real"\n')
    return _py_spec(
        root, id="C11", old='"real"', new='"mutated"', gate="exit 1", expect="green",
        probe=PythonProbe("m", "TOKEN", "mutated", "."),
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
    # A comment-only edit. The source changes; release artifacts do not.
    return MutationSpec(
        id="C10", lang=Lang.RUST, path="src/lib.rs",
        old="pub fn answer() -> u32 {",
        new="// a comment that changes no emitted byte\npub fn answer() -> u32 {",
        gate="cargo test --release", expect="red", probe=RustProbe("mutdemo"),
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
        gate="cargo test --release", expect="red",
        expect_red=("answer_is_42",), probe=RustProbe("mutdemo"),
    )


# --- N1 / N2 / N3: the harness must stay silent ----------------------------
def _build_n1(root: Path) -> MutationSpec:
    _write(root, "m.py", 'TOKEN = "real"\n')
    _write(root, "gate.py", 'import m, sys; sys.exit(0 if m.TOKEN == "real" else 1)\n')
    return _py_spec(
        root, id="N1", old='"real"', new='"mutated"',
        gate="python3 gate.py", expect="red",
        probe=PythonProbe("m", "TOKEN", "mutated", "."),
    )


def _build_n2(root: Path) -> MutationSpec:
    _write(root, "m.py", 'TOKEN = "real"\n')
    return _py_spec(
        root, id="N2", old='"real"', new='"mutated"', gate="true", expect="green",
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
    Control("C10", "a Rust edit that emits identical artifacts", _build_c10, Outcome.NOT_LIVE),
    Control("C11", "live, declared green, gate goes red", _build_c11, Outcome.UNEXPECTED_RED),
)

NEGATIVE_CONTROLS: tuple[Control, ...] = (
    Control("N1", "a genuinely live Python mutation reddens its gate",
            _build_n1, Outcome.RED_AS_EXPECTED),
    Control("N2", "a by-design green, proven live", _build_n2, Outcome.GREEN_AS_EXPECTED),
    Control("N4", "a genuinely live Rust mutation", _build_n4, Outcome.RED_AS_EXPECTED),
)
```

**Note on `C3` and `C7`:** neither is an `Outcome` reachable through `run_mutations` on a fixture — `C3` is a refusal to start and `C7` requires corrupting a backup behind the harness. Both are asserted directly in `selftest.py` (Step 2) and by `test_journal.py`'s sha256 test from Task 2. `N3` (a clean tree does not report `BASELINE_DIRTY`) is implied by every other negative control passing, and is asserted explicitly in `selftest.py`.

- [ ] **Step 2: Write `selftest.py`**

```python
"""Drive every control through the REAL pipeline. Spec §6.

`--self-test` runs before any real spec, matching the discipline every other
guard in this repo follows: a green is never vacuous because the matcher is
first shown to fire on a known positive and stay silent on a known negative.

This harness carries a stronger obligation than a matcher. Its whole claim is
detection, so it must be proven to detect the three mechanisms that actually
fooled this project. C2 is the one it exists for.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from mutation_harness.controls import NEGATIVE_CONTROLS, POSITIVE_CONTROLS, Control
from mutation_harness.journal import Journal
from mutation_harness.runner import run_mutations
from mutation_harness.types import Outcome


def run_control(control: Control) -> tuple[bool, str]:
    """Build the control's fixture in a temp dir and run it end to end."""
    with tempfile.TemporaryDirectory(prefix="mutate-selftest-") as tmp:
        root = Path(tmp)
        spec = control.build(root)
        results = run_mutations((spec,), root, root / ".journal")
        if len(results) != 1:
            return False, f"expected 1 result, got {len(results)}"
        actual = results[0].outcome
        if actual is not control.expect:
            return False, f"expected {control.expect.value}, got {actual.value}"
        residue = [p for p in root.rglob("*.orig")]
        if residue and Journal(root / ".journal").is_dirty():
            return False, "journal left dirty after a completed control"
        return True, actual.value


def check_journal_refusal() -> tuple[bool, str]:
    """C3: an undrained journal must be visible to the NEXT invocation.

    This is the structural fix for false green 3 — a mutation left applied by
    a stalled worker, previously caught only by a routine `git status`.
    """
    with tempfile.TemporaryDirectory(prefix="mutate-c3-") as tmp:
        root = Path(tmp)
        target = root / "f.txt"
        target.write_text("original\n")
        Journal(root / ".journal").record(target)
        target.write_text("mutated\n")

        reopened = Journal(root / ".journal")
        if not reopened.is_dirty():
            return False, "a reopened journal did not see the outstanding entry"
        if reopened.dirty_paths() != [str(target.resolve())]:
            return False, "dirty_paths did not name the mutated file"
        reopened.drain()
        if target.read_text() != "original\n":
            return False, "drain did not restore the original bytes"
        return True, "refusal state visible and drainable"


def run_self_test() -> int:
    failures = 0
    print("mutation harness self-test")
    print("=" * 60)

    for control in POSITIVE_CONTROLS:
        ok, detail = run_control(control)
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {control.label}: {control.why} -> {detail}")
        failures += 0 if ok else 1

    ok, detail = check_journal_refusal()
    print(f"  [{'PASS' if ok else 'FAIL'}] C3: journal refusal -> {detail}")
    failures += 0 if ok else 1

    for control in NEGATIVE_CONTROLS:
        ok, detail = run_control(control)
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {control.label}: {control.why} -> {detail}")
        failures += 0 if ok else 1

    total = len(POSITIVE_CONTROLS) + len(NEGATIVE_CONTROLS) + 1
    covered = {c.expect for c in POSITIVE_CONTROLS} | {c.expect for c in NEGATIVE_CONTROLS}
    uncovered = sorted(o.value for o in Outcome if o not in covered)
    if uncovered:
        # RESTORE_FAILED is covered by test_journal.py rather than by a control,
        # because it needs the backup corrupted behind the harness.
        if uncovered != ["RESTORE_FAILED"]:
            print(f"  [FAIL] outcome coverage: no control reaches {uncovered}")
            failures += 1
        else:
            print("  [PASS] outcome coverage: all but RESTORE_FAILED (see test_journal.py)")

    print("=" * 60)
    print(f"{total - failures}/{total} checks passed")
    return 1 if failures else 0
```

- [ ] **Step 3: Write the entrypoint `scripts/mutate.py`**

```python
#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
r"""A verified mutation harness (#644).

WHY THIS EXISTS
---------------
This repo cites mutation results as load-bearing evidence in CLAUDE.md and in
every handoff, and until now nothing checked that the mutation took effect.
Three distinct mechanisms have produced a GREEN that proved nothing: stale
bytecode on a size-preserving edit, a later class-body assignment silently
overriding an earlier splice, and a mutation left applied by a stalled worker.

All three were caught by someone finding a result surprising. That stops
working the moment a mutation is expected to be green by design, where a false
green and a true green are indistinguishable by inspection.

USAGE
-----
    uv run scripts/mutate.py --self-test
    uv run scripts/mutate.py <spec.toml> [--json] [--journal-dir DIR]
    uv run scripts/mutate.py --drain [--journal-dir DIR]

Read docs/superpowers/specs/2026-09-11-mutation-harness-design.md first.
Write the spec to the session scratchpad, never into the source tree (#516).
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mutation_harness.journal import Journal  # noqa: E402
from mutation_harness.report import render_json, render_markdown  # noqa: E402
from mutation_harness.runner import run_mutations  # noqa: E402
from mutation_harness.selftest import run_self_test  # noqa: E402
from mutation_harness.spec import SpecError, parse_spec  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_JOURNAL = Path(tempfile.gettempdir()) / "secretary-mutation-journal"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("spec", nargs="?", help="path to a mutation spec (TOML)")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--drain", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--journal-dir", default=str(DEFAULT_JOURNAL))
    args = parser.parse_args(argv)

    journal_dir = Path(args.journal_dir)

    if args.drain:
        restored = Journal(journal_dir).drain()
        for path in restored:
            print(f"restored {path}")
        print(f"{len(restored)} file(s) restored")
        return 0

    if args.self_test:
        return run_self_test()

    if not args.spec:
        parser.error("a spec path is required unless --self-test or --drain is given")

    # Refuse to start on an undrained journal. This is the structural fix for
    # a mutation left applied: it can no longer wait to be noticed by a
    # routine `git status`.
    journal = Journal(journal_dir)
    if journal.is_dirty():
        print("mutate: REFUSING TO RUN — an earlier run left files mutated:", file=sys.stderr)
        for path in journal.dirty_paths():
            print(f"  {path}", file=sys.stderr)
        print(f"Run: uv run scripts/mutate.py --drain --journal-dir {journal_dir}",
              file=sys.stderr)
        return 2

    try:
        specs = parse_spec(Path(args.spec).read_text(), REPO_ROOT)
    except SpecError as exc:
        print(f"mutate: {exc}", file=sys.stderr)
        return 2

    results = run_mutations(specs, REPO_ROOT, journal_dir)
    print(render_json(results) if args.json else render_markdown(results))
    return 0 if all(r.outcome.is_success for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
```

- [ ] **Step 4: Write `test_controls.py` so pytest runs the same table**

```python
import pytest

from mutation_harness.controls import NEGATIVE_CONTROLS, POSITIVE_CONTROLS
from mutation_harness.selftest import check_journal_refusal, run_control

ALL = POSITIVE_CONTROLS + NEGATIVE_CONTROLS


@pytest.mark.parametrize("control", ALL, ids=[c.label for c in ALL])
def test_control_reaches_its_declared_outcome(control):
    ok, detail = run_control(control)
    assert ok, f"{control.label} ({control.why}): {detail}"


def test_journal_refusal_is_visible_to_the_next_invocation():
    ok, detail = check_journal_refusal()
    assert ok, detail
```

- [ ] **Step 5: Run the self-test**

```bash
cd /Users/hherb/src/secretary/.worktrees/mutation-harness
uv run scripts/mutate.py --self-test; echo "SELFTEST EXIT: $?"
```

Expected: every control `PASS`, exit 0. The Rust controls (`C10`, `N4`) each build a trivial standalone crate and take a few seconds.

**If `C10` reports `live` rather than `NOT_LIVE`**, the comment-only edit did change the artifact (release builds can embed source paths or line tables). Do NOT weaken the control — change the fixture so the edit is genuinely invisible to codegen (for example add a trailing blank line inside an existing comment block) and record what you found in the handoff. `C10`'s claim is that the harness detects an artifact-invisible edit; the fixture just has to produce one.

- [ ] **Step 6: Run the full pytest suite**

```bash
uv run --with pytest pytest scripts/mutation_harness/tests/ -q
```

Expected: all pass, including the 12 parametrized controls.

- [ ] **Step 7: Verify no source-tree residue and every file under 500 lines**

```bash
git status --short
wc -l scripts/mutate.py scripts/mutation_harness/*.py scripts/mutation_harness/tests/*.py
```

Expected: `git status` clean apart from the new files; every count under 500.

- [ ] **Step 8: Commit**

```bash
git add scripts/mutate.py scripts/mutation_harness/
git commit -m "feat(mutate): control table, --self-test, and the entrypoint (#644)

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Prove it in practice, then document

**Files:**
- Create: (scratchpad only) a spec reproducing a mutation from a shipped slice
- Modify: `CLAUDE.md`
- Modify: `ROADMAP.md`
- Modify: `README.md` only if a check confirms it needs it

**Interfaces:**
- Consumes: the finished harness.
- Produces: evidence for the handoff.

**Spec §9 criterion 3:** a real spec covering a known mutation from a shipped slice must reproduce that slice's recorded result. This is the step that distinguishes a harness that passes its own controls from one that works.

- [ ] **Step 1: Write a real spec against a shipped mutation**

The 2026-09-10 baton records `M12a/b`: dropping or flipping a row in the rule-token vocabulary fixture reds Section RTV. Reproduce it. Write to the scratchpad, NOT the source tree:

```bash
SCRATCH=$(mktemp -d)
cat > "$SCRATCH/real.toml" <<'EOF'
[[mutation]]
id = "M12b"
lang = "python"
path = "core/tests/python/conformance_lib/codec/manifest_rules.py"
old = 'token = "array_sort_order"'
new = 'token = "rule2_indefinite_length"'
gate = "uv run core/tests/python/conformance.py"
expect = "green"
note = "phase-dependent token swapped for another; tolerated by design (baton M8)"
probe = { module = "conformance_lib.codec.manifest_rules", expr = "ArraySortOrderViolation.token", equals = "rule2_indefinite_length", syspath = "core/tests/python" }
EOF
uv run scripts/mutate.py "$SCRATCH/real.toml"; echo "EXIT: $?"
```

First confirm the anchor exists and the current token spelling, since the spec above is written from the baton rather than from the file:

```bash
grep -n "token = " core/tests/python/conformance_lib/codec/manifest_rules.py
```

Adjust `old`, `equals` and `expr` to what the file actually contains. **Do not adjust the expected outcome to match whatever comes out** — if the result contradicts the baton, that is a finding to report, not a number to fit.

- [ ] **Step 2: Confirm the tree is clean afterwards**

```bash
git status --short
git diff --stat
```

Expected: empty. The restore is sha256-verified, so a non-empty diff here is a harness bug and must be investigated before proceeding.

- [ ] **Step 3: Prove `C2` is non-vacuous by mutating the harness itself**

The control that matters most must be shown to fail when its mechanism is removed:

```bash
# Make probe_python trust the file rather than the interpreter.
python3 - <<'PY'
import pathlib
p = pathlib.Path("scripts/mutation_harness/liveness.py")
s = p.read_text()
s = s.replace("    if observed == repr(probe.equals):",
              "    if True:  # MUTATION: trust the file, not the interpreter")
p.write_text(s)
PY
uv run scripts/mutate.py --self-test; echo "EXPECT NONZERO: $?"
git checkout scripts/mutation_harness/liveness.py
uv run scripts/mutate.py --self-test; echo "EXPECT ZERO: $?"
```

Expected: `C2` FAILs with the mutation applied and PASSes after restore. Record the exact output for the handoff. Do the same for `C1` (delete the `clear_pycache` call in `runner._probe`) and `C3` (make `Journal._load` return `[]` unconditionally).

- [ ] **Step 4: Update `CLAUDE.md`**

Add a subsection under the Commands block, after the existing guard commands:

```markdown
# Mutation testing: run the harness, do not hand-roll one (#644)
# This repo cites mutation results as evidence in CLAUDE.md and in every
# handoff. Until #644 nothing checked that the mutation took effect, and
# three distinct mechanisms had each produced a GREEN that proved nothing:
# stale bytecode on a size-preserving edit, a later class-body assignment
# silently overriding an earlier splice, and a mutation left applied by a
# stalled worker. All three were caught by someone finding a result
# SURPRISING, which stops working the moment a mutation is expected to be
# green by design — there a false green and a true green are
# indistinguishable by inspection.
#
# Write the spec to the session SCRATCHPAD, never the source tree (#516).
# `--self-test` first, as with every other guard: it reproduces all three
# false greens as positive controls, and C2 (a splice overridden by a later
# assignment) is the one the harness exists for.
uv run scripts/mutate.py --self-test
uv run scripts/mutate.py "$SCRATCH/mutations.toml"
#
# An interrupted run leaves a JOURNAL rather than a mutated tree, and the
# next invocation REFUSES to start until it is drained:
uv run scripts/mutate.py --drain
```

Also add a bullet to the "Memory hygiene"-adjacent invariants noting that the
Python and Rust liveness proofs are **not of equal strength** — Python
observes the value the interpreter binds, Rust observes that the compiler
emitted different bytes — and that the report names which was used.

- [ ] **Step 5: Update `ROADMAP.md`**

Record #644 as delivered under the tooling/hardening track, with one sentence naming the mechanism (a liveness proof plus a durable journal), not the file list.

- [ ] **Step 6: Check whether `README.md` needs anything**

```bash
grep -n "mutation\|scripts/" README.md | head -20
```

README describes user-facing capability and the conformance harnesses. A developer-only mutation harness likely does not belong there. **Check, then state the conclusion in the handoff either way** — the last three batons each recorded this check explicitly rather than leaving it to inference.

- [ ] **Step 7: Run the repo's own gate set**

The harness adds no Rust and no FFI surface, so the crypto gates should be untouched. Run them anyway to prove it, and because a `scripts/` addition is exactly the kind of change assumed to be inert:

```bash
cd /Users/hherb/src/secretary/.worktrees/mutation-harness
pwd && git branch --show-current
uv run core/tests/python/conformance.py > /tmp/conf.txt 2>&1; echo "CONF: $?"
grep -c "^FAIL" /tmp/conf.txt; grep "section registry" /tmp/conf.txt
bash ffi/scripts/check-lean-binding.sh --self-test         && bash ffi/scripts/check-lean-binding.sh
bash ios/scripts/check-public-log-hygiene.sh --self-test   && bash ios/scripts/check-public-log-hygiene.sh
bash android/scripts/check-log-hygiene.sh --self-test      && bash android/scripts/check-log-hygiene.sh
bash scripts/check-secret-slot-hygiene.sh --self-test      && bash scripts/check-secret-slot-hygiene.sh
uv run scripts/check-error-payload-hygiene.py --self-test  && uv run scripts/check-error-payload-hygiene.py
uv run scripts/check-test-support-placement.py --self-test && uv run scripts/check-test-support-placement.py
```

**`check-secret-slot-hygiene.sh` is the one that could genuinely red:** it checks declared scan roots against the root manifest's `[workspace] members`. `scripts/` is not a workspace member, so it should be unaffected — but confirm rather than assume, since a fail-open root list is exactly what that guard was rewritten to prevent.

- [ ] **Step 8: Commit**

```bash
git add CLAUDE.md ROADMAP.md README.md
git commit -m "docs: record the verified mutation harness and its limits (#644)

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage.** §1 (the problem) → Task 7's documentation. §2 (scope) → Global Constraints. §3 (placement) → the File Structure table, Tasks 1-6. §4 (spec format) → Task 1. §5.1 → Task 3. §5.2 → Task 3's `clear_pycache`/`python_env`, called from Task 5's `runner._probe`. §5.3 → Task 2's `restore`. §5.4 → Task 2's journal plus Task 6's entrypoint refusal. §5.5 → Task 1's `Outcome`, Task 4's `classify`. §5.6 → Task 5's `run_mutations`. §6 (controls) → Task 6. §7 (output) → Task 5's `report.py`. §8 (non-claims) → Task 3's and Task 7's comments. §9 (success criteria) → criterion 1 Task 6 Step 5, criterion 2 Task 7 Step 3, criterion 3 Task 7 Step 1, criterion 4 Task 6 Step 2 / Task 2, criterion 5 Task 6 Step 7, criterion 6 the mapping above.

**Placeholder scan.** No "TBD", no "add error handling", no "similar to Task N". Every code step carries real code. Task 7 Steps 1 and 5 deliberately require the implementer to read the tree first — that is an instruction to measure, not a placeholder, and each says what to do with a surprising result.

**Type consistency.** `MutationSpec.probe` is `PythonProbe | RustProbe` in Task 1 and is consumed as such in Tasks 3 and 5. `classify` returns `tuple[Outcome, tuple[str, ...]]` in Task 4 and is unpacked as two values in Task 5. `Journal.record` returns `JournalEntry` in Task 2 and is passed to `Journal.restore` in Task 5. `JournalEntry.backup_name` is used consistently in Task 2's tests and implementation. `Control.build` takes a `Path` and returns `MutationSpec` in Task 6 and is called that way in `selftest.run_control`. `run_control` returns `tuple[bool, str]` and is unpacked identically in `selftest.run_self_test` and `test_controls.py`.

**Known uncertainty carried deliberately.** `C10` assumes a comment-only Rust edit leaves release artifacts byte-identical. That is plausible but unverified — release builds can embed line tables. Task 6 Step 5 tells the implementer what to do if it does not hold, and forbids weakening the control to fit. This is the one place the plan expects a possible surprise, recorded here rather than discovered mid-task.
