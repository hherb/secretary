"""Parse and STRUCTURALLY validate a mutation spec. Fail-closed throughout.

An unknown key is an ERROR, never ignored. A typo'd key that silently
degrades a check is the failure mode `payload_guard`'s `ControlExpectation`
already records; the same ruling applies here.

**A wrong-TYPED value is an error too, and `str()` coercion is not
validation** (final whole-branch review, Findings 4/5 — the fifth instance of
this defect class on this branch, which is why it is closed by rule rather
than per site). Every string-typed field is required to BE a string:

* Coercion was WIDER than previously recorded. `gate = { a = 1 }` became the
  literal shell command `{'a': 1}` — a spec typo turned into an executed
  command line — and `new = [1, 2]` spliced `[1, 2]` into a source file, both
  silently.
* Two fields reached an UNHASHABLE-type crash before any `str()` could help:
  `expect = ["red"]` raised a bare `TypeError: unhashable type: 'list'` out
  of the `in VALID_EXPECT` test, and `lang = { a = 1 }` the same out of
  `Lang(...)`'s enum lookup — neither a `SpecError`, so neither reached
  `mutate.main`'s handler as an exit-2 `mutate:` line.

`_require_str` is therefore applied before any field is USED, and the two
membership tests come after it.

Deliberately NOT checked here: whether `old` occurs exactly once in `path`.
Spec §5.5 makes that `Outcome.NOT_APPLIED`, a per-row outcome, so the runner
owns it. Parse-time validation is structure only.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from mutation_harness.types import Lang, MutationSpec, PythonProbe, RustProbe

TOP_LEVEL_KEYS = frozenset(
    {
        "id", "lang", "path", "old", "new", "gate", "expect", "expect_red",
        "note", "probe", "timeout",
    }
)
DEFAULT_TIMEOUT = 3600
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
    if raw_rows is not None and not isinstance(raw_rows, list):
        raise SpecError(
            "spec's 'mutation' must be an array of tables — write [[mutation]], not [mutation]"
        )
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

    if not isinstance(raw, dict):
        raise SpecError(f"{where}: each [[mutation]] must be a table, got {type(raw).__name__}")

    unknown = sorted(set(raw) - TOP_LEVEL_KEYS)
    if unknown:
        raise SpecError(f"{where}: unknown key(s) {unknown}")
    missing = sorted(REQUIRED_KEYS - set(raw))
    if missing:
        raise SpecError(f"{where}: missing required key(s) {missing}")

    # Every string-typed field is type-checked BEFORE it is used — see the
    # module docstring. `lang` and `expect` are first because an unhashable
    # value makes their membership tests raise `TypeError`, not `SpecError`.
    try:
        lang = Lang(_require_str(raw, "lang", where))
    except ValueError:
        raise SpecError(f"{where}: lang must be 'python' or 'rust'") from None

    expect = _require_str(raw, "expect", where)
    if expect not in VALID_EXPECT:
        raise SpecError(f"{where}: expect must be one of {sorted(VALID_EXPECT)}")

    path = _require_str(raw, "path", where)
    _require_path_inside_repo(path, repo_root, where)

    expect_red = raw.get("expect_red", [])
    if not isinstance(expect_red, list) or not all(isinstance(s, str) for s in expect_red):
        raise SpecError(f"{where}: expect_red must be a list of strings")
    if expect_red and expect != "red":
        # `classify` only ever consults `expect_red` when `expect == "red"`
        # (spec §5.5); a non-empty list on a `green` row would be silently
        # inert. An assertion the author believes applies but never runs is
        # worse than a missing one, so this is parse-time, not a runtime
        # no-op.
        raise SpecError(f"{where}: expect_red is meaningless with expect='green'")

    timeout = _validate_timeout(raw.get("timeout", DEFAULT_TIMEOUT), where)

    note = raw.get("note", "")
    if not isinstance(note, str):
        raise SpecError(f"{where}: note must be a string, got {type(note).__name__}")

    return MutationSpec(
        id=_require_str(raw, "id", where),
        lang=lang,
        path=path,
        old=_require_str(raw, "old", where),
        new=_require_str(raw, "new", where),
        gate=_require_str(raw, "gate", where),
        expect=expect,
        probe=_validate_probe(raw["probe"], lang, where),
        expect_red=tuple(expect_red),
        note=note,
        timeout=timeout,
    )


def _require_str(raw: dict, key: str, where: str) -> str:
    """A spec field that must BE a string, never one coerced into one.

    `str()` on a TOML table or array produces a plausible-looking value —
    `{'a': 1}` for `gate`, `[1, 2]` for `new` — that is then executed as a
    shell command or spliced into a source file. Refusing is the only
    fail-closed reading.
    """
    value = raw[key]
    if not isinstance(value, str):
        raise SpecError(f"{where}: {key} must be a string, got {type(value).__name__}")
    return value


def _validate_timeout(raw_timeout: object, where: str) -> int:
    """Seconds before `run_gate` gives up. `bool` is excluded explicitly —
    it is a subclass of `int` in Python, and `timeout = true` would
    otherwise silently parse as `timeout = 1`."""
    if isinstance(raw_timeout, bool) or not isinstance(raw_timeout, int):
        raise SpecError(f"{where}: timeout must be a positive integer (seconds)")
    if raw_timeout <= 0:
        raise SpecError(f"{where}: timeout must be a positive integer (seconds)")
    return raw_timeout


def _require_path_inside_repo(rel: str, repo_root: Path, where: str) -> None:
    """`..` and absolute paths are rejected. The harness mutates tracked
    source files; escaping the repo is never a legitimate spec. `rel` has
    already been through `_require_str`, so the path arithmetic below cannot
    be reached by a non-string."""
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
            module=_require_str(raw, "module", f"{where}: probe"),
            expr=_require_str(raw, "expr", f"{where}: probe"),
            equals=_require_str(raw, "equals", f"{where}: probe"),
            syspath=_require_str(raw, "syspath", f"{where}: probe"),
        )
    return RustProbe(package=_require_str(raw, "package", f"{where}: probe"))
