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
    if expect_red and expect != "red":
        # `classify` only ever consults `expect_red` when `expect == "red"`
        # (spec §5.5); a non-empty list on a `green` row would be silently
        # inert. An assertion the author believes applies but never runs is
        # worse than a missing one, so this is parse-time, not a runtime
        # no-op.
        raise SpecError(f"{where}: expect_red is meaningless with expect='green'")

    timeout = _validate_timeout(raw.get("timeout", DEFAULT_TIMEOUT), where)

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
        timeout=timeout,
    )


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
    source files; escaping the repo is never a legitimate spec."""
    if not isinstance(rel, str):
        raise SpecError(f"{where}: path must be a string, got {type(rel).__name__}")
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
