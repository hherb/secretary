"""Section NDL -- crypto-design §6.2 rule 6: no canonical-CBOR document nests
deeper than 256 (#667).

Before #667 the Rust decoders rejected past 256 (ciborium's recursion limit)
and this verifier did not: a record or manifest nested 257-993 deep was
ACCEPTED here, and past ~995 the recursive scanner raised `RecursionError`,
a harness failure rather than a verdict.  `manifest_body` is token-compared
and replayed in CI, and no corpus input reached either.

Checks, each reporting what it RAN:
  1. BOUNDARY, per CBOR decoder: depth 256 is not refused for depth (the
     decoders with an unknown bag accept it); depth 257 raises NestingTooDeep.
  2. A VERDICT AT EVERY DEPTH: 257, 1,000 and 10,000 each raise NestingTooDeep,
     never `RecursionError` or an untokened exception.
  3. TAGS ARE LEVELS: a tag at level 257 is NestingTooDeep, not rule 4; the
     same tag at level 256 is rule 4 (the control).  Run on `_RECORD`
     (Task 4's `walk_body`) and `_MANIFEST` (`reject_excessive_nesting`) --
     the two decoders with different mechanisms -- named explicitly rather
     than picked by `_DECODERS` position (review finding, fix round 1).
  4. DEPTH OUTRANKS A SHALLOW TAG, and the depth pass is content-blind.  A tag
     earlier in byte order is only REMEMBERED by both mechanisms, so depth
     wins on the record (walk) and the manifest (pass).  Invalid UTF-8 earlier
     in byte order is a well-formedness fault the record WALK raises at once,
     in byte order, exactly as its Rust twin does, so that case runs on the
     manifest's content-blind pass only, which must still report the depth.
     The control for the pass's silence: a truncated body with no depth
     problem makes `reject_excessive_nesting` return, and the decoder reports
     what it always did.  Same `_RECORD`/`_MANIFEST` naming as check 3.
  5. CENSUS, both ways, default-deny: every top-level `py_decode_*` under
     `codec/` is either a CBOR-document decoder in `_DECODERS` or named in
     `_NOT_CBOR_DOCUMENTS` with its reason.  A new decoder nobody classified
     fails -- "has no check to find" is its own search (#669).

LIMITS.  The census reads top-level `def py_decode_*` names in `codec/*.py`
and nothing else: a decoder under another name, or one nested in a class, is
invisible to it.  The depth pass protects the decoders that call it; a
`wire/` inspector enforces no acceptance set and is out of scope, as Section
VT's check 3 already rules.

GUARD AGAINST AN ESCAPING TRACEBACK (controller ruling on #667's Task 5).
`conformance.py`'s `main()` iterates the section table with no per-section
try/except, so an exception raised out of a section driver aborts the whole
run before later sections (including Section REG) ever execute -- exactly
the class of gap the #669 review found in a sibling section.  Two things a
fixture-driven check like this one can hit that are not a plain assertion
failure: `d.base()` reads a fixture off disk (missing file, truncated
seed), and the census's `_discovered_decoders()` parses every `codec/*.py`
file with `ast.parse` (unreadable file, a syntax a future Python version
no longer parses).  Both are guarded PER CASE, so one decoder's or one
file's failure becomes an ISSUE line naming the step and
`type(exc).__name__: exc` rather than a traceback, and does not discard the
other decoders' or files' results.  `section_nesting_depth` additionally
wraps its own body in one last catch-all, so that even a failure this
module's author did not anticipate still returns `(False, [...])` rather
than propagating -- the same "any unexpected exception maps to its class
name" posture `_outcome` already takes for a decoder call.

PASS LINES REPORT WHAT RAN, NOT WHAT WAS DECLARED (review finding, fix
round 1).  The first version of this section computed each PASS line as
`declared_total - len(issues)`, so when a guard above skipped several cases
in one decoder, ONE issue line stood in for all of them and the count read
as if only that one case had failed -- e.g. "PASS 1: 7/8" when a skipped
decoder actually meant only 6 of the 8 declared boundary checks ran at all.
Each of `_boundary_issues` / `_every_depth_issues` / `_tag_level_issues` /
`_precedence_issues` now increments `executed` and `passed` per case AS IT
COMPLETES, and `_pass_line` reports `passed/executed`, naming the declared
total separately (`... executed of N declared`) whenever a skip made the two
diverge; when nothing was skipped it reads exactly as before.  `_census_line`
does the same for the file-level guard in `_discovered_decoders`.
"""

from __future__ import annotations

import ast
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from conformance_lib import fixtures
from conformance_lib.codec.card import py_decode_contact_card
from conformance_lib.codec.cbor_faults import NestingTooDeep, V1_MAX_NESTING_DEPTH
from conformance_lib.codec.manifest_decode import py_decode_manifest
from conformance_lib.codec.record import py_decode_record
from conformance_lib.codec.scanner import NonCanonicalItem
from conformance_lib.codec.trash_entry import py_decode_trash_entry
from conformance_lib.codec.well_formed import reject_excessive_nesting
from conformance_lib.sections.nesting_depth_bodies import (
    ARRAY_2, INVALID_UTF8, TAG_1, TEXT_1, UINT_0, FUTURE_KEY,
    document_nested_to, nested_value, with_top_level_entry,
)

_CODEC_DIR = Path(__file__).resolve().parent.parent / "codec"
# The census must see at least this many decoders, or it scanned the wrong
# directory and would pass having read nothing (#669's MIN_SCANNED_CODEC_MODULES lesson).
_MIN_DISCOVERED_DECODERS = 8
_DEEP_DEPTHS = (V1_MAX_NESTING_DEPTH + 1, 1_000, 10_000)
# The trash-entry base Section VT's check 2b uses: every key valid.
_TRASH_BASE = {
    "block_uuid": bytes(16),
    "tombstoned_at_ms": 5,
    "tombstoned_by": bytes(16),
    "fingerprint": bytes(32),
    "purged_at_ms": 7,
}


@dataclass(frozen=True)
class _Decoder:
    decode: Callable[[bytes], object]
    base: Callable[[], bytes]
    # True when the schema keeps an unknown key, so a depth-256 body is ACCEPTED;
    # False when it rejects one for its schema (the contact card).
    keeps_unknown_keys: bool


def _seed(target: str, name: str) -> Callable[[], bytes]:
    return lambda: (fixtures.fuzz_seed_dir(target) / name).read_bytes()


def _trash_base() -> bytes:
    import cbor2

    return cbor2.dumps(_TRASH_BASE, canonical=True)


# Named module-level bindings, not tuple positions (review finding, fix
# round 1).  Checks 3 and 4 exist specifically to cover TWO DIFFERENT
# nesting-depth mechanisms -- `_RECORD` goes through Task 4's recursive
# `walk_body`, `_MANIFEST` through the content-blind `reject_excessive_nesting`
# pass -- and picking them as `_DECODERS[0]`/`_DECODERS[1]` (or `[:2]`) meant a
# reorder, or inserting a fifth decoder ahead of these two, would silently
# retarget both checks onto the wrong mechanism with nothing going red.
_RECORD = _Decoder(py_decode_record, _seed("record", "login.cbor"), True)
_MANIFEST = _Decoder(py_decode_manifest, _seed("manifest_body", "uniq__control__all_distinct.bin"), True)
_CONTACT_CARD = _Decoder(py_decode_contact_card, _seed("contact_card", "with_sigs.cbor"), False)
_TRASH_ENTRY = _Decoder(py_decode_trash_entry, _trash_base, True)

_DECODERS: tuple[_Decoder, ...] = (_RECORD, _MANIFEST, _CONTACT_CARD, _TRASH_ENTRY)
_NOT_CBOR_DOCUMENTS: dict[str, str] = {
    "py_decode_bundle_file": "a binary envelope read by offset",
    "py_decode_block_file": "a binary envelope read by offset",
    "py_decode_manifest_file": "a binary envelope read by offset",
    "py_decode_vault_toml": "TOML, not CBOR",
}


@dataclass(frozen=True)
class _CheckResult:
    """What one check (PASS 1-4) actually did.  `executed` and `passed` are
    incremented per case AS IT COMPLETES, never derived from `declared` --
    that derivation is what let a single guard-triggered ISSUE line stand in
    for several silently-skipped cases (review finding, fix round 1)."""

    issues: list[str]
    executed: int
    passed: int
    declared: int


def _pass_line(number: str, result: _CheckResult, noun: str) -> str:
    """`PASS <number>: <passed>/<executed> <noun>`, naming the declared total
    separately whenever a guard made `executed` fall short of it, so a skip
    is visible in the line itself and not only as an ISSUE (review finding)."""
    if result.executed == result.declared:
        return f"PASS {number}: {result.passed}/{result.executed} {noun}"
    return f"PASS {number}: {result.passed}/{result.executed} {noun} executed of {result.declared} declared"


def _outcome(decode: Callable[[bytes], object], body: bytes) -> str:
    """'accept', 'too_deep', 'rule4', or the exception class name."""
    try:
        decode(body)
    except NestingTooDeep:
        return "too_deep"
    except NonCanonicalItem as exc:
        return "rule4" if exc.rule == 4 else type(exc).__name__
    except Exception as exc:  # noqa: BLE001 -- the class name IS the finding
        return type(exc).__name__
    return "accept"


def _base_or_issue(d: _Decoder, step: str) -> tuple[bytes | None, str | None]:
    """Load `d`'s fixture, catching any failure so it becomes an ISSUE line
    rather than a traceback out of the section (controller ruling).  Reading
    a fixture is the one thing in this section that touches the filesystem
    outside `_discovered_decoders`, and it must not abort the other
    decoders' checks."""
    try:
        return d.base(), None
    except Exception as exc:  # noqa: BLE001 -- guard: report, never propagate
        return None, f"{step}: {d.decode.__name__} base() raised {type(exc).__name__}: {exc}"


def _boundary_issues() -> _CheckResult:
    issues: list[str] = []
    executed = 0
    passed = 0
    declared = 2 * len(_DECODERS)
    for d in _DECODERS:
        name = d.decode.__name__
        base, err = _base_or_issue(d, "PASS 1 (boundary)")
        if err is not None:
            issues.append(err)
            continue
        at_limit = _outcome(d.decode, document_nested_to(base, V1_MAX_NESTING_DEPTH))
        executed += 1
        if at_limit == "too_deep" or (d.keeps_unknown_keys and at_limit != "accept"):
            issues.append(f"{name} at depth {V1_MAX_NESTING_DEPTH}: {at_limit}; rule 6 allows exactly this depth")
        else:
            passed += 1
        past = _outcome(d.decode, document_nested_to(base, V1_MAX_NESTING_DEPTH + 1))
        executed += 1
        if past != "too_deep":
            issues.append(f"{name} at depth {V1_MAX_NESTING_DEPTH + 1}: {past}, expected NestingTooDeep")
        else:
            passed += 1
    return _CheckResult(issues, executed, passed, declared)


def _every_depth_issues() -> _CheckResult:
    issues: list[str] = []
    executed = 0
    passed = 0
    declared = len(_DECODERS) * len(_DEEP_DEPTHS)
    for d in _DECODERS:
        base, err = _base_or_issue(d, "PASS 2 (every depth)")
        if err is not None:
            issues.append(err)
            continue
        for depth in _DEEP_DEPTHS:
            got = _outcome(d.decode, document_nested_to(base, depth))
            executed += 1
            if got != "too_deep":
                issues.append(f"{d.decode.__name__} at depth {depth}: {got}, expected NestingTooDeep")
            else:
                passed += 1
    return _CheckResult(issues, executed, passed, declared)


def _tag_level_issues() -> _CheckResult:
    """A tag as the last level: 257 is depth, 256 is rule 4.  Run on
    `_RECORD` (the walk) and `_MANIFEST` (the pass) BY NAME -- see the
    module-level comment beside their declaration."""
    issues: list[str] = []
    executed = 0
    passed = 0
    declared = 4
    for d in (_RECORD, _MANIFEST):
        base, err = _base_or_issue(d, "PASS 3 (tag level)")
        if err is not None:
            issues.append(err)
            continue
        for level, want in ((V1_MAX_NESTING_DEPTH + 1, "too_deep"), (V1_MAX_NESTING_DEPTH, "rule4")):
            # Root map is level 1, `level - 2` arrays, then the tag at `level`.
            value = nested_value(level - 2, innermost=bytes([TAG_1, UINT_0]))
            got = _outcome(d.decode, with_top_level_entry(base, FUTURE_KEY, value))
            executed += 1
            if got != want:
                issues.append(f"{d.decode.__name__}: a tag at level {level} gave {got}, expected {want}")
            else:
                passed += 1
    return _CheckResult(issues, executed, passed, declared)


def _precedence_issues() -> _CheckResult:
    issues: list[str] = []
    executed = 0
    passed = 0
    declared = 5  # len(cases) + 2, fixed regardless of a guard firing below
    # A two-item array whose SECOND item is the chain: the first item sits
    # earlier in byte order, and the chain takes the document past the limit.
    deep = nested_value(V1_MAX_NESTING_DEPTH)
    # (decoder, label, the shallow first item): a tag is only remembered, by
    # the walk AND the pass; invalid UTF-8 is raised at once by the record walk
    # (in byte order, as its Rust twin does), so it runs on the pass only.
    # `_RECORD`/`_MANIFEST` by NAME -- same reasoning as `_tag_level_issues`.
    cases = (
        (_RECORD, "a tag", bytes([ARRAY_2, TAG_1, UINT_0])),
        (_MANIFEST, "a tag", bytes([ARRAY_2, TAG_1, UINT_0])),
        (_MANIFEST, "invalid utf-8", bytes([ARRAY_2, TEXT_1, INVALID_UTF8])),
    )
    for d, label, prefix in cases:
        base, err = _base_or_issue(d, "PASS 4 (precedence)")
        if err is not None:
            issues.append(err)
            continue
        got = _outcome(d.decode, with_top_level_entry(base, FUTURE_KEY, prefix + deep))
        executed += 1
        if got != "too_deep":
            issues.append(f"{d.decode.__name__}: {label} before excess depth gave {got}, expected NestingTooDeep")
        else:
            passed += 1
    manifest_base, err = _base_or_issue(_MANIFEST, "PASS 4 (precedence, truncation control)")
    if err is not None:
        issues.append(err)
        return _CheckResult(issues, executed, passed, declared)
    truncated = manifest_base[:-1]
    try:
        reject_excessive_nesting(truncated)
    except Exception as exc:  # noqa: BLE001 -- any raise breaks the pass's silence
        executed += 1
        issues.append(f"reject_excessive_nesting raised {type(exc).__name__} on a truncated body with no depth fault")
    else:
        executed += 1
        passed += 1
    got = _outcome(_MANIFEST.decode, truncated)
    executed += 1
    if got in ("too_deep", "accept"):
        issues.append(f"py_decode_manifest on a truncated body gave {got}; the decoder must report the truncation")
    else:
        passed += 1
    return _CheckResult(issues, executed, passed, declared)


def _discovered_decoders() -> tuple[set[str], list[str], int, int]:
    """Top-level `py_decode_*` names under `codec/*.py`, plus any per-file
    read/parse failure as an ISSUE rather than a traceback (controller
    ruling) -- one bad file must not blank the whole census.

    Returns `(names, issues, executed_files, declared_files)`: `declared_files`
    is every `*.py` the glob found, `executed_files` how many of those were
    actually read and parsed (review finding -- the census count must reveal
    a skipped file too, not only the decoder-classification issues)."""
    names: set[str] = set()
    issues: list[str] = []
    paths = sorted(_CODEC_DIR.glob("*.py"))
    declared_files = len(paths)
    executed_files = 0
    for path in paths:
        try:
            tree = ast.parse(path.read_text())
        except Exception as exc:  # noqa: BLE001 -- guard: report, never propagate
            issues.append(f"PASS 5 (census): reading {path.name} raised {type(exc).__name__}: {exc}")
            continue
        executed_files += 1
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name.startswith("py_decode_"):
                names.add(node.name)
    return names, issues, executed_files, declared_files


@dataclass(frozen=True)
class _CensusResult:
    issues: list[str]
    found: int
    executed_files: int
    declared_files: int


def _census_issues() -> _CensusResult:
    found, issues, executed_files, declared_files = _discovered_decoders()
    if len(found) < _MIN_DISCOVERED_DECODERS:
        issues = issues + [f"census found {len(found)} decoders under {_CODEC_DIR}, floor is {_MIN_DISCOVERED_DECODERS}"]
        return _CensusResult(issues, len(found), executed_files, declared_files)
    classified = {d.decode.__name__ for d in _DECODERS} | set(_NOT_CBOR_DOCUMENTS)
    issues = issues + [f"codec decoder {n} is unclassified: add it to _DECODERS or _NOT_CBOR_DOCUMENTS" for n in sorted(found - classified)]
    issues = issues + [f"classified decoder {n} no longer exists under codec/" for n in sorted(classified - found)]
    return _CensusResult(issues, len(found), executed_files, declared_files)


def _census_line(result: _CensusResult) -> str:
    """Mirrors `_pass_line`'s "reveal a skip in the line itself" rule for the
    census's file-level guard (review finding): unchanged wording when every
    discovered file was read, an appended file-coverage fragment when one
    was not."""
    base = f"PASS 5: {result.found} codec decoders censused, {len(result.issues)} unclassified or missing"
    if result.executed_files == result.declared_files:
        return base
    return f"{base} ({result.executed_files}/{result.declared_files} codec/ files read)"


def _run_checks() -> tuple[bool, list[str]]:
    boundary = _boundary_issues()
    every = _every_depth_issues()
    tags = _tag_level_issues()
    order = _precedence_issues()
    census = _census_issues()
    issues = boundary.issues + every.issues + tags.issues + order.issues + census.issues
    lines = [
        _pass_line("1", boundary, f"boundary cases across {len(_DECODERS)} CBOR decoders"),
        _pass_line("2", every, f"deep bodies refused with a verdict (depths {', '.join(map(str, _DEEP_DEPTHS))})"),
        _pass_line("3", tags, "tag-level cases"),
        _pass_line("4", order, "precedence and pass-silence cases"),
        _census_line(census),
    ]
    lines.extend(f"  ISSUE: {issue}" for issue in issues)
    return (not issues, lines)


def section_nesting_depth() -> tuple[bool, list[str]]:
    """Entry point the registry calls.  Wrapped in one last catch-all so that
    even a failure none of the per-case guards above anticipated still
    reports as a failing section rather than aborting `main()` before later
    sections -- including Section REG -- ever run (controller ruling)."""
    try:
        return _run_checks()
    except Exception as exc:  # noqa: BLE001 -- guard: report, never propagate
        return False, [f"PASS: section_nesting_depth raised {type(exc).__name__}: {exc}"]
