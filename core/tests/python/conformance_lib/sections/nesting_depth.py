"""Section NDL -- crypto-design §6.2 rule 6: no canonical-CBOR document nests
deeper than 256 (#667).

Before #667 the Rust decoders rejected past 256 (ciborium's recursion limit)
and this verifier did not: a record nested 257-995 deep, or a manifest
257-993, was ACCEPTED here, and past that the recursive scanner raised `RecursionError`,
a harness failure rather than a verdict.  `manifest_body` is token-compared
and replayed in CI, and no corpus input reached either.

SCOPE.  "Every CBOR decoder" in this section's title means every CBOR-document
decoder under `codec/`, the packages that decide acceptance.  A `wire/`
inspector enforces no acceptance set and is out of scope, as Section VT's
check 3 already rules.

Checks, each reporting what it RAN:
  1. BOUNDARY, per CBOR decoder: depth 256 gives the decoder's declared
     outcome EXACTLY (accept, or the card's unknown-key `ValueError` -- so a
     crash is never read as "not refused for depth"); 257 is NestingTooDeep.
  2. A VERDICT AT EVERY DEPTH: 257, 1,000 and 10,000 each raise NestingTooDeep,
     never `RecursionError` or an untokened exception.
  3. TAGS ARE LEVELS: a tag at level 257 is NestingTooDeep, not rule 4; the
     same tag at level 256 is rule 4 (the control).  Run on `_RECORD` and
     `_MANIFEST` by name.  Both go through the iterative `walk_body` since
     #666 (`py_decode_manifest` no longer has a `reject_excessive_nesting`
     pass of its own), so this is no longer two mechanisms proving the same
     thing -- it is one mechanism pinned at both its entry points, so a
     future divergence between them still reds here rather than at neither.
  4. DEPTH OUTRANKS A SHALLOW TAG.  A tag earlier in byte order is only
     REMEMBERED by `walk_body`, so depth still wins over it -- on both
     `_RECORD` and `_MANIFEST`.  Invalid UTF-8 earlier in byte order is a
     well-formedness fault `walk_body` raises AT ONCE, in byte order, exactly
     as its Rust twin does on every decode path -- so depth never gets a
     chance to fire on EITHER decoder, which is why this case runs on both
     (regression pin for #666: before it, `py_decode_manifest` ran a
     content-blind PASS here that could not see the fault, so depth won on
     the manifest and not on the record -- an asymmetry that is gone now).
     `reject_excessive_nesting` is now the first statement of the CARD decoder
     alone -- #666 moved the manifest and the trash entry onto `walk_body` --
     and its `later_phases_scan_in_byte_order` flag is gone with them, so its
     contract is pinned directly in the one direction that survives: a
     structural fault RAISES. (The flag's `True` arm swallowed it; #666 left
     that arm with no production caller and the PR #689 review retired it
     rather than leave a fail-open defended only by this check.) Alongside it,
     the control that `py_decode_manifest` still reports `MalformedCbor` on
     that same truncated body -- via `walk_body` now, not via that pass.  And the
     converse, on the two cbor2-backed decoders: a stray break ahead of a
     deep chain is `MalformedCbor` from the pass itself, since cbor2 accepts
     that break and would parse on (PR #684 review: the encoder, failing on
     cbor2's sentinel, used to answer).
  5. CENSUS, both ways, default-deny: every top-level `py_decode_*` under
     `codec/` is either a CBOR-document decoder in `_DECODERS` or named in
     `_NOT_CBOR_DOCUMENTS` with its reason.  A new decoder nobody classified
     fails -- "has no check to find" is its own search (#669).  A decoder
     listed as not-CBOR whose body names a CBOR entry point (`_CBOR_ENTRY_NAMES`)
     fails too, so moving one there to skip checks 1-2 is not silent.
  6. SEED BINDING: the committed `nesting__` seeds, two-way against
     `expected_nesting_seeds()`, each replayed with the verdict its depth
     states -- accept at or under the limit, `NestingTooDeep` past it.

LIMITS.  The census reads every `*.py` under `codec/`, recursively (`rglob`,
as Section VT's check 3 does, so a module split into a directory stays
visible), skipping `__pycache__`.  In each file it reads only TOP-LEVEL
`def py_decode_*` names: a decoder under another name, or one nested in a
class or function, is invisible to it.  A symlinked subdirectory is not
followed -- `Path.rglob` does not follow symlinked directories, the same gap
#510 records for `scripts/payload_guard`, and nothing tracks it for this
census; `_MIN_DISCOVERED_DECODERS` floors the result.

GUARD AGAINST AN ESCAPING TRACEBACK.  `conformance.py`'s `main()` has no
per-section try/except (#682), so an exception out of a section driver aborts
the run before later sections, REG included, execute.  Two steps here can
fail other than by assertion: `d.base()` reads a fixture off disk, and the
census parses every `codec/` file with `ast.parse`.  Both are guarded PER
CASE, so a failure becomes an ISSUE line naming the step and
`type(exc).__name__: exc`, and the other decoders' and files' results stand.
`section_nesting_depth` wraps its whole body in a last catch-all as well.

PASS LINES REPORT WHAT RAN, NOT WHAT WAS DECLARED.  A line computed as
`declared - len(issues)` lets one guard-triggered ISSUE stand in for several
skipped cases (a skipped decoder reads "7/8" when only 6 of 8 ran).  Each
check counts `executed` and `passed` per case AS IT COMPLETES, and
`_pass_line` names the declared total separately whenever a skip made the two
diverge.  `_census_line` does the same for the census's file-level guard.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from conformance_lib import fixtures
from conformance_lib.codec.card import py_decode_contact_card
from conformance_lib.codec.cbor_faults import MalformedCbor, NestingTooDeep, V1_MAX_NESTING_DEPTH
from conformance_lib.codec.manifest_decode import py_decode_manifest
from conformance_lib.codec.record import py_decode_record
from conformance_lib.codec.scanner import NonCanonicalItem
from conformance_lib.codec.trash_entry import py_decode_trash_entry
from conformance_lib.codec.well_formed import reject_excessive_nesting
from conformance_lib.diff_replay import replay_bytes
from conformance_lib.sections.nesting_depth_bodies import (
    ARRAY_2, BREAK, INVALID_UTF8, TAG_1, TEXT_1, UINT_0, FUTURE_KEY, NESTING_SEED_PREFIX,
    document_nested_to, expected_nesting_seeds, nested_value, with_top_level_entry,
)

_CODEC_DIR = Path(__file__).resolve().parent.parent / "codec"
# The census must see at least this many decoders, or it scanned the wrong
# directory and would pass having read nothing (#669's MIN_SCANNED_CODEC_MODULES lesson).
_MIN_DISCOVERED_DECODERS = 8
# Identifiers only a CBOR-document decoder's own body has cause to name.
_CBOR_ENTRY_NAMES = frozenset({"cbor2", "walk_body", "reject_excessive_nesting", "_scan_item"})
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
    # `_outcome` at exactly depth 256: "accept" where the schema keeps an
    # unknown key, else the class the schema rejects one with (the card).
    at_limit: str


def _seed(target: str, name: str) -> Callable[[], bytes]:
    return lambda: (fixtures.fuzz_seed_dir(target) / name).read_bytes()


def _trash_base() -> bytes:
    import cbor2

    return cbor2.dumps(_TRASH_BASE, canonical=True)


# Named bindings, not tuple positions.  Checks 3 and 4 pin `_RECORD` and
# `_MANIFEST` -- both go through the iterative `walk_body` since #666 -- by
# NAME rather than by position, so selecting them as `_DECODERS[0]`/`[1]`
# would let a reorder, or a decoder inserted ahead of them, retarget both
# checks with nothing going red.
_RECORD = _Decoder(py_decode_record, _seed("record", "login.cbor"), "accept")
_MANIFEST = _Decoder(py_decode_manifest, _seed("manifest_body", "uniq__control__all_distinct.bin"), "accept")
_CONTACT_CARD = _Decoder(py_decode_contact_card, _seed("contact_card", "with_sigs.cbor"), "ValueError")
_TRASH_ENTRY = _Decoder(py_decode_trash_entry, _trash_base, "accept")

_DECODERS: tuple[_Decoder, ...] = (_RECORD, _MANIFEST, _CONTACT_CARD, _TRASH_ENTRY)
_NOT_CBOR_DOCUMENTS: dict[str, str] = {
    "py_decode_bundle_file": "a binary envelope read by offset",
    "py_decode_block_file": "a binary envelope read by offset",
    "py_decode_manifest_file": "a binary envelope read by offset",
    "py_decode_vault_toml": "TOML, not CBOR",
}


@dataclass(frozen=True)
class _CheckResult:
    """What one check (PASS 1-4, 6) actually did.  `executed` and `passed` are
    incremented per case AS IT COMPLETES, never derived from `declared`, so
    one guard-triggered ISSUE line cannot stand in for several skipped cases."""

    issues: list[str]
    executed: int
    passed: int
    declared: int


def _pass_line(number: str, result: _CheckResult, noun: str) -> str:
    """`PASS <number>: <passed>/<executed> <noun>`, naming the declared total
    separately whenever a guard made `executed` fall short of it, so a skip
    is visible in the line itself and not only as an ISSUE."""
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
    rather than a traceback out of the section and does not abort the other
    decoders' checks (see GUARD in the module docstring)."""
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
        if at_limit != d.at_limit:
            issues.append(f"{name} at depth {V1_MAX_NESTING_DEPTH}: {at_limit}, expected {d.at_limit}; rule 6 allows exactly this depth")
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
    declared = 8  # len(cases) + 2, fixed regardless of a guard firing below
    # A two-item array whose SECOND item is the chain: the first item sits
    # earlier in byte order, and the chain takes the document past the limit.
    deep = nested_value(V1_MAX_NESTING_DEPTH)
    # (decoder, label, the shallow first item): a tag is only REMEMBERED by
    # `walk_body`, so depth still wins over a shallow tag earlier in byte
    # order -- on both `_RECORD` and `_MANIFEST`, which have shared this one
    # mechanism since #666 (`py_decode_manifest` adopted `walk_body`; it no
    # longer has a content-blind pass of its own). Invalid UTF-8 earlier in
    # byte order is a well-formedness fault `walk_body` raises AT ONCE, in
    # byte order, exactly as the Rust twin does on every decode path -- so
    # depth never gets a chance to fire on EITHER decoder now, which is why
    # this case is run on both. Before #666 the manifest ran a content-blind
    # PASS here (`reject_excessive_nesting`) that could not see the fault and
    # let depth win; that asymmetry is gone, and this row is its regression
    # pin. `_RECORD`/`_MANIFEST` by NAME -- same reasoning as
    # `_tag_level_issues`.
    # A stray break is a structural fault the pass RAISES for the cbor2-backed
    # decoders, so there the break, earlier in byte order, is what is reported.
    cases = (
        (_RECORD, "a tag", bytes([ARRAY_2, TAG_1, UINT_0]), "too_deep"),
        (_MANIFEST, "a tag", bytes([ARRAY_2, TAG_1, UINT_0]), "too_deep"),
        (_RECORD, "invalid utf-8", bytes([ARRAY_2, TEXT_1, INVALID_UTF8]), MalformedCbor.__name__),
        (_MANIFEST, "invalid utf-8", bytes([ARRAY_2, TEXT_1, INVALID_UTF8]), MalformedCbor.__name__),
        (_CONTACT_CARD, "a stray break", bytes([ARRAY_2, BREAK]), MalformedCbor.__name__),
        (_TRASH_ENTRY, "a stray break", bytes([ARRAY_2, BREAK]), MalformedCbor.__name__),
    )
    for d, label, prefix, want in cases:
        base, err = _base_or_issue(d, "PASS 4 (precedence)")
        if err is not None:
            issues.append(err)
            continue
        got = _outcome(d.decode, with_top_level_entry(base, FUTURE_KEY, prefix + deep))
        executed += 1
        if got != want:
            issues.append(f"{d.decode.__name__}: {label} before excess depth gave {got}, expected {want}")
        else:
            passed += 1
    manifest_base, err = _base_or_issue(_MANIFEST, "PASS 4 (precedence, truncation control)")
    if err is not None:
        issues.append(err)
        return _CheckResult(issues, executed, passed, declared)
    truncated = manifest_base[:-1]
    # `reject_excessive_nesting` RAISES a structural fault, unconditionally.
    # It used to take a `later_phases_scan_in_byte_order` flag and this control
    # drove the `True` arm, which SWALLOWED the fault -- an arm #666 left with
    # no production caller (the manifest and the trash entry moved to
    # `walk_body`; the card, its one remaining caller, passed `False`). The
    # flag is gone, so this control now pins the surviving contract in the
    # direction the card actually depends on (PR #689 review).
    try:
        reject_excessive_nesting(truncated)
    except MalformedCbor:
        executed += 1
        passed += 1
    except Exception as exc:  # noqa: BLE001
        executed += 1
        issues.append(
            f"reject_excessive_nesting raised {type(exc).__name__} on a truncated body, "
            f"expected {MalformedCbor.__name__}"
        )
    else:
        executed += 1
        issues.append(
            "reject_excessive_nesting ACCEPTED a truncated body; it must raise a "
            "structural fault, since its one caller's next phase (cbor2.loads) is "
            "not a byte-order well-formedness check"
        )
    got = _outcome(_MANIFEST.decode, truncated)
    executed += 1
    if got != MalformedCbor.__name__:
        issues.append(f"py_decode_manifest on a truncated body gave {got}, expected {MalformedCbor.__name__}")
    else:
        passed += 1
    if executed != declared:
        # A shortfall used to surface ONLY inside the PASS line's own text, so
        # deleting a case row left the section GREEN printing
        # "7/7 ... of 8 declared" — and the single row pinning #666's Python
        # change is one of those rows (PR #689 review). `_pass_line`'s
        # docstring claimed the shortfall was surfaced "in the line itself and
        # not only as an ISSUE", implying an ISSUE too; there was none.
        issues.append(
            f"PASS 4 executed {executed} of {declared} declared case(s) — a row was "
            f"dropped, or a guard skipped one"
        )
    return _CheckResult(issues, executed, passed, declared)


_DEPTH_IN_NAME = re.compile(rf"^{NESTING_SEED_PREFIX}(?P<depth>\d+)_")


def _seed_issues() -> _CheckResult:
    """Check 6: the committed `nesting__` seeds, two-way against
    `expected_nesting_seeds()`, each replayed with the verdict its depth
    states.  `executed`/`passed` are counted per seed actually replayed; a
    directory listing or file read failure becomes an ISSUE line rather than
    a traceback, and does not stop the other seeds or targets."""
    issues: list[str] = []
    executed = 0
    passed = 0
    expected = expected_nesting_seeds()
    declared = sum(len(names) for names in expected.values())
    if declared == 0:
        issues.append("expected_nesting_seeds() declares no seeds; check 6 would bind nothing")
    for target, want in expected.items():
        directory = fixtures.fuzz_seed_dir(target)
        try:
            on_disk = {p.name for p in directory.iterdir() if p.name.startswith(NESTING_SEED_PREFIX)}
        except OSError as exc:
            issues.append(f"{target}: cannot list nesting seeds: {type(exc).__name__}: {exc}")
            continue
        issues += [f"{target}: committed seed {n} is not expected" for n in sorted(on_disk - want)]
        issues += [f"{target}: expected seed {n} is not committed" for n in sorted(want - on_disk)]
        for name in sorted(on_disk & want):
            try:
                data = (directory / name).read_bytes()
            except OSError as exc:
                issues.append(f"{target}/{name}: cannot read seed: {type(exc).__name__}: {exc}")
                continue
            match = _DEPTH_IN_NAME.match(name)
            if match is None:
                issues.append(f"{target}/{name}: cannot parse a depth from the seed name")
                continue
            executed += 1
            depth = int(match["depth"])
            verdict = replay_bytes(target, data).verdict
            if depth <= V1_MAX_NESTING_DEPTH:
                if verdict.get("status") != "accept":
                    issues.append(f"{target}/{name}: expected accept, got {verdict}")
                else:
                    passed += 1
            elif (verdict.get("status"), verdict.get("error_class"), verdict.get("rule")) != (
                "reject", "NestingTooDeep", "malformed_cbor"
            ):
                issues.append(f"{target}/{name}: expected NestingTooDeep (malformed_cbor), got {verdict}")
            else:
                passed += 1
    return _CheckResult(issues, executed, passed, declared)


def _discovered_decoders() -> tuple[dict[str, set[str]], list[str], int, int]:
    """Top-level `py_decode_*` names in every `codec/**/*.py` outside
    `__pycache__`, plus any per-file read/parse failure as an ISSUE rather
    than a traceback -- one bad file must not blank the whole census.

    Returns `(names, issues, executed_files, declared_files)`, `names` mapping
    each decoder to the `_CBOR_ENTRY_NAMES` its body mentions; `declared_files`
    is every `*.py` the scan found, `executed_files` how many of those were
    actually read and parsed, so a skipped file shows in the PASS line."""
    names: dict[str, set[str]] = {}
    issues: list[str] = []
    paths = sorted(
        p for p in _CODEC_DIR.rglob("*.py")
        if "__pycache__" not in p.relative_to(_CODEC_DIR).parts
    )
    declared_files = len(paths)
    executed_files = 0
    for path in paths:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001 -- guard: report, never propagate
            rel = path.relative_to(_CODEC_DIR)
            issues.append(f"PASS 5 (census): reading codec/{rel} raised {type(exc).__name__}: {exc}")
            continue
        executed_files += 1
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name.startswith("py_decode_"):
                idents = {getattr(n, "id", None) or getattr(n, "attr", None) for n in ast.walk(node)}
                names[node.name] = idents & _CBOR_ENTRY_NAMES
    return names, issues, executed_files, declared_files


@dataclass(frozen=True)
class _CensusResult:
    issues: list[str]
    found: int
    # Unclassified plus classified-but-gone decoders; None when the floor
    # failed and the classification was never compared.
    misclassified: int | None
    executed_files: int
    declared_files: int


def _census_issues() -> _CensusResult:
    found, issues, executed_files, declared_files = _discovered_decoders()
    if len(found) < _MIN_DISCOVERED_DECODERS:
        issues = issues + [f"census found {len(found)} decoders under {_CODEC_DIR}, floor is {_MIN_DISCOVERED_DECODERS}"]
        return _CensusResult(issues, len(found), None, executed_files, declared_files)
    classified = {d.decode.__name__ for d in _DECODERS} | set(_NOT_CBOR_DOCUMENTS)
    wrong = [f"codec decoder {n} is unclassified: add it to _DECODERS or _NOT_CBOR_DOCUMENTS" for n in sorted(found.keys() - classified)]
    wrong += [f"classified decoder {n} no longer exists under codec/" for n in sorted(classified - found.keys())]
    wrong += [
        f"{n} is listed as not a CBOR document but names {sorted(found[n])}"
        for n in sorted(set(_NOT_CBOR_DOCUMENTS) & found.keys()) if found[n]
    ]
    return _CensusResult(issues + wrong, len(found), len(wrong), executed_files, declared_files)


def _census_line(result: _CensusResult) -> str:
    """`_pass_line`'s "reveal a skip in the line itself" rule, for the census:
    the classification count covers only unclassified or missing decoders,
    and a file the scan could not read, or a floor that stopped the
    classification, is named in the line rather than folded into that count."""
    if result.misclassified is None:
        base = f"PASS 5: {result.found} codec decoders censused, below the floor of {_MIN_DISCOVERED_DECODERS}, not classified"
    else:
        base = f"PASS 5: {result.found} codec decoders censused, {result.misclassified} unclassified or missing"
    if result.executed_files == result.declared_files:
        return base
    return f"{base} ({result.executed_files}/{result.declared_files} codec/ files read)"


def _run_checks() -> tuple[bool, list[str]]:
    boundary = _boundary_issues()
    every = _every_depth_issues()
    tags = _tag_level_issues()
    order = _precedence_issues()
    census = _census_issues()
    seeds = _seed_issues()
    issues = boundary.issues + every.issues + tags.issues + order.issues + census.issues + seeds.issues
    lines = [
        _pass_line("1", boundary, f"boundary cases across {len(_DECODERS)} CBOR decoders"),
        _pass_line("2", every, f"deep bodies refused with a verdict (depths {', '.join(map(str, _DEEP_DEPTHS))})"),
        _pass_line("3", tags, "tag-level cases"),
        _pass_line("4", order, "precedence and pass-silence cases"),
        _census_line(census),
        _pass_line("6", seeds, "committed nesting seeds replay with the verdict their depth states"),
    ]
    lines.extend(f"  ISSUE: {issue}" for issue in issues)
    return (not issues, lines)


def section_nesting_depth() -> tuple[bool, list[str]]:
    """Entry point the registry calls.  Wrapped in one last catch-all so that
    even a failure none of the per-case guards above anticipated still
    reports as a failing section rather than aborting `main()` before later
    sections -- including Section REG -- ever run (#682)."""
    try:
        return _run_checks()
    except Exception as exc:  # noqa: BLE001 -- guard: report, never propagate
        return False, [f"  ISSUE: section_nesting_depth raised {type(exc).__name__}: {exc}"]
