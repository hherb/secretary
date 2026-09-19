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
     same tag at level 256 is rule 4 (the control).
  4. DEPTH OUTRANKS A SHALLOW TAG, and the depth pass is content-blind.  A tag
     earlier in byte order is only REMEMBERED by both mechanisms, so depth
     wins on the record (walk) and the manifest (pass).  Invalid UTF-8 earlier
     in byte order is a well-formedness fault the record WALK raises at once,
     in byte order, exactly as its Rust twin does, so that case runs on the
     manifest's content-blind pass only, which must still report the depth.
     The control for the pass's silence: a truncated body with no depth
     problem makes `reject_excessive_nesting` return, and the decoder reports
     what it always did.
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


_DECODERS: tuple[_Decoder, ...] = (
    _Decoder(py_decode_record, _seed("record", "login.cbor"), True),
    _Decoder(py_decode_manifest, _seed("manifest_body", "uniq__control__all_distinct.bin"), True),
    _Decoder(py_decode_contact_card, _seed("contact_card", "with_sigs.cbor"), False),
    _Decoder(py_decode_trash_entry, _trash_base, True),
)
_NOT_CBOR_DOCUMENTS: dict[str, str] = {
    "py_decode_bundle_file": "a binary envelope read by offset",
    "py_decode_block_file": "a binary envelope read by offset",
    "py_decode_manifest_file": "a binary envelope read by offset",
    "py_decode_vault_toml": "TOML, not CBOR",
}


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


def _boundary_issues() -> tuple[list[str], int]:
    issues = []
    for d in _DECODERS:
        name = d.decode.__name__
        base, err = _base_or_issue(d, "PASS 1 (boundary)")
        if err is not None:
            issues.append(err)
            continue
        at_limit = _outcome(d.decode, document_nested_to(base, V1_MAX_NESTING_DEPTH))
        if at_limit == "too_deep" or (d.keeps_unknown_keys and at_limit != "accept"):
            issues.append(f"{name} at depth {V1_MAX_NESTING_DEPTH}: {at_limit}; rule 6 allows exactly this depth")
        past = _outcome(d.decode, document_nested_to(base, V1_MAX_NESTING_DEPTH + 1))
        if past != "too_deep":
            issues.append(f"{name} at depth {V1_MAX_NESTING_DEPTH + 1}: {past}, expected NestingTooDeep")
    return issues, 2 * len(_DECODERS)


def _every_depth_issues() -> tuple[list[str], int]:
    issues = []
    for d in _DECODERS:
        base, err = _base_or_issue(d, "PASS 2 (every depth)")
        if err is not None:
            issues.append(err)
            continue
        for depth in _DEEP_DEPTHS:
            got = _outcome(d.decode, document_nested_to(base, depth))
            if got != "too_deep":
                issues.append(f"{d.decode.__name__} at depth {depth}: {got}, expected NestingTooDeep")
    return issues, len(_DECODERS) * len(_DEEP_DEPTHS)


def _tag_level_issues() -> tuple[list[str], int]:
    """A tag as the last level: 257 is depth, 256 is rule 4.  Run on the two
    decoders with different mechanisms: the record walk and the manifest pass."""
    issues = []
    for d in _DECODERS[:2]:
        base, err = _base_or_issue(d, "PASS 3 (tag level)")
        if err is not None:
            issues.append(err)
            continue
        for level, want in ((V1_MAX_NESTING_DEPTH + 1, "too_deep"), (V1_MAX_NESTING_DEPTH, "rule4")):
            # Root map is level 1, `level - 2` arrays, then the tag at `level`.
            value = nested_value(level - 2, innermost=bytes([TAG_1, UINT_0]))
            got = _outcome(d.decode, with_top_level_entry(base, FUTURE_KEY, value))
            if got != want:
                issues.append(f"{d.decode.__name__}: a tag at level {level} gave {got}, expected {want}")
    return issues, 4


def _precedence_issues() -> tuple[list[str], int]:
    issues = []
    # A two-item array whose SECOND item is the chain: the first item sits
    # earlier in byte order, and the chain takes the document past the limit.
    deep = nested_value(V1_MAX_NESTING_DEPTH)
    record, manifest = _DECODERS[0], _DECODERS[1]
    budget = 5  # len(cases) + 2, fixed regardless of a guard firing below
    # (decoder, label, the shallow first item): a tag is only remembered, by
    # the walk AND the pass; invalid UTF-8 is raised at once by the record walk
    # (in byte order, as its Rust twin does), so it runs on the pass only.
    cases = (
        (record, "a tag", bytes([ARRAY_2, TAG_1, UINT_0])),
        (manifest, "a tag", bytes([ARRAY_2, TAG_1, UINT_0])),
        (manifest, "invalid utf-8", bytes([ARRAY_2, TEXT_1, INVALID_UTF8])),
    )
    for d, label, prefix in cases:
        base, err = _base_or_issue(d, "PASS 4 (precedence)")
        if err is not None:
            issues.append(err)
            continue
        got = _outcome(d.decode, with_top_level_entry(base, FUTURE_KEY, prefix + deep))
        if got != "too_deep":
            issues.append(f"{d.decode.__name__}: {label} before excess depth gave {got}, expected NestingTooDeep")
    manifest_base, err = _base_or_issue(manifest, "PASS 4 (precedence, truncation control)")
    if err is not None:
        issues.append(err)
        return issues, budget
    truncated = manifest_base[:-1]
    try:
        reject_excessive_nesting(truncated)
    except Exception as exc:  # noqa: BLE001 -- any raise breaks the pass's silence
        issues.append(f"reject_excessive_nesting raised {type(exc).__name__} on a truncated body with no depth fault")
    got = _outcome(manifest.decode, truncated)
    if got in ("too_deep", "accept"):
        issues.append(f"py_decode_manifest on a truncated body gave {got}; the decoder must report the truncation")
    return issues, budget


def _discovered_decoders() -> tuple[set[str], list[str]]:
    """Top-level `py_decode_*` names under `codec/*.py`, plus any per-file
    read/parse failure as an ISSUE rather than a traceback (controller
    ruling) -- one bad file must not blank the whole census."""
    names: set[str] = set()
    issues: list[str] = []
    for path in sorted(_CODEC_DIR.glob("*.py")):
        try:
            tree = ast.parse(path.read_text())
        except Exception as exc:  # noqa: BLE001 -- guard: report, never propagate
            issues.append(f"PASS 5 (census): reading {path.name} raised {type(exc).__name__}: {exc}")
            continue
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name.startswith("py_decode_"):
                names.add(node.name)
    return names, issues


def _census_issues() -> tuple[list[str], int]:
    found, issues = _discovered_decoders()
    if len(found) < _MIN_DISCOVERED_DECODERS:
        issues.append(f"census found {len(found)} decoders under {_CODEC_DIR}, floor is {_MIN_DISCOVERED_DECODERS}")
        return issues, 0
    classified = {d.decode.__name__ for d in _DECODERS} | set(_NOT_CBOR_DOCUMENTS)
    issues += [f"codec decoder {n} is unclassified: add it to _DECODERS or _NOT_CBOR_DOCUMENTS" for n in sorted(found - classified)]
    issues += [f"classified decoder {n} no longer exists under codec/" for n in sorted(classified - found)]
    return issues, len(found)


def _run_checks() -> tuple[bool, list[str]]:
    boundary, n1 = _boundary_issues()
    every, n2 = _every_depth_issues()
    tags, n3 = _tag_level_issues()
    order, n4 = _precedence_issues()
    census, n5 = _census_issues()
    issues = boundary + every + tags + order + census
    lines = [
        f"PASS 1: {n1 - len(boundary)}/{n1} boundary cases across {len(_DECODERS)} CBOR decoders",
        f"PASS 2: {n2 - len(every)}/{n2} deep bodies refused with a verdict (depths {', '.join(map(str, _DEEP_DEPTHS))})",
        f"PASS 3: {n3 - len(tags)}/{n3} tag-level cases",
        f"PASS 4: {n4 - len(order)}/{n4} precedence and pass-silence cases",
        f"PASS 5: {n5} codec decoders censused, {len(census)} unclassified or missing",
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
