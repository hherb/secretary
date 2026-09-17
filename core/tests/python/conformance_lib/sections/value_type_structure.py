"""Section VT's STRUCTURAL half -- the rules that stop either of #669's two
mechanisms recurring silently.

Split out of `value_type_discipline.py` so each rule and its LIMITS block sit
in one file and cannot drift from a summary written elsewhere -- the treatment
the #605 review gave `required_key_structure.py`, and for the same reason.

TWO MECHANISMS, TWO RULES, and the second is not a generalisation of the
first:

  check 3  M1 -- `isinstance(..., int)` may be written under `codec/` only
           inside `integer_rules.py`. Python's `bool` subclasses `int`, so a
           bare `isinstance` accepts a boolean that every Rust `take_u*`
           rejects. Default-deny.

  check 4  M2 -- every OPTIONAL key of every `codec/` schema map must have a
           wrong-type behavioural case. A key with no check at all is
           invisible to check 3, which is exactly how `trash[].fingerprint`
           and `trash[].purged_at_ms` went unvalidated on a token-compared
           target. Two-way census.

  check 4b the companion to check 4 for decoders that check in WIRE order
           rather than schema order: their dispatch must be TOTAL.

=============================================================================
LIMITS -- what these rules do NOT cover
=============================================================================

Read this before describing any of them as "the structural rule for #669";
claiming more coverage than the code delivers is this repository's
most-repeated review finding.

CHECK 3 READS TEXT.
  `isinstance` is matched by SPELLING, through the AST but without resolving
  names. `from builtins import isinstance as _ii` then `_ii(x, int)` evades
  it entirely, as does any metaprogrammed call, and `int` is whatever a
  module binds to that identifier. It scans `codec/` recursively and nowhere
  else -- `wire/` is deliberately outside its scope, because `wire/` parses
  to INSPECT the committed golden vault and enforces no acceptance set, so
  there is no Rust counterpart for it to diverge from. (`wire/vault_toml.py`
  carries the same defect and is fixed, just not policed here.)

CHECK 4 DOES NOT READ TEXT AT ALL, so it has none of those limits: it is a
set comparison over AST-evaluated literal constants plus behavioural cases.
Its limits are different and narrower:

  - IT GOVERNS OPTIONAL KEYS ONLY. A REQUIRED key losing its type check is a
    real defect this rule does not see. No measurement has observed one --
    the 439-body wrong-type sweep found zero -- and #678 tracks the
    table-driven change that would cover it, deferred because the obvious
    implementation introduces a cross-language divergence of its own (it
    would flatten the interleaved type/sentinel checks that
    `_validate_manifest_shape` and Rust's `parse_manifest_map` BOTH perform,
    changing which fault a two-fault body reports on a token-compared
    target). Do not describe check 4 as covering "every key".

  - IT GOVERNS ONLY KEY SETS IT CAN DISCOVER, and discovery is by name shape
    (`KNOWN` / `REQUIRED`). A key set built dynamically, or named outside
    that shape, is not mis-reported -- it is simply not covered. The
    pairing census below is what stops a NEWLY ADDED set being skipped
    silently.

  - IT SAYS NOTHING ABOUT WHETHER A CASE ASSERTS THE RIGHT THING. That is
    what check 2's per-case ambiguity control and the committed seeds are
    for.

CHECK 4b IS BEHAVIOURAL, so an aliased or restructured dispatch cannot evade
it -- but it proves only that the dispatch has an ARM for each declared key,
never that the arm checks the right property.

WHY THE PAIRING IS DECLARED RATHER THAN INFERRED.
  The five files use FIVE different naming conventions --
  `*_KNOWN_KEYS`/`*_REQUIRED_KEYS`, `KNOWN_CARD_KEYS`/`REQUIRED_CARD_FIELDS`,
  `RECORD_FIELD_KNOWN_KEYS`/`REQUIRED_FIELD_KEYS`, `KNOWN_KEYS`/`REQUIRED`,
  and `KNOWN_KDF_KEYS`, which had no required set at all until #669 added
  one. A stem heuristic was prototyped and mis-paired SIX of the ten sets,
  which is why `KEY_SET_PAIRS` is written out and censused rather than
  derived.
"""

from __future__ import annotations

import ast
from pathlib import Path

CODEC_ROOT = Path(__file__).resolve().parents[1] / "codec"

#: The one module permitted to write `isinstance(..., int)`.
SANCTIONED_INTEGER_MODULE = "integer_rules.py"


def _names_int(node: ast.expr) -> bool:
    """True if `node` is the `int` classinfo argument of an `isinstance` call,
    directly or as a member of a tuple of types."""
    if isinstance(node, ast.Name) and node.id == "int":
        return True
    if isinstance(node, ast.Tuple):
        return any(_names_int(element) for element in node.elts)
    return False


def sanctioned_module_issues() -> list[str]:
    """Check 3 -- `isinstance(..., int)` is confined to `integer_rules.py`.

    Default-deny: any call anywhere else under `codec/` is an issue, whatever
    guard happens to sit beside it. A correct hand-written
    `isinstance(value, bool) or not isinstance(value, int)` is still denied,
    deliberately -- #669 was FOUR copies of that sentence of which two were
    right, so "this copy is correct" is not the property worth enforcing.
    """
    issues: list[str] = []
    for path in sorted(CODEC_ROOT.rglob("*.py")):
        if path.name == SANCTIONED_INTEGER_MODULE:
            continue
        try:
            tree = ast.parse(path.read_text())
        except (OSError, SyntaxError) as exc:
            # Fail closed: a file that cannot be parsed has not been scanned.
            issues.append(f"{path.name}: cannot be scanned: {type(exc).__name__}: {exc}")
            continue
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "isinstance"
                and len(node.args) == 2
                and _names_int(node.args[1])
            ):
                issues.append(
                    f"{path.name}:{node.lineno} tests `isinstance(..., int)` directly; "
                    f"call `integer_rules.is_integer` instead -- a bare isinstance "
                    f"accepts a bool, which is what #669 was"
                )
    return issues


def scanned_module_count() -> int:
    """How many `codec/` modules check 3 actually read.

    Reported in the section's PASS line: a rule that silently scanned nothing
    would otherwise be indistinguishable from a rule that found nothing.
    """
    return sum(1 for p in CODEC_ROOT.rglob("*.py") if p.name != SANCTIONED_INTEGER_MODULE)


# ---------------------------------------------------------------------------
# Check 4 -- the optional-key census
# ---------------------------------------------------------------------------


class KeySetPair:
    """One schema map's known/required key-set pair, and how its OPTIONAL keys
    are covered.

    `coverage` is verified, not merely declared -- each value names a
    mechanism the census then checks the keys actually reach:

      "cases"    a Section VT check-1 row, replayed through `replay_bytes`.
      "direct"   a case that calls the decoder directly, for a decoder no
                 replay target reaches (`codec/trash_entry.py`).
      "dispatch" mechanism A: a total `check_*_value` dispatch whose `else`
                 raises `UncheckedKnownKey` (#641's M8). Probed in check 4b.
      "none"     this map declares no optional key at all. The census
                 requires `known - required` to be EMPTY, so growing an
                 optional key here is a deliberate edit to this table rather
                 than a silent gap -- which is precisely how
                 `trash[].fingerprint` and `trash[].purged_at_ms` arrived.
    """

    def __init__(self, file: str, known: str, required: str, coverage: str) -> None:
        self.file = file
        self.known = known
        self.required = required
        self.coverage = coverage

    def label(self) -> str:
        return f"{self.file}:{self.known}"


#: Declared, never inferred -- see the module docstring's last paragraph.
KEY_SET_PAIRS: tuple[KeySetPair, ...] = (
    KeySetPair("manifest_schema.py", "MANIFEST_KNOWN_KEYS", "MANIFEST_REQUIRED_KEYS", "none"),
    KeySetPair("manifest_schema.py", "BLOCK_ENTRY_KNOWN_KEYS", "BLOCK_ENTRY_REQUIRED_KEYS", "none"),
    KeySetPair("manifest_schema.py", "TRASH_ENTRY_KNOWN_KEYS", "TRASH_ENTRY_REQUIRED_KEYS", "cases"),
    KeySetPair("manifest_schema.py", "KDF_PARAMS_KNOWN_KEYS", "KDF_PARAMS_REQUIRED_KEYS", "none"),
    KeySetPair("manifest_schema.py", "VECTOR_CLOCK_ENTRY_KNOWN_KEYS",
               "VECTOR_CLOCK_ENTRY_REQUIRED_KEYS", "none"),
    KeySetPair("record.py", "RECORD_KNOWN_KEYS", "RECORD_REQUIRED_KEYS", "dispatch"),
    KeySetPair("record.py", "RECORD_FIELD_KNOWN_KEYS", "REQUIRED_FIELD_KEYS", "none"),
    KeySetPair("card.py", "KNOWN_CARD_KEYS", "REQUIRED_CARD_FIELDS", "none"),
    KeySetPair("trash_entry.py", "KNOWN_KEYS", "REQUIRED", "direct"),
    KeySetPair("vault_toml.py", "KNOWN_KDF_KEYS", "REQUIRED_KDF_KEYS", "none"),
)

#: The measured population of optional keys across every pair above. Stated so
#: a pairing that silently stops resolving shows up as a moved number rather
#: than as a quietly smaller census.
EXPECTED_OPTIONAL_KEY_COUNT = 7

_NAME_SHAPES = ("KNOWN", "REQUIRED")


def _literal_key_sets(path: Path) -> dict[str, frozenset[str]]:
    """Every name in `path` bound to a literal set/list/tuple of strings.

    Evaluated from the AST, so nothing in the decoder is imported or run.
    Module-level and function-local bindings both count -- `card.py`,
    `trash_entry.py` and `vault_toml.py` all declare theirs inside the decoder
    function. A plain `X = Y` alias resolves to `Y`'s keys, which is how the
    five `*_REQUIRED_KEYS = *_KNOWN_KEYS` lines are read.
    """
    out: dict[str, frozenset[str]] = {}
    try:
        tree = ast.parse(path.read_text())
    except (OSError, SyntaxError):
        return out
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Assign) and len(node.targets) == 1):
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name):
            continue
        value = node.value
        if isinstance(value, ast.Call) and getattr(value.func, "id", "") == "frozenset" and value.args:
            value = value.args[0]
        if isinstance(value, (ast.Set, ast.List, ast.Tuple)):
            keys = frozenset(
                e.value for e in value.elts
                if isinstance(e, ast.Constant) and isinstance(e.value, str)
            )
            if keys:
                out[target.id] = keys
        elif isinstance(value, ast.Name) and value.id in out:
            out[target.id] = out[value.id]
    return out


def _discovered_key_sets() -> set[tuple[str, str]]:
    """Every `(file, name)` under `codec/` whose name carries a KNOWN/REQUIRED
    shape and which binds a literal set of strings."""
    found: set[tuple[str, str]] = set()
    for path in sorted(CODEC_ROOT.rglob("*.py")):
        for name in _literal_key_sets(path):
            if any(shape in name.upper() for shape in _NAME_SHAPES):
                found.add((path.name, name))
    return found


def optional_key_issues(case_keys: frozenset[str], direct_keys: frozenset[str]) -> tuple[list[str], int]:
    """Check 4 -- every optional key is covered, and every key set is paired.

    `case_keys` and `direct_keys` are DERIVED by the caller from the cases that
    actually run, never declared here: a table that both declared the coverage
    and certified it would be self-certifying, which is the defect #599's
    review found in a sibling corpus.

    Returns the issues and the optional-key population, so the caller can
    report the number.
    """
    issues: list[str] = []
    per_file = {p.file: _literal_key_sets(CODEC_ROOT / p.file) for p in KEY_SET_PAIRS}

    # Direction 1: every pairing resolves, and its optional keys are covered.
    optional_total = 0
    for pair in KEY_SET_PAIRS:
        sets = per_file.get(pair.file, {})
        missing = [n for n in (pair.known, pair.required) if n not in sets]
        if missing:
            issues.append(
                f"{pair.label()}: the pairing names {missing}, which "
                f"{pair.file} does not bind to a literal set of strings"
            )
            continue
        optional = sorted(sets[pair.known] - sets[pair.required])
        optional_total += len(optional)
        if pair.coverage == "none":
            if optional:
                issues.append(
                    f"{pair.label()}: declares optional key(s) {optional}, but its "
                    f"coverage is 'none'. An optional key with no type check is what "
                    f"#669 was -- add a case and reclassify this row"
                )
            continue
        for key in optional:
            if pair.coverage == "cases" and key not in case_keys:
                issues.append(
                    f"{pair.label()}: optional key {key!r} has no Section VT check-1 case"
                )
            elif pair.coverage == "direct" and key not in direct_keys:
                issues.append(
                    f"{pair.label()}: optional key {key!r} has no direct-decoder case"
                )
        # "dispatch" keys are verified behaviourally by check 4b.

    # Direction 2: no key set under codec/ is outside the pairing table. This
    # is what stops a NEWLY ADDED schema map being skipped in silence.
    declared = {(p.file, p.known) for p in KEY_SET_PAIRS} | {
        (p.file, p.required) for p in KEY_SET_PAIRS
    }
    for file, name in sorted(_discovered_key_sets() - declared):
        issues.append(
            f"{file}:{name} looks like a schema key set but is in no KEY_SET_PAIRS row, "
            f"so its optional keys are censused by nothing"
        )

    if optional_total != EXPECTED_OPTIONAL_KEY_COUNT:
        issues.append(
            f"EXPECTED_OPTIONAL_KEY_COUNT is {EXPECTED_OPTIONAL_KEY_COUNT}, the census "
            f"found {optional_total}"
        )
    return issues, optional_total


# ---------------------------------------------------------------------------
# Check 4b -- mechanism A: the wire-order dispatch must be TOTAL
# ---------------------------------------------------------------------------


def dispatch_totality_issues() -> list[str]:
    """Check 4b -- `record.py`'s dispatches have an arm for every declared key.

    `py_decode_record` checks values in WIRE order, not schema order, so a
    `*_VALUE_CHECKS` table would be the wrong shape for it. Its guarantee is
    a TOTAL dispatch instead: `check_record_value` / `check_field_value` end
    in an `else` that raises `UncheckedKnownKey`, a `RuntimeError` kept out of
    `conformance_lib.rejection`'s verdict allowlist so the differential replay
    scores it a harness failure rather than a rejection (#641's M8).

    #669 does not refactor any of that -- this check starts ENFORCING it.
    Behavioural, so an aliased or restructured dispatch cannot evade it; it
    proves only that an arm EXISTS for each key, never that the arm checks the
    right property.
    """
    from conformance_lib.codec.record_rules import (
        UncheckedKnownKey,
        check_field_value,
        check_record_value,
    )

    issues: list[str] = []
    sets = _literal_key_sets(CODEC_ROOT / "record.py")
    probe = object()  # Fails every type check; reaches every arm.

    for name, call in (
        ("RECORD_KNOWN_KEYS", lambda k: check_record_value(k, probe)),
        ("RECORD_FIELD_KNOWN_KEYS", lambda k: check_field_value("f", k, probe)),
    ):
        if name not in sets:
            issues.append(f"record.py:{name} does not bind a literal set of strings")
            continue
        for key in sorted(sets[name]):
            if key == "fields":
                continue  # Not a value the dispatch checks; parsed structurally.
            try:
                call(key)
            except UncheckedKnownKey:
                issues.append(
                    f"record.py: the dispatch has no arm for known key {key!r} "
                    f"(UncheckedKnownKey) -- its value would be accepted unchecked"
                )
            except Exception:
                pass  # Any other raise means the arm exists and ran.

    # NEGATIVE CONTROL, and without it this whole check is vacuous.
    #
    # Every currently-declared key HAS an arm, so the `else` never fires and
    # deleting `raise UncheckedKnownKey` is invisible to the loop above --
    # measured, when this row was written as a mutation. The guarantee 4b
    # exists for is about a FUTURE key, so it has to be tested with a key that
    # is not declared: the fall-through must still raise.
    for label, call in (
        ("check_record_value", lambda k: check_record_value(k, probe)),
        ("check_field_value", lambda k: check_field_value("f", k, probe)),
    ):
        try:
            call("vt_probe_undeclared_key")
        except UncheckedKnownKey:
            continue
        except Exception as exc:  # noqa: BLE001
            issues.append(
                f"record.py: {label} answered an UNDECLARED key with "
                f"{type(exc).__name__} instead of UncheckedKnownKey; a key added to "
                f"the known set without an arm would be checked by the wrong arm"
            )
            continue
        issues.append(
            f"record.py: {label} ACCEPTED an undeclared key without raising "
            f"UncheckedKnownKey -- the fall-through that makes a missing check "
            f"unrepresentable is gone, so a future known key would be accepted unchecked"
        )
    return issues
