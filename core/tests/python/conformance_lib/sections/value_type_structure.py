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
