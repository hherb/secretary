"""The AST scans behind Section DET's structural half (#597, #605 review).

Section DET's checks 1 and 2 observe seven inputs. What makes them more than a
snapshot is this module: the claim that those seven ARE the population, and
that no eighth required-key check has appeared that selects a key some other
way. Both directions are scanned:

  * `helper_call_sites` -- every `codec/` call of the helper must have a case.
  * `unmediated_required_selections` -- no `codec/` construct may pick one key
    out of a required-key SET without imposing an order first.

WHY THE SECOND RULE IS SHAPED THE WAY IT IS. #597 was `for k in SOME_SET:` and
the first version of this scan matched exactly that: an `ast.For` whose iterable
is a set literal or a bare `Name`. The #605 review planted eight further
spellings of the SAME defect and watched all eight scan GREEN -- a generator
expression, a list comprehension, `for k in frozenset(X)`, `for k in list(X)`,
`for k in mod.REQUIRED_KEYS`, `async for`, and `absent = REQUIRED - set(d)`
followed by `absent.pop()`. That last one is not hypothetical: it is the idiom
`wire/card.py` uses, which the probe's own docstring holds up as the sanctioned
eighth site, so it is the most likely thing for a future author to copy without
copying its `sorted(...)`. Every one of them was measured nondeterministic.

The rules below therefore key on WHAT IMPOSES AN ORDER rather than on which
statement form is written. `sorted(...)` is the only mediating call, and it is
recognised by spelling.

LIMITS, and this list is meant to be exhaustive for the RULES rather than
reassuring. Measured, not argued:

  * SCOPE. `codec/` only, recursively. A decoder in `wire/` or `merge/` is
    invisible. `wire/card.py:50-52` is the one required-key check deliberately
    outside the helper -- it reports the WHOLE missing set already sorted, so
    it has no first-key choice to make.
  * NAME SHAPE. A required-key set is recognised only by its identifier
    containing `REQUIRED` or ending `_KEYS` / `_FIELDS`, case-insensitively.
    A set bound to `MANDATORY` or `FIELD_NAMES` is invisible. This is why the
    rules also match a bare set LITERAL, which needs no name.
  * NO NAME RESOLUTION. Every match is by spelling. `sorted` is whatever the
    module binds to that identifier; `from x import sorted_by_len as sorted`
    would be honoured as mediating, and `import builtins` then
    `builtins.sorted(X)` would not.
  * SUBSCRIPTS. `for k in table[kind]:` is an `ast.Subscript` and is NOT
    matched -- there is no identifier to test. Inside set algebra it is
    matched through its OTHER operand, if that one is testable.
  * SET ALGEBRA is followed (`|`, `&`, `-`, `^`), so a union or intersection
    of required-key sets is still recognised as one. A set built by a METHOD
    (`REQUIRED.union(...)`) is matched only for `difference` /
    `symmetric_difference`, which are the ones that SELECT a missing key.
  * MACROS OF THE PYTHON KIND. A selection built through `getattr`, `eval`,
    or a dict of callables is invisible, as it is to any AST scan.
  * A HAND-ROLLED `sorted(...)` IS PERMITTED. These rules enforce
    DETERMINISM, not routing: `for k in sorted(REQUIRED):` in a new decoder
    passes both, because it is not a defect. Only `helper_call_sites`'s
    census speaks to routing, and only for sites that do call the helper.

FALSE POSITIVES ARE FAIL-CLOSED AND DELIBERATE. A legitimate unknown-key sweep
written `for k in set(decoded) - KNOWN_CARD_KEYS:` is flagged, and correctly so
-- it names one unknown key in hash order, which is #597 one map over. The
remedy is the same `sorted(...)` the required-key sites use.
"""

from __future__ import annotations

import ast
from pathlib import Path

HELPER = "first_missing_key_in_sorted_order"

# A name matching one of these denotes a required-key set. Matched
# CASE-INSENSITIVELY: two of the seven live sites bind their required set to
# the lowercase PARAMETER `required_keys` (`manifest_schema.py`), so a
# case-sensitive matcher would miss the ordinary-Python-naming half of the very
# shape it exists to catch.
_REQUIRED_SET_MARKERS = ("REQUIRED",)
_REQUIRED_SET_SUFFIXES = ("_KEYS", "_FIELDS")

# The only call that imposes an order on a set. `frozenset`, `set`, `list`,
# `tuple`, `iter` and `reversed` all PRESERVE hash order -- treating "it is an
# `ast.Call`, so it is mediated" as sound is the inference the #605 review
# falsified, and this tuple is what replaced it.
_MEDIATING_CALLS = ("sorted",)

_PACKAGE_ROOT = Path(__file__).resolve().parents[1]
CODEC_DIR = _PACKAGE_ROOT / "codec"

_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)


def _is_required_set_name(name: str) -> bool:
    upper = name.upper()
    return any(m in upper for m in _REQUIRED_SET_MARKERS) or upper.endswith(
        _REQUIRED_SET_SUFFIXES
    )


def _named(node: ast.AST) -> str | None:
    """The identifier a node is spelled with, for the two forms we can test."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


_SET_ALGEBRA = (ast.BitOr, ast.BitAnd, ast.Sub, ast.BitXor)


def _is_required_set_expr(node: ast.AST) -> bool:
    """Does `node` denote a required-key set, in one of the testable spellings?

    Set ALGEBRA is followed through: `REQUIRED_A | REQUIRED_B` and
    `REQUIRED - set(decoded)` are still required-key sets, and iterating either
    is still a hash-order read. Only the operand spellings below are testable,
    so `table[kind] | OTHER` is recognised through its right half alone.
    """
    if isinstance(node, (ast.Set, ast.SetComp)):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, _SET_ALGEBRA):
        return _is_required_set_expr(node.left) or _is_required_set_expr(node.right)
    name = _named(node)
    return name is not None and _is_required_set_name(name)


def _is_unmediated_iterable(node: ast.AST) -> bool:
    """Is iterating `node` a hash-order-dependent read of a required-key set?"""
    if isinstance(node, ast.Call):
        callee = _named(node.func)
        if callee in _MEDIATING_CALLS:
            return False
        # `frozenset(REQUIRED)`, `list(REQUIRED)`, `tuple({...})` -- the call
        # is real but imposes no order, so the set inside it still leaks one.
        return any(_is_required_set_expr(a) for a in node.args)
    return _is_required_set_expr(node)


def parse_codec_modules() -> tuple[list[tuple[Path, ast.AST]], list[str]]:
    """Every `codec/` module, parsed once, plus any issue that stopped one.

    `rglob`, not `glob`: this repo splits a module into a DIRECTORY module once
    it passes 500 lines, and a non-recursive glob would make the first such
    split silently invisible to both scans.

    Parsed HERE rather than per scan so the two cannot end up reading different
    sets, and so a file that cannot be read or parsed becomes a reported issue
    rather than a traceback out of `main()` with no `FAIL:` line -- the exit-code
    contract in `conformance.py` promises one failure line per failed section.
    An EMPTY result is visible to the caller for the same reason: a glob that
    matches nothing would let both scans report no violations having read
    nothing at all.
    """
    parsed: list[tuple[Path, ast.AST]] = []
    issues: list[str] = []
    for path in sorted(CODEC_DIR.rglob("*.py")):
        try:
            source = path.read_text(encoding="utf-8")
        except OSError as e:
            issues.append(f"{path} could not be read, so it went unscanned: {e}")
            continue
        except UnicodeDecodeError as e:
            issues.append(f"{path} is not UTF-8, so it went unscanned: {e}")
            continue
        try:
            parsed.append((path, ast.parse(source)))
        except SyntaxError as e:
            issues.append(f"{path} could not be parsed, so it went unscanned: {e}")
    if not parsed and not issues:
        issues.append(
            f"no *.py under {CODEC_DIR} -- both structural scans would report "
            "no violations having read no source at all"
        )
    return parsed, issues


def _enclosing_function_names(tree: ast.AST) -> dict[ast.AST, str | None]:
    """Each node's nearest enclosing `def` name, or `None` at module level."""
    enclosing: dict[ast.AST, str | None] = {}

    def visit(node: ast.AST, current: str | None) -> None:
        for child in ast.iter_child_nodes(node):
            inner = (
                child.name
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                else current
            )
            enclosing[child] = inner
            visit(child, inner)

    visit(tree, None)
    return enclosing


def helper_call_sites(
    modules: list[tuple[Path, ast.AST]],
) -> dict[str, list[int]]:
    """Every `codec/` call of the helper, keyed `codec/<path>::<function>`.

    Keyed by ENCLOSING FUNCTION rather than counted, because a count is not a
    mapping: with `len(call_sites) != len(CASES)` as the whole check, an eighth
    call site no case exercises AND an eighth case duplicating an existing one
    scanned GREEN under a PASS line reading "8 call sites, one case each" that
    was false in that state. The key matches `Case.site`'s spelling so the two
    sets can be compared directly, and the LINE NUMBERS are returned so the
    caller can reject two checks sharing one key -- per-function parity is
    still parity, and the #605 review scored a second helper call inside
    `py_decode_trash_entry` as GREEN under `PASS 7 ... each matched to its own
    case`.

    Both `helper(...)` and `required_keys.helper(...)` are matched; an
    attribute-spelled call used to be invisible, which defeated the census for
    a site that was otherwise perfectly correct. An `import ... as` alias is
    still invisible -- nothing here resolves a name.

    The module DEFINING the helper is not excluded. It does not need to be: a
    `def` is an `ast.FunctionDef`, never an `ast.Call`, so the definition
    cannot be miscounted as a use. The exclusion this replaces was keyed on
    BASENAME, which -- once `rglob` started recursing -- silently dropped a
    live call site in `codec/<sub>/required_keys.py`.

    Read through `ast`, not by line matching, so a comment or docstring naming
    the helper cannot inflate the count into a false red either.
    """
    hits: dict[str, list[int]] = {}
    for path, tree in modules:
        enclosing = _enclosing_function_names(tree)
        relative = path.relative_to(CODEC_DIR)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if _named(node.func) != HELPER:
                continue
            function = enclosing.get(node) or "<module>"
            hits.setdefault(f"codec/{relative}::{function}", []).append(node.lineno)
    return hits


def _sorted_wrapped_nodes(tree: ast.AST) -> set[int]:
    """`id()` of every expression passed directly to a `sorted(...)` call.

    `sorted(REQUIRED - set(decoded))` is the safe spelling of the set-difference
    idiom -- it is what `wire/card.py` does -- so the difference inside it must
    not be reported.
    """
    wrapped: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _named(node.func) in _MEDIATING_CALLS:
            for arg in node.args:
                wrapped.add(id(arg))
    return wrapped


def unmediated_required_selections(
    modules: list[tuple[Path, ast.AST]],
) -> list[str]:
    """Every `codec/` construct that picks a key out of a required-key set
    without imposing an order first. After #597 this should be empty."""
    hits: list[str] = []
    for path, tree in modules:
        relative = path.relative_to(CODEC_DIR)
        wrapped = _sorted_wrapped_nodes(tree)

        def report(node: ast.AST, what: str) -> None:
            hits.append(f"codec/{relative}:{node.lineno} ({what})")

        for node in ast.walk(tree):
            # R1 -- `for` / `async for` over an unmediated required-key set.
            if isinstance(node, (ast.For, ast.AsyncFor)):
                if _is_unmediated_iterable(node.iter):
                    report(node, f"{ast.unparse(node.iter)} iterated directly")

            # R2 -- the same read, spelled as a comprehension or generator.
            # `next((k for k in REQUIRED if k not in d), None)` is the most
            # natural modern spelling of the very logic the helper holds.
            elif isinstance(node, _COMPREHENSIONS):
                for clause in node.generators:
                    if _is_unmediated_iterable(clause.iter):
                        report(
                            node,
                            f"{ast.unparse(clause.iter)} in a comprehension",
                        )

            # R3 -- set difference. Its result is a SET, so any single-element
            # selection from it (`.pop()`, `next(iter(...))`) is hash-ordered.
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Sub):
                if id(node) in wrapped:
                    continue
                if _is_required_set_expr(node.left) or _is_required_set_expr(
                    node.right
                ):
                    report(node, f"{ast.unparse(node)} -- unsorted set difference")

            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr not in ("difference", "symmetric_difference"):
                    continue
                if id(node) in wrapped:
                    continue
                if _is_required_set_expr(node.func.value) or any(
                    _is_required_set_expr(a) for a in node.args
                ):
                    report(node, f"{ast.unparse(node)} -- unsorted set difference")
    return hits
