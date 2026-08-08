"""Rule E3: every CONSTRUCTION SITE of a bridge error's gated field must
build its value from a sanctioned source — the other half of rule E2's
carve-out (a bridge error may carry a `String` under a `GATED_FIELD_NAMES`
name instead of denying it by type; this rule gates what that field is
actually set to). Moved out of the former single-file
`scripts/check-error-payload-hygiene.py` in #486 (task 4). Read the entry
point's module docstring first for the WHY and THE BRIDGE RULES.
"""

from __future__ import annotations

import re

from payload_guard.config import GATED_FIELD_NAMES
from payload_guard.discovery import _inside, discovery_cfg_test_spans
from payload_guard.lexer import (
    balanced_slice, discovery_view, strip_comments, string_literal_token_ends,
)
from payload_guard.types import Finding

# `pub(crate) fn name(` in `error/detail.rs` — the sanctioned detail
# constructors rule E3 accepts a call to. Private-to-the-crate by design: a
# `pub fn` would be callable from outside the bridge, and a bare `fn` is not
# reachable from the call sites this rule gates.
SANCTIONED_CTOR_RE = re.compile(r"pub\(crate\)\s+fn\s+([a-z_][a-z0-9_]*)")


def sanctioned_constructor_names(detail_src: str | None) -> frozenset[str]:
    """The set of `detail::<name>(...)` constructors rule E3 accepts a call
    to — every `pub(crate) fn` declared in `error/detail.rs` (#480).

    A MISSING file (or an empty/unreadable one) yields the EMPTY set, which
    denies every constructor call rather than accepting any: if the one file
    that defines what "sanctioned" means cannot be read, nothing is
    sanctioned. That is the whole rule's fail-closed hinge — the alternative
    (treat "no constructor list" as "no restriction") would silently disable
    E3 the moment someone moved or renamed the module.

    Read from the DISCOVERY VIEW (comments AND string CONTENTS blanked), not
    `strip_comments`. This registry GRANTS acceptance, so its fail-closed
    direction is to find FEWER names: a `pub(crate) fn evil(` written inside
    a string literal in `detail.rs` must not sanction `detail::evil(...)` at
    a call site, which is the same self-authorisation class
    `discovery_view`'s own docstring records for `#[error("...")]` messages.
    A lexer desync that HID a real constructor would instead cost a
    fail-closed E3 finding at each of its call sites.

    `#[cfg(test)]`-gated declarations are excluded, like every other
    discovery walk in this file. This one was missed on the first pass, and
    it is a GRANT: a `#[cfg(test)] pub(crate) fn evil_toplevel(...)` added to
    `detail.rs` registered as sanctioned and authorised `detail::evil_toplevel(..)`
    at SHIPPED call sites — verified by execution. A test-only declaration is
    not part of the shipped crate and must not vouch for shipped code, which
    is the same rule `discover_declarations` applies to its own three
    registries.
    """
    if not detail_src:
        return frozenset()
    view = discovery_view(detail_src)
    excluded = discovery_cfg_test_spans(detail_src)
    return frozenset(
        m.group(1)
        for m in SANCTIONED_CTOR_RE.finditer(view)
        if not _inside(m.start(), excluded)
    )


# A gated field name in INITIALIZER position: `<name>:` not followed by a
# second `:`. The negative lookahead excludes the MODULE PATH `detail::` (as
# in `detail::gated(...)`, which is a call, not a field), and `\b` excludes a
# gated name that is merely the TAIL of a longer field name — `record_uuid_hex:`
# must not match on `uuid_hex:`, since the DTO-carrying names are deliberately
# NOT members of `GATED_FIELD_NAMES` (see there).
GATED_INIT_RE = re.compile(
    r"\b(" + "|".join(sorted(GATED_FIELD_NAMES)) + r")\s*:(?!:)"
)
# #488 shapes 2 and 3: a `let` binding to a gated name. E3's arm 4 accepts an
# initializer that is the field's own name, which means
# `let detail = format!("{x}"); E::V { detail: detail }` — and the shorthand
# `E::V { detail }`, which produces no `detail:` token at all — launder any
# expression through a local variable.
#
# The closure needs no dataflow: a `let` binding to a gated name IS a
# construction of a gated value, so its initializer is gated by the same test
# as a field's. The launder becomes the candidate. Pattern bindings
# (`FfiVaultError::X { detail } =>`) and function parameters produce no `let`
# and are untouched — which is what lets arm 4 stay as it is.
#
# `(?!=)` excludes `==`; `let` cannot introduce a comparison, but the same
# guard on GATED_ASSIGN_RE below genuinely matters, so both carry it for
# symmetry and to keep a future edit from splitting the behaviour.
GATED_LET_RE = re.compile(
    r"\blet\s+(?:mut\s+)?(" + "|".join(sorted(GATED_FIELD_NAMES)) + r")\s*=(?!=)"
)
# #488 shape 1: post-construction assignment. `e.detail = format!("{x}")` is a
# WRITE, and the initializer-position rule never saw a write. The optional
# `(?:[+\-*/%^&|]|<<|>>)?` admits every Rust COMPOUND assignment operator
# (`+=`, `-=`, `*=`, `/=`, `%=`, `^=`, `&=`, `|=`, `<<=`, `>>=`) as well as
# plain `=` — `x.detail += &format!("{e}")` is exactly the class this rule
# exists to catch (a build-then-mutate write), and the base pattern's bare
# `=` never matched the two-character forms at all; review caught this gap
# after the initial #488 landing, before it shipped.
# `(?!=)` is still load-bearing on the trailing `=` — `x.detail == s` is a
# comparison, not a construction, and matching it would produce a false
# positive on every equality test; `x.detail != s` was already excluded
# without help (`!` is not one of the admitted operator characters, so the
# required literal `=` never lines up with the `!`), and is now pinned by a
# control rather than left as an unstated fact about the regex.
GATED_ASSIGN_RE = re.compile(
    r"\.\s*("
    + "|".join(sorted(GATED_FIELD_NAMES))
    + r")\s*(?:[+\-*/%^&|]|<<|>>)?=(?!=)"
)
# A call whose path ENDS in `detail::<name>(`. The leading segments are
# unconstrained so both the in-module spelling (`detail::gated(`) and the
# fully-qualified one (`crate::error::detail::gated(`) match; what is pinned
# is that the immediately-enclosing module segment is literally `detail`, so
# a same-named local function (`gated(&e)`) does not pass.
DETAIL_CALL_RE = re.compile(
    r"(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*detail\s*::\s*([a-z_][a-z0-9_]*)\s*\("
)


def initializer_end(view: str, start: int) -> int:
    """The offset at which the initializer expression beginning at `start`
    ends: the first `,` or `;` at top-level nesting, or the first `)`, `]`
    or `}` that CLOSES the construct the initializer sits in (i.e. appears
    at depth zero). `(`, `[` and `{` open a nesting level.

    `view` must be the DISCOVERY VIEW: with string contents blanked, a comma,
    semicolon or brace inside a literal (`format!("a, b")`, `"}"`) cannot end
    the expression early. That choice is fail-closed in both directions —
    every view here only ever BLANKS, and blanking can neither introduce a
    `,`/`;` that truncates an expression nor remove one in a way that
    shortens it, so a lexer desync can only ever make the extracted
    expression LONGER, which makes it LESS likely to match one of the narrow
    accepted shapes.

    Closing delimiters at depth zero are genuine terminators, not a
    heuristic: they are the `)` of `fn f(detail: String)`, the `}` of
    `E::V { detail: x }`. Without them a function parameter's type would run
    on into the function BODY and every such parameter would produce a
    spurious finding.

    The `;` terminator (#488) is what makes this function usable for
    `GATED_LET_RE`'s candidates too: a `let` statement's initializer ends at
    its own `;`, not at any enclosing `)`/`]`/`}` — `let detail =
    detail::gated(e); detail` must stop at the `;`, or the extracted
    "initializer" swallows the trailing `detail` expression-statement too and
    a legitimate re-wrap misreads as an unrecognised shape. A bare `;` cannot
    legally appear inside a field-initializer or fn-parameter expression at
    depth zero, so adding this terminator changes nothing for `GATED_INIT_RE`
    candidates.
    """
    depth = 0
    i, n = start, len(view)
    while i < n:
        ch = view[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif ch in ",;" and depth == 0:
            break
        i += 1
    return i


def initializer_is_gated(
    view: str,
    start: int,
    end: int,
    name: str,
    literal_ends: dict[int, int],
    sanctioned: frozenset[str],
) -> bool:
    """Rule E3's ACCEPT test for the (already whitespace-trimmed) expression
    `view[start:end]` assigned to gated field `name` (#480).

    FOUR shapes are accepted, and nothing else — this is a default-DENY
    predicate, so a construct this function does not recognise is a finding:

    1. A single STRING LITERAL, optionally followed by exactly `.into()` or
       `.to_string()`. The literal is identified by an exact offset match
       against `string_literal_token_ends` (see there), not by a `"` prefix
       test, so a desynced lexer widens rather than admits. The `.into()` /
       `.to_string()` tail is matched with ALL whitespace removed, so
       `"x" . into ()` passes and `"x".into().unwrap()` does not — the point
       is that the value is still exactly the literal.
    2. A call whose path ends `detail::<name>(`, with `<name>` in the
       `sanctioned` set (`sanctioned_constructor_names`) AND the call
       consuming the WHOLE expression. Requiring the whole expression is
       deliberately stricter than "starts with a sanctioned call":
       `detail::gated(&e) + leak()` starts with one too.
    3. The exact token `String` — a DECLARATION's type position (a struct
       field, an enum variant field, a function parameter), not a value.
       Rule E2 already decides whether a `String` DECLARATION under a gated
       name is acceptable; E3 is about construction, and a declaration is
       not a construction. `String::new()` is NOT this shape and denies,
       which is what keeps the acceptance from becoming "any expression
       starting with String".
    4. The exact same identifier as the field name — the `detail: detail`
       re-wrap. THIS ARM TRUSTS THE NAME, NOT THE VALUE'S PROVENANCE, and
       saying otherwise would be a false claim about a security control. An
       earlier version of this docstring asserted the value "is gated where
       it was built"; that is only true for the shape this arm exists to
       serve (re-wrapping a field of an already-gated error).

       #488 closed the plainest counterexample: a SIMPLE `let` binding is
       now itself a candidate (`GATED_LET_RE`), so

           fn f() -> E { let detail = format!("{}", leak());
                         E::V { detail: detail } }

       now produces ONE finding — from the `let`, not from this arm — where
       it used to produce zero (verified by execution; pinned by
       `BP36`/`BP37`). The trust this arm places in the NAME is still real,
       though, for any binding shape that produces no `let ... =` token and
       no `.name =` write, because those are the only two positions this
       rule watches. A PATTERN-DESTRUCTURING bind is one such shape,
       verified by execution to still produce zero findings:

           fn f(e: SomeErr) -> E { let SomeErr { detail } = e;
                                    E::V { detail: detail } }   // zero findings

       Tuple (`let (a, detail) = ...`), tuple-struct (`let Wrap(detail) =
       ...`), slice (`let [detail] = ...`) patterns, and `if let` / `while
       let` / `for` bindings share the same gap — none produce the
       `let <name> =` token `GATED_LET_RE` matches. A function PARAMETER of
       the same name (`fn f(detail: String) -> E { E::V { detail: detail }
       }`, `BN10`) shares it too, and is the legitimate shape every shipped
       re-wrap site today actually is. The rule keeps the arm because the
       approved plan mandates the re-wrap form and because the alternative
       — denying every re-wrap — would flag the legitimate sites and teach
       reviewers to wave E3 findings through. It is an explicit, named
       ACCEPT with a stated gap, recorded in the module docstring's LIMITS
       beside the other two.

       Field shorthand (`E::V { detail }`) has no `:` at all and never
       becomes a candidate AT THIS POSITION — but where the value feeding
       it comes from a SIMPLE `let`, that `let`'s own initializer is now the
       candidate that catches it (`BP36`); only a pattern bind or a
       parameter still reaches the shorthand door unwatched.

    Note what is NOT covered, and cannot be by a construction-site matcher:
    a value reaching a gated field through a PATTERN bind (tuple,
    tuple-struct, struct, slice, `if let`, `while let`, `for`) or through a
    function PARAMETER is not checked — see arm 4 above. #488 closed the
    shape this note used to name here, PLAIN post-construction assignment
    (`x.detail = format!(...)`, now `GATED_ASSIGN_RE`, pinned by `BP38`);
    that is no longer a blind spot. The remaining gaps are recorded in the
    module docstring's LIMITS.
    """
    if start >= end:
        return False
    stripped = view[start:end].strip()
    # (3) declaration type position, and (4) the same-name re-wrap.
    if stripped == "String" or stripped == name:
        return True
    # (1) a single string literal, optionally `.into()` / `.to_string()`.
    lit_end = literal_ends.get(start)
    if lit_end is not None and lit_end <= end:
        tail = "".join(view[lit_end:end].split())
        if tail in ("", ".into()", ".to_string()"):
            return True
    # (2) a sanctioned `detail::<name>(...)` call consuming the expression.
    cm = DETAIL_CALL_RE.match(view, start)
    if cm and cm.end() <= end and cm.group(1) in sanctioned:
        _, after = balanced_slice(view, cm.end() - 1)
        if after <= end and not view[after:end].strip():
            return True
    return False


def scan_bridge_construction_sites(
    path_label: str, raw: str, sanctioned: frozenset[str]
) -> list[Finding]:
    """Rule E3 (#480): every CONSTRUCTION SITE of a gated field must build
    its value from a sanctioned source.

    Rule E2 lets a bridge error carry a `String` under one of the six
    `GATED_FIELD_NAMES` instead of denying it by TYPE. That carve-out is only
    sound if something checks what those fields are actually SET TO — which
    is what this rule does, and why E2 without E3 would be a hole rather than
    a design.

    Candidates are DETECTED on the DISCOVERY view (comments and string
    CONTENTS blanked) and CLASSIFIED against the comments-blanked view, where
    literals are intact. The split is deliberate and the two halves have
    opposite needs:

    - DETECTION on the discovery view means a `detail:` sequence written
      inside a string — `assert!(ok, "Display did not include detail: {r}")`
      — is not a construction site and does not produce a finding. Three
      such false positives existed in `error/vault/tests.rs` before this.
      The cost is real and is stated plainly: this is the ONE place in this
      file where a lexer desync is fail-OPEN, because text the lexer
      wrongly calls a literal stops being a candidate. `BP30`-`BP33` are the
      negative-direction controls for exactly that — a real `detail: leak()`
      placed immediately after a raw string with a `#` run, an escaped
      quote, a byte string, and a lifetime/loop-label shape must still fire.
    - CLASSIFICATION reads the literal-intact view, because deciding whether
      an expression IS a string literal is impossible on a view where the
      literal has been blanked to spaces.

    `#[cfg(test)]`-gated items are skipped (`discovery_cfg_test_spans`): a
    detail string built by a test never reaches a platform.

    Like rule E1's, an E3 allowlist key is the normalized text of the site,
    so two textually IDENTICAL construction sites in one file share a key.
    That is the same characteristic the two shell guards' exact-trimmed-line
    keys have, and it is why the intended remedy for an E3 finding is to
    rewrite the site through `detail::*` (Tasks 4-7), not to allowlist it.
    """
    src = strip_comments(raw)
    depth_view = discovery_view(raw)
    excluded = discovery_cfg_test_spans(raw)
    literal_ends = string_literal_token_ends(raw)
    findings: list[Finding] = []
    # THREE candidate forms, one shared gate (#480 initializer, #488 let and
    # assignment). Ordering is by match offset so findings stay in source
    # order regardless of which form produced them.
    candidates = sorted(
        [
            (m.start(), m.end(), m.group(1))
            for regex in (GATED_INIT_RE, GATED_LET_RE, GATED_ASSIGN_RE)
            for m in regex.finditer(depth_view)
        ]
    )
    for m_start, m_end, name in candidates:
        if _inside(m_start, excluded):
            continue
        start, end = m_end, initializer_end(depth_view, m_end)
        while start < end and src[start] in " \t\r\n":
            start += 1
        while end > start and src[end - 1] in " \t\r\n":
            end -= 1
        if initializer_is_gated(src, start, end, name, literal_ends, sanctioned):
            continue
        expr = " ".join(src[start:end].split()) or "<empty>"
        findings.append(
            Finding(
                path=path_label,
                line=src.count("\n", 0, m_start) + 1,
                source_line=" ".join(f"{name}: {expr}".split()),
                variant="<construction site>",
                field=name,
                field_type=expr,
                rule="E3",
            )
        )
    return findings
