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
    ends: the first `,` at top-level nesting, or the first `)`, `]` or `}`
    that CLOSES the construct the initializer sits in (i.e. appears at depth
    zero). `(`, `[` and `{` open a nesting level.

    `view` must be the DISCOVERY VIEW: with string contents blanked, a comma
    or brace inside a literal (`format!("a, b")`, `"}"`) cannot end the
    expression early. That choice is fail-closed in both directions — every
    view here only ever BLANKS, and blanking can neither introduce a `,` that
    truncates an expression nor remove one in a way that shortens it, so a
    lexer desync can only ever make the extracted expression LONGER, which
    makes it LESS likely to match one of the narrow accepted shapes.

    Closing delimiters at depth zero are genuine terminators, not a
    heuristic: they are the `)` of `fn f(detail: String)`, the `}` of
    `E::V { detail: x }`. Without them a function parameter's type would run
    on into the function BODY and every such parameter would produce a
    spurious finding.
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
        elif ch == "," and depth == 0:
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
       serve (re-wrapping a field of an already-gated error), and it is
       FALSE in general — verified by execution:

           fn f() -> E { let detail = format!("{}", leak());
                         E::V { detail: detail } }      // zero findings

       A local binding (or a function parameter) named `detail` launders any
       expression through this arm. The rule keeps the form because the
       approved plan mandates it and because the alternative — denying every
       re-wrap — would flag the legitimate sites and teach reviewers to wave
       E3 findings through. It is an explicit, named ACCEPT with a stated
       gap, recorded in the module docstring's LIMITS beside the other two.
       Field shorthand (`E::V { detail }`) has no `:` at all and never
       becomes a candidate in the first place — same gap, different door.

    Note what is NOT covered, and cannot be by a construction-site matcher:
    a field assigned AFTER construction (`x.detail = format!(...)`) is a
    write this rule never sees. That is a real blind spot, recorded in the
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
    for m in GATED_INIT_RE.finditer(depth_view):
        if _inside(m.start(), excluded):
            continue
        name = m.group(1)
        start, end = m.end(), initializer_end(depth_view, m.end())
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
                line=src.count("\n", 0, m.start()) + 1,
                source_line=" ".join(f"{name}: {expr}".split()),
                variant="<construction site>",
                field=name,
                field_type=expr,
                rule="E3",
            )
        )
    return findings
