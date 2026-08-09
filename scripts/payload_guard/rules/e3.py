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
from payload_guard.discovery import (
    _inside, discovery_cfg_test_spans, discovery_cfg_test_spans_strict,
)
from payload_guard.lexer import (
    balanced_slice, discovery_view, strip_comments, string_literal_token_ends,
)
from payload_guard.parsing import split_top_level
from payload_guard.types import Finding

# `pub(crate) fn name(` in `error/detail.rs` — the sanctioned detail
# constructors rule E3 accepts a call to. Private-to-the-crate by design: a
# `pub fn` would be callable from outside the bridge, and a bare `fn` is not
# reachable from the call sites this rule gates.
SANCTIONED_CTOR_RE = re.compile(r"pub\(crate\)\s+fn\s+([a-z_][a-z0-9_]*)\s*\(")

# Parameter types a sanctioned constructor may take (#496).
#
# Until #496 this registry captured the constructor's NAME and never looked
# at its SIGNATURE, which made it self-authorising in a way nothing recorded:
# `detail.rs` granted acceptance for whatever it declared, and E3 re-verified
# nothing about the arguments. Appending
#
#     pub(crate) fn passthrough(anything: &str) -> String { anything.to_owned() }
#
# to any root's sanctioned module made `detail::passthrough(<any runtime
# string>)` legal in a gated field at every call site, with the whole guard
# reporting OK (verified by execution).
#
# Every type here is one that cannot carry runtime secret content: a
# compile-time string, an integer, a fixed-size byte array (rendered as hex
# by the constructor), a filesystem path (the ALREADY-DISCLOSED class — see
# allowlist Section 1), an `ErrorKind` discriminant, or an
# `impl GatedDetail`, whose impl set rule E4 pins to one reviewed file.
#
# A constructor with ANY parameter outside this set is DROPPED from the
# sanctioned set, so its call sites deny — the same fail-closed direction a
# missing `detail.rs` takes.
SAFE_PARAM_TYPES = frozenset(
    {
        "&'static str",
        "usize", "u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64",
        "&[u8; 16]", "&[u8; 32]",
        "&Path", "&std::path::Path",
        "&impl GatedDetail",
        "std::io::ErrorKind", "io::ErrorKind", "ErrorKind",
    }
)

# The two REVIEWED exceptions permitted a `&str` parameter, keyed on
# constructor name (#496).
#
# Both live in `ffi/secretary-ffi-py/src/detail.rs` and both only COMBINE
# values the bridge already owns and rules E2/E1 already gate — they author
# no new runtime content. Their own doc comments state the per-parameter
# provenance, including the one parameter (`uuid_prefixed`'s `detail_part`)
# whose backing is E2 + core E1 rather than E3.
#
# This is a point-in-time review claim the guard cannot verify, deliberately
# spelled as a SHORT pinned list rather than a blanket `&str` acceptance: a
# THIRD `&str`-taking constructor fails this guard until someone edits this
# set, which is the review checkpoint the bare-name registry never had.
STR_PARAM_CTOR_EXCEPTIONS = frozenset({"fingerprint_mismatch", "uuid_prefixed"})


def _ctor_params_are_safe(name: str, params_text: str) -> bool:
    """Every parameter of a candidate sanctioned constructor must carry a
    type from `SAFE_PARAM_TYPES` (or be one of the two reviewed `&str`
    exceptions). An unparseable parameter is NOT safe — default-deny."""
    allowed = SAFE_PARAM_TYPES | ({"&str"} if name in STR_PARAM_CTOR_EXCEPTIONS else set())
    inner = params_text.strip()
    if inner.startswith("(") and inner.endswith(")"):
        inner = inner[1:-1]
    if not inner.strip():
        return True
    for part in split_top_level(inner):
        part = part.strip()
        if not part:
            continue
        # `name: Type` — a parameter with no `:` is unparseable, hence unsafe.
        if ":" not in part:
            return False
        ty = " ".join(part.split(":", 1)[1].split())
        if ty not in allowed:
            return False
    return True


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

    The constructor's SIGNATURE is checked, not just its name (#496): every
    parameter type must sit in `SAFE_PARAM_TYPES`, or the constructor is
    dropped from the set and its call sites deny. Without that check this
    registry was self-authorising — it derived its allowlist from the very
    file it constrains and read only the name, so one `pub(crate) fn
    passthrough(anything: &str) -> String` added to `detail.rs` sanctioned an
    arbitrary runtime string at every call site. The two reviewed `&str`
    exceptions are pinned by name in `STR_PARAM_CTOR_EXCEPTIONS`.

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
    names: set[str] = set()
    for m in SANCTIONED_CTOR_RE.finditer(view):
        if _inside(m.start(), excluded):
            continue
        name = m.group(1)
        # SIGNATURE gate (#496): the match ends just past the `(`, so
        # `m.end() - 1` is the opening paren `balanced_slice` needs.
        params_text, _ = balanced_slice(view, m.end() - 1)
        if not _ctor_params_are_safe(name, params_text):
            continue
        names.add(name)
    return frozenset(names)


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

# #487: `std::io::Error` is E4-allowlisted as a CARRIER — unlike ParseIntError,
# its Display renders whatever it was CONSTRUCTED with, so its safety is a
# claim about producers, not about the type. A bridge site can mint one from a
# runtime string, fold it into core's `VaultError::Io { source }`, and reach a
# gated field via that impl — a path E3's initializer rule never crossed,
# because it gates the BRIDGE's own `detail:` expression, not what feeds
# core's.
#
# The payload argument therefore becomes a candidate position in its own
# right. `new` takes it SECOND (after the ErrorKind); `other` takes it FIRST.
#
# LIMIT, inherited from every rule here: this matches the trait/type spelled
# out. `use std::io::Error;` followed by a bare `Error::new(...)` is invisible,
# the same aliasing blind spot rule E4 records for `GatedDetail`.
IO_ERROR_NEW_RE = re.compile(
    r"(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*io\s*::\s*Error\s*::\s*new\s*\("
)
IO_ERROR_OTHER_RE = re.compile(
    r"(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*io\s*::\s*Error\s*::\s*other\s*\("
)
# The synthetic `field` name reported for an io payload finding. Deliberately
# NOT a valid Rust identifier: `initializer_is_gated`'s arm 4 (and shape 5)
# compare the expression against the field NAME, and an io payload has no
# field name to re-wrap, so a name no expression can equal keeps those arms
# structurally unreachable here rather than relying on them happening not to
# match.
IO_PAYLOAD_FIELD = "<io::Error payload>"

# Rule E3 shape 5 (#486): a SINGLE-HOP field access whose final segment is
# the gated field's own name — `uuid_hex: a.uuid_hex`. Wrapper roots only.
#
# EXACTLY ONE DOT, on purpose (review finding, task 9): all four live sites
# are single-hop (`a.uuid_hex`, `w.block_uuid_hex`), arm 5's own docstring
# describes a single hop, and an earlier unbounded-depth version of this
# regex accepted `a.b.uuid_hex` / `a.b.c.uuid_hex` too — wider than the
# shape it was written to recognise, and untested in the extra width. A
# multi-hop chain is not the DTO pass-through this arm exists to serve; it
# is a claim about an intermediate value this rule has no way to vouch for,
# and granting it anyway would be exactly the "new acceptance nothing
# needs" laundering door this task's own commit message warns against.
# `WP3` pins a depth-2 chain (`a.b.uuid_hex`) denying.
FIELD_ACCESS_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*\.\s*[A-Za-z_][A-Za-z0-9_]*$")


def io_payload_candidates(depth_view: str) -> list[tuple[int, int, str]]:
    """`(match_start, payload_start, IO_PAYLOAD_FIELD)` for every
    `io::Error::new(kind, PAYLOAD)` and `io::Error::other(PAYLOAD)` in
    `depth_view` (#487).

    For `new`, the payload begins after the first top-level comma inside the
    call — located with `initializer_end`, which stops at exactly that comma.
    A call with no top-level comma (a macro-built argument list, a `new` with
    one argument that does not compile) yields NO candidate rather than a
    mis-sliced one; that is the fail-closed reading for a helper whose job is
    to find a slice, since a wrong slice would be classified as some OTHER
    expression and could be accepted.

    LIMIT, undocumented until now: `initializer_end` tracks `(`/`[`/`{`
    nesting, not `<`/`>` — a turbofish or a generic type in the `ErrorKind`
    argument (`io::Error::new(SomeEnum::<A, B>::Kind, real_payload)`) has a
    comma the depth counter reads as top-level, so the located "comma" is the
    one INSIDE the angle brackets, not the one separating the two `new`
    arguments. The extracted payload span is then garbled — it starts
    mid-way through the `ErrorKind` expression instead of at `real_payload`.
    This is still ALWAYS fail-closed: the mis-sliced text is not one of
    `initializer_is_gated`'s four accepted shapes (a construction a reviewer
    could actually compile does not happen to read as a literal, a sanctioned
    `detail::` call, the bare token `String`, or the field's own name), so it
    still DENIES — just with a `field_type` in the finding that does not
    describe the real payload expression. No live `io::Error::new` call site
    in the tree takes a generic/turbofish `ErrorKind` argument today.
    """
    out: list[tuple[int, int, str]] = []
    for m in IO_ERROR_OTHER_RE.finditer(depth_view):
        out.append((m.start(), m.end(), IO_PAYLOAD_FIELD))
    for m in IO_ERROR_NEW_RE.finditer(depth_view):
        comma = initializer_end(depth_view, m.end())
        if comma >= len(depth_view) or depth_view[comma] != ",":
            continue
        out.append((m.start(), comma + 1, IO_PAYLOAD_FIELD))
    return out


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
    a legitimate re-wrap misreads as an unrecognised shape.

    It is true that a bare `;` cannot legally appear inside a
    field-initializer or fn-parameter expression at depth zero — but that
    does NOT mean the terminator "changes nothing" for `GATED_INIT_RE`
    candidates, because `GATED_INIT_RE` fires on any `<name>:` sequence, not
    only on those two shapes. A type-annotated `let` with NO initializer —
    `let detail: String;` — reads to `GATED_INIT_RE` exactly like a field or
    parameter declaration (`detail:` followed by a type), and its `;`
    terminator IS legal Rust at depth zero: `let` always ends in `;`,
    initializer or not. Adding the `;` terminator therefore changes the
    SLICE this shape extracts — from "everything up to whatever brace
    happened to enclose it" (previously, typically garbled and denied by
    accident) to exactly `String` (now cleanly extracted) — and it is
    `initializer_is_gated`'s job, not this function's, to tell that
    terminator apart from a genuine declaration's `)`/`,`/`}` before trusting
    the bare-`String` shape it now yields. See its terminator-aware arm 3.
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
    allow_field_access: bool,
    terminator: str,
) -> bool:
    """Rule E3's ACCEPT test for the (already whitespace-trimmed) expression
    `view[start:end]` assigned to gated field `name` (#480).

    FOUR shapes are accepted everywhere, plus a FIFTH gated behind
    `allow_field_access` (#486, wrapper roots only) — and nothing else: this
    is a default-DENY predicate, so a construct this function does not
    recognise is a finding.

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
    3. The exact token `String` OR `Detail` (#500) — a DECLARATION's type
       position (a struct field, an enum variant field, a function
       parameter), not a value. Rule E2 already decides whether a `String`
       or `Detail` DECLARATION under a gated name is acceptable (per-root,
       `ScanRoot.gated_field_types`); E3 is about construction, and a
       declaration is not a construction. `String::new()` / `Detail::new()`
       are NOT this shape and deny, which is what keeps the acceptance from
       becoming "any expression starting with String/Detail".

       `Detail` joins this arm UNCONDITIONALLY, not read from
       `ScanRoot.gated_field_types` or threaded per-root: unlike E2, this arm
       makes no claim about which TYPES are policy-acceptable under a gated
       name on a given root — it only tells a declaration's type position
       apart from a construction expression, and `GATED_INIT_RE` matches
       `<name>:` regardless of root. E2 remains the sole per-root gate
       (wrapper roots' `gated_field_types` stays `{"String"}`, never
       `Detail`, so a wrapper declaration reading `field: Detail` still
       produces an E1/E2 finding — this arm merely keeps E3 from ALSO
       misreporting that same declaration as an unsanctioned construction
       site). Found live: without this, `pub enum FooError { #[error("boom:
       {detail}")] Boom { detail: Detail }, }` — an ordinary DECLARATION,
       the exact shape Task 3 (#500) is about to introduce across the bridge
       — read to `GATED_INIT_RE` identically to a construction site and
       produced a spurious E3 finding (`BN28`), which would have reddened
       the real scan the moment Task 3 landed a single `Detail`-typed field.

       GATED BEHIND THE TERMINATOR (regression fix, found in final review):
       a genuine declaration's type position is always closed by `)` (a
       function parameter), `,` (a non-last struct/enum field), or `}` (the
       last field before the closing brace) — never by a depth-zero `;`,
       because none of those three constructs is itself terminated by one.
       The ONE construct that reads identically to `GATED_INIT_RE` (a
       `<name>:` token) and IS terminated by `;` is a type-annotated `let`
       with NO initializer — `let detail: String;` — which is not a
       declaration this arm exists to serve; it is a value-less binding
       whose value is written on a LATER, separate statement
       (`detail = format!(...);`) that neither `GATED_LET_RE` (no `=` on
       the `let` itself) nor `GATED_ASSIGN_RE` (no receiver dot on a bare
       local) can see. Before this fix, that shape's initializer slice ran
       on into the enclosing block and typically stopped on an unrelated
       `}`, producing a garbled expression that matched no accepted shape
       and DENIED by accident; adding `;` as a terminator in
       `initializer_end` (#488) cleanly extracts `String` instead — which
       then hit this arm's bare-token acceptance and produced ZERO findings,
       a real regression against the pre-#488 guard (see `BP44`). Denying
       arm 3 whenever `terminator == ";"` closes it: a `String` extracted up
       to a depth-zero `;` is never a struct field, enum field, or function
       parameter, so refusing it there costs none of the three legitimate
       declaration shapes arm 3 exists to serve.
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
    5. WRAPPER ROOTS ONLY (`allow_field_access`, #486): a SINGLE-HOP field
       access — `receiver.field`, EXACTLY ONE DOT — whose field segment is
       the gated field's own name — `uuid_hex: a.uuid_hex`, the DTO
       pass-through shape all four live wrapper sites take. THIS ARM TRUSTS
       THE NAME TOO, one level deeper than arm 4: it claims that a field
       named `uuid_hex` on some OTHER type was gated where THAT type
       declared it. For the four live sites that claim holds (the source is
       a bridge DTO whose fields rules E2/E3 already gate), but it is a
       trust RELATION, not provenance — the same honesty arm 4's docstring
       insists on. Scoped OUT of the bridge root on purpose: nothing there
       needs it, and granting it anyway would be a laundering door opened
       for free (`BP43` pins the bridge still denying the identical
       expression). A field access whose LAST segment is NOT the gated
       name — `uuid_hex: a.some_other_field` — is not this shape and denies
       (`WP1`). ONE HOP ONLY, not an arbitrary-depth chain: `a.b.uuid_hex`
       is a claim about an INTERMEDIATE value (`a.b`) this rule has no way
       to vouch for, is not the shape any live site takes, and denies
       (`WP3`) — a review finding on the first version of this arm, which
       accepted any depth.

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
    # (4) the same-name re-wrap — trusted regardless of terminator, since a
    # `let detail = detail;` or `x.detail = detail` is not a declaration.
    if stripped == name:
        return True
    # (3) declaration type position — DENIED when `terminator` is `;`: the
    # only construct that extracts a bare `String`/`Detail` up to a
    # depth-zero `;` is a type-annotated `let` with NO initializer (`let
    # detail: String;`, #488/regression fix, `BP44`), never a struct field,
    # enum field, or function parameter — those are always closed by `)`,
    # `,`, or `}`. `Detail` (#500) is accepted alongside `String`
    # unconditionally, not per-root — see the docstring's arm 3 for why.
    if stripped in ("String", "Detail") and terminator != ";":
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
    # (5) a SINGLE-HOP field access ending in the gated name — the DTO
    #     pass-through (#486). WRAPPER ROOTS ONLY. `FIELD_ACCESS_RE` accepts
    #     EXACTLY ONE DOT, not an arbitrary-depth chain — `a.b.uuid_hex`
    #     denies (`WP3`), since it is a claim about an intermediate value
    #     this rule cannot vouch for and no live site takes that shape.
    #
    #     THIS ARM TRUSTS A NAME, one level deeper than arm 4 does: it claims
    #     that a field spelled `uuid_hex` on some OTHER type was gated where
    #     THAT type declared it. For the four live sites that claim holds —
    #     the source is a bridge DTO whose field rules E2/E3 gate — but it is
    #     a trust RELATION, not provenance, and this comment says so rather
    #     than dressing it up. It is scoped to the wrapper roots because all
    #     four sites are there; granting it in the bridge would open the same
    #     door for nothing in return (BP43 pins that).
    if allow_field_access and FIELD_ACCESS_RE.match(stripped):
        if stripped.split(".")[-1].strip() == name:
            return True
    return False


def scan_bridge_construction_sites(
    path_label: str,
    raw: str,
    sanctioned: frozenset[str],
    allow_field_access: bool = False,
) -> list[Finding]:
    """Rule E3 (#480): every CONSTRUCTION SITE of a gated field must build
    its value from a sanctioned source.

    `allow_field_access` (#486) enables shape 5 — a SINGLE-HOP field access
    ending in the gated name (`uuid_hex: a.uuid_hex`, not `a.b.uuid_hex`) —
    and defaults to `False` so a caller that does not pass it explicitly gets
    the bridge's stricter behaviour, not the wrapper roots' looser one. See
    `initializer_is_gated`'s shape 5 and `payload_guard.roots.ScanRoot.
    allow_field_access` for why it is scoped to the wrapper roots only.

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
    # STRICT: a skip here means the construction site is not scanned
    # (#496). `sanctioned_constructor_names` above keeps the PERMISSIVE
    # matcher on purpose — it GRANTS acceptance, so over-matching there
    # finds fewer sanctioned names, which is fail-closed.
    excluded = discovery_cfg_test_spans_strict(raw)
    literal_ends = string_literal_token_ends(raw)
    findings: list[Finding] = []
    # FOUR candidate forms, one shared gate (#480 initializer, #488 let and
    # assignment, #487 the io::Error payload argument). Ordering is by match
    # offset so findings stay in source order regardless of which form
    # produced them.
    candidates = sorted(
        [
            (m.start(), m.end(), m.group(1))
            for regex in (GATED_INIT_RE, GATED_LET_RE, GATED_ASSIGN_RE)
            for m in regex.finditer(depth_view)
        ]
        + io_payload_candidates(depth_view)
    )
    for m_start, m_end, name in candidates:
        if _inside(m_start, excluded):
            continue
        start, end = m_end, initializer_end(depth_view, m_end)
        # Captured BEFORE the trailing-whitespace trim below moves `end`:
        # `initializer_end` returns the offset of the terminator itself (or
        # `len(depth_view)` if none was found before EOF), so this is the
        # literal character that closed the expression — `)`/`,`/`}` for a
        # genuine declaration or top-level comma/assignment, `;` ONLY for a
        # `let` statement (with or without initializer). Threaded into
        # `initializer_is_gated` so its arm 3 (bare `String`) can tell a
        # real declaration apart from a deferred-init `let`'s empty type
        # position — see that function's regression-fix note and `BP44`.
        terminator = depth_view[end] if end < len(depth_view) else ""
        while start < end and src[start] in " \t\r\n":
            start += 1
        while end > start and src[end - 1] in " \t\r\n":
            end -= 1
        if initializer_is_gated(
            src,
            start,
            end,
            name,
            literal_ends,
            sanctioned,
            allow_field_access,
            terminator,
        ):
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
