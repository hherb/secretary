"""Declaration discovery for the error-payload hygiene guard (#474, #480, #486).

Moved out of the former single-file `scripts/check-error-payload-hygiene.py` in
#486 (task 3). Everything here answers "what thiserror enums / structs, type
aliases, and consts does this guard know about, and what does a file `use`
from outside the crate" -- the tree-global facts `is_data_free`
(`payload_guard.types`) and the scan passes in the entry point classify
fields against. Read the entry point's module docstring first for the WHY.

Two names below (`ERROR_ATTR_RE`, `STRUCT_RE`) are not part of this module's
own "discovery" vocabulary and are not literally what task 3's brief listed
as this module's exports. They were pulled in anyway, verbatim, because
`discover_error_struct_declarations` needs them, and Python resolves a
function's free variables against ITS OWN module's globals, not its
caller's -- so once that function moved here, its dependencies had to move
with it. `rules/e1.py`'s `scan_source` (#486 task 4) is the only outside
consumer, and imports them back from here; the reverse direction is not
possible, since `discovery.py` sits below `rules/*` in this package's
dependency order (`config` -> `lexer`, `parsing` -> `types` -> `discovery`
-> `rules/*` -> `scan`).

Task 3 pulled in two MORE names for the same reason -- `skip_attributes` and
`split_top_level` -- but both moved on again in task 4, to
`payload_guard.parsing`. Unlike `ERROR_ATTR_RE`/`STRUCT_RE`, both are also
needed by a rule module (`rules/e1.py`'s `scan_source` AND
`rules/e2.py`'s `_bridge_plain_enum_variant_findings`), and a rule module
importing them from HERE would invert the layering above -- `discovery.py`
sits below `rules/*`, not beside it. `parsing.py` sits below both, so this
module now imports them back from there, same as any other consumer; see
`_use_bound_names` (`split_top_level`) and
`discover_error_struct_declarations` (`skip_attributes`).
"""

from __future__ import annotations

import bisect
import re
from pathlib import Path

from payload_guard.config import LOCAL_USE_ROOTS
from payload_guard.lexer import (
    balanced_braces, balanced_slice, discovery_view, strip_comments,
)
from payload_guard.parsing import skip_attributes, split_top_level


# `enum Name` — used only to find enum bodies for `discover_declarations`;
# whether it's actually thiserror-derived is decided by whether its body
# contains `#[error(`, not by this regex.
ENUM_RE = re.compile(r"\benum\s+([A-Za-z_][A-Za-z0-9_]*)")
# `type Name = ` — only the head. The right-hand side is NOT `[^;]+` up to
# the next `;`: a fixed-size array alias like `type Fingerprint = [u8; 16];`
# has a `;` INSIDE the brackets (separating element type from length), so a
# naive "stop at the first semicolon" regex truncates the RHS to `[u8`. See
# `find_type_aliases`, which tracks bracket depth instead.
TYPE_ALIAS_HEAD_RE = re.compile(r"\btype\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*")

# A LOCAL declaration of a type called `Detail` (#500 fix round 1), one of
# `struct|enum|union Detail` or `type Detail = ...`/`type Detail<...>`.
# Moved here from `rules/e3.py` (#500 fix round 2, review finding "Important
# 2") so `discover_local_detail_decoys` below — which needs it for rule E2's
# gated-field carve-out, a DIFFERENT consumer than E3's `SAFE_PARAM_TYPES`
# signature gate — can share the one definition instead of a second, drifting
# copy. `rules/e3.py` imports it back from here (discovery.py sits below
# rules/* in this package's dependency order; see the module docstring), the
# same shape `ERROR_ATTR_RE`/`STRUCT_RE` already take in the other direction.
# See `rules/e3.py`'s own docstring paragraph above `sanctioned_constructor_names`
# for the full "why a bare-spelling match, not a resolved one" rationale — it
# is unchanged by the move.
LOCAL_DETAIL_TYPE_RE = re.compile(
    r"\b(?:struct|enum|union)\s+Detail\b|\btype\s+Detail\s*[=<]"
)

# A LOCAL declaration of a TRAIT called `GatedDetail` (#504 review R3): a
# wrapper root's `&impl GatedDetail` in `SAFE_PARAM_TYPES` was the sibling of
# the `Detail`/`&Detail` decoy hole #504's own review found and fixed — a
# wrapper crate cannot implement the BRIDGE's `pub(crate)` `GatedDetail` (it
# is sealed, #496), but nothing stops one declaring its OWN same-named local
# `trait GatedDetail`, implementing it for e.g. `String`, and writing
# `pub(crate) fn launder(d: &impl GatedDetail) -> String`, which then
# sanctions an arbitrary runtime string exactly like the `Detail` decoy did
# (verified by execution; zero live constructors take `&impl GatedDetail` in
# either wrapper crate today — census re-run at every guard scan via `WP11`).
#
# DELIBERATELY A SEPARATE REGEX, not a widened `LOCAL_DETAIL_TYPE_RE`: that
# regex is SHARED with rule E2's `discover_local_detail_decoys`, whose return
# value is a hardcoded `frozenset({"Detail"})` — folding a `GatedDetail`
# trait match into it would make an unrelated `GatedDetail` decoy shadow the
# "Detail" FIELD-type spelling for rule E2, a different rule with a different
# job. Keeping this match independent means rule E3's `GatedDetail`
# withdrawal (`rules/e3.py`'s `gated_detail_param_ok`) cannot perturb E2's
# behaviour, and vice versa — the same single-responsibility split the two
# rules already keep for `LOCAL_DETAIL_TYPE_RE` itself before this addition.
#
# RESIDUAL — IDENTICAL to `LOCAL_DETAIL_TYPE_RE`'s, restated here rather than
# left to be inferred from the sibling (#500 Task 8). This matcher sees a
# local DECLARATION of the trait and nothing else, so an IMPORT evades it in
# both spellings: `use crate::zz_evil::GatedDetail;` written inside a wrapper
# crate's own `detail.rs`, with the decoy trait declared in a SIBLING FILE of
# that same crate, leaves `pub(crate) fn launder(d: &impl GatedDetail) ->
# String` in the sanctioned set and the whole scan green — verified by
# execution, zero findings. (The bridge is unaffected: its `GatedDetail` is
# `pub(crate)` and SEALED, so no other crate can implement the REAL trait;
# what the decoy exploits is that `SAFE_PARAM_TYPES` matches the SPELLING.)
# That is parity with a documented blind spot rather than a regression, but
# an unstated limit on a brand-new security control is how the next reader
# stops checking, so it is written down. Tracked by #512 together with
# `LOCAL_DETAIL_TYPE_RE`'s identical residual — one root cause, one issue.
LOCAL_GATED_DETAIL_TRAIT_RE = re.compile(r"\btrait\s+GatedDetail\b")

# A `mod name {` block header, anchored at the END of the text preceding a
# `{`. `non_module_block_spans` uses it to tell the ONE kind of brace block
# that does not change an item's "is this declared at module scope?" status
# from every other kind (fn body, impl body, trait body, struct/enum body,
# match arm, closure, ...).
MOD_HEADER_RE = re.compile(r"(?:^|[^A-Za-z0-9_])mod\s+[A-Za-z_][A-Za-z0-9_]*\s*$")
# `#[cfg(test)]` and friends (`#[cfg(all(test, ...))]`, `#[cfg_attr(test, ...)]`).
# Matching on `\btest\b` inside the attribute's parentheses is safe on the
# DISCOVERY VIEW specifically: string literals are blanked there, so a
# `#[cfg(feature = "test-utils")]` does not match. There is no
# `#[cfg(not(test))]` under `core/src/**` today; were one added, this would
# over-match it and drop a declaration — the fail-CLOSED direction.
CFG_TEST_RE = re.compile(r"#\[cfg(?:_attr)?\s*\([^\]]*\btest\b[^\]]*\)\s*\]")

# The STRICT form, for the consumers where an exclusion is fail-OPEN (#496).
#
# `CFG_TEST_RE` matches on the PRESENCE of the token `test` anywhere in the
# attribute's parentheses. For the CREDIT registries above that is the
# fail-CLOSED direction, exactly as their docstrings say: over-matching drops
# a declaration, so fewer names vouch for anything.
#
# For the three rules that consume these spans as a SKIP LIST
# (`rules/e2.py`, `rules/e3.py`'s construction sites, `rules/e5.py`, plus
# `discover_error_struct_declarations` below) the polarity INVERTS: dropping
# an item means NOT SCANNING it. Under `CFG_TEST_RE` three ordinary,
# compiling, shipped-code spellings therefore silenced a real violation
# (verified by execution in #496's review):
#
#   #[cfg(not(test))]                    -- the strongest "this is production"
#                                           marker there is
#   #[cfg_attr(test, allow(dead_code))]  -- and every other `cfg_attr(test, ..)`
#   #[cfg(all(feature = "x", not(test)))]
#
# This matcher recognises ONLY the two spellings that genuinely mean
# "test-only": `#[cfg(test)]` and `#[cfg(all(test, ...))]`. Anything else
# containing `test` is not an exclusion, so it gets SCANNED — the fail-closed
# reading for a skip list. `cfg_attr` is excluded outright: it never removes
# an item from the build, it only adds attributes to it under a predicate.
#
# This is the "the fail-closed argument is per-PASS, not global" lesson from
# the entry point's LIMITS section, recurring in a different pass.
CFG_TEST_STRICT_RE = re.compile(
    r"#\[cfg\s*\(\s*test\s*\)\s*\]"
    r"|#\[cfg\s*\(\s*all\s*\(\s*test\s*,[^\]]*\)\s*\)\s*\]"
)


def non_module_block_spans(src: str) -> list[tuple[int, int]]:
    """Character-offset `[start, end)` ranges of every brace block in the
    DISCOVERY VIEW that is NOT a `mod name { ... }` block.

    A declaration is at MODULE SCOPE — the only scope from which a bare name
    can be referenced by a sibling item, and the only scope a `{NAME}` format
    capture in a `thiserror`-generated `Display` impl can reach — exactly
    when it sits inside no such span. One mechanism therefore excludes every
    non-module scope at once: `fn` bodies, `trait` bodies, `impl` bodies
    (this subsumes and replaces the earlier impl-block-only exclusion),
    `struct`/`enum` bodies, blocks, closures and `match` arms.

    Block kind is decided by the text between the previous `{`/`}`/`;` and
    the opening brace — the item's header — matched against `MOD_HEADER_RE`.
    """
    spans: list[tuple[int, int]] = []
    stack: list[tuple[int, bool]] = []
    header_start = 0
    for i, ch in enumerate(src):
        if ch == "{":
            stack.append((i, bool(MOD_HEADER_RE.search(src[header_start:i]))))
            header_start = i + 1
        elif ch == "}":
            if stack:
                start, is_mod = stack.pop()
                if not is_mod:
                    spans.append((start, i + 1))
            header_start = i + 1
        elif ch == ";":
            header_start = i + 1
    return spans


def cfg_test_spans(
    src: str, pattern: re.Pattern[str] = CFG_TEST_RE
) -> list[tuple[int, int]]:
    """Character-offset `[start, end)` ranges of every `#[cfg(test)]`-gated
    item in the DISCOVERY VIEW, attribute included.

    `pattern` selects the polarity: the default `CFG_TEST_RE` is the
    permissive matcher the CREDIT registries want (over-matching = fewer
    credits = fail-closed), and `CFG_TEST_STRICT_RE` is what a fail-OPEN
    SKIP-LIST consumer must pass instead. See `CFG_TEST_STRICT_RE`.

    A test-only declaration is not part of the shipped crate and must not
    vouch for a name a shipped `#[error("...")]` message captures. Six of the
    134 bare `const` names the round-3 rule harvested tree-wide came from
    `#[cfg(test)] mod tests { ... }` blocks — one of them literally named
    `SECRET_FIELD_NAME`.
    """
    spans: list[tuple[int, int]] = []
    n = len(src)
    for m in pattern.finditer(src):
        i = m.end()
        # Skip whitespace and any further attributes stacked on the item.
        while i < n:
            while i < n and src[i] in " \t\r\n":
                i += 1
            if i + 1 < n and src[i] == "#" and src[i + 1] == "[":
                depth, j = 0, i + 1
                while j < n:
                    if src[j] == "[":
                        depth += 1
                    elif src[j] == "]":
                        depth -= 1
                        if depth == 0:
                            j += 1
                            break
                    j += 1
                i = j
                continue
            break
        # The gated item runs to its balanced `{...}` body, or to the `;`
        # that ends a body-less item (`#[cfg(test)] mod tests;`).
        depth, j, end = 0, i, n
        while j < n:
            c = src[j]
            if c in "([":
                depth += 1
            elif c in ")]":
                depth -= 1
            elif depth == 0 and c == "{":
                body, _ = balanced_braces(src[j:])
                end = j + len(body)
                break
            elif depth == 0 and c == ";":
                end = j + 1
                break
            j += 1
        spans.append((m.start(), end))
    return spans


def _inside(pos: int, spans: list[tuple[int, int]]) -> bool:
    return any(start <= pos < end for start, end in spans)


def find_type_aliases(
    src: str, excluded_spans: list[tuple[int, int]] | None = None
) -> dict[str, str]:
    """Map alias name -> right-hand-side text for every module-scope `type X
    = Y;` in the DISCOVERY VIEW, respecting `[`/`(`/`{`/`<` nesting so a `;`
    inside e.g. `[u8; 16]` doesn't end the match early. A `type X = Y;` whose
    match START falls inside `excluded_spans` — most importantly a trait's or
    an `impl`'s ASSOCIATED type, which is a per-impl binding rather than a
    free-standing alias any field elsewhere could reference by that name — is
    skipped.
    """
    excluded_spans = excluded_spans or []
    aliases: dict[str, str] = {}
    for m in TYPE_ALIAS_HEAD_RE.finditer(src):
        if _inside(m.start(), excluded_spans):
            continue
        i, n = m.end(), len(src)
        depth = 0
        start = i
        while i < n:
            ch = src[i]
            if ch in "([{<":
                depth += 1
            elif ch in ")]}>":
                depth -= 1
            elif ch == ";" and depth == 0:
                break
            i += 1
        aliases[m.group(1)] = " ".join(src[start:i].split())
    return aliases


# `const NAME: Type = ` — requires the literal `const` keyword (never matches
# `static`, on purpose — see `find_consts`) and a `:` immediately after the
# name (never matches `const fn name(...)`, since `fn` there is followed by
# an argument list, not a colon).
CONST_RE = re.compile(r"\bconst\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*[^=;]+=")
# `static NAME:` / `static mut NAME:` — never a credit, always a SHADOW; see
# `find_const_shadows`.
STATIC_RE = re.compile(r"\bstatic\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:")


def find_consts(
    src: str, excluded_spans: list[tuple[int, int]] | None = None
) -> list[str]:
    """Bare names of every MODULE-SCOPE `const NAME: Type = value;` in the
    DISCOVERY VIEW, one entry per declaration (repeats are meaningful — see
    `resolve_consts`).

    Only `const`, never `static` — a Rust `const` is required by the
    compiler to be evaluable at COMPILE TIME (a non-const-evaluable
    initializer is a compile error), so it cannot carry runtime content
    regardless of its declared type: that guarantee is stronger than, and
    independent of, `DATA_FREE_TYPES`. A `static` (even an immutable one, let
    alone `static mut`) does not carry the same guarantee — a
    `static X: LazyLock<String>` is a perfectly ordinary way to hold runtime
    data behind a SCREAMING_SNAKE_CASE name — so `CONST_RE` is deliberately
    anchored on the literal `const` keyword, and `find_const_shadows` treats
    every `static` as actively DISQUALIFYING the name. `const fn name(...)`
    (a function, not a value) is also excluded: the regex requires a `:`
    immediately after the captured name, which a function's argument list
    never has.

    `excluded_spans` carries every scope a bare `{NAME}` capture cannot
    reach — non-module blocks (`fn` bodies, `trait` bodies, `impl` bodies:
    an ASSOCIATED const is a per-impl binding, not a free name) and
    `#[cfg(test)]`-gated items (not part of the shipped crate). See
    `non_module_block_spans` / `cfg_test_spans`.

    The anonymous `const _: () = ...;` form is dropped: `_` is not a name any
    placeholder can capture.

    Unlike `find_type_aliases` / the enum spellings in `discover_declarations`,
    only the BARE name is ever registered: a format-string placeholder
    `{NAME}` can only capture a bare, unqualified identifier — Rust's
    captured-identifier syntax does not accept a path — so a qualified
    spelling would never be looked up. That is also why consts get
    `resolve_consts`'s collision-drop instead: with no qualified spelling to
    disambiguate on, a bare name is all there is.
    """
    excluded_spans = excluded_spans or []
    names: list[str] = []
    for m in CONST_RE.finditer(src):
        if _inside(m.start(), excluded_spans):
            continue
        if m.group(1) == "_":
            continue
        names.append(m.group(1))
    return names


def find_const_shadows(
    src: str, excluded_spans: list[tuple[int, int]] | None = None
) -> set[str]:
    """Bare names that DISQUALIFY themselves from the const tier.

    Two kinds, both of which mean "a `{NAME}` capture of this spelling is not
    demonstrably a module-scope `const`":

    1. Every `static NAME: ...` — anywhere, at any scope. `static` is the
       other thing a bare SCREAMING_SNAKE_CASE identifier commonly resolves
       to, and it carries no compile-time-evaluation guarantee. This is the
       concrete counter-witness that killed the previous round's tree-global
       bare-name const union: a file declaring
       `pub static LEAKY_NAME: LazyLock<String> = ...` and capturing
       `{LEAKY_NAME}` correctly denied ON ITS OWN, but an unrelated,
       later-sorted file adding `pub const LEAKY_NAME: usize = 16;` made the
       finding DISAPPEAR. The guard's claim is "this placeholder RESOLVES TO
       a const", which is a name-resolution claim; a union over bare names
       does not establish it, and `static` is exactly the collision partner
       that proves so.
    2. Every `const NAME: ...` declared inside `excluded_spans` — a `fn`
       body, a `trait` body, an `impl` body, or a `#[cfg(test)]` item. Such a
       declaration is not a credit (see `find_consts`), and its EXISTENCE is
       evidence that this spelling means more than one thing in this tree.
    """
    excluded_spans = excluded_spans or []
    names: set[str] = set()
    for m in STATIC_RE.finditer(src):
        names.add(m.group(1))
    for m in CONST_RE.finditer(src):
        if m.group(1) != "_" and _inside(m.start(), excluded_spans):
            names.add(m.group(1))
    return names


def resolve_consts(declared: list[str], shadows: frozenset[str]) -> frozenset[str]:
    """The const tier's credited name set: a bare name is credited only when
    the guard saw EXACTLY ONE module-scope `const` declaration of it across
    everything it scanned, and saw nothing that disqualifies the spelling.

    This is the same collision-drop discipline `find_type_aliases` already
    gets in `run_real_scan`, for the same reason: a spelling that resolves to
    more than one declaration has not been RESOLVED, and a guard that guesses
    which one is "real" is a guard that can be aimed. Dropping costs nothing
    but a fail-closed `UNPARSED` finding a human then reads; guessing costs a
    silent pass.
    """
    counts: dict[str, int] = {}
    for name in declared:
        counts[name] = counts.get(name, 0) + 1
    return frozenset(
        name for name, count in counts.items() if count == 1 and name not in shadows
    )


USE_HEAD_RE = re.compile(r"\buse\s+")
# `mod name;` / `mod name { ... }`. Rust 2018 UNIFORM PATHS let a `use` start
# at a module declared in the CURRENT module, with no `crate::`/`self::`
# prefix — `core/src/vault/mod.rs` really does write `pub use block::{...};`
# beside its `pub mod block;`. Such a root is intra-crate, so it must not be
# mistaken for a third-party crate name.
MOD_DECL_RE = re.compile(r"\bmod\s+([A-Za-z_][A-Za-z0-9_]*)\s*[;{]")


def top_level_mod_names(view: str) -> set[str]:
    """Names of the modules this file declares AT ITS TOP LEVEL (brace depth
    0 in the discovery view).

    Only a top-level `mod name;` / `mod name { }` puts `name` in scope as the
    first segment of a uniform-path `use`. A NESTED one does not, and treating
    it as though it did is a bypass rather than a nicety:
    `mod outer { pub mod std { } }` compiles happily alongside
    `use std::io::Error;` (no E0659 — the nested `std` is not in scope here),
    and an unscoped harvest would then read that `use` as intra-crate and stop
    withdrawing the bare `Error` credit. `mod thiserror;` and a `mod std;`
    written textually AFTER the `use` are the same class.

    Reads the DISCOVERY VIEW, not raw: this function GRANTS local-ness, i.e.
    it suppresses a withdrawal, so its failure mode must be to find FEWER
    modules, not more. See `foreign_use_names`.
    """
    opens = [i for i, c in enumerate(view) if c == "{"]
    closes = [i for i, c in enumerate(view) if c == "}"]
    names: set[str] = set()
    for m in MOD_DECL_RE.finditer(view):
        depth = bisect.bisect_left(opens, m.start()) - bisect.bisect_left(
            closes, m.start()
        )
        if depth == 0:
            names.add(m.group(1))
    return names


def _use_bound_names(tree: str, parent_last: str | None = None) -> set[str]:
    """Every name a `use` tree binds into its file's namespace.

    Handles `a::b::C`, `a::b::C as D`, `a::{B, c::{D, self}}` and `a::*`
    (which binds nothing this function can enumerate — see
    `foreign_use_names`).
    """
    tree = tree.strip()
    if not tree:
        return set()
    brace = tree.find("{")
    if brace != -1:
        prefix = tree[:brace].strip().rstrip(":").strip()
        close = tree.rfind("}")
        inner = tree[brace + 1 : close if close > brace else len(tree)]
        segs = [s.strip() for s in prefix.split("::") if s.strip()]
        last = segs[-1] if segs else parent_last
        out: set[str] = set()
        for part in split_top_level(inner):
            out |= _use_bound_names(part, last)
        return out
    if " as " in tree:
        alias = tree.split(" as ")[-1].strip()
        return {alias} if alias and alias != "_" else set()
    segs = [s.strip() for s in tree.split("::") if s.strip()]
    if not segs:
        return set()
    leaf = segs[-1]
    if leaf == "*":
        return set()
    if leaf == "self":
        if len(segs) >= 2:
            return {segs[-2]}
        return {parent_last} if parent_last else set()
    return {leaf}


def foreign_use_names(raw: str) -> frozenset[str]:
    """Bare names this FILE binds to something OUTSIDE the crate.

    Tree-global discovery registers a BARE spelling for every `core`-local
    thiserror enum, type alias and const it finds, and `is_data_free` then
    credits that spelling anywhere in the tree. That is a name-resolution
    claim, and a `use` statement is the one piece of evidence a
    pattern-matcher can actually read that CONTRADICTS it:

        use std::io::Error;          // in this file, `Error` is std's
        ...
        K1BareIoError(#[from] Error) // NOT crate::error::Error

    `core/src/error.rs` declares `pub enum Error` with `#[error(` in its
    body, so the bare spelling `Error` is registered tree-wide — which made
    that variant pass silently even though `std::io::Error` renders a
    filesystem path. Every name bound here is removed from the BARE-name
    credits when this file is scanned; qualified spellings
    (`crate::unlock::UnlockError`, `device_file::DeviceFileError`) are
    untouched, since a path cannot be shadowed by a `use`.

    Roots `crate` / `super` / `self` are intra-crate and are skipped: those
    resolve to items this guard does scan. So is a root naming a TOP-LEVEL
    module of the same file (`top_level_mod_names`) — Rust 2018 uniform paths
    make `pub use block::{BlockError, ...};` beside `pub mod block;` an
    ordinary intra-crate re-export, and treating it as a third-party crate
    named `block` produced four spurious findings in `core/src/vault/mod.rs`.
    TOP-LEVEL is load-bearing and was not always so: harvesting every
    `mod NAME` at any depth meant `mod outer { pub mod std { } }` — which
    compiles, because the nested `mod std` is not in scope at file top level —
    silently reclassified `use std::io::Error;` as intra-crate and handed the
    bypass back. Nothing under `core/src/**` collides today; the narrowing is
    for the code that has not been written yet.

    THIS PASS DELIBERATELY READS THE RAW SOURCE, not `discovery_view`.
    Everywhere else, a lexer bug that HIDES text loses a credit and so
    produces a finding — the fail-closed direction. This pass is the
    inversion: it WITHDRAWS credits, so hiding a `use` here would RESTORE
    one. Round 5's review demonstrated exactly that against the round-4
    scanner — `fn zz_q() -> char { '"' }` desynced the string state across the
    following `use std::io::Error;`, the `use` was blanked, the withdrawal
    never happened, and the bypass round 4 closed came back. Reading raw means
    the failure mode is OVER-withdrawal (a `use` written inside a comment or a
    string costs that file a bare-name credit it may not have needed), which
    is noise in the safe direction and cannot resurrect a credit. The
    `local_roots` half — which RESTORES credit — reads `discovery_view`
    instead, for the mirror-image reason.

    LIMIT: a glob (`use some_crate::*;`) binds names this function cannot
    enumerate. Every glob under `core/src/**` today is an intra-crate
    `use super::*;` inside a `#[cfg(test)] mod tests`, plus
    `use proptest::prelude::*;`. A future foreign glob would leave the
    bare-name credit in place — the same residual "not a real import
    resolver" risk the module docstring's LIMITS already records.

    BOTH HALVES OF THE UNION ARE LOAD-BEARING, AND BOTH ARE NOW PINNED.
    P38/P39 fail if this pass reads the BLANKED view alone (an unterminated
    block comment runs to end-of-input and swallows the `use`). P41 fails if
    it reads the RAW source alone (`use std::/*why*/io::Error;` — `/` is not
    in `USE_TREE_CHARS_RE`, so an inline `/*...*/` is rejected by
    `_looks_like_use_tree`'s character-class gate before its adjacency check
    ever runs, and the raw read returns nothing). Until #482 only the first
    direction was covered, and the uncovered one is the fail-OPEN direction:
    this is the single pass in this guard where HIDING text GRANTS trust
    rather than withholding it, so
    "blanking can only ever HIDE text, therefore discovery is fail-closed" —
    true for the three CREDIT registries — is FALSE here. That asymmetry is
    exactly what made the missing control easy to miss.
    """
    local_roots = LOCAL_USE_ROOTS | top_level_mod_names(discovery_view(raw))
    # Two independent reads, unioned. Neither is trusted alone:
    #   RAW  — nothing can hide a `use` from it, which is the property this
    #          pass needs; but `use` is also an ordinary English word, so
    #          every doc comment saying "we use the manifest" would bind
    #          nonsense. `_looks_like_use_tree` filters those out. It is a
    #          NOISE filter, not a security control: everything it rejects is
    #          recovered by the second read whenever it was really code.
    #   COMMENTS-BLANKED — no prose, so no filter needed. Catches the shapes
    #          the filter rejects, e.g. `use std::/*why*/io::Error;`.
    # Union, so a `use` has to escape BOTH to escape the withdrawal.
    names = _scan_use_bindings(raw, local_roots, require_use_tree=True)
    names |= _scan_use_bindings(
        strip_comments(raw), local_roots, require_use_tree=False
    )
    return frozenset(names)


# A `use` tree is punctuation and identifiers, never prose. Both checks are
# needed: the character class alone still admits "the manifest", and the
# adjacency check alone still admits "`Foo` here".
#
# `|` is in the class ONLY because `_looks_like_use_tree` substitutes it for
# the ` as ` renaming keyword before matching. Omitting it made the
# normalisation defeat the very check it exists to enable — see there.
USE_TREE_CHARS_RE = re.compile(r"^[A-Za-z0-9_:{}*,|\s]+$")
USE_TREE_PROSE_RE = re.compile(r"[A-Za-z0-9_]\s+[A-Za-z0-9_]")


def _looks_like_use_tree(tree: str) -> bool:
    """Whether `tree` could be a Rust use tree rather than English prose.

    Two identifier-ish words separated by whitespace never occur in a use
    tree — except across the ` as ` renaming keyword, which is normalised
    away first. `use std :: io :: Error;` (spaces around `::`) is valid Rust
    and still passes, because a colon is not an identifier character.

    The `|` substituted for ` as ` MUST be a member of `USE_TREE_CHARS_RE`,
    or the normalisation inverts its own purpose: it was not, so EVERY
    `use foo::Bar as Baz;` failed the character-class check and this
    function returned False — the exact opposite of what the paragraph above
    claims. Measured over `core/src/**`, that left the raw read withdrawing
    52 names against the blanked read's 61 (union 67), so 15 withdrawals —
    every `use ... as ...` in the tree — rested on the blanked read ALONE.
    That read is the one a lexer desync can silently disarm, and the whole
    point of the union in `foreign_use_names` is that no single read is
    trusted. With `|` in the class the raw read withdraws all 67, a strict
    superset of the union, and the real scan's verdict is unchanged.
    """
    collapsed = " ".join(tree.split()).replace(" as ", "|")
    if not collapsed or not USE_TREE_CHARS_RE.match(collapsed):
        return False
    return not USE_TREE_PROSE_RE.search(collapsed)


def _scan_use_bindings(
    src: str, local_roots: frozenset[str], require_use_tree: bool
) -> set[str]:
    """Every foreign name bound by a `use` in `src` — see `foreign_use_names`."""
    names: set[str] = set()
    n = len(src)
    for m in USE_HEAD_RE.finditer(src):
        depth, j = 0, m.end()
        while j < n:
            c = src[j]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth < 0:
                    break
            elif c == ";" and depth == 0:
                break
            j += 1
        tree = src[m.end() : j]
        if require_use_tree and not _looks_like_use_tree(tree):
            continue
        root = tree.lstrip().lstrip(":").split("::")[0].split("{")[0].strip()
        if not root or root in local_roots:
            continue
        names |= _use_bound_names(tree)
    return names


def module_path_segments(path_label: str) -> list[str]:
    """The Rust module path implied by a file's location under `core/src/`.

    `core/src/unlock/device_file.rs` -> `["unlock", "device_file"]`;
    `core/src/unlock/mod.rs` -> `["unlock"]` (a `mod.rs` names its PARENT
    module, not a `mod` submodule of itself); `core/src/error.rs` ->
    `["error"]`. Returns `[]` for anything outside `core/src/` (e.g. a
    `--self-test` control, which has no real file path at all).
    """
    p = Path(path_label)
    try:
        rel = p.relative_to(Path("core") / "src")
    except ValueError:
        return []
    parts = list(rel.with_suffix("").parts)
    if parts and parts[-1] == "mod":
        parts = parts[:-1]
    return parts


def discover_declarations(
    raw: str, path_label: str | None = None
) -> tuple[frozenset[str], dict[str, str], list[str], frozenset[str]]:
    """Four textual facts this guard can prove about a chunk of Rust source
    without a real parser — the tier-2/3/4 inputs `is_data_free` and
    `scan_source`'s placeholder resolution need.

    1. Which `enum`s it defines that are THEMSELVES scanned by this guard,
       i.e. contain at least one `#[error(...)]` attribute in their body. A
       field naming one of these is data-free BY RECURSION (see THE RULE in
       the module docstring) — this guard will already fail at that enum's
       own definition if any of ITS variants interpolates a non-data-free
       field, so re-flagging the forward adds no signal, only allowlist
       noise the approved design explicitly wants to avoid.
    2. Which `type X = Y;` aliases it declares, one level deep. Declarations
       found inside a NON-MODULE block (a trait's or an `impl`'s associated
       type, an alias local to a `fn` body) are excluded — see
       `find_type_aliases` / `non_module_block_spans`.
    3. Which module-scope `const NAME: Type = value;` declarations it has,
       one entry per declaration — see `find_consts` for why `static` is
       deliberately excluded, why non-module scopes and `#[cfg(test)]` items
       are excluded, and `resolve_consts` for the collision-drop the repeats
       feed.
    4. Which bare names DISQUALIFY themselves from (3) — every `static`, and
       every `const` in an excluded scope. See `find_const_shadows`.

    EVERY one of these runs over `discovery_view(raw)`, in which string
    literal CONTENTS are blanked as well as comments. Text inside an
    `#[error("...")]` message is not a declaration, and treating it as one
    let an author self-authorise their own placeholder from inside the very
    message under test — see `discovery_view` and `lex_spans`.

    For each discovered enum/alias name, three spellings are registered so a
    reference site is recognised regardless of how it's qualified: the bare
    name (works for a same-module or `use`-imported reference, and is the
    ONLY spelling available when `path_label` is `None`, e.g. a self-test
    control that defines-and-uses a nested type in one string); the
    immediate parent module segment (`device_file::DeviceFileError` — the
    relative sibling-module spelling this codebase actually uses); and the
    full `crate::`-rooted path (`crate::unlock::UnlockError`). This is NOT a
    `use`-import resolver (see LIMITS): a bare or aliased reference to a
    type from OUTSIDE `core/src/**` is never registered here, so
    `std::io::Error` cannot collide with a same-named local type UNLESS the
    reference site itself drops the `std::` qualification down to a bare
    name that happens to match a local one — an acknowledged, narrow
    residual risk, not something this function tries to close.

    `const` names are registered BARE ONLY (see `find_consts`) — no
    qualified spellings, since a format-string capture can never be
    qualified.

    `run_real_scan` aggregates the RESULT of this function across every file
    under `core/src/**` — see that function's docstring for how a bare-name
    alias or `const` COLLISION across files is dropped rather than resolved,
    and why `local_error_enums` does not need the same treatment. Per-file
    `use`-shadowing is applied separately, at scan time — see
    `foreign_use_names`.
    """
    src = discovery_view(raw)
    segments = module_path_segments(path_label) if path_label else []
    # ONE exclusion set for ALL THREE registries. Round 4 applied the
    # `#[cfg(test)]` half to consts only, which left the enum and alias
    # registries able to be vouched for by test-only code: a
    # `#[cfg(test)] mod tests { enum ZzShared { #[error("code {0}")] A(u32) } }`
    # registered `ZzShared` tree-wide, and a SHIPPED `pub struct ZzShared {
    # pub raw: String }` in another file then rode on it. A test-only
    # declaration is not part of the shipped crate and must not vouch for
    # anything a shipped `#[error("...")]` renders — that is a property of the
    # DECLARATION, not of which registry happens to hold it.
    excluded = non_module_block_spans(src) + cfg_test_spans(src)

    def spellings(name: str) -> list[str]:
        out = [name]
        if segments:
            out.append(f"{segments[-1]}::{name}")
            out.append("crate::" + "::".join(segments) + f"::{name}")
        return out

    local_error_enums: set[str] = set()
    for m in ENUM_RE.finditer(src):
        if _inside(m.start(), excluded):
            continue
        name = m.group(1)
        brace = src.find("{", m.end())
        if brace == -1:
            continue
        body, _ = balanced_braces(src[brace:])
        if "#[error(" in body:
            local_error_enums.update(spellings(name))

    aliases: dict[str, str] = {}
    for alias_name, rhs in find_type_aliases(src, excluded).items():
        for spelling in spellings(alias_name):
            aliases[spelling] = rhs

    consts = find_consts(src, excluded)
    const_shadows = find_const_shadows(src, excluded)

    return frozenset(local_error_enums), aliases, consts, frozenset(const_shadows)


def enclosing_enum_names(raw: str) -> list[tuple[int, int, str]]:
    """`[(body_start, body_end, enum_name)]` for every `enum NAME { ... }`
    body span in `raw` (#480 review finding 2).

    Recovers the OWNING enum's name for a variant `scan_source` locates via
    `VARIANT_RE`, so rule E2's allowlist key can include it —
    `SettingsWarning::Corrupt` and `SettingsParseError::Corrupt` are the
    LIVE instance of two DIFFERENT types sharing a same-named,
    same-shaped variant, and collided on the bare key `Corrupt { ... }`
    before this existed: one allowlist entry would have silenced both,
    exactly the cross-exemption failure the whole-attribute key convention
    exists to prevent (see `scan_source`'s `key_text` comment).

    Computed over the DISCOVERY VIEW (`discovery_view(raw)`, comments AND
    string contents blanked) rather than `strip_comments` — the same
    self-authorisation concern `discover_declarations`'s own `ENUM_RE` walk
    guards against (P22): an `#[error("... enum Fake { ... } ...")]`
    message must not be read as a real enum declaration. Character offsets
    are valid against ANY of this module's views regardless
    (`check_view_invariants` pins that every view preserves length and line
    count), so the spans this returns are directly usable against
    `scan_source`'s own `strip_comments`-based `m.start()` positions.

    A WRONG owner name here can only ever produce a MISLEADING allowlist
    key — unlike `local_error_enums` (tier 2), this registry grants no
    safety credit; `is_bridge_field_safe` never consults it. The
    discovery-view choice is therefore belt-and-braces, not a soundness
    requirement, but it costs nothing and keeps the key accurate.
    """
    view = discovery_view(raw)
    spans: list[tuple[int, int, str]] = []
    for m in ENUM_RE.finditer(view):
        brace = view.find("{", m.end())
        if brace == -1:
            continue
        body, _ = balanced_braces(view[brace:])
        spans.append((brace, brace + len(body), m.group(1)))
    return spans


def _owning_enum_name(spans: list[tuple[int, int, str]], pos: int) -> str | None:
    """The name of the enum span containing `pos`, or `None` if `pos` is not
    inside any (a struct-shaped error, whose `STRUCT_RE` match already
    carries its own name — no owner lookup needed). Rust does not allow one
    `enum` to be declared inside another's body, so `pos` is inside at most
    one span; the first (only) match wins."""
    for start, end, name in spans:
        if start <= pos < end:
            return name
    return None


def discovery_cfg_test_spans(raw: str) -> list[tuple[int, int]]:
    r"""`cfg_test_spans`, computed over the DISCOVERY VIEW rather than
    `strip_comments`.

    `CFG_TEST_RE`'s own docstring states its `\btest\b` match is safe "on
    the DISCOVERY VIEW specifically: string literals are blanked there" —
    over `strip_comments` alone, a hypothetical
    `#[cfg(feature = "test-utils")]` would false-positive-match and exclude
    a SHIPPED declaration from a sweep, which is the fail-OPEN direction for
    a discovery pass that only ever REMOVES a candidate from being checked.
    `scan_bridge_plain_declarations` and `discover_error_struct_names`
    locate their own candidates on `strip_comments` (matching the module
    docstring's "comments-blanked view" — the same view `scan_source` uses
    to locate `#[error(`), but every span this module computes preserves
    LENGTH and LINE COUNT (`check_view_invariants` pins that), so an offset
    valid against ONE view is valid against ANY of them; there is no need
    to re-derive a candidate's own match against `discovery_view`, only to
    compute the EXCLUSION spans against it.

    Despite the name, this is general-purpose — not bridge-specific — and
    is used for BOTH scan roots wherever a `#[cfg(test)]` exclusion is
    needed against test-only content vouching for something shipped.

    CREDIT-registry polarity: over-matching drops a declaration, so fewer
    names vouch for anything. A fail-OPEN skip-list consumer must call
    `discovery_cfg_test_spans_strict` instead.
    """
    return cfg_test_spans(discovery_view(raw))


def discovery_cfg_test_spans_strict(raw: str) -> list[tuple[int, int]]:
    """`discovery_cfg_test_spans` under `CFG_TEST_STRICT_RE` (#496).

    For every consumer that treats these spans as a SKIP LIST — rules E2,
    E3's construction sites, E5, and `discover_error_struct_declarations` —
    an over-match means NOT SCANNING a shipped item. Read
    `CFG_TEST_STRICT_RE` for the three compiling spellings that silenced a
    real violation before this split existed.
    """
    return cfg_test_spans(discovery_view(raw), CFG_TEST_STRICT_RE)


# Needed by `discover_error_struct_declarations` below (#486 task 3: moved
# here verbatim because it moved). `STRUCT_RE`, defined just below, stays
# here for the same reason. Only `rules/e1.py`'s `scan_source` imports these
# two back (#486 task 4) — `_bridge_plain_enum_variant_findings`
# (`rules/e2.py`) does not use either; it uses `skip_attributes` /
# `split_top_level` instead, which moved to `payload_guard.parsing` in the
# same task (see this module's own docstring for why).
ERROR_ATTR_RE = re.compile(r"#\[error\(", re.MULTILINE)

# A `thiserror` error can also be a STRUCT — one shape, not an enum with
# variants — with `#[error("...")]` attached directly to `pub struct Name {
# ... }` / `pub struct Name(...);` rather than to a variant. Not used in
# `core/src` today, but nothing in the language prevents it.
STRUCT_RE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?struct\s+([A-Za-z_][A-Za-z0-9_]*)")


def discover_error_struct_declarations(raw: str) -> list[tuple[str, int, int]]:
    """`[(name, attr_start, decl_end)]` for every `#[error("...")]`-
    decorated STRUCT (thiserror's other error shape — the attribute
    decorates the struct declaration ITSELF, not a variant inside a body)
    in `raw`. `attr_start`/`decl_end` are character offsets spanning from
    the `#[error(` attribute through the END OF THE STRUCT'S NAME.

    `discover_declarations`'s `local_error_enums` tier does not see these —
    it only walks `ENUM_RE` bodies. This is a second, narrow pass reusing
    the exact `#[error(` + `STRUCT_RE` recognition `scan_source` itself
    performs. `discovery_cfg_test_spans` excludes a match starting inside a
    `#[cfg(test)]`-gated item — a test-only thiserror struct must not vouch
    for a SHIPPED plain struct sharing its name.

    RUNS OVER THE DISCOVERY VIEW (comments AND string contents blanked).
    ONE walk feeds TWO consumers with DIFFERENT keying needs (#480 review
    round 2, NEW-1), and the two need different things from the view:

    - `scan_bridge_plain_declarations`'s "already swept" struct check wants
      POSITIONS. A bare-name registry there was proven fail-open by two
      rustc-verified witnesses: (a) two DIFFERENT structs sharing a bare
      name in different modules — `mod a`'s real thiserror `DupError`
      incorrectly vouched for `mod b`'s real, DIFFERENT, plain `DupError`,
      letting its `leak: String` field escape; (b) self-authorisation — an
      `#[error("x")] pub struct LeakError {}` written INSIDE a raw-string
      `const`'s VALUE. Positions alone close BOTH, so this consumer does
      not depend on which view discovers the declaration.
    - `scanned_error_type_names` (rule E4, via `discover_error_struct_names`
      below) wants bare NAMES, and a name registry IS spoofable by witness
      (b): the fake declaration's NAME is indistinguishable from a real
      one's once the position is discarded, so an author could authorise
      `impl GatedDetail for crate::x::LeakError` from inside a string
      literal. Task 2 flagged this as an inert residual because E4 had no
      consumer yet; E4 now has one, so the walk moved to `discovery_view`,
      where a declaration written inside a literal simply is not there.
      `BP19` pins it.

    Blanking string contents can only ever REMOVE a declaration from this
    registry, and both consumers fail closed on a missing entry: the sweep
    consumer double-reports a struct (noise), and E4 denies an impl
    (finding). There is no direction in which the narrower view grants
    anything.

    One walk means both consumers see the identical set of REAL
    declarations, rather than two independently-maintained (and
    independently-buggable) scans of the same shape — the #475 lesson
    this file's own docstring already cites for `is_comment_line`.

    The span ENDS AT THE STRUCT NAME, not at end-of-line: two declarations
    written on ONE line (`#[error("x")] pub struct AError { .. } pub struct
    BError { .. }`) would otherwise put the SECOND one inside the FIRST's
    "already swept" span, silently exempting it from the sweep. `BP22`
    pins it.
    """
    src = discovery_view(raw)
    # STRICT: this exclusion removes a candidate from being SWEPT (#496).
    excluded = discovery_cfg_test_spans_strict(raw)
    out: list[tuple[str, int, int]] = []
    for m in ERROR_ATTR_RE.finditer(src):
        if _inside(m.start(), excluded):
            continue
        _, after = balanced_slice(src, m.end() - 1)
        tail_raw = src[after:]
        if tail_raw.lstrip().startswith("]"):
            close_off = tail_raw.find("]") + 1
            tail = tail_raw[close_off:]
            tail_start = after + close_off
        else:
            tail = tail_raw
            tail_start = after
        skipped = skip_attributes(tail)
        skipped_start = tail_start + (len(tail) - len(skipped))
        line_start = 0
        for line in skipped.splitlines(keepends=True):
            if line.strip():
                sm = STRUCT_RE.match(line)
                if sm:
                    line_abs_start = skipped_start + line_start
                    out.append((sm.group(1), m.start(), line_abs_start + sm.end()))
                break
            line_start += len(line)
    return out


def discover_error_struct_names(raw: str) -> frozenset[str]:
    """Bare names of every `#[error("...")]`-decorated STRUCT in `raw` —
    feeds `scanned_error_type_names` (rule E4's registry — see
    `discover_scanned_error_type_names`) alongside the bare spellings of
    `local_error_enums`. See `discover_error_struct_declarations`, this
    function's shared producer, for the position-vs-name keying rationale
    and for why that producer moved to the DISCOVERY VIEW once this
    NAME-only projection acquired a security-relevant consumer.
    """
    return frozenset(name for name, _, _ in discover_error_struct_declarations(raw))


def discover_local_detail_decoys(
    sources: list[tuple[str, str]], exempt_label: str | None
) -> frozenset[str]:
    """Bare gated-carve-out type spellings SHADOWED by a locally-declared
    `struct|enum|union|type` of the same name, anywhere in `sources` OTHER
    THAN `exempt_label` (#500 fix round 2, review finding "Important 2").

    `is_bridge_field_safe`'s gated-field carve-out (rule E2) matches a
    field's declared type by SPELLING alone — `Detail` under a
    `GATED_FIELD_NAMES` name is accepted on the strength of the bridge's
    OWN `pub struct Detail(String)` in `error/detail.rs`, whose private
    inner field makes a runtime `String` unrepresentable there. That
    guarantee holds only while "a field spelled `Detail`" and "the type
    `secretary_ffi_bridge::error::detail::Detail`" are the same thing. A
    SECOND, same-spelled declaration anywhere else in the root —

        pub struct Detail(pub String);      // any OTHER bridge file
        ...
        Boom { detail: Detail },            // credited identically.
                                             // Zero findings before this fix.

    — is textually indistinguishable from the real one to a spelling-only
    match, and rule E3's OWN `SAFE_PARAM_TYPES`/`LOCAL_DETAIL_TYPE_RE` check
    (`sanctioned_constructor_names`) does not help here: that check only
    ever inspects the ONE `detail_src` file (the root's sanctioned module),
    never the rest of the root, because its job is "is a CONSTRUCTOR call
    sanctioned", not "is this DECLARATION's type spelling trustworthy".

    Reuses `LOCAL_DETAIL_TYPE_RE` rather than a second, independently-
    maintained matcher — the two rules drifted out of step exactly once
    already (#500 fix round 1 closed E3's copy of this hole; this closes
    E2's). `exempt_label` is the root's own `detail_module_rel` (or `None`
    for a root with none, e.g. `core`): the bridge's OWN legitimate
    declaration must not shadow itself. STRICT `#[cfg(test)]` exclusion
    (`discovery_cfg_test_spans_strict`), not the permissive `cfg_test_spans`
    `discover_declarations` uses for its CREDIT registries — this registry
    DENIES, so an over-matched skip here would be fail-OPEN (hide a real
    decoy) rather than fail-closed (drop a credit), the same STRICT-vs-
    permissive split `scan_bridge_plain_declarations` already draws for its
    own (E2) sweep. `non_module_block_spans` excludes a decoy declared
    inside a `fn` body — a local item, in scope only where it is written,
    not a root-wide shadow — mirroring `find_type_aliases`'s identical
    exclusion for an associated `type`.

    Returns `frozenset({"Detail"})` the moment ANY qualifying match is
    found (short-circuits — `LOCAL_DETAIL_TYPE_RE` names exactly one
    spelling today), else `frozenset()`.

    LIMITS (#500 fix round 2 review) — four shapes this function does NOT
    catch, all defence-in-depth gaps rather than live leaks: in every one,
    rule E3's construction-site gate independently denies the actual
    CONSTRUCTION of a value from the decoy, because the decoy's own
    constructor (if any) still has to survive `SAFE_PARAM_TYPES`/
    `sanctioned_constructor_names`'s signature gate to be usable at all —
    verified by execution, not merely reasoned about.

    1. **Decoy and the field referencing it both inside `#[cfg(test)]`.**
       Excluded on purpose (see above) — the decoy is non-shippable code,
       so nothing crosses the FFI regardless of what E2 does with it here.
    2. **Decoy and the referencing field both inside ONE function body.**
       `non_module_block_spans` excludes it on purpose too — a fn-local
       `struct`/`enum`/`union`/`type` cannot be named from outside that
       function, so it cannot reach an FFI error type's field declaration
       (which is always module-scope) regardless of this function's
       verdict.
    3. **Decoy declared in a `mod` NESTED INSIDE the exempt file itself**
       (`error/detail.rs`'s own submodule, e.g. `mod inner { pub struct
       Detail(pub String); }`). `exempt_label` is a PATH match on the
       whole FILE, not a scope match on the module inside it — a
       genuinely different type at `crate::error::detail::inner::Detail`
       is invisible to a spelling-only carve-out exactly like an IMPORTED
       decoy is (see the module's own RESIDUAL paragraph on
       `LOCAL_DETAIL_TYPE_RE`'s `use`-blind spot): reaching it from a
       gated field elsewhere in the root needs a `use`, which this
       function does not resolve any more than `SAFE_PARAM_TYPES` does.
    4. **`pub struct r#Detail(pub String);`** — a RAW IDENTIFIER. This
       compiles (rustc-verified), and `r#Detail` names the exact same
       identifier `Detail` does as far as rustc's name resolution is
       concerned — the `r#` prefix is purely an ESCAPE for using a
       keyword-shaped token as an identifier, invisible to anything that
       actually resolves the name. `LOCAL_DETAIL_TYPE_RE` is a TEXTUAL
       match on the four bare keyword-plus-`Detail` shapes and has no
       notion of the `r#` escape, so it does not fire on this spelling —
       the one shape here that would surprise a reader, since the claim
       above is specifically about NAMES, and rustc agrees this name
       matches.
    5. **AN IMPORT, in BOTH its spellings** — the renaming
       `use std::string::String as Detail;` and the plain
       `use some_other_crate::Detail;`. This is the residual that BREAKS
       the pattern of 1-4, and it is stated last because it is the only
       one where rule E3's construction-site gate does NOT independently
       deny: verified by execution, `use std::string::String as Detail;`
       in a bridge file, a new `#[error("{detail}")] Boom { detail:
       Detail }`, and an E3 arm-4 parameter re-wrap
       (`fn f(detail: Detail) -> E { E::Boom { detail } }`) together
       produce ZERO findings — arm 4 accepts the same-name re-wrap
       precisely because it trusts the DECLARED type, which here is a
       `String` wearing the newtype's name. An import DECLARES nothing in
       this root, so no textual matcher sited on declarations can see it;
       closing it needs real name resolution. This is the same aliasing
       blind spot rule E4 records for `GatedDetail`, and it is the reason
       the entry point's "THE #500 NEWTYPE" section states the compiler
       guarantee as PER DECLARATION rather than per root. Tracked by
       #512 (this and the `GatedDetail` twin, one root cause): the 27 fields
       that ARE the bridge's real `Detail` cannot hold a `String`; a
       28th, newly written against an aliased import, can.
    """
    for label, raw in sources:
        if exempt_label is not None and label.replace("\\", "/") == exempt_label:
            continue
        view = discovery_view(raw)
        excluded = non_module_block_spans(view) + discovery_cfg_test_spans_strict(raw)
        for m in LOCAL_DETAIL_TYPE_RE.finditer(view):
            if not _inside(m.start(), excluded):
                return frozenset({"Detail"})
    return frozenset()


def _discover_tier_inputs(
    sources: list[tuple[str, str]],
) -> tuple[frozenset[str], dict[str, str], frozenset[str], frozenset[str]]:
    """`run_real_scan`'s Pass 1, factored out so it can run ONCE PER SCAN
    ROOT (#480): discover every thiserror enum, type alias, and const across
    THE WHOLE `sources` list before classifying anything — a field in
    vault/mod.rs can reference an enum defined in vault/record.rs, and a
    format string in vault/block.rs can capture a const imported from
    crypto/kem.rs, so a per-file-only discovery pass would miss the
    cross-file case entirely.

    Aliases are aggregated defensively: a bare (or qualified) spelling that
    resolves to DIFFERENT right-hand sides in different files is a name
    COLLISION, not one alias, and a plain last-write-wins dict.update merge
    means an unrelated, later-sorted file adding e.g. `type Foo = [u8; 16];`
    can silently launder an EXISTING, unsafe `type Foo = String;` defined
    elsewhere into a pass — proven live in review. A colliding spelling is
    dropped from the RESOLVABLE set (the returned `aliases` dict) entirely,
    so a TIER-3 lookup against it default-denies instead of guessing which
    definition was "real."

    The 4th return value, `alias_candidate_names`, is the RAW spelling set
    BEFORE that collision-drop — every name EVER seen as a `type X = Y;`
    LHS anywhere in `sources`, resolved or not (#500 fix round 2, review
    finding "Important 1"). This is deliberately NOT the same set as
    `frozenset(aliases)`: collision-drop is fail-CLOSED for tier-3 credit
    (a dropped name loses a resolution, denying more) but was found to be
    fail-OPEN when the SAME resolved dict was reused as a gated-field-
    carve-out DENY trigger (`is_bridge_field_safe`'s alias-shadow check,
    #500 fix round 1) — a colliding name resolves to NOTHING, so "member of
    the resolved dict" stops meaning "shadowed" the moment a second,
    conflicting `type Detail = ...;` appears anywhere else in the root,
    silently un-denying the very spelling the collision makes LESS
    trustworthy, not more. Verified by execution: the fix-round-1 fixture
    alone produced 2 findings; adding a second bridge-root file containing
    only `type Detail = Vec<u8>;` took it to zero. A shadow claim is "this
    spelling means more than one thing here", which the RAW candidate set
    establishes regardless of collision; the RESOLVED dict answers a
    different question ("what does it unambiguously resolve to") that only
    tier-3 credit needs.

    `const` names get the SAME collision-drop, applied by `resolve_consts`
    over the flat cross-file declaration list: a bare spelling this guard
    saw declared more than once, or saw disqualified by a `static` /
    excluded-scope declaration anywhere, is not credited. An earlier round
    unioned them instead, on the argument that "a const's safety comes from
    the compiler, not its value." The premise is true; the conclusion does
    not follow, because the guard's operative claim is not "consts are
    safe" but "this placeholder RESOLVES TO a const" — a name-resolution
    claim a bare-name union does not establish. `static` is the concrete
    counter-witness (`find_const_shadows`), and it was reproduced
    end-to-end: a `static LEAKY_NAME: LazyLock<String>` capture that
    correctly denied on its own went silent the moment an unrelated,
    later-sorted file added `pub const LEAKY_NAME: usize = 16;`.

    `local_error_enums` still does NOT get the treatment, for the reason
    the LIMITS block records: it is a pure membership set, and any enum
    registered in it is by construction a real thiserror enum this guard
    scans, so two same-named local enums are both soundly "safe by
    recursion." Its bare-name risk is a FOREIGN collision, and that is
    handled per-file by `foreign_use_names` in Pass 2.

    CALLED ONCE PER ROOT (core, bridge) — never merged: a bridge-local alias
    or const must not vouch for a core field, or vice versa. Core's own
    call site passes exactly the same `sources` list it always has, so core
    findings stay byte-identical to before this function existed.
    """
    local_error_enum_names: set[str] = set()
    alias_candidates: dict[str, set[str]] = {}
    declared_consts: list[str] = []
    const_shadow_names: set[str] = set()
    for label, raw in sources:
        enums, file_aliases, file_consts, file_shadows = discover_declarations(
            raw, label
        )
        local_error_enum_names.update(enums)
        for spelling, rhs in file_aliases.items():
            alias_candidates.setdefault(spelling, set()).add(rhs)
        declared_consts.extend(file_consts)
        const_shadow_names.update(file_shadows)
    local_error_enums: frozenset[str] = frozenset(local_error_enum_names)
    aliases = {
        spelling: next(iter(rhs_set))
        for spelling, rhs_set in alias_candidates.items()
        if len(rhs_set) == 1
    }
    consts = resolve_consts(declared_consts, frozenset(const_shadow_names))
    alias_candidate_names = frozenset(alias_candidates)
    return local_error_enums, aliases, consts, alias_candidate_names


def discover_scanned_error_type_names(
    core_sources: list[tuple[str, str]],
    bridge_sources: list[tuple[str, str]],
    core_enums: frozenset[str],
    bridge_enums: frozenset[str],
) -> frozenset[str]:
    """Every `#[error]`-bearing ENUM or STRUCT name this guard scans, under
    EITHER root (#480) — the registry rule E4 uses to verify
    that an `impl GatedDetail for X` in `error/detail.rs` names a type this
    guard itself independently checks (X's last path segment must be a
    member): the same "safe by recursion" argument tier 2 of `is_data_free`
    already makes for a FIELD reference to a local error enum.

    ENUM names come from `core_enums` / `bridge_enums` — already computed by
    `_discover_tier_inputs` (`discover_declarations`'s `local_error_enums`
    tier) — filtered down to BARE spellings only: a qualified spelling like
    `crate::vault::VaultError` names the SAME type as `VaultError`, and this
    registry is meant to be checked against a bare LAST PATH SEGMENT, so the
    qualified duplicates add nothing. STRUCT names are NOT part of that
    tier at all (`discover_declarations` only walks `ENUM_RE` bodies) and
    come from `discover_error_struct_names` instead, run over every file
    under both roots.

    Consumed by rule E4 only (`scan_bridge_gated_detail_impls`), never by
    E1/E2/E3 — an impl's target is a TYPE, not a field, so none of the
    field-classification tiers ever look here.
    """
    names = {n for n in core_enums if "::" not in n}
    names |= {n for n in bridge_enums if "::" not in n}
    for _, raw in core_sources:
        names |= discover_error_struct_names(raw)
    for _, raw in bridge_sources:
        names |= discover_error_struct_names(raw)
    return frozenset(names)

