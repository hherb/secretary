from __future__ import annotations

import re
from dataclasses import dataclass

from .config import DATA_FREE_TYPES, GATED_FIELD_NAMES


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    source_line: str
    variant: str
    field: str
    field_type: str
    # The allowlist's rule column, REQUIRED (#496 — it used to default to
    # `"E1"`). The allowlist key is `f"{path}\t{rule}\t{source_line}"`, so
    # the column is what scopes an exception to the rule that raised it. A
    # default silently undid that: a future rule module forgetting
    # `rule="E6"` would report under E1's wording AND be matchable — hence
    # silenceable — by an existing **E1** allowlist entry on the same path
    # and text. Every producer now names its own rule.
    #
    # The column also keeps the file format byte-identical to the two shell
    # guards' allowlists, which lets `scripts/lib/hygiene-allowlist.sh
    # ::allowlisted` parse this file unchanged —
    # `core/tests/error_payload_hygiene_parity.rs` exercises exactly that
    # claim.
    rule: str


# `[u8; 16]`, `[u8; RECORD_UUID_LEN]` — fixed-size numeric arrays.
ARRAY_RE = re.compile(r"^\[[ui](?:8|16|32|64|128|size);[^\]]+\]$")
# `Option<T>` is data-free exactly when `T` is.
OPTION_RE = re.compile(r"^Option<(.+)>$")
# A field-level attribute prefix (`#[from]`, `#[source]`) glued onto the raw
# type text by `parse_fields`, which does not separate attributes from types.
FIELD_ATTR_RE = re.compile(r"^#\[[^\]]*\]\s*")
# A field-level VISIBILITY modifier: `pub`, `pub(crate)`, `pub(super)`,
# `pub(self)`, `pub(in some::path)`. Requires either a parenthesised
# restriction or trailing whitespace, so it never bites an identifier that
# merely STARTS with `pub` (`pub_key`, `published`).
VISIBILITY_RE = re.compile(r"^pub(?:\s*\([^)]*\))?(?:\s+|(?=\s*$))")


def strip_visibility(text: str) -> str:
    """Strip a leading field-level visibility modifier.

    A `thiserror` error's fields may be `pub` — nothing in the language or
    in `thiserror` forbids it, and a struct-shaped error whose fields the
    crate exposes is ordinary Rust. `parse_fields` split on the first `:`
    and took the name side verbatim, so `pub struct X { pub index: usize }`
    produced a field literally named `"pub index"`; the `{index}` capture
    then matched nothing and the attribute fell through to a spurious
    `UNPARSED`. Fail-closed, so not a leak — but a guard that cries wolf on
    valid code is a guard whose findings get waved through.
    """
    text = text.strip()
    m = VISIBILITY_RE.match(text)
    return text[m.end() :].strip() if m else text


def normalize_type(ty: str) -> str:
    """Collapse whitespace and strip a leading field-level attribute, then a
    leading visibility modifier.

    `parse_fields` hands back the raw text after the field's `:` — for
    `Record(#[from] RecordError)` that is `"#[from] RecordError"`, not
    `"RecordError"`. A TUPLE field's visibility lands on the same side
    (`pub struct E(pub String)` -> `"pub String"`), so it is stripped here;
    a STRUCT field's lands on the name side and is stripped by `parse_fields`
    instead. Path qualification (`crate::unlock::UnlockError`,
    `device_file::DeviceFileError`) is deliberately left untouched: it is
    exactly the signal `discover_declarations`'s spellings rely on to tell a
    `core`-local reference from a foreign one (`std::io::Error`) apart —
    collapsing to the bare final segment would make the two indistinguishable
    and let a foreign type piggyback on a same-named local one.
    """
    ty = " ".join(ty.split())
    m = FIELD_ATTR_RE.match(ty)
    if m:
        ty = ty[m.end() :]
    return strip_visibility(ty)


def strip_field_attrs(text: str) -> str:
    """Strip any number of leading `#[...]` field-level attributes (and
    surrounding whitespace) from `text`.

    A struct field's attribute precedes its NAME (`#[source]\\n source: T`);
    a tuple field's attribute precedes its TYPE (`#[from] T`, handled by
    `normalize_type` instead). `parse_fields` calls this on the NAME side of
    a struct field — CRITICAL round-2 finding 1: `parse_fields` used to split
    on the first `:` and take the name side VERBATIM, so
    `#[source]\\n    source: std::io::Error` produced a field literally named
    `"#[source]\\n    source"`. The placeholder `{source}` then never matched
    any parsed field name, and the whole variant silently passed — live at
    `core/src/vault/mod.rs:157` and `core/src/sync/error.rs:35`.
    """
    text = text.strip()
    while True:
        m = FIELD_ATTR_RE.match(text)
        if not m:
            return text
        text = text[m.end() :].strip()


def _is_data_free_core(
    ty: str,
    local_error_enums: frozenset[str],
    denied: frozenset[str] = frozenset(),
) -> bool:
    """Tiers 1 and 2 only: literal data-free types, and `core`-local error
    enums this guard itself scans. Deliberately excludes tier 3 (alias
    resolution) — it is the target `is_data_free` calls an alias's
    right-hand side through, so an alias chain (`type A = B; type B = C;`)
    gets exactly one hop of credit, not an unbounded one.

    `denied` is checked FIRST and denies unconditionally, at EVERY tier and
    through the `Option<T>` recursion. Two independent sources feed it, both
    of which mean "this spelling does not resolve to the thing the tier
    below assumes":

    1. `foreign_use_names` — a bare spelling this file `use`s from outside
       the crate is not the local type that happens to share its name.
    2. `alias_shadowed_names` — a spelling a discovered `type X = Y;` alias
       shadows out of tier 1 or tier 2.
    """
    ty = normalize_type(ty)
    if ty in denied:
        return False
    if ty in DATA_FREE_TYPES:
        return True
    if ARRAY_RE.match(ty.replace(" ", "")):
        return True
    inner = OPTION_RE.match(ty)
    if inner:
        return _is_data_free_core(inner.group(1), local_error_enums, denied)
    return ty in local_error_enums


def alias_shadowed_names(
    aliases: dict[str, str] | None, local_error_enums: frozenset[str]
) -> frozenset[str]:
    """Spellings that a discovered `type X = Y;` alias SHADOWS out of an
    independent credit tier, and which must therefore stop being trusted.

    `DATA_FREE_TYPES` (tier 1) and `local_error_enums` (tier 2) are keyed on
    the type name AS WRITTEN. `is_data_free` consults them BEFORE the alias
    table, so a `type` alias that reuses one of their names was — until this
    drop existed — invisible: the tier-1/2 hit answered "safe" and the alias
    was never looked up.

        type CborFault = String;          // one file, no collision, no
        ...                               // ordering dependence
        Bad { fault: CborFault },         // credited by tier 1. Zero findings.

    That is a one-line, single-file, lint-clean bypass of the whole guard.
    `type usize = String;` is the same shape, and it is the ONLY half rustc
    happens to catch for us (`non_camel_case_types`, a `-D warnings` error in
    this workspace); `CborFault` is already CamelCase and compiles silently.
    Tier 2 has the identical hole (`type RecordError = String;` beside some
    other module's real `enum RecordError`), so both sets are intersected.

    Dropping — rather than resolving through the alias — is the same
    collision-drop discipline `run_real_scan` applies to a spelling with two
    different right-hand sides and `resolve_consts` applies to a colliding
    `const`: a name that means two things has not been RESOLVED, and a guard
    that guesses which meaning is "real" is a guard that can be aimed.
    Dropping costs a fail-closed finding a human then reads.
    """
    if not aliases:
        return frozenset()
    return frozenset(
        name
        for name in aliases
        if name in DATA_FREE_TYPES or name in local_error_enums
    )


def is_data_free(
    ty: str,
    local_error_enums: frozenset[str] = frozenset(),
    aliases: dict[str, str] | None = None,
    foreign_names: frozenset[str] = frozenset(),
) -> bool:
    """True when a value of `ty` provably cannot carry runtime content.

    Three tiers, all fail-closed — see the module docstring's THE RULE
    section for the design rationale:

    1. A literal entry in `DATA_FREE_TYPES`, a fixed-size numeric array, or
       an `Option<T>` of one.
    2. A `thiserror`-derived enum this guard itself scans somewhere under
       `core/src/**` (recognised by name via `discover_declarations` —
       bare, `<parent-module>::Name`, or `crate::<path>::Name`).
    3. A one-level `type X = Y;` alias whose RHS clears tier 1 or 2. An alias
       to something unresolvable — including a chain through a SECOND alias
       — still denies; see `_is_data_free_core`'s docstring.

    Two independent DENY sets are unioned and applied before any tier:

    - `foreign_names` — tiers 2 and 3 recognise BARE spellings tree-globally,
      so any bare name the SCANNED FILE imports from outside the crate denies
      outright, whichever tier would otherwise have credited it
      (`foreign_use_names`).
    - `alias_shadowed_names` — a name in tier 1's or tier 2's set that a
      discovered `type` alias also declares is a SHADOW, and is dropped
      rather than resolved. Note this denies even when the alias's own RHS
      would have cleared a tier: the claim being made is a name-resolution
      claim, and the shadow is the evidence that it does not hold.
    """
    denied = foreign_names | alias_shadowed_names(aliases, local_error_enums)
    if _is_data_free_core(ty, local_error_enums, denied):
        return True
    if aliases:
        base = normalize_type(ty)
        if base in denied:
            return False
        if base in aliases:
            return _is_data_free_core(aliases[base], local_error_enums, denied)
    return False


def is_bridge_field_safe(
    name: str,
    ty: str,
    local_error_enums: frozenset[str],
    aliases: dict[str, str] | None,
    foreign_names: frozenset[str],
    gated_field_types: frozenset[str],
) -> bool:
    """True when a BRIDGE- or WRAPPER-root field is safe under rule E2's
    carve-out (#480, per-root types #500).

    Either it independently clears `is_data_free` — the ordinary tiers,
    data-free by TYPE, exactly as core requires — or its declared type is
    EXACTLY one of `gated_field_types` under a name in `GATED_FIELD_NAMES`:
    data-free by CONSTRUCTION SITE instead.

    `gated_field_types` is per-root (`ScanRoot.gated_field_types`) and has NO
    DEFAULT on purpose. It used to be the hardcoded literal `"String"`, and a
    default here would let a future caller inherit whichever spelling happened
    to be listed first — the permissive outcome — without naming it. Callers
    state which root they are scanning.

    `normalize_type` is applied for the comparison so a field-level `#[from]`
    or visibility prefix does not defeat the match; `Option<Detail>`, `&str`,
    or any other near-miss spelling still denies — the carve-out is for the
    literal named types, not "close enough."
    """
    if is_data_free(ty, local_error_enums, aliases, foreign_names):
        return True
    return normalize_type(ty) in gated_field_types and name in GATED_FIELD_NAMES
