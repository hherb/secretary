#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
r"""Fail-closed guard: no `core` error variant may interpolate a runtime String.

WHY THIS EXISTS (#474)
----------------------
`RecordError::DuplicateKey` formatted a decrypted CBOR field name into its
message. That string reached iOS as `VaultAccessError.corruptVault` and Android
as `VaultBrowseError.SaveCryptoFailure`, which is why both platforms redacted
those arms WHOLESALE — losing the detail for every corruption diagnostic, not
just the leaking one.

The payload types are now data-free by construction. This guard keeps them that
way: a new variant carrying a runtime `String` into its `#[error]` message fails
CI in the Rust author's own pull request, rather than silently degrading a
platform two layers away. That drift — a Rust edit with no platform diff and no
failing test anywhere — is exactly how the original leak shipped.

THE RULE
--------
For every `#[error("...")]` attribute under `core/src/`, resolve the field types
of the variant (or struct — see below) it is attached to. If the message (or a
trailing format argument) interpolates a field whose declared type is not
provably data-free, fail — unless the attribute's exact normalized text is
allowlisted.

A field type is data-free when it is one of three things: a literal type in
`DATA_FREE_TYPES` (or a fixed-size numeric array / `Option<T>` of one); a
`thiserror`-derived enum THIS GUARD ITSELF SCANS somewhere under `core/src/**`
(see `discover_declarations`) — forwarding such an enum's `Display` via `{0}`
adds no new leak surface, because this same guard already fails at THAT enum's
own definition if any of its variants interpolates a non-data-free field; or a
one-level `type X = Y;` alias whose right-hand side clears one of the first two
checks (`pub type Fingerprint = [u8; 16];` is exactly as data-free as the array
it names).

The recursion argument is deliberately narrow: a nested error type from OUTSIDE
`core/src/**` — `std::io::Error`, `toml::de::Error`, any third-party crate's
error type — is NOT scanned by this guard, so it is NOT covered by the
recursion argument and MUST still deny. `std::io::Error` renders a filesystem
path; that is exactly the kind of payload a human should sign off on via the
allowlist, not something this guard should wave through because a same-named
local type happens to be safe.

`#[error(transparent)]` delegates `Display` WHOLESALE to its (thiserror-
required) sole field — that field is exactly as interpolated as if it were
named in a `{placeholder}`, even though the attribute text itself has none, so
it is classified the same way, recursion tier included.

`#[error("...")]` can decorate a STRUCT directly (`pub struct E { ... }`), not
only an enum variant — thiserror supports both shapes, and this guard scans
both.

DEFAULT-DENY covers STRUCTURE, not just TYPE: an unrecognised type name is a
FAILURE, not a pass, and so is a construct this guard cannot even locate or
resolve — an attribute whose variant/struct can't be found, or a placeholder
that doesn't match any parsed field, produces an `UNPARSED` finding rather
than being silently skipped. If the guard cannot understand a construct, a
human must look at it; "we didn't understand this" is not a pass.

LIMITS (stated, not hidden)
---------------------------
- It sees DECLARATIONS, not construction sites. A variant whose payload is
  `&'static str` is provably safe; a variant allowlisted because "its producers
  all pass literals" is a point-in-time claim this guard cannot verify. Those
  entries say so in the allowlist.
- It covers `core/src/**` only. The FFI bridge builds its own detail strings
  with `format!` (`ffi/secretary-ffi-bridge/**`) and is NOT scanned, so a
  bridge-authored `detail` reaching a platform is gated by review alone.
  #478 covers only the `VaultSyncError.Failed` / `FfiVaultError::SyncFailed`
  slice of that gap, and even there its acceptance offers two alternatives:
  extending THIS guard's scope to `ffi/secretary-ffi-bridge/src/**` (which
  would close the gap broadly) or gating the `SyncFailed` producers
  individually (which would not). Nothing tracks the rest — including the
  `CorruptVault` / `SaveCryptoFailure` folds whose platform-side redactions
  #474 removed. Do not read "#478" as "this gap is owned."
- Rust is parsed by pattern, not by a real parser. The shapes in this codebase
  are regular (thiserror derives); an exotic macro-generated error enum would
  be invisible. `--self-test` pins the shapes that do occur.
- The local-error-enum and type-alias recognition in `discover_declarations`
  matches by NAME (bare, `<parent-module>::Name`, or `crate::<path>::Name`),
  not by real `use`-import / path resolution. A BARE spelling is therefore a
  tree-global claim, and `foreign_use_names` withdraws it per-file for every
  name that file `use`s from outside the crate — which is what stops
  `use std::io::Error; ... Io(#[from] Error)` from riding on
  `core/src/error.rs`'s local `pub enum Error` (it did, silently, until this
  was added). That is evidence-based, not a resolver: it can only react to a
  `use` statement it can read. A GLOB (`use some_crate::*;`) binds names it
  cannot enumerate, and a name that reaches a file some other way is
  likewise invisible. Every glob under `core/src/**` today is an intra-crate
  `use super::*;` inside `#[cfg(test)] mod tests`, plus
  `use proptest::prelude::*;`.
- Name resolution stops at the type name as written, so a `type X = Y;`
  alias that SHADOWS a name some other tier already trusts is a real hazard.
  One half of it is closed, one half is not, and the difference is worth
  stating precisely.
    CLOSED: a shadow whose name IS in a trusted set. `type CborFault =
  String;` (tier 1) or `type RecordError = String;` beside another module's
  real `enum RecordError` (tier 2) used to be a one-line, single-file,
  lint-clean pass — the tier-1/2 lookup answered "safe" before the alias
  table was ever consulted, and the guard reported ZERO findings.
  `alias_shadowed_names` now DROPS any spelling a discovered alias shadows
  out of tier 1 or tier 2, on `run_real_scan`'s existing collision-drop
  discipline. Note that rustc closed only the `type usize = String;` costume
  of this (`non_camel_case_types`, a `-D warnings` error here); `CborFault`
  is already CamelCase and compiled clean. P34-P36 pin all three.
    STILL OPEN: a shadow whose name is in NO trusted set, i.e. one that gets
  its credit from the alias tier itself. Such a name is believed at its
  single declaration, because one-level alias resolution IS tier 3, and this
  guard has no notion of the SCOPE that declaration is visible in — an alias
  declared inside `mod inner { }` registers its bare spelling tree-globally,
  so a field written `x: Fingerprint` in a DIFFERENT file rides on it even
  though `Fingerprint` means something else there. The partial mitigation is
  `run_real_scan`'s cross-file drop: two files declaring the same spelling
  with DIFFERENT right-hand sides (`type Fingerprint = [u8; 16];` in
  `identity/fingerprint.rs` and `type Fingerprint = String;` elsewhere)
  collide and are dropped rather than guessed. What is left — telling a
  single-declaration shadow apart from the thing it shadows, in the scope
  the reference site actually sits in — is name resolution, and closing it
  requires a real type resolver, which is out of scope for a pattern-based
  guard. `--self-test` pins the shapes that DO occur, not every shape that
  could be contrived to evade it.
- `find_type_aliases` drops any spelling that resolves to DIFFERENT
  right-hand sides across files rather than guessing which one is "real" —
  see `run_real_scan`. `resolve_consts` drops a `const` spelling on the same
  discipline: more than one module-scope declaration, or any `static` /
  excluded-scope declaration of that name, and the spelling is not credited.
  An earlier round unioned const names tree-wide on the argument that "a
  const's safety comes from the compiler, not its value"; the premise is
  true but the conclusion does not follow, because the claim being made is
  "this placeholder RESOLVES TO a const", and `static` is exactly the
  same-convention collision partner that breaks it.
  `local_error_enums` still does NOT get the collision-drop: it is a pure
  membership set, not a name -> value map, and any enum whose name is
  registered is by construction a real `thiserror`-derived enum this guard
  independently scans somewhere under `core/src/**` — two DIFFERENT local
  enums sharing a bare name are both still soundly "safe by recursion."
  Its bare-name exposure is to a FOREIGN collision, which is what
  `foreign_use_names` addresses instead.
- Every view comes from ONE lexical pass (`lex_spans`), which handles line
  comments, NESTED block comments, ordinary and byte strings with escapes and
  `\` + newline continuations, RAW strings with a variable `#` run, char and
  byte-char literals, and the lifetime-vs-char ambiguity. It is a LEXER, not
  a parser: it knows where literals and comments are, and nothing else. It
  does not expand macros, so a `#[error(...)]` produced by a macro — or a
  declaration produced by one — is invisible to every registry here.
- `lex_spans` treats an UNTERMINATED literal or block comment as running to
  end-of-input. That is the conservative reading for the credit registries
  (the tail stops being code, so declarations in it stop being credited) and
  it is why `foreign_use_names` does not read those views — see the next
  point.
- THE FAIL-CLOSED ARGUMENT IS PER-PASS, NOT GLOBAL, and stating it globally
  was itself a defect. "Blanking can only HIDE text, so a view bug loses a
  credit and therefore only produces findings" is true for the three
  CREDIT-GRANTING registries (local error enums, type aliases, consts) and
  false for the two CREDIT-WITHDRAWING passes: hiding a `use` in
  `foreign_use_names`, or revealing an extra `mod` in `top_level_mod_names`,
  RESTORES a credit. Those two are wired to read the views whose failure
  direction matches their own polarity (raw + comments-blanked for the
  withdrawal; the fully blanked discovery view for the local-root grant).
  A correctness claim that does not hold for every consumer is worse than
  none, because it stops the next reader from checking.
- `scan_source` locates `#[error(` on the comments-blanked view, with string
  contents INTACT, deliberately. Hiding an attribute would be fail-open, so
  that pass does not trust the lexer's literal classification at all. The
  price is that an `#[error(` sequence written INSIDE another attribute's
  message text is visited as though it were an attribute, and may produce an
  extra finding with its own (different) allowlist key. That is noise in the
  safe direction: it can never hide a real attribute, and the spurious key
  does not match the real one, so allowlisting one does not silence the
  other.
- `discover_declarations` credits only MODULE-SCOPE declarations: anything
  inside a brace block that is not a `mod name { ... }` block is skipped
  (`non_module_block_spans`), which covers a trait's or an `impl`'s
  ASSOCIATED `type` / `const` (a per-impl binding, e.g. `type Ek = ...;` in a
  KEM trait impl), and anything local to a `fn` body. `const` discovery
  additionally skips `#[cfg(test)]`-gated items (`cfg_test_spans`): six of
  the 134 bare const names the round-3 rule harvested tree-wide came from
  test modules, one of them named `SECRET_FIELD_NAME`. (An earlier draft
  of this comment said 136; that measurement was taken with two of the
  measuring session's own throwaway attack files still in the tree. 134
  is the clean-tree figure.) Block kind is decided from
  the item's header text, so a `mod` declared through a macro would not be
  recognised as one — the fail-CLOSED direction (its contents lose credit).
- Declaration discovery runs over `discovery_view` — comments AND string
  literal contents blanked. Without the second half, text inside an
  `#[error("...")]` message registered as a declaration, letting an author
  self-authorise the very placeholder under test
  (`#[error("... {SELF_AUTH} const SELF_AUTH: usize = 1;")]` passed
  silently). Locating `#[error(` attributes still uses the un-blanked text,
  deliberately: blanking can only HIDE, which loses a credit (fail-closed)
  during discovery but would lose a whole ATTRIBUTE (fail-open) if the
  string scanner ever desynced. A `#[error(` written inside another
  attribute's message text is therefore still visited as if it were an
  attribute; that produces noise or nothing, never a missed real attribute.
- The recursion tier's soundness claim is "this guard fails at that enum's
  own definition." Once a leaf variant there is ALLOWLISTED — a human
  decision, not this guard's — the honest statement becomes "fails OR IS
  ALLOWLISTED at that enum's own definition." This guard does not re-verify
  that an allowlisted leaf stays sound as the type evolves; see
  `docs/superpowers/specs/2026-08-05-474-error-payload-hygiene-design.md` §4.
"""

from __future__ import annotations

import bisect
import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCAN_ROOT = REPO_ROOT / "core" / "src"
# #480: the FFI bridge builds its own detail strings with `format!` and was,
# until rule E2, entirely unscanned (see the module docstring's LIMITS —
# updated by Task 3, not this comment, since that rewrite is a separate
# task's job). Bridge files get their OWN discovery pass (`bridge_mode`)
# rather than being folded into `SCAN_ROOT`'s: a bridge-local alias/const/
# enum must not vouch for a core field, or vice versa.
BRIDGE_SCAN_ROOT = REPO_ROOT / "ffi" / "secretary-ffi-bridge" / "src"
ALLOWLIST_PATH = REPO_ROOT / "scripts" / "error-payload-hygiene-allowlist.txt"

# Types whose every value is a compile-time constant or a pure number, and so
# cannot carry runtime content. Everything else denies.
DATA_FREE_TYPES: frozenset[str] = frozenset(
    {
        "&'static str",
        "bool",
        "char",
        "usize",
        "isize",
        "u8", "u16", "u32", "u64", "u128",
        "i8", "i16", "i32", "i64", "i128",
        # The #474 classification type: a fieldless kind plus a byte offset.
        "CborFault",
        "crate::cbor::CborFault",
    }
)

# #480/rule E2: field NAMES whose construction site rule E3 (Task 3) will
# gate. A bridge field under one of these names, declared EXACTLY `String`,
# is not a structural finding — its VALUE is checked at the construction
# site instead of being denied outright by TYPE. Pinned to this exact set
# (spec §3.2): `record_uuid_hex` / `device_uuid_hex` are deliberately NOT
# members — those are DTO-carrying fields (sync/dto.rs, sync/status.rs), not
# diagnostic text, and gating them here would launder real payload data
# through a name that merely LOOKS like the diagnostic-hex convention.
GATED_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "detail",
        "uuid_hex",
        "block_uuid_hex",
        "recipient_fingerprint_hex",
        "expected_fingerprint_hex",
        "got_fingerprint_hex",
    }
)

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
    local_error_enums: frozenset[str] = frozenset(),
    aliases: dict[str, str] | None = None,
    foreign_names: frozenset[str] = frozenset(),
) -> bool:
    """True when a BRIDGE field is safe under rule E2's carve-out (#480).

    Either it independently clears `is_data_free` — the ordinary tiers,
    data-free by TYPE, exactly as core requires — or its declared type is
    EXACTLY `String` under a name in `GATED_FIELD_NAMES`: data-free by
    CONSTRUCTION SITE instead, which rule E3 (Task 3) gates. `normalize_type`
    is applied to `ty` for the exact-`String` comparison so a field-level
    `#[from]` / visibility prefix does not defeat the match; `Option<String>`,
    `&str`, or any other near-miss spelling still denies — the carve-out is
    for the literal named type, not "close enough."

    Shared by BOTH of rule E2's uses: the `bridge_mode` carve-out on the
    ordinary interpolated-field scan (`scan_source`), and the structural
    all-fields sweep (`bridge_declaration_findings`) that also checks fields
    the `#[error(...)]` message never mentions.
    """
    if is_data_free(ty, local_error_enums, aliases, foreign_names):
        return True
    return normalize_type(ty) == "String" and name in GATED_FIELD_NAMES


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


def cfg_test_spans(src: str) -> list[tuple[int, int]]:
    """Character-offset `[start, end)` ranges of every `#[cfg(test)]`-gated
    item in the DISCOVERY VIEW, attribute included.

    A test-only declaration is not part of the shipped crate and must not
    vouch for a name a shipped `#[error("...")]` message captures. Six of the
    134 bare `const` names the round-3 rule harvested tree-wide came from
    `#[cfg(test)] mod tests { ... }` blocks — one of them literally named
    `SECRET_FIELD_NAME`.
    """
    spans: list[tuple[int, int]] = []
    n = len(src)
    for m in CFG_TEST_RE.finditer(src):
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


# `use ...;` — the per-file name bindings that make a BARE spelling mean
# something other than what tree-global discovery assumed. Roots that stay
# inside this crate; anything else (`std`, `core`, a third-party crate) binds
# a name this guard does not scan and therefore cannot vouch for.
LOCAL_USE_ROOTS: frozenset[str] = frozenset({"crate", "super", "self"})
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


# ---------------------------------------------------------------------------
# ONE lexical pass. Every view below is derived from it.
# ---------------------------------------------------------------------------
#
# Rounds 1-4 grew a family of hand-rolled scanners, each patched for the shape
# that had just defeated it. Round 5's review broke four of them at once, and
# every break was the same bug in a different costume: the scanner did not
# actually know where Rust literals begin and end.
#
#   - `r#"a" const ZZ: usize = 1; "b"#` -- a raw string with an odd number of
#     internal quotes re-exposed its own contents as code, so an author could
#     self-authorise a placeholder from inside a message again (the CRITICAL
#     this branch supposedly closed in round 4).
#   - `let c = '}';` inside a `fn` popped the function's own brace, promoting
#     every following declaration in that body to "module scope".
#   - `fn q() -> char { '"' }` desynced the string scanner across the next
#     `use` statement, which RESTORED a withdrawn credit (see
#     `foreign_use_names` for why that direction is the dangerous one).
#
# So: classify every byte ONCE, correctly, and derive the views from that.
# Anything a future round needs is a new view over the same classification,
# never a fifth bespoke scanner.

KIND_COMMENT = "#"
KIND_DELIM = "d"  # a literal's delimiter bytes (quotes, `r##` prefix, ...)
KIND_LITERAL = "s"  # a literal's CONTENT bytes

# `r"`, `r#"`, `r##"`, and the byte-string forms `br"`, `br#"`, ...
RAW_STRING_START_RE = re.compile(r"(?:b?r)(?P<hashes>#*)\"")
# `'x'`, `'\n'`, `'\''`, `'\\'`, `'\u{1F600}'`, and the byte forms `b'x'`.
# Deliberately NOT matched: `'static` / `'a` / `'outer` -- a `'` that is not
# closed by a matching `'` two-ish characters later is a LIFETIME or a loop
# label, not a char literal. `&'static str` is the shape that makes this
# ambiguity unavoidable, and it is everywhere in this codebase.
CHAR_LITERAL_RE = re.compile(r"b?'(?:\\u\{[0-9a-fA-F_]{1,6}\}|\\.|[^\\'\n])'")


def _ident_char(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def lex_spans(src: str) -> list[tuple[int, int, str]]:
    r"""Classify `src` into ordered, non-overlapping, non-CODE spans.

    Returns `(start, end, kind)` for every comment and every string / char
    literal, in source order; anything not covered is code. Handles:

    - line comments, and block comments WITH NESTING (Rust's `/* /* */ */`
      nests, unlike C's -- an inner `/*` that a non-nesting scanner ignores
      makes the outer comment end early);
    - ordinary and byte strings with escapes, including the `\` + newline
      line continuation;
    - RAW strings with a variable `#` run (`r"..."`, `r#"..."#`, `r##"..."##`,
      `br#"..."#`), where `"` inside the body is an ordinary character;
    - char and byte-char literals, including `'"'`, `'{'`, `'}'`, `'\''`,
      `'\\'`;
    - the lifetime-vs-char ambiguity (`&'static str` is code, not a literal).

    Unterminated constructs run to end-of-input, which is the conservative
    reading: the tail is classified as literal/comment rather than code, so
    discovery loses credits (a finding) rather than gaining them.
    """
    spans: list[tuple[int, int, str]] = []
    n = len(src)
    i = 0
    while i < n:
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ""

        if ch == "/" and nxt == "/":
            end = src.find("\n", i)
            end = n if end == -1 else end
            spans.append((i, end, KIND_COMMENT))
            i = end
            continue

        if ch == "/" and nxt == "*":
            depth, j = 0, i
            while j < n:
                if src[j] == "/" and j + 1 < n and src[j + 1] == "*":
                    depth += 1
                    j += 2
                    continue
                if src[j] == "*" and j + 1 < n and src[j + 1] == "/":
                    depth -= 1
                    j += 2
                    if depth == 0:
                        break
                    continue
                j += 1
            j = min(j, n)
            spans.append((i, j, KIND_COMMENT))
            i = j
            continue

        # `r` / `b` / `br` are literal prefixes only when they are not the
        # tail of a longer identifier (`membr"` is not a thing in valid Rust,
        # but refusing to guess costs nothing).
        if ch in "rb" and (i == 0 or not _ident_char(src[i - 1])):
            m = RAW_STRING_START_RE.match(src, i)
            if m:
                closer = '"' + m.group("hashes")
                body = m.end()
                j = src.find(closer, body)
                if j == -1:
                    spans.append((i, body, KIND_DELIM))
                    spans.append((body, n, KIND_LITERAL))
                    i = n
                    continue
                spans.append((i, body, KIND_DELIM))
                spans.append((body, j, KIND_LITERAL))
                spans.append((j, j + len(closer), KIND_DELIM))
                i = j + len(closer)
                continue
            if ch == "b":
                m = CHAR_LITERAL_RE.match(src, i)
                if m:
                    spans.append((i, i + 2, KIND_DELIM))
                    spans.append((i + 2, m.end() - 1, KIND_LITERAL))
                    spans.append((m.end() - 1, m.end(), KIND_DELIM))
                    i = m.end()
                    continue
                if nxt == '"':
                    i, added = _lex_quoted(src, i, 2, spans)
                    if added:
                        continue

        if ch == '"':
            i, added = _lex_quoted(src, i, 1, spans)
            if added:
                continue

        if ch == "'":
            m = CHAR_LITERAL_RE.match(src, i)
            if m:
                spans.append((i, i + 1, KIND_DELIM))
                spans.append((i + 1, m.end() - 1, KIND_LITERAL))
                spans.append((m.end() - 1, m.end(), KIND_DELIM))
                i = m.end()
                continue
            # A lifetime or a loop label. Code.

        i += 1
    return spans


def _lex_quoted(
    src: str, start: int, prefix_len: int, spans: list[tuple[int, int, str]]
) -> tuple[int, bool]:
    r"""Lex an ordinary (or byte) string literal at `src[start]`, appending its
    spans. `\` consumes the next character whatever it is, which is what makes
    both `\"` and the `\` + newline continuation come out right.
    """
    n = len(src)
    body = start + prefix_len
    j = body
    while j < n:
        if src[j] == "\\":
            j += 2
            continue
        if src[j] == '"':
            break
        j += 1
    body_end = min(j, n)
    spans.append((start, body, KIND_DELIM))
    spans.append((body, body_end, KIND_LITERAL))
    if body_end < n:
        spans.append((body_end, body_end + 1, KIND_DELIM))
        return body_end + 1, True
    return n, True


def render_view(src: str, blank_kinds: str) -> str:
    r"""Blank the requested span kinds, preserving LENGTH and LINE COUNT.

    Every blanked byte becomes a space, except a newline which stays a
    newline. Both invariants are structural here rather than a special case
    that has to be remembered -- an earlier round shipped a `\` + newline
    continuation that emitted a space for the newline and silently shifted
    every subsequent reported line number in the file.
    """
    out: list[str] = []
    pos = 0
    for start, end, kind in lex_spans(src):
        if kind not in blank_kinds:
            continue
        out.append(src[pos:start])
        out.append("".join("\n" if c == "\n" else " " for c in src[start:end]))
        pos = end
    out.append(src[pos:])
    return "".join(out)


def strip_comments(src: str) -> str:
    """Blank `//` and `/* */` comments; leave literals verbatim.

    This is the view `scan_source` reads: locating `#[error(` attributes and
    extracting their message text needs the strings INTACT.
    """
    return render_view(src, KIND_COMMENT)


def discovery_view(raw: str) -> str:
    """The DECLARATION-DISCOVERY view: comments AND literal contents blanked,
    delimiters left in place.

    This is a security control. `find_consts`, `find_type_aliases` and
    `ENUM_RE` all answer "what names may this file vouch for?", and text
    inside an `#[error("...")]` MESSAGE declares nothing. Reading declarations
    from a view with string contents intact let an author self-authorise the
    very placeholder under test:

        #[error("leaked field name: {SELF_AUTH} const SELF_AUTH: usize = 1;")]
        SelfAuthorised,

    passed silently, in one file, with no collision and no file-ordering
    dependence. So did the raw-string form `r#"a" const ... "b"#`, which
    survived round 4 because that round blanked strings with a scanner that
    did not know what a raw string was.

    Char literal CONTENTS are blanked for the same reason braces matter:
    `let c = '}';` inside a `fn` body used to pop that function's own brace in
    `non_module_block_spans`, promoting the rest of the body to module scope.

    FAIL-CLOSED ONLY FOR CREDIT-GRANTING PASSES. Blanking can only ever HIDE
    text. For the three registries this view feeds -- local error enums, type
    aliases, consts -- hiding a declaration LOSES a credit, which produces a
    finding, so a lexer bug there degrades toward noise. That argument does
    NOT transfer to a WITHDRAWAL pass: `foreign_use_names` removes credits, so
    hiding a `use` there would RESTORE one. It therefore does not read this
    view at all -- see its docstring. Getting this backwards is exactly the
    kind of unchecked correctness claim this guard exists to eliminate.
    """
    return render_view(raw, KIND_COMMENT + KIND_LITERAL)



@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    source_line: str
    variant: str
    field: str
    field_type: str
    # The allowlist's rule column. `E1` (interpolated-field scan, `core/src/**`
    # and — under `bridge_mode` — the FFI bridge) is the default; rule `E2`
    # (#480: the bridge's structural all-fields declaration sweep) is set
    # explicitly by its two producers, `bridge_declaration_findings`. The
    # column exists so the file format is byte-identical to the two shell
    # guards' allowlists, which lets `scripts/lib/hygiene-allowlist.sh
    # ::allowlisted` parse this file unchanged —
    # `core/tests/error_payload_hygiene_parity.rs` exercises exactly that
    # claim.
    rule: str = "E1"


ERROR_ATTR_RE = re.compile(r"#\[error\(", re.MULTILINE)
# `.index` in a trailing format argument, e.g. `, .index + 1)`.
ARG_FIELD_RE = re.compile(r"\.([A-Za-z_][A-Za-z0-9_]*)")
VARIANT_RE = re.compile(r"^\s*([A-Z][A-Za-z0-9_]*)\s*(\{|\(|,|$)")
# A `thiserror` error can also be a STRUCT — one shape, not an enum with
# variants — with `#[error("...")]` attached directly to `pub struct Name {
# ... }` / `pub struct Name(...);` rather than to a variant. Not used in
# `core/src` today, but nothing in the language prevents it.
STRUCT_RE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?struct\s+([A-Za-z_][A-Za-z0-9_]*)")


def balanced_slice(src: str, start: int) -> tuple[str, int]:
    """Return the `(...)`-balanced text starting at `src[start] == '('`."""
    depth, i, in_string = 0, start, False
    while i < len(src):
        ch = src[i]
        if in_string:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return src[start : i + 1], i + 1
        i += 1
    return src[start:], len(src)


def skip_attributes(text: str) -> str:
    """Skip leading whitespace and any number of `#[...]`-attribute spans at
    the front of `text`.

    Without this, an intervening attribute between `#[error(...)]` and the
    variant/struct it decorates defeats the guard entirely: `VARIANT_RE`
    cannot match a line starting with `#`, and the old code only ever looked
    at the FIRST non-blank line after the `#[error(...)]` attribute, so

        #[error("leak: {detail}")]
        #[cfg(all())]
        Leaky { detail: String },

    found no variant at all and silently skipped — proven live for
    `#[cfg(...)]`, `#[allow(...)]`, and `#[doc = "..."]`. Brackets are
    balanced so a multi-line or argument-bearing attribute is consumed as a
    unit, not just cut off at its own first `]`.
    """
    i, n = 0, len(text)
    while True:
        while i < n and text[i] in " \t\r\n":
            i += 1
        if i + 1 < n and text[i] == "#" and text[i + 1] == "[":
            depth, j, in_string = 0, i + 1, False
            while j < n:
                ch = text[j]
                if in_string:
                    if ch == "\\":
                        j += 2
                        continue
                    if ch == '"':
                        in_string = False
                elif ch == '"':
                    in_string = True
                elif ch == "[":
                    depth += 1
                elif ch == "]":
                    depth -= 1
                    if depth == 0:
                        j += 1
                        break
                j += 1
            i = j
            continue
        break
    return text[i:]


def parse_fields(body: str) -> dict[str, str]:
    """Map field name -> declared type for a variant (or struct) body.

    Handles both struct-shaped bodies (`{ field: &'static str, index: usize
    }`) and tuple bodies (`(String)` -> `{"0": "String"}`). A struct field's
    `#[from]`/`#[source]` attribute precedes its NAME
    (`#[source]\\n source: T`), so the name side is run through
    `strip_field_attrs` — see that function's docstring for the bug this
    fixes — and then through `strip_visibility`, since a struct field's
    `pub` / `pub(crate)` lands on the name side too. The type side (tuple
    fields: `#[from] T`, `pub T`) is left as-is here; `normalize_type`
    strips both later, at classification time.
    """
    body = body.strip()
    fields: dict[str, str] = {}
    if body.startswith("{"):
        inner = body[1 : body.rindex("}")] if "}" in body else body[1:]
        for part in split_top_level(inner):
            if ":" not in part:
                continue
            name, ty = part.split(":", 1)
            name = strip_visibility(strip_field_attrs(name))
            if name.startswith("///") or not name:
                continue
            fields[name] = " ".join(ty.split())
    elif body.startswith("("):
        inner = body[1 : body.rindex(")")] if ")" in body else body[1:]
        for idx, part in enumerate(split_top_level(inner)):
            if part.strip():
                fields[str(idx)] = " ".join(part.split())
    return fields


def split_top_level(text: str) -> list[str]:
    """Split on commas that are not nested inside <>, (), [] or {}."""
    parts: list[str] = []
    depth = 0
    cur: list[str] = []
    for ch in text:
        if ch in "<([{":
            depth += 1
        elif ch in ">)]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append("".join(cur))
    return parts


def extract_placeholders(text: str) -> list[str | None]:
    """Every genuine `{name}` / `{name:?}` / `{}` placeholder in a Rust
    format string, in left-to-right order, with `None` standing in for a
    positional `{}`.

    Consumes `{{` / `}}` (escaped braces) as 2-character units in a single
    linear left-to-right pass, rather than using a regex negative-lookbehind
    to reject a `{` immediately preceded by another `{`. The lookbehind
    approach cannot tell an escape's SECOND brace from a genuine
    placeholder's OPENING one, so it silently drops a real placeholder that
    immediately follows an escape: `{{{name}}}` is valid Rust (`{{` literal +
    `{name}` real + `}}` literal), but a lookbehind rejects the `{` at the
    real placeholder's start because the character before it is also `{`. A
    scan that eats `{{`/`}}` FIRST, before ever trying to start a placeholder
    match, has no such blind spot.
    """
    names: list[str | None] = []
    i, n = 0, len(text)
    while i < n:
        if text[i] == "{" and i + 1 < n and text[i + 1] == "{":
            i += 2
            continue
        if text[i] == "}" and i + 1 < n and text[i + 1] == "}":
            i += 2
            continue
        if text[i] == "{":
            j = text.find("}", i)
            if j == -1:
                break
            inner = text[i + 1 : j]
            m = re.match(r"([A-Za-z_][A-Za-z0-9_]*|\d+)?", inner)
            names.append(m.group(1) if m else None)
            i = j + 1
            continue
        i += 1
    return names


def scan_source(
    path_label: str,
    raw: str,
    local_error_enums: frozenset[str] = frozenset(),
    aliases: dict[str, str] | None = None,
    consts: frozenset[str] = frozenset(),
    foreign_names: frozenset[str] = frozenset(),
    bridge_mode: bool = False,
) -> list[Finding]:
    """Find every `#[error]` variant/struct that interpolates a non-data-free
    field, PLUS every `#[error(...)]` attribute whose structure this guard
    could not resolve (an `UNPARSED` finding: an unrecognised STRUCTURE
    fails closed exactly like an unrecognised TYPE does, rather than
    silently passing via a bare `continue`).

    `local_error_enums` / `aliases` are the tier-2 / tier-3 inputs to
    `is_data_free` (see `discover_declarations`) — callers that skip real
    cross-file discovery (i.e. pass nothing) still get tier 1 (literal
    `DATA_FREE_TYPES` / arrays / `Option<T>`), just not the recursion or
    alias tiers.

    `consts` is a DIFFERENT kind of input: it is not a field TYPE tier at
    all (nothing goes through `is_data_free` for it), because a `const`
    capture is not a field in the first place. A NAMED placeholder that
    resolves to neither a parsed field name NOR a discovered `const` name
    still produces an `UNPARSED` finding — the const tier is an ADDITIONAL
    way to be recognised safe, never a fallback that accepts an unknown
    name. See `find_consts` for why only `const` (never `static`) qualifies.

    `foreign_names` is this FILE's `use`-bound foreign spellings
    (`foreign_use_names`); every bare-name credit — tier 2, tier 3 and the
    const tier — is withdrawn for those spellings while this file is
    scanned.

    `bridge_mode` (#480, rule E2) does TWO things, both scoped to
    `ffi/secretary-ffi-bridge/src/**` — core behaviour (the default,
    `bridge_mode=False`) is byte-identical to before this parameter existed:

    1. Rule E2's carve-out on the ordinary interpolated-field check below:
       `is_bridge_field_safe` replaces the bare `is_data_free` call, so a
       `String` field named in `GATED_FIELD_NAMES` is not a finding here
       (rule E3, Task 3, gates its construction site instead). Everything
       else still denies exactly as core's `E1` does.
    2. A STRUCTURAL sweep (`bridge_declaration_findings`, rule `E2`) over
       EVERY parsed field of the declaration — interpolated or not — since
       uniffi/PyO3 project every field regardless of what the `#[error(...)]`
       message actually renders. This is what catches a platform-projected
       `String` the `Display` text never mentions.

    Note `strip_comments`, NOT `discovery_view`: locating `#[error(`
    attributes and reading their message text needs the strings INTACT.
    Blanking is used only where it can only ever hide a credit, which is the
    fail-closed direction — see `discovery_view`.
    """
    src = strip_comments(raw)
    findings: list[Finding] = []

    for m in ERROR_ATTR_RE.finditer(src):
        attr_text, after = balanced_slice(src, m.end() - 1)
        attr_line_no = src.count("\n", 0, m.start()) + 1

        # The allowlist key AND the human-facing "source line" are the same
        # thing: the WHOLE `#[error(...)]` attribute's RAW text (character
        # offsets are 1:1 between `src` and `raw` — `strip_comments` never
        # changes length), whitespace-collapsed to one line. Not just the
        # attribute's first source line: a multi-line attribute
        # (`sync/error.rs:9`) would otherwise key on literally `#[error(`,
        # which is NOT unique — two different multi-line attributes in the
        # same file share that "line," so an entry meant to allowlist one
        # would silently also allowlist the other. That is the exact
        # "substring exempts everything" failure the exact-line convention
        # is supposed to prevent, one level up. Collapsing to one line also
        # keeps the key free of raw tabs/newlines, since the allowlist file
        # is TAB-delimited.
        tail_raw = src[after:]
        if tail_raw.lstrip().startswith("]"):
            close_off = tail_raw.find("]") + 1
            attr_end = after + close_off
            tail = tail_raw[close_off:]
        else:
            attr_end = after
            tail = tail_raw
        key_text = " ".join(raw[m.start() : attr_end].split())

        def emit_unparsed(
            reason: str, variant: str = "<unparsed>", field: str = "<unparsed>"
        ) -> None:
            findings.append(
                Finding(
                    path=path_label,
                    line=attr_line_no,
                    source_line=key_text,
                    variant=variant,
                    field=field,
                    field_type=f"UNPARSED: {reason}",
                )
            )

        # Locate the variant/struct this attribute decorates. Done
        # UNCONDITIONALLY (not only when there's a placeholder to resolve):
        # `#[error(transparent)]` (below) needs the field list to know what
        # it implicitly interpolates, and default-deny wants an
        # unrecognisable STRUCTURE to fail closed even when the attribute's
        # OWN text happens to have nothing to interpolate — being unable to
        # locate the variant at all is itself suspicious.
        tail = skip_attributes(tail)
        vm = None
        for line in tail.splitlines():
            if line.strip():
                vm = VARIANT_RE.match(line) or STRUCT_RE.match(line)
                break
        if not vm:
            emit_unparsed(
                "could not locate the variant/struct declaration following "
                "this #[error(...)] attribute"
            )
            continue
        variant = vm.group(1)

        rest = tail[tail.find(variant) + len(variant) :].lstrip()
        if rest.startswith("{"):
            body, _ = balanced_braces(rest)
        elif rest.startswith("("):
            body, _ = balanced_slice(rest, 0)
        else:
            body = ""
        fields = parse_fields(body)
        ordered = list(fields.items())

        # Rule E2, sweep 1 (#480): every PARSED field of a bridge
        # declaration, interpolated or not — see `bridge_declaration_findings`.
        # Runs UNCONDITIONALLY once fields are known, independent of whether
        # the message below interpolates anything, is `transparent`, or is
        # itself UNPARSED for an unrelated reason.
        if bridge_mode:
            decl_text = " ".join(f"{variant} {body}".split())
            findings.extend(
                bridge_declaration_findings(
                    path_label,
                    attr_line_no,
                    variant,
                    decl_text,
                    fields,
                    local_error_enums,
                    aliases,
                    foreign_names,
                )
            )

        # `#[error(transparent)]` delegates Display WHOLESALE to its (sole,
        # thiserror-required) field — that field is what gets interpolated
        # even though the attribute itself has zero `{...}` placeholders, so
        # it needs its own name-resolution path instead of falling into the
        # "nothing to interpolate" skip below.
        is_transparent = attr_text.strip().strip("()").strip() == "transparent"

        names: set[str] = set()
        if is_transparent:
            if len(fields) == 1:
                names.add(next(iter(fields)))
            else:
                emit_unparsed(
                    f"#[error(transparent)] on {variant} does not have "
                    f"exactly one field ({len(fields)} found) — thiserror "
                    "requires exactly one",
                    variant=variant,
                )
                continue
        else:
            # A non-transparent `#[error(...)]` is only understood when its
            # body is a STRING-LITERAL format ( `"..."` / `r"..."` / `r#"..."#`
            # ). thiserror 2.x also accepts `#[error(fmt = <path>)]`, whose
            # named formatter is handed EVERY field and can render any of them
            # — there is no format string to extract placeholders from, so the
            # `if not names: continue` skip below would wave it through as
            # "nothing interpolated" (it is not: the formatter sees the whole
            # variant). Default-deny on STRUCTURE, per the module docstring:
            # a body this guard cannot model as a format string fails closed as
            # UNPARSED, forcing a human (and an allowlist entry) rather than a
            # silent pass. Covers `fmt = ...` and any future `key = value` form.
            inner = attr_text[1:-1].strip() if len(attr_text) >= 2 else ""
            if not (inner.startswith('"') or re.match(r'r#*"', inner)):
                emit_unparsed(
                    f"{variant} has an #[error(...)] body this guard cannot "
                    "model as a string-literal format — e.g. thiserror's "
                    "`fmt = <path>` custom-formatter form, whose formatter can "
                    "render any field. Deny by default; allowlist after review",
                    variant=variant,
                )
                continue
            # Every placeholder name in the format string, plus every
            # `.field` referenced by a trailing format argument (the
            # mnemonic.rs shape).
            positional = 0
            for token in extract_placeholders(attr_text):
                if not token:
                    names.add(f"__positional_{positional}")
                    positional += 1
                else:
                    names.add(token)
            arg_split = attr_text.find(",")
            if arg_split != -1:
                for am in ARG_FIELD_RE.finditer(attr_text[arg_split:]):
                    names.add(am.group(1))
            if not names:
                # Nothing is interpolated — provably nothing to check, not a
                # parse failure (see N4). Distinct from `not vm` above: THAT
                # means "we don't even know what this decorates"; this means
                # "we know, and it interpolates nothing."
                continue

        # Positional `{}` placeholders bind to fields in declaration order.
        # `seen_fields` dedupes the case where the SAME field is reachable
        # two ways in one attribute (a positional `{}` plus an explicit
        # `.field` argument for that field) — cosmetic only, but there is no
        # reason to report one leak twice.
        seen_fields: set[str] = set()
        for name in sorted(names):
            if name.startswith("__positional_"):
                idx = int(name.rsplit("_", 1)[1])
                if idx < len(ordered):
                    fname, ftype = ordered[idx]
                else:
                    emit_unparsed(
                        f"positional placeholder #{idx} in {variant} has no "
                        f"corresponding field ({len(ordered)} declared)",
                        variant=variant,
                    )
                    continue
            elif name in fields:
                fname, ftype = name, fields[name]
            elif name in consts and name not in foreign_names:
                # A `const` capture, not a field — Rust requires a `const`'s
                # initializer to be compile-time evaluable, so it cannot
                # carry runtime content regardless of its declared type.
                # Nothing further to classify; this is not a field lookup.
                # `foreign_names` withdraws the credit when THIS file binds
                # the spelling to something outside the crate.
                continue
            else:
                emit_unparsed(
                    f"{variant} interpolates `{{{name}}}`, which does not "
                    "match any field or discovered const this guard could "
                    "parse — it cannot verify what is being rendered",
                    variant=variant,
                    field=name,
                )
                continue
            if fname in seen_fields:
                continue
            seen_fields.add(fname)
            # Rule E2 item 1 (#480): in bridge_mode, an interpolated field
            # gets the SAME carve-out the structural sweep above uses —
            # `String` under a `GATED_FIELD_NAMES` name is not a finding
            # HERE (rule E3, Task 3, gates its construction site instead).
            # Everything else denies exactly as core's E1 does today.
            field_is_safe = (
                is_bridge_field_safe(fname, ftype, local_error_enums, aliases, foreign_names)
                if bridge_mode
                else is_data_free(ftype, local_error_enums, aliases, foreign_names)
            )
            if not field_is_safe:
                findings.append(
                    Finding(
                        path=path_label,
                        line=attr_line_no,
                        source_line=key_text,
                        variant=variant,
                        field=fname,
                        field_type=ftype,
                    )
                )
    return findings


def bridge_declaration_findings(
    path_label: str,
    line_no: int,
    variant: str,
    decl_text: str,
    fields: dict[str, str],
    local_error_enums: frozenset[str],
    aliases: dict[str, str] | None,
    foreign_names: frozenset[str],
) -> list[Finding]:
    """Rule E2's structural sweep (#480): every PARSED field of a bridge
    declaration — interpolated or not, since uniffi/PyO3 project every field
    regardless of what `#[error(...)]`'s message actually mentions — must
    independently satisfy `is_bridge_field_safe`.

    Shared by both of rule E2's producers: `scan_source`'s `bridge_mode`
    sweep 1 (thiserror-derived declarations, anchored on their own
    `#[error(` attribute) and `scan_bridge_plain_enums`'s sweep 2
    (plain-derive `*Error`/`*Warning` enums with no such attribute to anchor
    on). Both callers precompute `decl_text` — the whitespace-collapsed
    `"<variant/struct name> <body>"` text — themselves, since sweep 1 has an
    `#[error(...)]` attribute's surrounding context to draw on and sweep 2
    does not.
    """
    out: list[Finding] = []
    for fname, ftype in fields.items():
        if is_bridge_field_safe(fname, ftype, local_error_enums, aliases, foreign_names):
            continue
        out.append(
            Finding(
                path=path_label,
                line=line_no,
                source_line=decl_text,
                variant=variant,
                field=fname,
                field_type=ftype,
                rule="E2",
            )
        )
    return out


# `enum Name` where NAME ends `Error` or `Warning` — rule E2's SECOND sweep
# target (#480): a bridge enum following this codebase's own error/warning
# naming convention but carrying NO `#[error(...)]` attribute anywhere in
# its body — a plain `#[derive(Debug, ...)]`, not thiserror (e.g.
# `SettingsWarning`, today's `SettingsParseError`). uniffi/PyO3 project
# every field of such a type regardless of derive shape, so it needs the
# same all-fields sweep a thiserror declaration gets via `scan_source`'s
# `#[error(` anchor; this shape has no such anchor, so it is found by NAME
# instead. A heuristic, not a language guarantee — see the module
# docstring's LIMITS on pattern-based discovery generally.
BRIDGE_PLAIN_ENUM_RE = re.compile(r"\benum\s+([A-Za-z_][A-Za-z0-9_]*(?:Error|Warning))\b")


def _parse_enum_variant_fields(body: str) -> list[tuple[str, str, dict[str, str]]]:
    """`(variant_name, collapsed_declaration_text, fields)` for every variant
    in an enum BODY (`{...}`, outer braces included).

    Mirrors `scan_source`'s own single-variant parse (`VARIANT_RE` + a
    balanced field body + `parse_fields`), applied once per TOP-LEVEL
    comma-separated member instead of once per `#[error(...)]` attribute:
    `scan_bridge_plain_enums`'s target has no attribute to anchor on (that is
    the whole reason it needed its own discovery pass), so it must walk
    every variant in the body itself. `skip_attributes` handles a variant
    carrying its own attribute (e.g. `#[non_exhaustive]`) the same way
    `scan_source` does.
    """
    inner = body[1 : body.rindex("}")] if "}" in body else body[1:]
    out: list[tuple[str, str, dict[str, str]]] = []
    for part in split_top_level(inner):
        text = skip_attributes(part.strip())
        if not text:
            continue
        vm = VARIANT_RE.match(text)
        if not vm:
            continue
        name = vm.group(1)
        rest = text[len(name) :].lstrip()
        if rest.startswith("{"):
            fbody, _ = balanced_braces(rest)
        elif rest.startswith("("):
            fbody, _ = balanced_slice(rest, 0)
        else:
            fbody = ""
        decl_text = " ".join(f"{name} {fbody}".split())
        out.append((name, decl_text, parse_fields(fbody)))
    return out


def bridge_cfg_test_spans(raw: str) -> list[tuple[int, int]]:
    r"""`cfg_test_spans`, computed over the DISCOVERY VIEW rather than
    `strip_comments`.

    `CFG_TEST_RE`'s own docstring states its `\btest\b` match is safe "on
    the DISCOVERY VIEW specifically: string literals are blanked there" —
    over `strip_comments` alone, a hypothetical
    `#[cfg(feature = "test-utils")]` would false-positive-match and exclude
    a SHIPPED declaration from the sweep, which is the fail-OPEN direction
    for a discovery pass that only ever REMOVES a candidate from being
    checked. `scan_bridge_plain_enums` locates its `enum` candidates on
    `strip_comments` (matching the module docstring's "comments-blanked
    view" — the same view `scan_source` itself uses to locate `#[error(`),
    but every span this module computes preserves LENGTH and LINE COUNT
    (`check_view_invariants` pins that), so an offset valid against ONE view
    is valid against ANY of them; there is no need to re-derive the enum
    match itself against `discovery_view`, only to compute the EXCLUSION
    spans against it.
    """
    return cfg_test_spans(discovery_view(raw))


def scan_bridge_plain_enums(
    path_label: str,
    raw: str,
    local_error_enums: frozenset[str] = frozenset(),
    aliases: dict[str, str] | None = None,
    foreign_names: frozenset[str] = frozenset(),
) -> list[Finding]:
    """Rule E2's second sweep (#480) — see `BRIDGE_PLAIN_ENUM_RE`.

    Skips any candidate whose body contains `#[error(` at all
    (thiserror-derived; already swept by `scan_source`'s `bridge_mode` sweep
    1, so re-sweeping here would double-report the same field under the same
    rule) and any candidate starting inside a `#[cfg(test)]`-gated item
    (`bridge_cfg_test_spans`) — a test-only declaration is not part of the
    shipped crate and must not be swept, mirroring
    `discover_declarations`'s identical exclusion for the E1 tiers.
    """
    src = strip_comments(raw)
    excluded = bridge_cfg_test_spans(raw)
    findings: list[Finding] = []
    for m in BRIDGE_PLAIN_ENUM_RE.finditer(src):
        if _inside(m.start(), excluded):
            continue
        brace = src.find("{", m.end())
        if brace == -1:
            continue
        body, _ = balanced_braces(src[brace:])
        if "#[error(" in body:
            continue
        line_no = src.count("\n", 0, m.start()) + 1
        for variant, decl_text, fields in _parse_enum_variant_fields(body):
            findings.extend(
                bridge_declaration_findings(
                    path_label,
                    line_no,
                    variant,
                    decl_text,
                    fields,
                    local_error_enums,
                    aliases,
                    foreign_names,
                )
            )
    return findings


def discover_error_struct_names(raw: str) -> frozenset[str]:
    """Bare names of every `#[error("...")]`-decorated STRUCT (thiserror's
    other error shape — the attribute decorates the struct declaration
    ITSELF, not a variant inside a body) in `raw`.

    `discover_declarations`'s `local_error_enums` tier does not see these —
    it only walks `ENUM_RE` bodies. This is a second, narrow pass reusing
    the exact `#[error(` + `STRUCT_RE` recognition `scan_source` itself
    performs, on the SAME comments-blanked view, so a struct this guard
    scans is found the same way `scan_source` finds it rather than by a
    second, potentially-divergent rule.

    Feeds `scanned_error_type_names` (Task 3's E4 registry — see
    `discover_scanned_error_type_names`) alongside the bare spellings of
    `local_error_enums`.
    """
    src = strip_comments(raw)
    names: set[str] = set()
    for m in ERROR_ATTR_RE.finditer(src):
        _, after = balanced_slice(src, m.end() - 1)
        tail_raw = src[after:]
        tail = (
            tail_raw[tail_raw.find("]") + 1 :]
            if tail_raw.lstrip().startswith("]")
            else tail_raw
        )
        tail = skip_attributes(tail)
        for line in tail.splitlines():
            if line.strip():
                sm = STRUCT_RE.match(line)
                if sm:
                    names.add(sm.group(1))
                break
    return frozenset(names)


def balanced_braces(src: str) -> tuple[str, int]:
    """Return the `{...}`-balanced text starting at `src[0] == '{'`."""
    depth, i, in_string = 0, 0, False
    while i < len(src):
        ch = src[i]
        if in_string:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return src[: i + 1], i + 1
        i += 1
    return src, len(src)


def load_allowlist(path: Path) -> set[str]:
    """Parse the allowlist into a set of `path\\trule\\tnormalized attribute
    text` keys.

    Format, one per line, TAB-separated — IDENTICAL to the two shell guards'
    allowlists so that `scripts/lib/hygiene-allowlist.sh::allowlisted` can parse
    this same file:

        <repo-relative-path><TAB><rule><TAB><normalized #[error(...)] text><TAB><reason>

    The third column is the ENTIRE `#[error(...)]` attribute — not just its
    first source line — whitespace-collapsed to one line (`scan_source`'s
    `key_text`). Keying on just the first line would give a multi-line
    attribute (`sync/error.rs:9`) the literal key `#[error(`, which is not
    unique: any other multi-line attribute in the same file collides on it,
    so one reviewed entry would silently also exempt an unreviewed one. That
    is the exact "substring exempts everything" failure the exact-match
    convention exists to prevent, one level up. Matching is on the EXACT
    normalized text, never a substring, for the same reason #467/#475
    established it for the shell guards.
    """
    entries: set[str] = set()
    if not path.exists():
        return entries
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        entries.add(f"{parts[0].strip()}\t{parts[1].strip()}\t{parts[2].strip()}")
    return entries


def _discover_tier_inputs(
    sources: list[tuple[str, str]],
) -> tuple[frozenset[str], dict[str, str], frozenset[str]]:
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
    dropped from the resolvable set entirely, so a lookup against it
    default-denies instead of guessing which definition was "real."

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
    return local_error_enums, aliases, consts


def discover_scanned_error_type_names(
    core_sources: list[tuple[str, str]],
    bridge_sources: list[tuple[str, str]],
    core_enums: frozenset[str],
    bridge_enums: frozenset[str],
) -> frozenset[str]:
    """Every `#[error]`-bearing ENUM or STRUCT name this guard scans, under
    EITHER root (#480) — the registry Task 3's rule E4 will use to verify
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

    Not consumed by rules E1/E2 — computed here, in `run_real_scan`'s own
    discovery phase, so Task 3 only has to ADD a consumer rather than build
    the cross-root discovery plumbing this function already does.
    """
    names = {n for n in core_enums if "::" not in n}
    names |= {n for n in bridge_enums if "::" not in n}
    for _, raw in core_sources:
        names |= discover_error_struct_names(raw)
    for _, raw in bridge_sources:
        names |= discover_error_struct_names(raw)
    return frozenset(names)


def run_real_scan() -> int:
    allowlist = load_allowlist(ALLOWLIST_PATH)
    core_sources = [
        (str(rs.relative_to(REPO_ROOT)), rs.read_text(encoding="utf-8"))
        for rs in sorted(SCAN_ROOT.rglob("*.rs"))
    ]
    bridge_sources = [
        (str(rs.relative_to(REPO_ROOT)), rs.read_text(encoding="utf-8"))
        for rs in sorted(BRIDGE_SCAN_ROOT.rglob("*.rs"))
    ]

    # Pass 1, once per root — core's tier inputs come from ONLY core
    # sources, bridge's from ONLY bridge sources; see `_discover_tier_inputs`.
    core_enums, core_aliases, core_consts = _discover_tier_inputs(core_sources)
    bridge_enums, bridge_aliases, bridge_consts = _discover_tier_inputs(bridge_sources)

    # Task 3's E4 registry (#480): not consumed by E1/E2 — computing it on
    # every real-scan run proves the cross-root discovery plumbing Task 3
    # will build its rule on actually runs clean, rather than being an
    # unexercised, unproven claim. Task 3's E4 reads `scanned_error_type_names`
    # here once it has a consumer; unused until then.
    scanned_error_type_names = discover_scanned_error_type_names(
        core_sources, bridge_sources, core_enums, bridge_enums
    )

    # Pass 2: the actual scan, now with tiers 2, 3, and 4 available — each
    # file's own foreign `use` bindings withdrawing the bare-name credits
    # that file's namespace contradicts. Core files scan EXACTLY as before
    # this function grew a bridge half: same sources, same discovery inputs,
    # same `scan_source` call (`bridge_mode` defaults False).
    violations: list[Finding] = []
    for label, raw in core_sources:
        foreign = foreign_use_names(raw)
        for f in scan_source(label, raw, core_enums, core_aliases, core_consts, foreign):
            if f"{f.path}\t{f.rule}\t{f.source_line}" in allowlist:
                continue
            violations.append(f)

    # Bridge files: rule E1's interpolated-field scan runs in `bridge_mode`
    # (the carve-out — item 1), PLUS rule E2's two structural sweeps (items
    # 2 and 3) — `scan_source` itself (sweep 1, thiserror-derived
    # declarations) and `scan_bridge_plain_enums` (sweep 2, plain-derive
    # `*Error`/`*Warning` enums with no `#[error(...)]` attribute at all).
    for label, raw in bridge_sources:
        foreign = foreign_use_names(raw)
        findings = scan_source(
            label,
            raw,
            bridge_enums,
            bridge_aliases,
            bridge_consts,
            foreign,
            bridge_mode=True,
        )
        findings += scan_bridge_plain_enums(label, raw, bridge_enums, bridge_aliases, foreign)
        for f in findings:
            if f"{f.path}\t{f.rule}\t{f.source_line}" in allowlist:
                continue
            violations.append(f)

    if violations:
        print("error-payload hygiene: FAIL\n", file=sys.stderr)
        for v in violations:
            if v.field_type.startswith("UNPARSED:"):
                detail = f"{v.field_type} (variant hint: {v.variant}, field hint: {v.field})"
            elif v.rule == "E2":
                # Rule E2 findings come from the STRUCTURAL sweep
                # (`bridge_declaration_findings`) — the field need not be
                # interpolated into any message at all (uniffi/PyO3 project
                # every field regardless of `Display`), so "interpolates"
                # would misdescribe it.
                detail = f"variant {v.variant} declares `{v.field}: {v.field_type}` (not gated)"
            else:
                detail = f"variant {v.variant} interpolates `{v.field}: {v.field_type}`"
            print(
                f"  {v.path}:{v.line}\n"
                f"    {detail}\n"
                f"    {v.source_line}",
                file=sys.stderr,
            )
        print(
            f"\n{len(violations)} violation(s). A `core` or bridge error "
            "declaration must not carry an ungated runtime String — it "
            "reaches both platform UIs and their logs (#474/#480). Carry a "
            "&'static str hint plus an ordinal, or record a reviewed "
            "exception in\n  "
            f"{ALLOWLIST_PATH.relative_to(REPO_ROOT)}",
            file=sys.stderr,
        )
        return 1
    print("error-payload hygiene: OK")
    return 0


# `(label, source)` or `(label, source, expectation)`. The optional third
# element is a `ControlExpectation` (below) asserting WHICH finding the
# control must produce — see its comment for why "something fired" is not a
# strong enough assertion for a control that pins a parser fix.
POSITIVE_CONTROLS: list[tuple] = [
    (
        "P1 struct variant with a String payload",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("duplicate map key: {key}")]
            DuplicateKey { key: String },
        }
        ''',
    ),
    (
        "P2 tuple variant with a String payload",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("CBOR decode error: {0}")]
            CborDecode(String),
        }
        ''',
    ),
    (
        "P3 Vec<u8> payload",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("bad bytes: {raw:?}")]
            BadBytes { raw: Vec<u8> },
        }
        ''',
    ),
    (
        "P4 unrecognised type denies by default",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("wrapped: {inner}")]
            Wrapped { inner: SomeFutureType },
        }
        ''',
    ),
    (
        "P5 trailing format argument referencing a field that is NOT "
        "positionally first (the mnemonic.rs shape) — proves ARG_FIELD_RE "
        "is load-bearing, not just positional-index luck",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("word #{} is unknown", .word)]
            UnknownWord { index: usize, word: String },
        }
        ''',
    ),
    (
        "P6 multi-line attribute",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error(
                "a long message that wraps: {detail}"
            )]
            Wrapped { detail: String },
        }
        ''',
    ),
    (
        "P7 PathBuf payload",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("no such folder: {path}")]
            Missing { path: PathBuf },
        }
        ''',
    ),
    (
        "P8 third-party nested error must still deny (proves the recursion "
        "tier isn't over-relaxed — std::io::Error is not scanned by this "
        "guard, so it gets no credit from being a nested #[from] error)",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("io failure: {0}")]
            Io(#[from] std::io::Error),
        }
        ''',
        # Not merely "something fired": the finding must be the TYPE verdict
        # on the io field. An UNPARSED here would mean the guard lost track
        # of the structure and passed the control for the wrong reason.
        {"field": "0", "field_type": "#[from] std::io::Error"},
    ),
    (
        "P9 alias to String is not data-free (aliasing doesn't launder a "
        "runtime string into something the guard trusts)",
        '''
        type DetailText = String;

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("leak: {detail}")]
            Leaky { detail: DetailText },
        }
        ''',
    ),
    (
        "P10 struct-shaped thiserror error (not an enum variant) is scanned",
        '''
        #[derive(thiserror::Error, Debug)]
        #[error("leak: {detail}")]
        pub struct E {
            detail: String,
        }
        ''',
    ),
    (
        "P11 a real placeholder immediately after an escaped brace "
        "({{{name}}}) must still resolve — the triple-brace shape a "
        "lookbehind-based matcher misses",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("{{{secret}}}")]
            Wrapped { secret: String },
        }
        ''',
    ),
    (
        "P12 #[source] on a STRUCT-variant field — the live vault/mod.rs "
        "and sync/error.rs shape; the attribute lands on the NAME side, "
        "not the type side",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("io error ({context}): {source}")]
            Wrapped {
                context: &'static str,
                #[source]
                source: std::io::Error,
            },
        }
        ''',
        # THE control for `strip_field_attrs`, so it must assert on the
        # RESULT, not on non-emptiness. Reverting that fix (dropping back to
        # a bare `.strip()` on the name side) leaves the field named
        # `#[source] source`, `{source}` matches nothing, and the attribute
        # falls through to UNPARSED — which is still a finding, so a
        # non-emptiness assertion stayed green and the control stopped
        # pinning its own mechanism. Naming the field and type here is what
        # makes reverting the fix break THIS control.
        {"variant": "Wrapped", "field": "source", "field_type": "std::io::Error"},
    ),
    (
        "P13 #[error(transparent)] over a third-party source must still "
        "deny — the live sync/error.rs:24 shape, with a non-core source",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error(transparent)]
            Wrapped(#[from] std::io::Error),
        }
        ''',
        {"variant": "Wrapped", "field": "0", "field_type": "#[from] std::io::Error"},
    ),
    (
        "P14 an intervening #[allow(...)] attribute between #[error] and "
        "the variant must not hide it",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("leak: {detail}")]
            #[allow(dead_code)]
            Leaky { detail: String },
        }
        ''',
        # THE control for `skip_attributes`, so — exactly as with P12 — it
        # asserts on the verdict. Reverting that fix (making
        # `skip_attributes` the identity) leaves the guard unable to locate
        # the variant at all, which now emits UNPARSED rather than silently
        # passing; a non-emptiness assertion could not tell the two apart.
        {"variant": "Leaky", "field": "detail", "field_type": "String"},
    ),
    (
        "P15 an unrecognisable construct after #[error(...)] must fail "
        "closed as UNPARSED, not silently pass",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("leak: {detail}")]
            !!!not_a_valid_variant_shape!!!
        }
        ''',
    ),
    (
        "P16 a placeholder that matches no parsed field name must fail "
        "closed as UNPARSED, not silently pass",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("leak: {nonexistent}")]
            Leaky { detail: String },
        }
        ''',
    ),
    (
        "P17 a positional placeholder with no corresponding declared field "
        "must fail closed as UNPARSED, not silently pass",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("leak #{}")]
            Empty,
        }
        ''',
    ),
    (
        "P18 a placeholder naming something that is neither a parsed field "
        "NOR a discovered const must still fail closed as UNPARSED — proves "
        "the const tier is an ADDITIONAL recognised-safe category, not a "
        "fallback that accepts any unknown name (a real const is present "
        "in this same snippet, so discovery genuinely ran)",
        '''
        pub const KNOWN_CONST: usize = 16;

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("leak: {totally_unknown_name}")]
            Leaky { detail: String },
        }
        ''',
    ),
    (
        "P19 a placeholder naming a `static`, not a `const`, must still "
        "fail closed as UNPARSED — a static (even immutable) does not "
        "carry the same compile-time-evaluated guarantee",
        '''
        pub static NOT_A_CONST: usize = 16;

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("leak: {NOT_A_CONST}")]
            Leaky { detail: String },
        }
        ''',
        {"unparsed": True, "field": "NOT_A_CONST"},
    ),
    # P20-P22 are deliberately STRUCT-shaped errors at module scope, not
    # enum variants. In an enum, the injected text lands inside the enum's
    # own braces, which `non_module_block_spans` already excludes — so an
    # enum-shaped control fires whether or not string blanking works, and
    # pins nothing. Mutating `discovery_view` back to `strip_comments`
    # (no blanking) must break exactly these three.
    (
        "P20 a `const` declaration written INSIDE the #[error] message text "
        "must not self-authorise its own placeholder — declaration "
        "discovery runs over a view with string literals blanked",
        '''
        #[derive(thiserror::Error, Debug)]
        #[error("leaked field name: {SELF_AUTH} const SELF_AUTH: usize = 1;")]
        pub struct SelfAuthorised;
        ''',
        {"unparsed": True, "field": "SELF_AUTH"},
    ),
    (
        "P21 a `type` alias written INSIDE the #[error] message text must "
        "not launder the field it names (same root cause as P20, tier 3)",
        '''
        #[derive(thiserror::Error, Debug)]
        #[error("x type ZzFakeAlias = usize; leak {detail}")]
        pub struct AliasInjected {
            detail: ZzFakeAlias,
        }
        ''',
        {"variant": "AliasInjected", "field": "detail", "field_type": "ZzFakeAlias"},
    ),
    (
        "P22 a thiserror-shaped `enum` written INSIDE the #[error] message "
        "text must not earn the recursion tier (same root cause as P20, "
        "tier 2)",
        '''
        #[derive(thiserror::Error, Debug)]
        #[error("x enum ZzFakeEnum { #[error(\\"y\\")] Aaa, } leak {0}")]
        pub struct EnumInjected(ZzFakeEnum);
        ''',
        {"variant": "EnumInjected", "field": "0", "field_type": "ZzFakeEnum"},
    ),
    (
        "P23 a `static` of the same name DISQUALIFIES a const spelling — the "
        "cross-module shape that made a real `static LazyLock<String>` "
        "capture go silent once an unrelated const of that name existed",
        '''
        mod a {
            pub static LEAKY_NAME: LazyLock<String> =
                LazyLock::new(|| std::env::var("SECRET_FIELD").unwrap_or_default());
        }

        mod b {
            pub const LEAKY_NAME: usize = 16;
        }

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("duplicate key: {LEAKY_NAME}")]
            LeakViaStatic,
        }
        ''',
        {"unparsed": True, "field": "LEAKY_NAME"},
    ),
    (
        "P24 two module-scope consts of the same bare name are a COLLISION, "
        "not a resolution — the spelling is dropped, same discipline as a "
        "colliding type alias",
        '''
        mod a {
            pub const DUP_LEN: usize = 16;
        }

        mod b {
            pub const DUP_LEN: usize = 32;
        }

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("expected {DUP_LEN} bytes")]
            Bad,
        }
        ''',
        {"unparsed": True, "field": "DUP_LEN"},
    ),
    (
        "P25 a #[cfg(test)] const does not vouch for a shipped message — "
        "six of the tree's 134 harvested const names came from test "
        "modules, one literally named SECRET_FIELD_NAME",
        '''
        #[cfg(test)]
        mod tests {
            pub const SECRET_FIELD_NAME: usize = 16;
        }

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("expected {SECRET_FIELD_NAME} bytes")]
            Bad,
        }
        ''',
        {"unparsed": True, "field": "SECRET_FIELD_NAME"},
    ),
    (
        "P26 a const declared inside a fn body is not a module-scope name a "
        "format capture could reach",
        '''
        fn helper() {
            const INNER_LEN: usize = 16;
            let _ = INNER_LEN;
        }

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("expected {INNER_LEN} bytes")]
            Bad,
        }
        ''',
        {"unparsed": True, "field": "INNER_LEN"},
    ),
    (
        "P27 a trait's associated const is a per-impl binding, not a free "
        "name (the associated-`type` exclusion, applied to consts)",
        '''
        pub trait Sized2 {
            const TRAIT_LEN: usize = 16;
        }

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("expected {TRAIT_LEN} bytes")]
            Bad,
        }
        ''',
        {"unparsed": True, "field": "TRAIT_LEN"},
    ),
    (
        "P28 a bare name this file `use`s from OUTSIDE the crate is not the "
        "core-local enum that shares its spelling — core/src/error.rs's "
        "`pub enum Error` made `use std::io::Error;` pass silently",
        '''
        mod local {
            #[derive(thiserror::Error, Debug)]
            pub enum Error {
                #[error("inner failure code {code}")]
                Failure { code: u32 },
            }
        }

        use std::io::Error;

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("io: {0}")]
            BareIoError(#[from] Error),
        }
        ''',
        {"variant": "BareIoError", "field": "0", "field_type": "#[from] Error"},
    ),
    (
        "P29 a RAW string with an odd number of internal quotes must not "
        "re-expose its contents as code — the round-4 blanker had no notion "
        "of `r#\"...\"#`, so this walked straight through the fix that was "
        "supposed to have closed self-authorisation",
        '''
        const ZZ_HELP: &str = r#"a" const RAW_INJECTED: usize = 1; "b"#;

        #[derive(thiserror::Error, Debug)]
        #[error("expected {RAW_INJECTED} bytes")]
        pub struct Bad;
        ''',
        {"unparsed": True, "field": "RAW_INJECTED"},
    ),
    (
        "P30 a char literal holding a brace must not move the braces — "
        "`let c = '}';` in a fn body popped that function's own block and "
        "promoted every following declaration to module scope",
        '''
        fn zz_helper() -> char {
            let c = '}';
            const FN_LOCAL_LEN: usize = 1;
            let _ = FN_LOCAL_LEN;
            c
        }

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("expected {FN_LOCAL_LEN} bytes")]
            Bad,
        }
        ''',
        {"unparsed": True, "field": "FN_LOCAL_LEN"},
    ),
    (
        "P31 a char literal holding a QUOTE must not desync the string "
        "state across the following `use` — that inverted the withdrawal "
        "pass and handed back the bare-name enum bypass",
        '''
        mod local {
            #[derive(thiserror::Error, Debug)]
            pub enum Error {
                #[error("inner failure code {code}")]
                Failure { code: u32 },
            }
        }

        fn zz_q() -> char { '"' }

        use std::io::Error;

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("io: {0}")]
            BareIoError(#[from] Error),
        }
        ''',
        {"variant": "BareIoError", "field": "0", "field_type": "#[from] Error"},
    ),
    (
        "P32 a NESTED `mod std` must not make `use std::…` look intra-crate "
        "— `mod outer { pub mod std { } }` compiles beside the import, so an "
        "unscoped harvest of every `mod NAME` reopened the bypass",
        '''
        mod local {
            #[derive(thiserror::Error, Debug)]
            pub enum Error {
                #[error("inner failure code {code}")]
                Failure { code: u32 },
            }
        }

        mod outer { pub mod std { } }

        use std::io::Error;

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("io: {0}")]
            BareIoError(#[from] Error),
        }
        ''',
        {"variant": "BareIoError", "field": "0", "field_type": "#[from] Error"},
    ),
    (
        "P33 a #[cfg(test)] ENUM must not vouch for a shipped message "
        "either — round 4 applied the test exclusion to consts only, so a "
        "test-only error enum still registered its bare name tree-wide and "
        "a shipped struct of the same name rode on it",
        '''
        #[cfg(test)]
        mod tests {
            #[derive(thiserror::Error, Debug)]
            pub enum ZzShared {
                #[error("code {0}")]
                A(u32),
            }
        }

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("shared: {0}")]
            Wrapped(ZzShared),
        }
        ''',
        {"variant": "Wrapped", "field": "0", "field_type": "ZzShared"},
    ),
    # P34-P36 pin `alias_shadowed_names`. Before it existed, EVERY one of
    # these reported ZERO findings: `is_data_free` consulted tier 1 (a name
    # match against `DATA_FREE_TYPES`) before it ever looked at the alias
    # table, so a `type` alias that reused a trusted name was invisible. One
    # file, no collision, no ordering dependence, no `#[allow]` — the same
    # reachability as the round-4 string-literal self-authorisation CRITICAL.
    (
        "P34 `type CborFault = String;` must not launder a String through "
        "tier 1 — the shape rustc does NOT catch (already CamelCase, so "
        "`non_camel_case_types` never fires) and the reason this drop is a "
        "CRITICAL rather than a tidy-up",
        '''
        type CborFault = String;

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("CBOR fault: {fault}")]
            Bad { fault: CborFault },
        }
        ''',
        {"variant": "Bad", "field": "fault", "field_type": "CborFault"},
    ),
    (
        "P35 `type usize = String;` must not launder a String through tier 1 "
        "— the shape the module docstring used to name as the WHOLE limit, "
        "and the only one this repo's -D warnings gate happens to reject on "
        "its own",
        '''
        type usize = String;

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("length {length}")]
            Bad { length: usize },
        }
        ''',
        {"variant": "Bad", "field": "length", "field_type": "usize"},
    ),
    (
        "P36 `type bool = String;` — the shadow must deny through the "
        "`Option<T>` recursion too, not only at the top level",
        '''
        type bool = String;

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("flag {flag:?}")]
            Bad { flag: Option<bool> },
        }
        ''',
        {"variant": "Bad", "field": "flag", "field_type": "Option<bool>"},
    ),
    (
        "P37 Rust block comments NEST — `/* a /* b */ const … */` is comment "
        "all the way to the LAST `*/`, so the const inside it declares "
        "nothing. A C-style (non-nesting) scanner ends the comment at the "
        "FIRST `*/`, promotes the const to code, and hands back the round-4 "
        "self-authorisation CRITICAL in a new costume. `LEXER_SAMPLE` "
        "carries a nested comment but only feeds the length/line invariants, "
        "which C semantics preserve — nothing pinned the SEMANTICS until "
        "this control",
        '''
        /* outer /* inner */ pub const NESTED_INJECTED: usize = 1; */

        #[derive(thiserror::Error, Debug)]
        #[error("expected {NESTED_INJECTED} bytes")]
        pub struct Bad;
        ''',
        {"unparsed": True, "field": "NESTED_INJECTED"},
    ),
    (
        "P38 an UNTERMINATED block comment must not hide a `use` from the "
        "withdrawal pass — `lex_spans` deliberately runs such a construct to "
        "end-of-input, which is fail-CLOSED for the credit registries and "
        "fail-OPEN for `foreign_use_names`. THE control for round 5's "
        "headline fix (that pass reading RAW, unioned with the blanked "
        "read): pointing it at the blanked view alone leaves P31 green, "
        "because the lexer handles `'\\\"'` correctly today, and leaves this "
        "one RED",
        '''
        mod local {
            #[derive(thiserror::Error, Debug)]
            pub enum Error {
                #[error("inner failure code {code}")]
                Failure { code: u32 },
            }
        }

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("io: {0}")]
            BareIoError(#[from] Error),
        }

        /* this block comment is never closed, so every view derived from the
           lexer blanks the `use` below — but the raw text still carries it
        use std::io::Error;
        ''',
        {"variant": "BareIoError", "field": "0", "field_type": "#[from] Error"},
    ),
    (
        "P39 P38's shape written as a RENAMING import. This is the control "
        "`_looks_like_use_tree`'s ` as ` -> `|` normalisation has to survive: "
        "with `|` absent from USE_TREE_CHARS_RE every `use … as …;` failed "
        "the raw read's prose filter, so all 15 renaming imports under "
        "core/src/** rested on the blanked read alone — and the blanked read "
        "is exactly what an unterminated comment disarms. Breaks under "
        "EITHER mutation (drop `|` from the class, or point the withdrawal "
        "pass back at the blanked view); P38 breaks only under the second, "
        "which is what separates the two",
        '''
        mod local {
            #[derive(thiserror::Error, Debug)]
            pub enum ZzRenamedError {
                #[error("inner failure code {code}")]
                Failure { code: u32 },
            }
        }

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("io: {0}")]
            BareIoError(#[from] ZzRenamedError),
        }

        /* never closed, so the blanked view cannot see the rename below
        use std::io::Error as ZzRenamedError;
        ''',
        {
            "variant": "BareIoError",
            "field": "0",
            "field_type": "#[from] ZzRenamedError",
        },
    ),
    (
        "P40 thiserror 2.x `#[error(fmt = <path>)]` — a custom formatter is "
        "handed EVERY field and can render a `String` into `Display`, but the "
        "attribute has no format string, so placeholder extraction yields "
        "nothing and the `if not names` skip once waved it through (#485). It "
        "compiles clean and passes clippy, so nothing else catches it. Must "
        "now fail closed as UNPARSED — an #[error(...)] body this guard cannot "
        "model as a string-literal format",
        '''
        fn render(_detail: &String, _f: &mut std::fmt::Formatter<'_>)
            -> std::fmt::Result { Ok(()) }

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error(fmt = render)]
            Leak(String),
        }
        ''',
        {"unparsed": True, "variant": "Leak"},
    ),
]

NEGATIVE_CONTROLS: list[tuple[str, str]] = [
    (
        "N1 &'static str hint plus an ordinal — the #474 fix shape",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("duplicate map key at entry #{} of {field}", .index + 1)]
            DuplicateKey { field: &'static str, index: usize },
        }
        ''',
    ),
    (
        "N2 CborFault payload",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("CBOR decode error: {0}")]
            CborDecode(CborFault),
        }
        ''',
    ),
    (
        "N3 fixed-size byte array",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("block {block_uuid:02x?} failed")]
            Failed { block_uuid: [u8; 16] },
        }
        ''',
    ),
    (
        "N4 message interpolates nothing",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("expected top-level CBOR map")]
            NotAMap,
        }
        ''',
    ),
    (
        "N5 Option<usize>",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("failed at {offset:?}")]
            At { offset: Option<usize> },
        }
        ''',
    ),
    (
        "N6 a commented-out #[error(...)] above a LIVE, unattributed "
        "variant must not fire — proves comment-stripping is load-bearing "
        "(without it, VARIANT_RE would happily match the real variant text "
        "that follows the fake attribute)",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            // #[error("leaky: {key}")]
            Leaky { key: String },
            #[error("fine")]
            Fine,
        }
        ''',
    ),
    (
        "N7 the whole violation is inside a block comment",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            /* #[error("leaky: {key}")]
               Leaky { key: String }, */
            #[error("fine")]
            Fine,
        }
        ''',
    ),
    (
        "N8 escaped braces are not placeholders, even with a String field "
        "present to catch a phantom match",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("expected {{ }} shape")]
            Shape { secret: String },
        }
        ''',
    ),
    (
        "N9 nested core-local error type is data-free by recursion (this "
        "guard already scans InnerError's own definition below, so the "
        "forward through Wrapped's {0} adds no new leak surface)",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum InnerError {
            #[error("inner failure code {code}")]
            Failure { code: u32 },
        }

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("outer: {0}")]
            Wrapped(#[from] InnerError),
        }
        ''',
    ),
    (
        "N10 alias to a fixed-size byte array resolves data-free",
        '''
        type BlockUuid = [u8; 16];

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("block {block_uuid:02x?} failed")]
            Failed { block_uuid: BlockUuid },
        }
        ''',
    ),
    (
        "N11 #[error(transparent)] over a core-local, already-scanned "
        "error type is data-free by recursion",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum Inner {
            #[error("inner failure code {code}")]
            Failure { code: u32 },
        }

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error(transparent)]
            Wrapped(#[from] Inner),
        }
        ''',
    ),
    (
        "N12 a placeholder capturing a real module-level `const` is "
        "data-free by definition — compile-time evaluated, so it cannot "
        "carry runtime content regardless of its declared type (the live "
        "vault/record.rs:155 shape: one placeholder is a genuine field, "
        "the other is a const)",
        '''
        pub const RECORD_UUID_LEN: usize = 16;

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("invalid UUID: expected {RECORD_UUID_LEN} bytes, got {length}")]
            InvalidUuid { length: usize },
        }
        ''',
    ),
    (
        "N13 an INTRA-crate `use` of a core-local error type keeps the "
        "recursion tier — P28's foreign-import drop must be about the "
        "import's ROOT, not about `use` statements in general",
        '''
        mod local {
            #[derive(thiserror::Error, Debug)]
            pub enum Error {
                #[error("inner failure code {code}")]
                Failure { code: u32 },
            }
        }

        use crate::local::Error;

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("wrapped: {0}")]
            Wrapped(#[from] Error),
        }
        ''',
    ),
    (
        "N14 a const declared at module scope INSIDE a `mod` block is still "
        "module scope — the non-module-block exclusion must exempt exactly "
        "`mod { }` and nothing else, or every const in the tree vanishes",
        '''
        mod inner {
            pub const INNER_CONST: usize = 16;
        }

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("expected {INNER_CONST} bytes, got {length}")]
            Bad { length: usize },
        }
        ''',
    ),
    (
        "N15 a Rust-2018 UNIFORM-PATH re-export (`use inner::X;` beside "
        "`mod inner;`, no crate:: prefix) is intra-crate — the live "
        "core/src/vault/mod.rs shape; misreading `inner` as a third-party "
        "crate name produced four spurious findings there",
        '''
        mod inner {
            #[derive(thiserror::Error, Debug)]
            pub enum InnerError {
                #[error("inner failure code {code}")]
                Failure { code: u32 },
            }
        }

        pub use inner::InnerError;

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("wrapped: {0}")]
            Wrapped(#[from] InnerError),
        }
        ''',
    ),
    (
        "N16 a raw string must END where Rust says it ends — a scanner that "
        "over-consumes hides every declaration after it, so the const "
        "DELIBERATELY sits below the raw string",
        '''
        pub const HELP: &str = r#"usage: thing "quoted" here"#;
        pub const REAL_LEN: usize = 16;

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("expected {REAL_LEN} bytes, got {length}")]
            Bad { length: usize },
        }
        ''',
    ),
    (
        "N17 a LIFETIME is not a char literal — `&'static str` is the shape "
        "that makes the apostrophe ambiguous, and a scanner that opens a "
        "char literal there runs to end-of-file swallowing the const below",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("field {field}: expected {LIFE_LEN}")]
            Bad { field: &'static str, length: usize },
        }

        pub const LIFE_LEN: usize = 16;
        ''',
    ),
    (
        "N18 a field-level VISIBILITY modifier is not part of the field's "
        "name (or of its type) — `parse_fields` split on the first `:` and "
        "took the name side verbatim, so `pub index: usize` became a field "
        "literally named `pub index`, `{index}` matched nothing, and valid "
        "code produced a spurious UNPARSED. Covers all three shapes: a `pub` "
        "struct field, a `pub(crate)` one, and a `pub` TUPLE field (whose "
        "modifier lands on the TYPE side instead, hence a second strip in "
        "`normalize_type`)",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("entry #{index} of {field}")]
            Bad {
                pub field: &'static str,
                pub(crate) index: usize,
            },
            #[error("length {0}")]
            Len(pub usize),
        }
        ''',
    ),
]


# Rule E2 (#480) — mirrors `POSITIVE_CONTROLS` / `NEGATIVE_CONTROLS`, run
# through `scan_bridge_control` (`bridge_mode=True` + `scan_bridge_plain_enums`)
# instead of `scan_control`. Same `(label, source)` / `(label, source,
# expectation)` tuple shape.
BRIDGE_POSITIVE_CONTROLS: list[tuple] = [
    (
        "BP1 String field under an unsanctioned name in a thiserror enum",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("bad version")]
            UnknownVersion { version: String },
        }
        ''',
    ),
    (
        "BP2 String field under an unsanctioned name, interpolated (E1 path "
        "still denies in bridge_mode)",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("bad: {version}")]
            UnknownVersion { version: String },
        }
        ''',
    ),
    (
        "BP3 non-thiserror *Error enum with a stray String field",
        '''
        pub enum SettingsParseError {
            UnknownVersion { version: String },
        }
        ''',
    ),
    (
        "BP4 Vec<u8> under a gated name still denies (type must be exactly "
        "String)",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("x")]
            V { detail: Vec<u8> },
        }
        ''',
    ),
]

BRIDGE_NEGATIVE_CONTROLS: list[tuple[str, str]] = [
    (
        "BN1 detail: String under a gated name passes the declaration scan",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("sync failed: {detail}")]
            SyncFailed { detail: String },
        }
        ''',
    ),
    (
        "BN2 data-free payloads pass untouched",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("at #{index}")]
            V { index: usize },
        }
        ''',
    ),
    (
        "BN3 *Error enum inside cfg(test) is not swept",
        '''
        #[cfg(test)]
        mod tests {
            pub enum FakeError {
                V { leak: String },
            }
        }
        ''',
    ),
]


# `(variant, field, field_type)` claims a POSITIVE control makes about the
# finding it expects, beyond "something fired". `unparsed` asserts the
# finding IS (or is not) the default-deny-on-structure kind.
#
# Non-emptiness alone is not enough for a control that pins a PARSER fix:
# once an unresolvable construct became an `UNPARSED` finding rather than a
# silent skip, reverting such a fix left the control green — the guard still
# reported something, just not the thing the control existed to prove. P12
# and P14 were both in that state.
ControlExpectation = dict[str, object]


def _finding_matches(f: Finding, expect: ControlExpectation) -> bool:
    is_unparsed = f.field_type.startswith("UNPARSED:")
    if "unparsed" in expect and bool(expect["unparsed"]) is not is_unparsed:
        return False
    if "variant" in expect and f.variant != expect["variant"]:
        return False
    if "field" in expect and f.field != expect["field"]:
        return False
    if "field_type" in expect and f.field_type != expect["field_type"]:
        return False
    return True


#  A synthetic source carrying every lexical shape the guard has ever been
#  broken by, plus the ones it has not: nested block comments, a `\` + newline
#  continuation, raw strings with a `#` run and internal quotes, byte and raw
#  byte strings, char literals holding a quote / a brace / an escaped quote,
#  and a lifetime. Used by `check_view_invariants` — see there.
LEXER_SAMPLE = (
    '#[error("continued \\\n        message: {a}")]\n'
    "/* block\n   comment /* nested */ still comment */ const A: usize = 1;\n"
    "// line comment\n"
    'let s = "quote \\" inside";\n'
    'let r = r#"raw " with quote and /* not a comment */"#;\n'
    'let r2 = r##"raw "# inner"##;\n'
    'let b = b"bytes \\x00";\n'
    'let br = br#"raw " bytes"#;\n'
    "let q = '\"';\n"
    "let ob = '{';\n"
    "let cb = '}';\n"
    "let esc = '\\'';\n"
    "let bs = '\\\\';\n"
    "let bc = b'x';\n"
    "fn f<'a>(x: &'a str) -> &'static str { x }\n"
)


def check_view_invariants() -> list[str]:
    r"""The lexer and both views it feeds are indexed into by CHARACTER
    OFFSET — the reported line number, every `_inside(...)` span check and the
    raw-text allowlist key all assume a view lines up with its source
    byte-for-byte and line-for-line.

    An earlier round shipped a violation of exactly this: a `\` + newline
    string continuation emitted a space for the newline, so every subsequent
    line number in the file was reported low. Three properties are asserted
    over every self-test control plus `LEXER_SAMPLE`:

    1. `lex_spans` returns spans that are ordered, non-overlapping and inside
       the source. A classification that overlaps itself is a classification
       that has lost track of where it is, which is the single root cause
       behind every view bug this guard has had.
    2. Both views preserve LENGTH.
    3. Both views preserve LINE COUNT.
    """
    samples = [src for _, src, *_ in POSITIVE_CONTROLS]
    samples += [src for _, src in NEGATIVE_CONTROLS]
    samples += [src for _, src, *_ in BRIDGE_POSITIVE_CONTROLS]
    samples += [src for _, src in BRIDGE_NEGATIVE_CONTROLS]
    samples.append(LEXER_SAMPLE)
    failures: list[str] = []
    for i, src in enumerate(samples):
        prev_end = 0
        for start, end, kind in lex_spans(src):
            if not (0 <= start <= end <= len(src)):
                failures.append(
                    f"LEXER INVARIANT: span ({start},{end},{kind}) out of "
                    f"range on sample #{i} (len {len(src)})"
                )
            if start < prev_end:
                failures.append(
                    f"LEXER INVARIANT: span ({start},{end},{kind}) overlaps "
                    f"the previous span on sample #{i}"
                )
            prev_end = max(prev_end, end)
        for name, view in (
            ("strip_comments", strip_comments(src)),
            ("discovery_view", discovery_view(src)),
        ):
            if len(view) != len(src):
                failures.append(
                    f"VIEW INVARIANT: {name} changed length on sample #{i} "
                    f"({len(view)} != {len(src)})"
                )
            if view.count("\n") != src.count("\n"):
                failures.append(
                    f"VIEW INVARIANT: {name} changed line count on sample "
                    f"#{i} ({view.count(chr(10))} != {src.count(chr(10))})"
                )
    return failures


def check_key_shape(label: str, findings: list[Finding]) -> list[str]:
    """The allowlist key (`Finding.source_line`) must contain no TAB and no
    newline.

    `scripts/lib/hygiene-allowlist.sh::allowlisted` — the shared parser this
    file's allowlist format exists to stay compatible with — splits entries
    on TAB, and reads them one line at a time. A key carrying either
    character could not be written as an entry at all, or worse could be
    written in a way that silently truncates and matches more than it names.
    `scan_source` builds the key with `" ".join(text.split())`, which
    collapses both; this asserts the property rather than trusting it.
    """
    failures: list[str] = []
    for f in findings:
        if "\t" in f.source_line or "\n" in f.source_line:
            failures.append(
                f"ALLOWLIST KEY SHAPE: {label} produced a key containing a "
                f"TAB or newline: {f.source_line!r}"
            )
    return failures


def scan_control(src: str) -> list[Finding]:
    """Run the FULL pipeline over a self-test control string.

    Each control is self-contained (it declares any nested enum / alias /
    const / `use` it references in the same string), so a per-control
    discovery pass — no real file path, hence no `path_label` — exercises the
    real discovery, collision-drop and import-shadow code paths rather than a
    hardcoded name list.
    """
    enums, aliases, declared_consts, shadows = discover_declarations(src)
    consts = resolve_consts(declared_consts, shadows)
    return scan_source(
        "<self-test>", src, enums, aliases, consts, foreign_use_names(src)
    )


def scan_bridge_control(src: str) -> list[Finding]:
    """`scan_control`, run in `bridge_mode` PLUS rule E2's second sweep
    (#480) — mirrors `scan_control`'s self-contained-fixture design (no real
    file path, hence no qualified spellings; see `module_path_segments`).

    Runs BOTH of rule E2's producers, exactly as `run_real_scan` does for a
    real bridge file: `scan_source(..., bridge_mode=True)` (sweep 1,
    thiserror-derived declarations) and `scan_bridge_plain_enums` (sweep 2,
    plain-derive `*Error`/`*Warning` enums).
    """
    enums, aliases, declared_consts, shadows = discover_declarations(src)
    consts = resolve_consts(declared_consts, shadows)
    foreign = foreign_use_names(src)
    found = scan_source(
        "<self-test-bridge>", src, enums, aliases, consts, foreign, bridge_mode=True
    )
    found += scan_bridge_plain_enums("<self-test-bridge>", src, enums, aliases, foreign)
    return found


def run_self_test() -> int:
    failures: list[str] = check_view_invariants()
    for entry in POSITIVE_CONTROLS:
        label, src = entry[0], entry[1]
        expect: ControlExpectation | None = entry[2] if len(entry) > 2 else None
        found = scan_control(src)
        failures += check_key_shape(label, found)
        if not found:
            failures.append(f"POSITIVE control did not fire: {label}")
        elif expect and not any(_finding_matches(f, expect) for f in found):
            failures.append(
                f"POSITIVE control fired for the WRONG REASON: {label} -> "
                f"expected {expect}, got "
                f"{[(f.variant, f.field, f.field_type) for f in found]}"
            )
    for label, src in NEGATIVE_CONTROLS:
        found = scan_control(src)
        if found:
            failures.append(
                f"NEGATIVE control fired: {label} -> "
                f"{[(f.variant, f.field, f.field_type) for f in found]}"
            )
    for entry in BRIDGE_POSITIVE_CONTROLS:
        label, src = entry[0], entry[1]
        bridge_expect: ControlExpectation | None = entry[2] if len(entry) > 2 else None
        found = scan_bridge_control(src)
        failures += check_key_shape(label, found)
        if not found:
            failures.append(f"POSITIVE control did not fire: {label}")
        elif bridge_expect and not any(_finding_matches(f, bridge_expect) for f in found):
            failures.append(
                f"POSITIVE control fired for the WRONG REASON: {label} -> "
                f"expected {bridge_expect}, got "
                f"{[(f.variant, f.field, f.field_type) for f in found]}"
            )
    for label, src in BRIDGE_NEGATIVE_CONTROLS:
        found = scan_bridge_control(src)
        if found:
            failures.append(
                f"NEGATIVE control fired: {label} -> "
                f"{[(f.variant, f.field, f.field_type) for f in found]}"
            )
    if failures:
        print("self-test: FAIL", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    print(
        f"self-test: OK ({len(POSITIVE_CONTROLS)} positive / "
        f"{len(NEGATIVE_CONTROLS)} negative / "
        f"{len(BRIDGE_POSITIVE_CONTROLS)} bridge positive / "
        f"{len(BRIDGE_NEGATIVE_CONTROLS)} bridge negative)"
    )
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        sys.exit(run_self_test())
    sys.exit(run_real_scan())
