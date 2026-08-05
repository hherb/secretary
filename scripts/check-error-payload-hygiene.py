#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Fail-closed guard: no `core` error variant may interpolate a runtime String.

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
  (`ffi/secretary-ffi-bridge/**`) and is NOT scanned — see issue #478.
- Rust is parsed by pattern, not by a real parser. The shapes in this codebase
  are regular (thiserror derives); an exotic macro-generated error enum would
  be invisible. `--self-test` pins the shapes that do occur.
- The local-error-enum and type-alias recognition in `discover_declarations`
  matches by NAME (bare, `<parent-module>::Name`, or `crate::<path>::Name`),
  not by real `use`-import / path resolution. A bare, unqualified reference to
  a type from OUTSIDE `core/src/**` whose name collides with a `core`-local
  enum or alias (e.g. `use std::io::Error; ... Io(#[from] Error)`, colliding
  with `crate::error::Error`) would be misclassified as data-free. Nothing in
  this codebase currently does that; `--self-test` cannot pin the absence of a
  pattern, only its presence, so this is a standing risk for future code, not
  a closed gap.
- Name resolution stops at the type name as written. `type usize = String;`
  shadowing a `DATA_FREE_TYPES` primitive with an actual `String`, and then
  using that shadowed name as a field's declared type, is invisible to a
  matcher that only ever asks "does this token equal a known-safe name?" — it
  has no notion of scope, so it cannot tell the shadow from the primitive.
  Closing this requires a real type resolver, which is out of scope for a
  pattern-based guard; `--self-test` pins the shapes that DO occur, not every
  shape that could be contrived to evade it.
- `find_type_aliases` drops any spelling that resolves to DIFFERENT
  right-hand sides across files rather than guessing which one is "real" —
  see `run_real_scan`. `local_error_enums` does not need the same treatment:
  it is a pure membership set, not a name -> value map, and any enum whose
  name is registered is, by construction, a real `thiserror`-derived enum
  this guard independently scans somewhere under `core/src/**` — two
  DIFFERENT local enums sharing a bare name are both still soundly "safe by
  recursion," regardless of which one a given reference textually resolves
  to; there is no analogous "which value is real" ambiguity to collide on.
- `strip_comments` does not special-case RAW string literals (`r"..."`,
  `r#"..."#`). A raw string ending in a literal backslash immediately before
  its closing quote (`r"...\"`) is misread as an escaped quote, and the
  scanner stays "in a string" past the raw string's true end, leaving
  everything after it unstripped until the next real `"`. No `#[error(...)]`
  attribute under `core/src/**` uses a raw string today; a correct fix needs
  variable-length `#`-run tracking (`r#"..."#`, `r##"..."##`, ...), which is
  out of scope for now.
- `discover_declarations` excludes `type X = Y;` declarations found inside
  `impl ... { }` blocks (a trait's ASSOCIATED type, e.g. `type Ek = ...;` in
  a KEM trait impl) from alias discovery — an associated type is a per-impl
  binding, not a free-standing alias any field elsewhere could legitimately
  reference by that name.
- The recursion tier's soundness claim is "this guard fails at that enum's
  own definition." Once a leaf variant there is ALLOWLISTED — a human
  decision, not this guard's — the honest statement becomes "fails OR IS
  ALLOWLISTED at that enum's own definition." This guard does not re-verify
  that an allowlisted leaf stays sound as the type evolves; see
  `docs/superpowers/specs/2026-08-05-474-error-payload-hygiene-design.md` §4.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCAN_ROOT = REPO_ROOT / "core" / "src"
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

# `[u8; 16]`, `[u8; RECORD_UUID_LEN]` — fixed-size numeric arrays.
ARRAY_RE = re.compile(r"^\[[ui](?:8|16|32|64|128|size);[^\]]+\]$")
# `Option<T>` is data-free exactly when `T` is.
OPTION_RE = re.compile(r"^Option<(.+)>$")
# A field-level attribute prefix (`#[from]`, `#[source]`) glued onto the raw
# type text by `parse_fields`, which does not separate attributes from types.
FIELD_ATTR_RE = re.compile(r"^#\[[^\]]*\]\s*")


def normalize_type(ty: str) -> str:
    """Collapse whitespace and strip a leading field-level attribute.

    `parse_fields` hands back the raw text after the field's `:` — for
    `Record(#[from] RecordError)` that is `"#[from] RecordError"`, not
    `"RecordError"`. Path qualification (`crate::unlock::UnlockError`,
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
    return ty.strip()


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


def _is_data_free_core(ty: str, local_error_enums: frozenset[str]) -> bool:
    """Tiers 1 and 2 only: literal data-free types, and `core`-local error
    enums this guard itself scans. Deliberately excludes tier 3 (alias
    resolution) — it is the target `is_data_free` calls an alias's
    right-hand side through, so an alias chain (`type A = B; type B = C;`)
    gets exactly one hop of credit, not an unbounded one.
    """
    ty = normalize_type(ty)
    if ty in DATA_FREE_TYPES:
        return True
    if ARRAY_RE.match(ty.replace(" ", "")):
        return True
    inner = OPTION_RE.match(ty)
    if inner:
        return _is_data_free_core(inner.group(1), local_error_enums)
    return ty in local_error_enums


def is_data_free(
    ty: str,
    local_error_enums: frozenset[str] = frozenset(),
    aliases: dict[str, str] | None = None,
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
    """
    if _is_data_free_core(ty, local_error_enums):
        return True
    if aliases:
        base = normalize_type(ty)
        if base in aliases:
            return _is_data_free_core(aliases[base], local_error_enums)
    return False


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
# `impl ... {` — used only to find impl-block bodies so a `type X = Y;`
# ASSOCIATED type (a trait's per-impl binding, e.g. `type Ek = ...;` inside
# `impl Kem for X25519Kem { ... }`) is excluded from alias discovery: it is
# not a free-standing alias any field elsewhere could reference by that name.
IMPL_RE = re.compile(r"\bimpl\b[^{;]*\{")


def impl_block_spans(src: str) -> list[tuple[int, int]]:
    """Character-offset `[start, end)` ranges of every `impl ... { ... }`
    body in (comment-stripped) `src` — see `IMPL_RE`.
    """
    spans: list[tuple[int, int]] = []
    for m in IMPL_RE.finditer(src):
        brace = m.end() - 1  # m.end() lands just past the matched '{'.
        body, _ = balanced_braces(src[brace:])
        spans.append((brace, brace + len(body)))
    return spans


def _inside(pos: int, spans: list[tuple[int, int]]) -> bool:
    return any(start <= pos < end for start, end in spans)


def find_type_aliases(
    src: str, impl_spans: list[tuple[int, int]] | None = None
) -> dict[str, str]:
    """Map alias name -> right-hand-side text for every top-level `type X =
    Y;` in (comment-stripped) `src`, respecting `[`/`(`/`{`/`<` nesting so a
    `;` inside e.g. `[u8; 16]` doesn't end the match early. A `type X = Y;`
    whose match START falls inside an `impl` block (`impl_spans`) is an
    ASSOCIATED type, not a free-standing alias, and is skipped.
    """
    impl_spans = impl_spans or []
    aliases: dict[str, str] = {}
    for m in TYPE_ALIAS_HEAD_RE.finditer(src):
        if _inside(m.start(), impl_spans):
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
) -> tuple[frozenset[str], dict[str, str]]:
    """Two textual facts this guard can prove about a chunk of Rust source
    without a real parser — the tier-2 and tier-3 inputs `is_data_free` needs.

    1. Which `enum`s it defines that are THEMSELVES scanned by this guard,
       i.e. contain at least one `#[error(...)]` attribute in their body. A
       field naming one of these is data-free BY RECURSION (see THE RULE in
       the module docstring) — this guard will already fail at that enum's
       own definition if any of ITS variants interpolates a non-data-free
       field, so re-flagging the forward adds no signal, only allowlist
       noise the approved design explicitly wants to avoid.
    2. Which `type X = Y;` aliases it declares, one level deep. `type X = Y;`
       declarations found INSIDE an `impl ... { }` block (a trait's
       associated type, not a free-standing alias) are excluded — see
       `find_type_aliases`.

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

    `run_real_scan` aggregates the RESULT of this function across every file
    under `core/src/**` — see that function's docstring for why a bare-name
    alias COLLISION across files is dropped rather than resolved.
    """
    src = strip_comments(raw)
    segments = module_path_segments(path_label) if path_label else []
    impl_spans = impl_block_spans(src)

    def spellings(name: str) -> list[str]:
        out = [name]
        if segments:
            out.append(f"{segments[-1]}::{name}")
            out.append("crate::" + "::".join(segments) + f"::{name}")
        return out

    local_error_enums: set[str] = set()
    for m in ENUM_RE.finditer(src):
        if _inside(m.start(), impl_spans):
            continue
        name = m.group(1)
        brace = src.find("{", m.end())
        if brace == -1:
            continue
        body, _ = balanced_braces(src[brace:])
        if "#[error(" in body:
            local_error_enums.update(spellings(name))

    aliases: dict[str, str] = {}
    for alias_name, rhs in find_type_aliases(src, impl_spans).items():
        for spelling in spellings(alias_name):
            aliases[spelling] = rhs

    return frozenset(local_error_enums), aliases


def strip_comments(src: str) -> str:
    """Blank out `//` and `/* */` comments, preserving line structure.

    Replaces comment bytes with spaces rather than deleting them so that line
    numbers and column offsets stay exact. String literals are respected, so a
    `//` inside `"..."` is not treated as a comment.

    LIMIT: does not special-case raw string literals (`r"..."`, `r#"..."#`)
    — see the module docstring's LIMITS section.
    """
    out: list[str] = []
    i, n = 0, len(src)
    in_line_comment = in_block_comment = in_string = False
    while i < n:
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
                out.append(ch)
            else:
                out.append(" ")
            i += 1
        elif in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                out.append("  ")
                i += 2
            else:
                out.append("\n" if ch == "\n" else " ")
                i += 1
        elif in_string:
            if ch == "\\":
                # A backslash escape consumes 2 source characters (`\` plus
                # whatever follows). Emitting two spaces is right for an
                # ordinary escape like `\"`, but Rust also allows a bare
                # `\` + newline as a string line-continuation. Blanking
                # THAT newline to a space would silently drop it from the
                # line count, desynchronizing every subsequent line number
                # (and hence every subsequent Finding.source_line) for the
                # rest of the file from a single continued string upstream.
                out.append("\n" if nxt == "\n" else " ")
                out.append(" ")
                i += 2
                continue
            if ch == '"':
                in_string = False
            out.append(ch)
            i += 1
        elif ch == "/" and nxt == "/":
            in_line_comment = True
            out.append("  ")
            i += 2
        elif ch == "/" and nxt == "*":
            in_block_comment = True
            out.append("  ")
            i += 2
        elif ch == '"':
            in_string = True
            out.append(ch)
            i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    source_line: str
    variant: str
    field: str
    field_type: str


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
    fixes. The type side (tuple fields: `#[from] T`) is left as-is here;
    `normalize_type` strips it later, at classification time.
    """
    body = body.strip()
    fields: dict[str, str] = {}
    if body.startswith("{"):
        inner = body[1 : body.rindex("}")] if "}" in body else body[1:]
        for part in split_top_level(inner):
            if ":" not in part:
                continue
            name, ty = part.split(":", 1)
            name = strip_field_attrs(name)
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
            else:
                emit_unparsed(
                    f"{variant} interpolates `{{{name}}}`, which does not "
                    "match any field this guard could parse — it cannot "
                    "verify what is being rendered",
                    variant=variant,
                    field=name,
                )
                continue
            if fname in seen_fields:
                continue
            seen_fields.add(fname)
            if not is_data_free(ftype, local_error_enums, aliases):
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


# This guard has exactly one rule. The column exists so the file format is
# byte-identical to the two shell guards' allowlists, which lets
# `scripts/lib/hygiene-allowlist.sh::allowlisted` parse this file unchanged —
# the INTENT is a parity test in `core/tests/` exercising all three guards'
# allowlists identically. That test does not exist yet (Task 9 territory);
# nothing today actually proves the claim, so treat it as design intent, not
# a checked guarantee — asserting otherwise would be exactly the kind of
# false confidence this guard exists to avoid.
RULE = "E1"


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


def run_real_scan() -> int:
    allowlist = load_allowlist(ALLOWLIST_PATH)
    sources = [
        (str(rs.relative_to(REPO_ROOT)), rs.read_text(encoding="utf-8"))
        for rs in sorted(SCAN_ROOT.rglob("*.rs"))
    ]

    # Pass 1: discover every core-local thiserror enum and type alias across
    # THE WHOLE TREE before classifying anything — a field in vault/mod.rs
    # can reference an enum defined in vault/record.rs, so a per-file-only
    # discovery pass would miss the cross-file case entirely.
    #
    # Aliases are aggregated defensively: a bare (or qualified) spelling that
    # resolves to DIFFERENT right-hand sides in different files is a name
    # COLLISION, not one alias, and a plain last-write-wins dict.update
    # merge means an unrelated, later-sorted file adding e.g.
    # `type Foo = [u8; 16];` can silently launder an EXISTING, unsafe
    # `type Foo = String;` defined elsewhere into a pass — proven live in
    # review. A colliding spelling is dropped from the resolvable set
    # entirely, so a lookup against it default-denies instead of guessing
    # which definition was "real."
    local_error_enum_names: set[str] = set()
    alias_candidates: dict[str, set[str]] = {}
    for label, raw in sources:
        enums, file_aliases = discover_declarations(raw, label)
        local_error_enum_names.update(enums)
        for spelling, rhs in file_aliases.items():
            alias_candidates.setdefault(spelling, set()).add(rhs)
    local_error_enums: frozenset[str] = frozenset(local_error_enum_names)
    aliases = {
        spelling: next(iter(rhs_set))
        for spelling, rhs_set in alias_candidates.items()
        if len(rhs_set) == 1
    }

    # Pass 2: the actual scan, now with tiers 2 and 3 available.
    violations: list[Finding] = []
    for label, raw in sources:
        for f in scan_source(label, raw, local_error_enums, aliases):
            if f"{f.path}\t{RULE}\t{f.source_line}" in allowlist:
                continue
            violations.append(f)

    if violations:
        print("error-payload hygiene: FAIL\n", file=sys.stderr)
        for v in violations:
            if v.field_type.startswith("UNPARSED:"):
                detail = f"{v.field_type} (variant hint: {v.variant}, field hint: {v.field})"
            else:
                detail = f"variant {v.variant} interpolates `{v.field}: {v.field_type}`"
            print(
                f"  {v.path}:{v.line}\n"
                f"    {detail}\n"
                f"    {v.source_line}",
                file=sys.stderr,
            )
        print(
            f"\n{len(violations)} violation(s). A `core` error message must not "
            "interpolate a runtime String — it reaches both platform UIs and "
            "their logs (#474). Carry a &'static str hint plus an ordinal, or "
            "record a reviewed exception in\n  "
            f"{ALLOWLIST_PATH.relative_to(REPO_ROOT)}",
            file=sys.stderr,
        )
        return 1
    print("error-payload hygiene: OK")
    return 0


POSITIVE_CONTROLS: list[tuple[str, str]] = [
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
]


def run_self_test() -> int:
    failures: list[str] = []
    for label, src in POSITIVE_CONTROLS:
        # Each control is self-contained (defines any nested enum/alias it
        # references in the same string), so a per-control discovery pass —
        # no real file path, hence no path_label — exercises the real
        # discovery path rather than a hardcoded name list.
        enums, aliases = discover_declarations(src)
        if not scan_source("<self-test>", src, enums, aliases):
            failures.append(f"POSITIVE control did not fire: {label}")
    for label, src in NEGATIVE_CONTROLS:
        enums, aliases = discover_declarations(src)
        found = scan_source("<self-test>", src, enums, aliases)
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
        f"{len(NEGATIVE_CONTROLS)} negative)"
    )
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        sys.exit(run_self_test())
    sys.exit(run_real_scan())
