"""Rule E2: every field of a bridge- OR WRAPPER-root error declaration must
be data-free or a `String` under a `GATED_FIELD_NAMES` name.

Two sweeps — `scan_source`'s `bridge_mode` (thiserror-derived declarations,
rule module `e1`) and this module's `scan_bridge_plain_declarations`
(plain-derive `*Error`/`*Warning` declarations with no `#[error(...)]`
attribute to anchor on) both funnel into `bridge_declaration_findings` here.
Moved out of the former single-file `scripts/check-error-payload-hygiene.py`
in #486 (task 4). Read the entry point's module docstring first for the WHY
and THE BRIDGE RULES.

Despite every "bridge" in the names below, this rule runs over THREE crates
as of #486: the FFI bridge and both binding wrapper crates, each carrying
`bridge_mode=True` in `payload_guard/roots.py`. That includes sweep 2's
`*Error`/`*Warning` NAMING HEURISTIC — so its blind spot (a plain-derive
error type named against convention is never swept) now applies to those two
crates as well. These docstrings kept saying "bridge" until #496.
"""

from __future__ import annotations

import re

from payload_guard.discovery import (
    _inside, discover_error_struct_declarations, discovery_cfg_test_spans_strict,
)
from payload_guard.lexer import balanced_braces, balanced_slice, strip_comments
from payload_guard.parsing import skip_attributes, split_top_level
from payload_guard.rules.e1 import VARIANT_RE, parse_fields
from payload_guard.types import Finding, is_bridge_field_safe


def bridge_declaration_findings(
    path_label: str,
    line_no: int,
    variant: str,
    decl_text: str,
    fields: dict[str, str],
    local_error_enums: frozenset[str],
    aliases: dict[str, str] | None,
    foreign_names: frozenset[str],
    gated_field_types: frozenset[str],
) -> list[Finding]:
    """Rule E2's structural sweep (#480): every PARSED field of a bridge
    declaration — interpolated or not, since uniffi/PyO3 project every field
    regardless of what `#[error(...)]`'s message actually mentions — must
    independently satisfy `is_bridge_field_safe`.

    Shared by both of rule E2's producers: `scan_source`'s `bridge_mode`
    sweep 1 (thiserror-derived declarations, anchored on their own
    `#[error(` attribute) and `scan_bridge_plain_declarations`'s sweep 2
    (plain-derive `*Error`/`*Warning` enums with no such attribute to anchor
    on). Both callers precompute `decl_text` — the whitespace-collapsed
    `"<variant/struct name> <body>"` text — themselves, since sweep 1 has an
    `#[error(...)]` attribute's surrounding context to draw on and sweep 2
    does not.

    `gated_field_types` (#500) is `ScanRoot.gated_field_types` — the per-root
    set of type spellings `is_bridge_field_safe` accepts under a
    `GATED_FIELD_NAMES` name. REQUIRED, no default, threaded from both
    producers above, which each get it from their own caller in turn — see
    `is_bridge_field_safe`'s docstring for why a default anywhere on this
    chain would be unsafe.
    """
    out: list[Finding] = []
    for fname, ftype in fields.items():
        if is_bridge_field_safe(
            fname, ftype, local_error_enums, aliases, foreign_names, gated_field_types
        ):
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


# `enum Name` / `struct Name` where NAME ends `Error` or `Warning` — rule
# E2's SECOND sweep target (#480): a bridge declaration following this
# codebase's own error/warning naming convention but carrying NO
# `#[error(...)]` attribute anywhere — a plain `#[derive(Debug, ...)]`, not
# thiserror (e.g. `SettingsWarning`, `SettingsParseError`,
# `SettingsBoundsError`). uniffi/PyO3 project every field of such a type
# regardless of derive shape, so it needs the same all-fields sweep a
# thiserror declaration gets via `scan_source`'s `#[error(` anchor; this
# shape has no such anchor, so it is found by NAME instead. A heuristic, not
# a language guarantee — see the module docstring's LIMITS on pattern-based
# discovery generally.
BRIDGE_PLAIN_ENUM_RE = re.compile(r"\benum\s+([A-Za-z_][A-Za-z0-9_]*(?:Error|Warning))\b")
BRIDGE_PLAIN_STRUCT_RE = re.compile(r"\bstruct\s+([A-Za-z_][A-Za-z0-9_]*(?:Error|Warning))\b")


def _bridge_plain_enum_variant_findings(
    path_label: str,
    line_no: int,
    owner_name: str,
    body: str,
    local_error_enums: frozenset[str],
    aliases: dict[str, str] | None,
    foreign_names: frozenset[str],
    gated_field_types: frozenset[str],
) -> list[Finding]:
    """Rule E2 sweep 2's per-variant walk for a plain-derive enum BODY
    (`{...}`, outer braces included) — #480 review finding 1.

    Mirrors `scan_source`'s own single-variant parse (`VARIANT_RE` + a
    balanced field body + `parse_fields`), applied once per TOP-LEVEL
    comma-separated member instead of once per `#[error(...)]` attribute:
    this shape has no attribute to anchor on (that is the whole reason it
    needed its own discovery pass), so it must walk every variant in the
    body itself. `skip_attributes` handles a variant carrying its own
    attribute (e.g. `#[non_exhaustive]`) the same way `scan_source` does.

    Three outcomes per part, all fail-closed on STRUCTURE the same way
    `scan_source`'s own attribute walk is — and two of the three were
    proven reachable BY EXECUTION during review round 2, not merely
    reasoned about, after an earlier version of this comment claimed (by
    reasoning alone) that only the harmless case could occur:

    - The RAW part (before `skip_attributes` even runs) is EMPTY once
      whitespace is stripped: `split_top_level`'s trailing tail after a
      body's closing (near-universal, rustfmt-default) trailing comma —
      Rust does not allow two consecutive top-level commas in COMPILING
      source, so an empty RAW part can only ever be that harmless tail,
      never a dropped declaration. Skipped silently, mirroring
      `scan_source`'s OWN identical "nothing is interpolated — provably
      nothing to check, not a parse failure" distinction (see its `if not
      names: continue`, comment tag N4).
    - The RAW part is non-empty, but `skip_attributes` reduces it to
      nothing anyway: `skip_attributes` has no raw-string awareness — a
      raw string inside a field-level attribute
      (`#[doc = r#"a " b"#]`) desyncs its naive quote-toggle, which
      swallows the attribute's closing `]` and everything after it,
      including the variant it was meant to skip PAST. Rustc-verified
      witness (`--crate-type lib --edition 2021`):
      `pub enum FooError { #[doc = r#"a " b"#] Leaky { leak: String }, }`
      — `leak: String` was dropped with ZERO findings before this branch
      existed. `scan_source` itself has no equivalent silent branch (an
      empty `tail` there just fails to match `VARIANT_RE`/`STRUCT_RE`,
      which its EXISTING `if not vm: emit_unparsed(...)` already catches
      unconditionally) — this branch restores that same coverage here.
    - A non-empty, successfully-`skip_attributes`d part still does not
      match `VARIANT_RE` — e.g. a raw-identifier variant name
      (`r#Match { leak: String }`) — IS a genuine parse failure.
    - AFTER a field body is extracted (`balanced_braces`/`balanced_slice`),
      anything left over in `rest` is a sign `split_top_level` itself
      mis-split: it has no string-literal awareness, so a `}` inside a
      field-level attribute's string content (`#[doc = "}"]`) drives its
      bracket-depth tracking negative, which suppresses the NEXT real
      top-level comma from splitting — merging TWO variants into one
      `part` and silently discarding the second. Rustc-verified witness:
      `pub enum BazError { #[doc = "}"] A { x: usize }, B { leak: String },
      }` — `B`'s `leak: String` was dropped with ZERO findings (only `A`,
      data-free, was ever seen) before this check existed.
    """
    inner = body[1 : body.rindex("}")] if "}" in body else body[1:]
    findings: list[Finding] = []
    for part in split_top_level(inner):
        if not part.strip():
            continue
        text = skip_attributes(part.strip())
        if not text:
            findings.append(
                Finding(
                    path=path_label,
                    line=line_no,
                    source_line=f"{owner_name} {{ {' '.join(part.strip().split())} }}",
                    variant="<unparsed>",
                    field="<unparsed>",
                    field_type=(
                        "UNPARSED: skip_attributes could not locate content "
                        f"past this part's attributes in {owner_name}'s body "
                        "(e.g. a raw string inside an attribute desyncing "
                        "the naive #[...] scanner)"
                    ),
                    rule="E2",
                )
            )
            continue
        vm = VARIANT_RE.match(text)
        if not vm:
            collapsed = " ".join(part.strip().split())
            findings.append(
                Finding(
                    path=path_label,
                    line=line_no,
                    source_line=f"{owner_name} {{ {collapsed} }}",
                    variant="<unparsed>",
                    field="<unparsed>",
                    field_type=(
                        f"UNPARSED: could not locate a variant declaration "
                        f"in {owner_name}'s body"
                    ),
                    rule="E2",
                )
            )
            continue
        name = vm.group(1)
        rest = text[len(name) :].lstrip()
        if rest.startswith("{"):
            fbody, _ = balanced_braces(rest)
        elif rest.startswith("("):
            fbody, _ = balanced_slice(rest, 0)
        else:
            fbody = ""
        remainder = rest[len(fbody) :]
        if remainder.strip():
            findings.append(
                Finding(
                    path=path_label,
                    line=line_no,
                    source_line=f"{owner_name} {{ {' '.join(remainder.split())} }}",
                    variant="<unparsed>",
                    field="<unparsed>",
                    field_type=(
                        f"UNPARSED: unconsumed content after {owner_name}::"
                        f"{name}'s declaration — split_top_level likely "
                        "mis-split on a string-embedded bracket character"
                    ),
                    rule="E2",
                )
            )
        decl_text = " ".join(f"{owner_name}::{name} {fbody}".split())
        findings.extend(
            bridge_declaration_findings(
                path_label,
                line_no,
                name,
                decl_text,
                parse_fields(fbody),
                local_error_enums,
                aliases,
                foreign_names,
                gated_field_types,
            )
        )
    return findings


def _bridge_plain_struct_findings(
    path_label: str,
    line_no: int,
    name: str,
    body: str,
    local_error_enums: frozenset[str],
    aliases: dict[str, str] | None,
    foreign_names: frozenset[str],
    gated_field_types: frozenset[str],
) -> list[Finding]:
    """Rule E2 sweep 2's struct counterpart (#480 review finding 3): a
    plain-derive `*Error`/`*Warning` STRUCT (`SettingsBoundsError`) has no
    variants to walk — its own field list IS the declaration, so this is a
    thin wrapper around `bridge_declaration_findings`, not a walk. `body` is
    the struct's already-located `{...}` or `(...)` text; a unit struct
    (`;`, no body) never reaches this function — see
    `scan_bridge_plain_declarations`.
    """
    decl_text = " ".join(f"{name} {body}".split())
    return bridge_declaration_findings(
        path_label,
        line_no,
        name,
        decl_text,
        parse_fields(body),
        local_error_enums,
        aliases,
        foreign_names,
        gated_field_types,
    )


def scan_bridge_plain_declarations(
    path_label: str,
    raw: str,
    local_error_enums: frozenset[str] = frozenset(),
    aliases: dict[str, str] | None = None,
    foreign_names: frozenset[str] = frozenset(),
    *,
    gated_field_types: frozenset[str],
) -> list[Finding]:
    """Rule E2's second sweep (#480) — bridge `enum`/`struct` declarations
    named `*Error`/`*Warning` (see `BRIDGE_PLAIN_ENUM_RE` /
    `BRIDGE_PLAIN_STRUCT_RE`) carrying NO `#[error(...)]` attribute at all:
    a PLAIN derive (`SettingsWarning`, `SettingsParseError`,
    `SettingsBoundsError` — #480 review finding 3), not a thiserror one.
    thiserror-derived declarations are swept by `scan_source`'s own
    `bridge_mode` sweep 1 via its `#[error(` attribute anchor; a plain
    derive has no such attribute to anchor on, so this function
    re-discovers candidates by NAME CONVENTION instead.

    An ENUM candidate is "already swept" (skip, avoid double-reporting
    under the same rule) when `#[error(` appears ANYWHERE in its body
    (decorating a variant). A STRUCT's `#[error(...)]`, if any, decorates
    the STRUCT ITSELF — preceding it, not living inside a body — so the
    equivalent check instead consults the POSITIONS reported by
    `discover_error_struct_declarations`, the same walk
    `scanned_error_type_names` (rule E4) takes its names from. Position, not
    name: see that function's docstring for the two rustc-verified witnesses
    a bare-name check was fail-open to.

    Both candidate kinds skip a match starting inside a `#[cfg(test)]`-
    gated item (`discovery_cfg_test_spans`) — a test-only declaration is
    not part of the shipped crate and must not be swept, mirroring
    `discover_declarations`'s identical exclusion for the E1 tiers.

    Genuinely UNPARSEABLE structure fails closed as an `UNPARSED` finding
    rather than being silently dropped (#480 review finding 1): an enum
    name matched but no `{` found anywhere after it, or a struct whose
    continuation after its name is none of `{`, `(`, or `;`.

    `gated_field_types` (#500) is `ScanRoot.gated_field_types`, threaded
    unchanged into both `bridge_declaration_findings` producers below.
    REQUIRED, no default — see `is_bridge_field_safe`'s docstring.
    """
    src = strip_comments(raw)
    # STRICT: a skip here means the declaration is not swept (#496).
    excluded = discovery_cfg_test_spans_strict(raw)
    findings: list[Finding] = []

    for m in BRIDGE_PLAIN_ENUM_RE.finditer(src):
        if _inside(m.start(), excluded):
            continue
        name = m.group(1)
        line_no = src.count("\n", 0, m.start()) + 1
        brace = src.find("{", m.end())
        if brace == -1:
            findings.append(
                Finding(
                    path=path_label,
                    line=line_no,
                    source_line=f"enum {name}",
                    variant="<unparsed>",
                    field="<unparsed>",
                    field_type=f"UNPARSED: could not locate a body for enum {name}",
                    rule="E2",
                )
            )
            continue
        body, _ = balanced_braces(src[brace:])
        if "#[error(" in body:
            continue  # thiserror-derived; already swept by scan_source's sweep 1
        findings.extend(
            _bridge_plain_enum_variant_findings(
                path_label,
                line_no,
                name,
                body,
                local_error_enums,
                aliases,
                foreign_names,
                gated_field_types,
            )
        )

    # POSITION-keyed, not name-keyed (#480 review round 2, NEW-1): a
    # bare-name check here is fail-open to a same-named sibling struct in a
    # different module AND to a self-authorised fake occurrence inside a
    # string literal — see `discover_error_struct_declarations`'s
    # docstring for both rustc-verified witnesses.
    already_swept_struct_spans = [
        (start, end) for _, start, end in discover_error_struct_declarations(raw)
    ]
    for m in BRIDGE_PLAIN_STRUCT_RE.finditer(src):
        if _inside(m.start(), excluded):
            continue
        if _inside(m.start(), already_swept_struct_spans):
            continue  # thiserror-decorated; already swept by scan_source's sweep 1
        name = m.group(1)
        line_no = src.count("\n", 0, m.start()) + 1
        tail = src[m.end() :].lstrip()
        if tail.startswith("{"):
            body, _ = balanced_braces(tail)
        elif tail.startswith("("):
            body, _ = balanced_slice(tail, 0)
        elif tail.startswith(";"):
            continue  # unit struct — no fields, provably nothing to check
        else:
            findings.append(
                Finding(
                    path=path_label,
                    line=line_no,
                    source_line=f"struct {name}",
                    variant="<unparsed>",
                    field="<unparsed>",
                    field_type=(
                        f"UNPARSED: struct {name} has a body shape this guard "
                        "cannot model (expected `{...}`, `(...)`, or `;`)"
                    ),
                    rule="E2",
                )
            )
            continue
        findings.extend(
            _bridge_plain_struct_findings(
                path_label,
                line_no,
                name,
                body,
                local_error_enums,
                aliases,
                foreign_names,
                gated_field_types,
            )
        )
    return findings
