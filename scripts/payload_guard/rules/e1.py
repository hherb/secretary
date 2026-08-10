"""Rule E1: every `#[error]` variant/struct's interpolated fields must be
data-free. Scans ALL FOUR roots — `core/src/**`, the FFI bridge, and (since
#486) both binding wrapper crates, the latter three via `bridge_mode`. The
"BOTH roots" this docstring claimed until #496 was stale from before the
wrapper roots landed; `payload_guard/roots.py`'s `SCAN_ROOTS` is the
authority, and `scan.py` runs `scan_source` for every entry in it. Moved out of the former single-file
`scripts/check-error-payload-hygiene.py` in #486 (task 4). Read the entry
point's module docstring first for the WHY and THE RULE.
"""

from __future__ import annotations

import re

from payload_guard.discovery import ERROR_ATTR_RE, STRUCT_RE, _owning_enum_name, enclosing_enum_names
from payload_guard.lexer import balanced_braces, balanced_slice, strip_comments
from payload_guard.parsing import skip_attributes, split_top_level
from payload_guard.types import (
    Finding, is_bridge_field_safe, is_data_free, strip_field_attrs, strip_visibility,
)

# `.index` in a trailing format argument, e.g. `, .index + 1)`.
ARG_FIELD_RE = re.compile(r"\.([A-Za-z_][A-Za-z0-9_]*)")
VARIANT_RE = re.compile(r"^\s*([A-Z][A-Za-z0-9_]*)\s*(\{|\(|,|$)")


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
    *,
    gated_field_types: frozenset[str],
    shadowed_type_names: frozenset[str],
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

    `bridge_mode` (#480, rule E2) does TWO things. It is `True` on THREE
    roots — the bridge and both wrapper crates (`roots.py`) — not on the
    bridge alone; this said "scoped to `ffi/secretary-ffi-bridge/src/**`"
    until #515, which `e2.py`'s own module docstring already contradicted.
    Core behaviour (the default, `bridge_mode=False`) is byte-identical to
    before this parameter existed:

    1. Rule E2's carve-out on the ordinary interpolated-field check below:
       `is_bridge_field_safe` replaces the bare `is_data_free` call, so a
       `String` field named in `GATED_FIELD_NAMES` is not a finding here
       (rule E3 gates its construction site instead). Everything
       else still denies exactly as core's `E1` does.
    2. A STRUCTURAL sweep (`bridge_declaration_findings`, rule `E2`) over
       EVERY parsed field of the declaration — interpolated or not — since
       uniffi/PyO3 project every field regardless of what the `#[error(...)]`
       message actually renders. This is what catches a platform-projected
       `String` the `Display` text never mentions.

    `gated_field_types` (#500) is the per-root set of type spellings
    `is_bridge_field_safe` accepts under a `GATED_FIELD_NAMES` name —
    `ScanRoot.gated_field_types`. It is a REQUIRED keyword-only argument with
    NO DEFAULT, even though it is read only when `bridge_mode=True`: a
    default would let a future non-bridge caller inherit an unnamed,
    possibly-permissive spelling. Callers that never exercise `bridge_mode`
    (the `core` root) still pass `frozenset()`, matching `core`'s own
    `ScanRoot.gated_field_types`.

    `shadowed_type_names` (#500 fix round 2) is the SAME kind of REQUIRED,
    no-default parameter, for the same reason: it names every
    `gated_field_types` spelling shadowed by a same-named local declaration
    elsewhere in the root (a raw `type X = Y;` alias candidate, collision or
    not, plus a decoy `struct|enum|union|type` outside the sanctioned
    module — see `is_bridge_field_safe`'s docstring), and denies
    unconditionally ahead of the carve-out. Threaded through unchanged to
    both consumers below.

    Note `strip_comments`, NOT `discovery_view`: locating `#[error(`
    attributes and reading their message text needs the strings INTACT.
    Blanking is used only where it can only ever hide a credit, which is the
    fail-closed direction — see `discovery_view`.
    """
    src = strip_comments(raw)
    # Only computed in bridge_mode — see the call site's comment (#480
    # review finding 2) and `enclosing_enum_names`'s own docstring. Core
    # behaviour (`bridge_mode=False`) never reads this.
    enum_spans = enclosing_enum_names(raw) if bridge_mode else []
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
                    rule="E1",
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
        #
        # #480 review finding 2: the key must include the OWNING type name,
        # not just the variant's own — `SettingsWarning::Corrupt` and
        # `SettingsParseError::Corrupt` are the LIVE instance of two
        # DIFFERENT types sharing a variant name, which collided on the bare
        # key `Corrupt { ... }` before `enum_spans` existed. A STRUCT-shaped
        # error's `variant` IS already the owning type's own name (no
        # enclosing enum), so `owner` is `None` and no prefix is added.
        if bridge_mode:
            # Deferred import (#486 task 4): `rules/e2.py` imports
            # `VARIANT_RE` / `parse_fields` back from THIS module at its own
            # top level, so a top-level import here of `rules.e2` would be
            # circular — whichever of the two loads first would ask the
            # other for a name it has not defined yet. Deferring this one
            # side to call time is enough: by the time `scan_source` is
            # actually INVOKED (never during either module's own import),
            # both modules are fully loaded.
            from payload_guard.rules.e2 import bridge_declaration_findings

            owner = _owning_enum_name(enum_spans, m.start())
            prefix = f"{owner}::" if owner else ""
            decl_text = " ".join(f"{prefix}{variant} {body}".split())
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
                    gated_field_types,
                    shadowed_type_names,
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
            # HERE (rule E3 gates its construction site instead).
            # Everything else denies exactly as core's E1 does today.
            field_is_safe = (
                is_bridge_field_safe(
                    fname, ftype, local_error_enums, aliases, foreign_names,
                    gated_field_types, shadowed_type_names,
                )
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
                        rule="E1",
                    )
                )
    return findings
