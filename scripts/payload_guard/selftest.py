"""The self-test harness (#474, #480, #486): `run_self_test` drives every
control in `payload_guard.controls.core` / `payload_guard.controls.bridge` /
`payload_guard.controls.wrapper` through the real scan pipeline and asserts
each fires (or does not fire) for the reason its label claims.

Moved out of the former single-file `scripts/check-error-payload-hygiene.py`
in #486 (task 5); extended with the wrapper-root controls in #486 (task 9).
Nothing in this package may import `selftest` — it sits at the TOP of the
dependency order, alongside `controls/*`, consuming
`config` -> `lexer`, `parsing` -> `types` -> `discovery` -> `rules/*` ->
`scan` from below. Read the entry point's module docstring first for the WHY.
"""

from __future__ import annotations

import sys

from payload_guard.controls.bridge import (
    BRIDGE_NEGATIVE_CONTROLS, BRIDGE_POSITIVE_CONTROLS, SELF_TEST_DETAIL_SRC,
)
from payload_guard.controls.core import NEGATIVE_CONTROLS, POSITIVE_CONTROLS
from payload_guard.controls.wrapper import (
    WRAPPER_NEGATIVE_CONTROLS, WRAPPER_POSITIVE_CONTROLS,
)
from payload_guard.discovery import (
    discover_declarations, discover_scanned_error_type_names, foreign_use_names,
    resolve_consts,
)
from payload_guard.lexer import LEXER_SAMPLE, discovery_view, lex_spans, strip_comments
from payload_guard.roots import SCAN_ROOTS
from payload_guard.rules.e1 import scan_source
from payload_guard.rules.e2 import scan_bridge_plain_declarations
from payload_guard.rules.e3 import (
    sanctioned_constructor_names, scan_bridge_construction_sites,
)
from payload_guard.rules.e4 import scan_bridge_gated_detail_impls
from payload_guard.types import Finding

# `(variant, field, field_type, field_type_prefix)` claims a POSITIVE control
# makes about the finding it expects, beyond "something fired". `unparsed`
# asserts the finding IS (or is not) the default-deny-on-structure kind;
# `field_type_prefix` asserts WHICH denial arm produced it (rule E4's reason
# codes).
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
    # `field_type_prefix` exists for rule E4's reason codes (see `E4_OUTSIDE`
    # and friends): an exact `field_type` match would pin a whole paragraph
    # of prose, so editing the wording would break the control rather than
    # the logic it guards.
    prefix = expect.get("field_type_prefix")
    if prefix is not None and not f.field_type.startswith(str(prefix)):
        return False
    # `rule` pins WHICH rule produced the finding — a control that must fire
    # under E3 is not satisfied by an unrelated E2 finding in the same
    # fixture, which matters for the multi-declaration fixtures.
    if "rule" in expect and f.rule != expect["rule"]:
        return False
    return True


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
    samples += [src for _, src, *_ in BRIDGE_NEGATIVE_CONTROLS]
    samples += [src for _, src, *_ in WRAPPER_POSITIVE_CONTROLS]
    samples += [src for _, src, *_ in WRAPPER_NEGATIVE_CONTROLS]
    samples.append(SELF_TEST_DETAIL_SRC)
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




# Rule E3's `allow_field_access` (shape 5, #486) is read from `SCAN_ROOTS`
# here rather than hardcoded separately in `scan_bridge_control` /
# `scan_wrapper_control`: a control corpus that hardcodes the very flag it
# exists to test cannot catch a `roots.py` edit that changes it. Mutating
# `ScanRoot.allow_field_access` must be OBSERVABLE through `--self-test` —
# that is exactly what `BP43` (bridge, must stay denied) and `WN1` (wrapper,
# must stay accepted) exist to prove, and neither proves anything if the
# value under test is a literal sitting beside them instead of the one
# `run_real_scan` itself reads.
_ROOTS_BY_LABEL = {r.label: r for r in SCAN_ROOTS}


def _wrapper_allow_field_access() -> bool:
    """The ONE `allow_field_access` value the wrapper-root rule set uses,
    read off BOTH wrapper `ScanRoot`s and asserted to agree.

    The design's premise (`payload_guard.roots` module docstring) is a
    single shared wrapper-root rule set, not two independently configurable
    ones — a control corpus that silently tolerated the two wrapper roots
    drifting apart on this flag would be testing less than it claims to.
    """
    values = {
        _ROOTS_BY_LABEL[label].allow_field_access for label in ("ffi-py", "ffi-uniffi")
    }
    assert len(values) == 1, (
        f"wrapper roots disagree on allow_field_access: {values} — "
        "scan_wrapper_control assumes one shared wrapper-root rule set"
    )
    return next(iter(values))


def scan_bridge_control(
    src: str,
    path_label: str = "<self-test-bridge>",
    detail_src: str = SELF_TEST_DETAIL_SRC,
) -> list[Finding]:
    """`scan_control`, run in `bridge_mode` PLUS rules E2/E3/E4 (#480) —
    mirrors `scan_control`'s self-contained-fixture design (no real file path,
    hence no qualified spellings; see `module_path_segments`).

    Runs EVERY bridge producer, exactly as `run_real_scan` does for a real
    bridge file: `scan_source(..., bridge_mode=True)` (rule E2 sweep 1,
    thiserror-derived declarations), `scan_bridge_plain_declarations` (rule E2
    sweep 2, plain-derive `*Error`/`*Warning` declarations),
    `scan_bridge_construction_sites` (rule E3) and
    `scan_bridge_gated_detail_impls` (rule E4).

    `path_label` defaults to a label that is NOT the detail module, so a
    control exercises rule E4's "impl outside detail.rs" arm by default; a
    control that needs the OTHER arm (an impl INSIDE detail.rs, checked
    against the scanned-type registry) passes `path_label=DETAIL_MODULE_REL`
    via its options dict.

    `scanned_error_type_names` is derived from the CONTROL ITSELF (both the
    "core" and "bridge" halves collapse to this one source), so a control
    that wants a name registered declares the `#[error]`-bearing type in the
    same string — the same self-contained design every other control uses.

    Rule E3's `allow_field_access` (shape 5, #486) is read from the BRIDGE
    `ScanRoot` (`_ROOTS_BY_LABEL["bridge"]`), not hardcoded — see the module-
    level comment above `_ROOTS_BY_LABEL` for why. It is `False` today, so
    every existing bridge control's behaviour is unchanged; `BP43` proves
    shape 5 stays denied here even when a WRAPPER root grants it elsewhere.
    """
    enums, aliases, declared_consts, shadows = discover_declarations(src)
    consts = resolve_consts(declared_consts, shadows)
    foreign = foreign_use_names(src)
    found = scan_source(
        path_label, src, enums, aliases, consts, foreign, bridge_mode=True
    )
    found += scan_bridge_plain_declarations(path_label, src, enums, aliases, foreign)
    found += scan_bridge_construction_sites(
        path_label,
        src,
        sanctioned_constructor_names(detail_src),
        allow_field_access=_ROOTS_BY_LABEL["bridge"].allow_field_access,
    )
    found += scan_bridge_gated_detail_impls(
        path_label,
        src,
        discover_scanned_error_type_names([], [(path_label, src)], enums, enums),
    )
    return found


def scan_wrapper_control(
    src: str,
    path_label: str = "<self-test-wrapper>",
    detail_src: str = SELF_TEST_DETAIL_SRC,
) -> list[Finding]:
    """`scan_bridge_control`, but for a WRAPPER ROOT (#486): `bridge_mode=True`
    plus rules E2/E3, with rule E3's `allow_field_access` (shape 5) turned ON —
    and NO rule E4 at all.

    `gated_detail_impls` is `False` on both wrapper `ScanRoot`s
    (`payload_guard.roots.SCAN_ROOTS`) because `GatedDetail` is `pub(crate)`
    in the bridge crate: no wrapper crate can implement it even if a future
    author tried, so E4's premise — the set of types a detail string can be
    built from is exactly the set of impls in one reviewed file — is
    unaffected by scanning these roots at all. Mirroring that omission here
    means a wrapper control can never accidentally pass BECAUSE E4 fired for
    an unrelated reason, the same shape-of-control discipline
    `scan_bridge_control` keeps for its own rule set.

    Rule E3's `allow_field_access` (shape 5) is read from BOTH wrapper
    `ScanRoot`s via `_wrapper_allow_field_access()`, not hardcoded — see the
    module-level comment above `_ROOTS_BY_LABEL` for why. It is `True` today;
    `WN1` proves the DTO pass-through stays accepted, and flipping either
    wrapper root's flag to `False` in `roots.py` must make `WN1` fire.
    """
    enums, aliases, declared_consts, shadows = discover_declarations(src)
    consts = resolve_consts(declared_consts, shadows)
    foreign = foreign_use_names(src)
    found = scan_source(
        path_label, src, enums, aliases, consts, foreign, bridge_mode=True
    )
    found += scan_bridge_plain_declarations(path_label, src, enums, aliases, foreign)
    found += scan_bridge_construction_sites(
        path_label,
        src,
        sanctioned_constructor_names(detail_src),
        allow_field_access=_wrapper_allow_field_access(),
    )
    return found


def _check_distinct_e2_keys(label: str, src: str, variant: str) -> list[str]:
    """Shared assertion for `check_bridge_key_distinctness`: scanning `src`
    must produce exactly two rule-E2 findings for `variant`, with two
    DISTINCT `source_line` keys."""
    found = [f for f in scan_bridge_control(src) if f.rule == "E2" and f.variant == variant]
    keys = {f.source_line for f in found}
    if len(found) != 2 or len(keys) != 2:
        return [
            f"BRIDGE KEY DISTINCTNESS ({label}): two different types' "
            f"same-named variants must produce two DISTINCT E2 keys, got "
            f"{len(found)} finding(s) with {len(keys)} distinct key(s): "
            f"{[f.source_line for f in found]}"
        ]
    return []


def check_bridge_key_distinctness() -> list[str]:
    """Rule E2's allowlist key must include the OWNING type name, not just
    the variant/struct's own name (#480 review finding 2): two DIFFERENT
    types in ONE file with a same-named, same-shaped variant must not
    collide on the same key. `SettingsWarning::Corrupt` and
    `SettingsParseError::Corrupt` (settings/parse.rs:24, :39) are the LIVE
    instance of exactly this shape — before `enclosing_enum_names` existed,
    both produced the bare key `Corrupt { detail: String, }`, so one
    allowlist entry would have silently exempted both.

    A dedicated check rather than a `BRIDGE_POSITIVE_CONTROLS` entry: this
    makes a claim ACROSS two findings from ONE scan (their keys must
    DIFFER), not a per-control fired-or-not verdict `ControlExpectation`
    can express. Both messages are deliberately NOT interpolated (`"bad"`,
    no `{leak}`) so only rule E2's structural sweep fires — an interpolated
    message would ALSO produce rule-E1 findings keyed on the (identical,
    for both types) ATTRIBUTE TEXT, which is a separate, pre-existing E1
    characteristic this check is not about.

    Covers BOTH of rule E2's producers, since they thread the owning name
    through independently and a fix (or regression) in one does not imply
    the other: `scan_source`'s `bridge_mode` sweep 1 (thiserror-derived,
    via `enclosing_enum_names`) and `scan_bridge_plain_declarations`'s
    sweep 2 (plain-derive, via its own regex-captured enum name) — a
    mutation dropping ONLY the sweep-2 prefix was caught live during this
    fix's own review: self-test stayed green with a THISERROR-only version
    of this check while the plain-derive path — the shape the real
    `SettingsWarning`/`SettingsParseError` collision actually takes —
    silently regressed.
    """
    failures = _check_distinct_e2_keys(
        "sweep 1, thiserror",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum TypeA {
            #[error("bad")]
            Bad { leak: String },
        }

        #[derive(thiserror::Error, Debug)]
        pub enum TypeB {
            #[error("bad")]
            Bad { leak: String },
        }
        ''',
        "Bad",
    )
    failures += _check_distinct_e2_keys(
        "sweep 2, plain-derive",
        '''
        pub enum TypeCWarning {
            Bad { leak: String },
        }

        pub enum TypeDWarning {
            Bad { leak: String },
        }
        ''',
        "Bad",
    )
    return failures


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
        opts: dict = entry[3] if len(entry) > 3 else {}
        found = scan_bridge_control(src, **opts)
        failures += check_key_shape(label, found)
        if not found:
            failures.append(f"POSITIVE control did not fire: {label}")
        elif bridge_expect and not any(_finding_matches(f, bridge_expect) for f in found):
            failures.append(
                f"POSITIVE control fired for the WRONG REASON: {label} -> "
                f"expected {bridge_expect}, got "
                f"{[(f.variant, f.field, f.field_type) for f in found]}"
            )
    for entry in BRIDGE_NEGATIVE_CONTROLS:
        label, src = entry[0], entry[1]
        neg_opts: dict = entry[2] if len(entry) > 2 else {}
        found = scan_bridge_control(src, **neg_opts)
        if found:
            failures.append(
                f"NEGATIVE control fired: {label} -> "
                f"{[(f.variant, f.field, f.field_type) for f in found]}"
            )
    failures += check_bridge_key_distinctness()
    for entry in WRAPPER_POSITIVE_CONTROLS:
        label, src = entry[0], entry[1]
        wrapper_expect: ControlExpectation | None = entry[2] if len(entry) > 2 else None
        wrapper_opts: dict = entry[3] if len(entry) > 3 else {}
        found = scan_wrapper_control(src, **wrapper_opts)
        failures += check_key_shape(label, found)
        if not found:
            failures.append(f"POSITIVE control did not fire: {label}")
        elif wrapper_expect and not any(_finding_matches(f, wrapper_expect) for f in found):
            failures.append(
                f"POSITIVE control fired for the WRONG REASON: {label} -> "
                f"expected {wrapper_expect}, got "
                f"{[(f.variant, f.field, f.field_type) for f in found]}"
            )
    for entry in WRAPPER_NEGATIVE_CONTROLS:
        label, src = entry[0], entry[1]
        wrapper_neg_opts: dict = entry[2] if len(entry) > 2 else {}
        found = scan_wrapper_control(src, **wrapper_neg_opts)
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
        f"{len(BRIDGE_NEGATIVE_CONTROLS)} bridge negative / "
        f"{len(WRAPPER_POSITIVE_CONTROLS)} wrapper positive / "
        f"{len(WRAPPER_NEGATIVE_CONTROLS)} wrapper negative)"
    )
    return 0
