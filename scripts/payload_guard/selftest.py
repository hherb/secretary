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
from payload_guard.rules.e5 import scan_wrapper_format_confinement
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

# Every key `_finding_matches` understands. A key outside this set is a TYPO,
# and `_finding_matches` ignores what it does not recognise — so before #496
# writing `{"feild": "uuid_hex"}` instead of `{"field": ...}` silently
# degraded that control back to "something fired", the exact vacuity the
# comment above records for P12/P14, while `--self-test` printed OK
# (verified by execution). `_check_expectation_keys` makes it a failure.
_EXPECTATION_KEYS = frozenset(
    {"unparsed", "variant", "field", "field_type", "field_type_prefix", "rule"}
)


def _check_expectation_keys() -> list[str]:
    """Every `ControlExpectation` key must be one `_finding_matches` reads.

    Cheap structural stand-in for the dataclass this dict wants to be: a
    typo'd key cannot silently weaken the control it belongs to.
    """
    failures: list[str] = []
    corpora = (
        ("POSITIVE", POSITIVE_CONTROLS),
        ("BRIDGE POSITIVE", BRIDGE_POSITIVE_CONTROLS),
        ("WRAPPER POSITIVE", WRAPPER_POSITIVE_CONTROLS),
    )
    for corpus_name, corpus in corpora:
        for entry in corpus:
            if len(entry) < 3 or not isinstance(entry[2], dict):
                continue
            unknown = set(entry[2]) - _EXPECTATION_KEYS
            if unknown:
                failures.append(
                    f"CONTROL EXPECTATION KEY: {corpus_name} control "
                    f"{entry[0]} carries unrecognised key(s) "
                    f"{sorted(unknown)} — _finding_matches ignores unknown "
                    "keys, so this control asserts less than it appears to. "
                    f"Known keys: {sorted(_EXPECTATION_KEYS)}"
                )
    return failures


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

    `gated_field_types` is read off the `core` `ScanRoot` (`_ROOTS_BY_LABEL`,
    defined below) rather than hardcoded as `frozenset()` here — same
    discipline the module comment above `_ROOTS_BY_LABEL` gives for
    `allow_field_access`: a control corpus that hardcodes the very value it
    exists to test cannot catch a `roots.py` edit that changes it. `core`'s
    `bridge_mode=False` means this value is never actually consulted by
    `is_bridge_field_safe`, but `scan_source` requires it regardless (#500).
    """
    enums, aliases, declared_consts, shadows = discover_declarations(src)
    consts = resolve_consts(declared_consts, shadows)
    return scan_source(
        "<self-test>", src, enums, aliases, consts, foreign_use_names(src),
        gated_field_types=_ROOTS_BY_LABEL["core"].gated_field_types,
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


# The REVIEWED rule matrix (#496). `roots.py` decides which rules run over
# which tree, and until #496 nothing read four of its five booleans: flipping
# `construction_sites`, `gated_detail_impls` or `format_confinement` to
# `False` disabled rule E3, E4 or E5 tree-wide while BOTH `--self-test` and
# the real scan stayed green (verified by execution).
#
# Two independent mechanisms close that, because they fail differently:
#
#  1. This table — a tripwire naming the expected value of every flag, so a
#     `roots.py` edit produces ONE legible failure that says which flag moved.
#     It is deliberately a hardcoded duplicate: changing the rule matrix is
#     meant to be a two-file, reviewed edit, not a one-line one.
#  2. `scan_bridge_control` / `scan_wrapper_control` now DISPATCH off the
#     same flags `run_real_scan` reads, so a flag flip also drops the
#     corresponding controls — proving the flags are load-bearing rather
#     than merely declared. This is the discipline the `_ROOTS_BY_LABEL`
#     comment above already states for `allow_field_access`, carried to the
#     other four.
#
# `gated_field_types` (#500) joins the table as a SIXTH flag, and it is not
# a `bool` — it is `ScanRoot`'s per-root frozenset of type spellings E2's
# carve-out accepts. `_check_root_rule_flags` used to compare with `is not`,
# which is correct only by ACCIDENT for the five booleans (`True`/`False`
# are interned singletons, so `is not` and `!=` agree for them) — it is
# WRONG for a frozenset: two separately-constructed frozensets with equal
# content are never the same object, so `is not` would report every root's
# `gated_field_types` as a mismatch even when it exactly matches the
# reviewed value below (verified: `frozenset({"x"}) is frozenset({"x"})` is
# `False` in CPython). Fixed to `!=`, which is correct for both.
_EXPECTED_ROOT_FLAGS: dict[str, dict[str, object]] = {
    "core": {
        "bridge_mode": False, "construction_sites": False,
        "gated_detail_impls": False, "format_confinement": False,
        "allow_field_access": False, "gated_field_types": frozenset(),
    },
    "bridge": {
        "bridge_mode": True, "construction_sites": True,
        "gated_detail_impls": True, "format_confinement": False,
        "allow_field_access": False,
        "gated_field_types": frozenset({"String", "Detail"}),
    },
    "ffi-py": {
        "bridge_mode": True, "construction_sites": True,
        "gated_detail_impls": False, "format_confinement": True,
        "allow_field_access": True, "gated_field_types": frozenset({"String"}),
    },
    "ffi-uniffi": {
        "bridge_mode": True, "construction_sites": True,
        "gated_detail_impls": False, "format_confinement": True,
        "allow_field_access": True, "gated_field_types": frozenset({"String"}),
    },
}


def _check_root_rule_flags() -> list[str]:
    """Assert `SCAN_ROOTS` still matches the reviewed rule matrix (#496).

    See `_EXPECTED_ROOT_FLAGS`. Also pins the SET of root labels, so
    deleting a root — which would otherwise surface as a raw `KeyError`
    traceback out of `_ROOTS_BY_LABEL`, loud in the wrong way for a CI
    security gate — is reported as a normal harness failure.
    """
    failures: list[str] = []
    actual_labels = {r.label for r in SCAN_ROOTS}
    expected_labels = set(_EXPECTED_ROOT_FLAGS)
    if actual_labels != expected_labels:
        return [
            "SCAN ROOT SET: payload_guard.roots.SCAN_ROOTS labels "
            f"{sorted(actual_labels)} != reviewed {sorted(expected_labels)} — "
            "adding or removing a scan root is a reviewed change; update "
            "_EXPECTED_ROOT_FLAGS in the same edit"
        ]
    for root in SCAN_ROOTS:
        for flag, expected in _EXPECTED_ROOT_FLAGS[root.label].items():
            got = getattr(root, flag)
            # `!=`, not `is not` (#500) — see the comment above
            # `_EXPECTED_ROOT_FLAGS` for why identity comparison silently
            # broke once a non-singleton value (`frozenset`) joined the table.
            if got != expected:
                failures.append(
                    f"SCAN ROOT FLAG: {root.label}.{flag} is {got}, reviewed "
                    f"value is {expected} — this flag decides whether a whole "
                    "RULE runs over that tree; if the change is intended, "
                    "update _EXPECTED_ROOT_FLAGS in the same commit"
                )
    return failures


def _check_wrapper_roots_agree() -> list[str]:
    """The design's premise (`payload_guard.roots` module docstring) is a
    single shared wrapper-root rule set, not two independently configurable
    ones — a control corpus that silently tolerated the two wrapper roots
    drifting apart on `allow_field_access` would be testing less than it
    claims to. This surfaces that disagreement as a NORMAL harness failure
    (review finding, task 9): the check used to be a bare `assert` inside
    `_wrapper_allow_field_access`, and `run_self_test` is not wrapped at its
    call site, so a real disagreement would have escaped as a raw Python
    traceback instead of the usual `self-test: FAIL` reporting — loud in the
    wrong way for a CI security gate. Wired into `run_self_test` alongside
    `check_view_invariants` / `check_bridge_key_distinctness`.
    """
    failures: list[str] = []
    # Widened in #496 from `allow_field_access` alone to every RULE-SELECTING
    # flag: `scan_wrapper_control` now dispatches off all of them, so a
    # disagreement on any one makes "the wrapper-root rule set" ambiguous.
    for flag in (
        "bridge_mode", "construction_sites", "gated_detail_impls",
        "format_confinement", "allow_field_access",
    ):
        values = {
            label: getattr(_ROOTS_BY_LABEL[label], flag)
            for label in ("ffi-py", "ffi-uniffi")
        }
        if len(set(values.values())) != 1:
            failures.append(
                "WRAPPER ROOT AGREEMENT: ffi-py and ffi-uniffi disagree on "
                f"{flag} ({values}) — scan_wrapper_control assumes one shared "
                "wrapper-root rule set"
            )
    return failures


def _wrapper_flag(flag: str) -> bool:
    """The value of a rule-selecting flag across BOTH wrapper roots.

    `all(...)` rather than either root's value alone, for the reason
    `_wrapper_allow_field_access` gives: if the two ever disagree, the
    fail-closed reading of an ACCEPTANCE is "not uniformly authorised".
    For a rule-ENABLING flag the same `all(...)` turns a disagreement into
    "the rule does not run in the harness", which drops that rule's controls
    and fails the self-test loudly — the direction that gets noticed.
    `_check_wrapper_roots_agree` reports the disagreement itself.
    """
    return all(
        getattr(_ROOTS_BY_LABEL[label], flag) for label in ("ffi-py", "ffi-uniffi")
    )


def _wrapper_allow_field_access() -> bool:
    """The `allow_field_access` value the wrapper-root rule set uses, read
    off BOTH wrapper `ScanRoot`s.

    Requires BOTH roots to grant it (`all(...)`) rather than picking either
    one arbitrarily: if the two ever disagree, the fail-closed reading is
    "shape 5 is not uniformly authorised", which DENIES rather than
    ACCEPTS — narrowing what shape 5 accepts, never widening it. The
    disagreement itself is what `_check_wrapper_roots_agree` reports as a
    self-test failure; this function only has to stay safe while that
    failure is being read.
    """
    return all(
        _ROOTS_BY_LABEL[label].allow_field_access for label in ("ffi-py", "ffi-uniffi")
    )


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

    Rule E2's `gated_field_types` (#500) is read the same way, off the same
    `ScanRoot`: today `frozenset({"String", "Detail"})`, so a bridge control
    exercises the WIDENED carve-out `is_bridge_field_safe` grants for the
    duration of the #500 migration.
    """
    root = _ROOTS_BY_LABEL["bridge"]
    enums, aliases, declared_consts, shadows = discover_declarations(src)
    consts = resolve_consts(declared_consts, shadows)
    foreign = foreign_use_names(src)
    # Every rule below dispatches off the SAME `ScanRoot` flags `run_real_scan`
    # reads (#496) — see `_EXPECTED_ROOT_FLAGS`. Calling them unconditionally
    # is what let E3/E4 be switched off tree-wide with the self-test green.
    found = scan_source(
        path_label, src, enums, aliases, consts, foreign,
        bridge_mode=root.bridge_mode,
        gated_field_types=root.gated_field_types,
    )
    if root.bridge_mode:
        found += scan_bridge_plain_declarations(
            path_label, src, enums, aliases, foreign,
            gated_field_types=root.gated_field_types,
        )
    if root.construction_sites:
        found += scan_bridge_construction_sites(
            path_label,
            src,
            sanctioned_constructor_names(detail_src),
            allow_field_access=root.allow_field_access,
        )
    if root.gated_detail_impls:
        found += scan_bridge_gated_detail_impls(
            path_label,
            src,
            discover_scanned_error_type_names([], [(path_label, src)], enums, enums),
        )
    return found


# Rule E5's default self-test detail-module path (#486, task 11): read off
# the ffi-py `ScanRoot` rather than duplicated as a bare string literal here,
# for the same reason `_ROOTS_BY_LABEL`'s module comment gives for
# `allow_field_access` — a control corpus that hardcodes the very path it
# exists to test cannot catch a `roots.py` edit that changes it. Unlike
# `allow_field_access`, the two wrapper roots' `detail_module_rel` values are
# LEGITIMATELY different (different crates, different files), so there is no
# "must agree" check to make here: picking ONE root's value is enough to
# exercise `scan_wrapper_format_confinement`'s equality test in both
# directions (`WP4` proves a non-matching `path_label` still scans; `WN2`
# points its fixture's `path_label` at this exact value to prove a matching
# one is skipped).
_WRAPPER_DETAIL_MODULE_REL_FOR_SELFTEST = _ROOTS_BY_LABEL["ffi-py"].detail_module_rel


# Rule E2's `gated_field_types` (#500), read the same single-root way and for
# the same reason: unlike `detail_module_rel`, the two wrapper roots' values
# ARE meant to agree (`frozenset({"String"})`, no `Detail` — the wrapper
# crates keep `String` because uniffi's UDL must project a `string` and PyO3
# exceptions take a message), and that agreement is already pinned
# independently by `_EXPECTED_ROOT_FLAGS`/`_check_root_rule_flags`, which
# checks EACH wrapper root against the same literal — so picking one root's
# value here does not weaken what is enforced elsewhere.
_WRAPPER_GATED_FIELD_TYPES_FOR_SELFTEST = _ROOTS_BY_LABEL["ffi-py"].gated_field_types


def scan_wrapper_control(
    src: str,
    path_label: str = "<self-test-wrapper>",
    detail_src: str = SELF_TEST_DETAIL_SRC,
) -> list[Finding]:
    """`scan_bridge_control`, but for a WRAPPER ROOT (#486): `bridge_mode=True`
    plus rules E2/E3, with rule E3's `allow_field_access` (shape 5) turned ON,
    plus rule E5 (`format!` confinement, task 11) — and NO rule E4 at all.

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

    Rule E5's `detail_module_rel` is read the same way, off ONE wrapper root
    (`_WRAPPER_DETAIL_MODULE_REL_FOR_SELFTEST`) — see that constant's
    comment for why one root suffices here.

    Rule E2's `gated_field_types` (#500) is read the same single-root way,
    off `_WRAPPER_GATED_FIELD_TYPES_FOR_SELFTEST` — today
    `frozenset({"String"})`, unchanged by the #500 migration (see that
    constant's comment for why the two wrapper roots' agreement is already
    enforced elsewhere).
    """
    enums, aliases, declared_consts, shadows = discover_declarations(src)
    consts = resolve_consts(declared_consts, shadows)
    foreign = foreign_use_names(src)
    # Same flag-driven dispatch as `scan_bridge_control` (#496), read off BOTH
    # wrapper roots via `_wrapper_flag`.
    found = scan_source(
        path_label, src, enums, aliases, consts, foreign,
        bridge_mode=_wrapper_flag("bridge_mode"),
        gated_field_types=_WRAPPER_GATED_FIELD_TYPES_FOR_SELFTEST,
    )
    if _wrapper_flag("bridge_mode"):
        found += scan_bridge_plain_declarations(
            path_label, src, enums, aliases, foreign,
            gated_field_types=_WRAPPER_GATED_FIELD_TYPES_FOR_SELFTEST,
        )
    if _wrapper_flag("construction_sites"):
        found += scan_bridge_construction_sites(
            path_label,
            src,
            sanctioned_constructor_names(detail_src),
            allow_field_access=_wrapper_allow_field_access(),
        )
    if _wrapper_flag("format_confinement"):
        found += scan_wrapper_format_confinement(
            path_label, src, _WRAPPER_DETAIL_MODULE_REL_FOR_SELFTEST
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
    failures += _check_root_rule_flags()
    failures += _check_wrapper_roots_agree()
    failures += _check_expectation_keys()
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
