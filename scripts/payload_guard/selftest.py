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

import contextlib
import dataclasses
import io
import re
import sys

from payload_guard.config import DETAIL_MODULE_REL, REPO_ROOT
from payload_guard.controls.bridge import (
    BRIDGE_NEGATIVE_CONTROLS, BRIDGE_POSITIVE_CONTROLS, SELF_TEST_DETAIL_SRC,
)
from payload_guard.controls.core import NEGATIVE_CONTROLS, POSITIVE_CONTROLS
from payload_guard.controls.wrapper import (
    WRAPPER_NEGATIVE_CONTROLS, WRAPPER_POSITIVE_CONTROLS,
)
from payload_guard.discovery import (
    _discover_tier_inputs, discover_declarations, discover_local_detail_decoys,
    discover_scanned_error_type_names, foreign_use_names, resolve_consts,
)
from payload_guard.lexer import LEXER_SAMPLE, discovery_view, lex_spans, strip_comments
from payload_guard.roots import SCAN_ROOTS, ScanRoot
from payload_guard.rules.e1 import scan_source
from payload_guard.rules.e2 import scan_bridge_plain_declarations
from payload_guard.rules.e3 import (
    SAFE_PARAM_TYPES, _ctor_params_are_safe, sanctioned_constructor_names,
    scan_bridge_construction_sites,
)
from payload_guard.rules.e4 import scan_bridge_gated_detail_impls
from payload_guard.rules.e5 import scan_wrapper_format_confinement
from payload_guard.scan import run_real_scan
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
    `shadowed_type_names` (#500 fix round 2) is the SAME story: `core`'s
    `gated_field_types` is always empty, so nothing can ever be shadowed
    OUT of it, and `frozenset()` here is passed for the same
    never-consulted-under-`bridge_mode=False` reason.
    """
    enums, aliases, declared_consts, shadows = discover_declarations(src)
    consts = resolve_consts(declared_consts, shadows)
    return scan_source(
        "<self-test>", src, enums, aliases, consts, foreign_use_names(src),
        gated_field_types=_ROOTS_BY_LABEL["core"].gated_field_types,
        shadowed_type_names=frozenset(),
    )




# Rule E3's `allow_field_access` (shape 5, #486) is read from `SCAN_ROOTS`
# here rather than hardcoded separately in `scan_bridge_control` /
# `scan_wrapper_control`: a control corpus that hardcodes the very flag it
# exists to test cannot catch a `roots.py` edit that changes it. Mutating
# `ScanRoot.allow_field_access` must be OBSERVABLE through `--self-test` —
# that is exactly what `BP43` (bridge, must stay denied) and `WP7` (wrapper,
# must stay denied too now that the flag is OFF everywhere — it was `WN1`,
# "must stay accepted", until #497/#500 retired shape 5) exist to prove, and
# neither proves anything if the value under test is a literal sitting beside
# them instead of the one `run_real_scan` itself reads.
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
# SIBLING PIN: `_WRAPPER_AGREEMENT_FLAGS_REVIEWED` (below) pins WHICH fields
# the two wrapper roots must AGREE on; this table pins WHAT each root's value
# is. They overlap — this table's per-root key set is already exactly those
# seven flags, so a set-equality pin here could have replaced that literal
# with no new text — and they are deliberately kept separate anyway: they fail
# INDEPENDENTLY, and every fail-open bug found on this branch was one registry
# being silently narrowed while another still looked right. Editing either
# without considering the other is the mistake to avoid.
_EXPECTED_ROOT_FLAGS: dict[str, dict[str, object]] = {
    "core": {
        "owns_detail_type": False,
        "bridge_mode": False, "construction_sites": False,
        "gated_detail_impls": False, "format_confinement": False,
        "allow_field_access": False, "gated_field_types": frozenset(),
    },
    "bridge": {
        "owns_detail_type": True,
        "bridge_mode": True, "construction_sites": True,
        "gated_detail_impls": True, "format_confinement": False,
        "allow_field_access": False,
        # #500 (task 4): narrowed from {"String", "Detail"} now that every
        # bridge declaration has moved off `String` — see roots.py.
        "gated_field_types": frozenset({"Detail"}),
    },
    # `allow_field_access` is False on BOTH wrapper roots as of #497/#500:
    # E3 shape 5's four DTO pass-through sites all moved to
    # `detail::project(...)`, leaving the acceptance with zero live sites.
    "ffi-py": {
        "owns_detail_type": False,
        "bridge_mode": True, "construction_sites": True,
        "gated_detail_impls": False, "format_confinement": True,
        "allow_field_access": False, "gated_field_types": frozenset({"String"}),
    },
    "ffi-uniffi": {
        "owns_detail_type": False,
        "bridge_mode": True, "construction_sites": True,
        "gated_detail_impls": False, "format_confinement": True,
        "allow_field_access": False, "gated_field_types": frozenset({"String"}),
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


# Fields that are LEGITIMATELY per-crate and must NOT be compared between the
# two wrapper roots: the root's own identity and the paths into its crate.
# EVERYTHING ELSE must agree, and the list is DERIVED from `ScanRoot` rather
# than spelled out (#500 fix round 2).
#
# It used to be a hardcoded 5-tuple whose comment claimed it covered "every
# RULE-SELECTING flag: `scan_wrapper_control` now dispatches off all of them".
# That claim decayed twice. `gated_field_types` (#500 Task 2) was never added
# — the plan's parked minor P6 — and `owns_detail_type` (#500 fix round 1) was
# dispatched on by `scan_wrapper_control` while missing here, so setting it
# asymmetrically WITH `_EXPECTED_ROOT_FLAGS` updated to match left the
# self-test green: the harness then ran strict (`_wrapper_flag`'s `all(...)`)
# while the real scan ran permissive on the exempted root, and rule E3's
# local-`Detail` decoy laundered unflagged there.
#
# Deriving inverts the default. A new `ScanRoot` field is compared unless
# someone deliberately exempts it here, so forgetting is fail-CLOSED (a
# spurious agreement failure) instead of fail-open (a silent divergence).
# `_check_wrapper_agreement_is_live` proves the check actually fires for every
# flag it claims to cover.
_WRAPPER_AGREEMENT_EXEMPT = frozenset({"label", "path", "detail_module_rel"})

# The reviewed answer to "which `ScanRoot` fields must the two wrapper roots
# agree on". Duplicated from the derivation on purpose, exactly as
# `_EXPECTED_ROOT_FLAGS` duplicates `roots.py`'s values: the derivation is the
# MECHANISM and this is the REVIEW, and a check that reads only the mechanism
# cannot notice the mechanism being narrowed.
#
# SIBLING PIN: `_EXPECTED_ROOT_FLAGS` (above) pins each root's VALUE for these
# same seven flags, and its key set is already exactly this tuple — so this
# literal could be derived from it. It is not, on purpose: two pins that fail
# independently catch a single narrowed registry, which is the shape of every
# fail-open bug found on this branch. Edit one, check the other.
_WRAPPER_AGREEMENT_FLAGS_REVIEWED: tuple[str, ...] = (
    "bridge_mode",
    "gated_field_types",
    "construction_sites",
    "gated_detail_impls",
    "format_confinement",
    "owns_detail_type",
    "allow_field_access",
)


def _wrapper_agreement_flags() -> tuple[str, ...]:
    """Every `ScanRoot` field the two wrapper roots must agree on."""
    return tuple(
        f.name
        for f in dataclasses.fields(ScanRoot)
        if f.name not in _WRAPPER_AGREEMENT_EXEMPT
    )


def _check_wrapper_roots_agree(
    roots: dict[str, ScanRoot] | None = None,
) -> list[str]:
    """The design's premise (`payload_guard.roots` module docstring) is a
    single shared wrapper-root rule set, not two independently configurable
    ones — a control corpus that silently tolerated the two wrapper roots
    drifting apart on any policy field would be testing less than it claims
    to. The compared set is DERIVED (`_wrapper_agreement_flags`), not listed,
    because the listed version fell behind twice. This surfaces that
    disagreement as a NORMAL harness failure
    (review finding, task 9): the check used to be a bare `assert` inside
    `_wrapper_allow_field_access`, and `run_self_test` is not wrapped at its
    call site, so a real disagreement would have escaped as a raw Python
    traceback instead of the usual `self-test: FAIL` reporting — loud in the
    wrong way for a CI security gate. Wired into `run_self_test` alongside
    `check_view_invariants` / `check_bridge_key_distinctness`.
    """
    failures: list[str] = []
    roots = roots if roots is not None else _ROOTS_BY_LABEL
    for flag in _wrapper_agreement_flags():
        values = {
            label: getattr(roots[label], flag)
            for label in ("ffi-py", "ffi-uniffi")
        }
        if len(set(values.values())) != 1:
            failures.append(
                "WRAPPER ROOT AGREEMENT: ffi-py and ffi-uniffi disagree on "
                f"{flag} ({values}) — scan_wrapper_control assumes one shared "
                "wrapper-root rule set"
            )
    return failures


def _perturb(value: object) -> object:
    """A value guaranteed different from `value`, for the agreement probe.

    Guaranteed different from the value it is GIVEN — which is ffi-py's — not
    from ffi-uniffi's. So on a run where the two roots ALREADY disagree on a
    bool, flipping ffi-py's makes them agree and this flag's probe reports a
    spurious liveness failure beside the real agreement failure. Extra noise
    on an already-failing run, never a missed one; not worth restructuring
    the probe to avoid.
    """
    if isinstance(value, bool):
        return not value
    if isinstance(value, frozenset):
        return frozenset(value | {"<probe>"})
    if isinstance(value, str):
        return value + "<probe>"
    return object()


def _check_wrapper_agreement_is_live() -> list[str]:
    """`_check_wrapper_roots_agree` must actually FIRE for every field
    `_wrapper_agreement_flags` claims to cover (#500 fix round 2).

    This is the non-vacuity proof the hardcoded tuple never had, and the
    reason it decayed twice unnoticed (see `_WRAPPER_AGREEMENT_EXEMPT`). It
    perturbs ONE field at a time on a COPY of the two wrapper roots and
    asserts the disagreement is reported and NAMES that field — so a future
    edit that drops a field from the compared set, or exempts one, fails here
    rather than silently widening what the two roots may disagree about.

    Copies only: `SCAN_ROOTS` is never mutated, and `ScanRoot` is a frozen
    dataclass, so `dataclasses.replace` is the only way to vary one anyway.
    """
    failures: list[str] = []
    flags = _wrapper_agreement_flags()
    # PIN the SET first. The per-flag probe below derives its list from the
    # same function it is testing, so it can only prove that the fields
    # CURRENTLY compared are live — it is structurally blind to a field being
    # dropped from the set, which is the precise failure being fixed here
    # (verified: adding `owns_detail_type` to `_WRAPPER_AGREEMENT_EXEMPT`
    # leaves the probe loop green, because the loop never visits it). Pinning
    # against a reviewed literal closes both directions: exempting a field, or
    # `ScanRoot` gaining one nobody classified, fails until someone edits this
    # tuple — the same review-checkpoint move `_EXPECTED_ROOT_FLAGS` and
    # `STR_PARAM_CTOR_EXCEPTIONS` make for their own registries.
    if set(flags) != set(_WRAPPER_AGREEMENT_FLAGS_REVIEWED):
        failures.append(
            "WRAPPER AGREEMENT SET: the wrapper roots are compared on "
            f"{sorted(flags)}, reviewed set is "
            f"{sorted(_WRAPPER_AGREEMENT_FLAGS_REVIEWED)} — a ScanRoot field "
            "is compared unless deliberately exempted, so both adding a field "
            "and exempting one are reviewed changes; update "
            "_WRAPPER_AGREEMENT_FLAGS_REVIEWED in the same commit"
        )
    if not flags:
        return failures + [
            "WRAPPER AGREEMENT LIVENESS: _wrapper_agreement_flags() is EMPTY "
            "— the agreement check would compare nothing and pass vacuously"
        ]
    for flag in flags:
        base_py = _ROOTS_BY_LABEL["ffi-py"]
        probe = {
            "ffi-py": dataclasses.replace(
                base_py, **{flag: _perturb(getattr(base_py, flag))}
            ),
            "ffi-uniffi": _ROOTS_BY_LABEL["ffi-uniffi"],
        }
        reported = _check_wrapper_roots_agree(probe)
        if not any(flag in msg for msg in reported):
            failures.append(
                "WRAPPER AGREEMENT LIVENESS: the two wrapper roots were made "
                f"to disagree on {flag!r} and _check_wrapper_roots_agree did "
                "NOT report it — that field is dispatched on but unguarded, "
                "which is exactly how owns_detail_type and gated_field_types "
                "each slipped through"
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
    shape 5 stays denied here. That used to read "even when a WRAPPER root
    grants it elsewhere", which since #497/#500 describes a state that cannot
    obtain — the flag is False on every root, and `WP7` pins the wrapper
    denial.

    Rule E2's `gated_field_types` (#500) is read the same way, off the same
    `ScanRoot`: today `frozenset({"Detail"})` — narrowed from the migration-
    duration `{"String", "Detail"}` by task 4 now that every bridge
    declaration has moved off `String`, so a bridge control exercises the
    NARROWED carve-out `is_bridge_field_safe` grants.

    `shadowed_type_names` (#500 fix round 2) is derived from THIS control's
    own fixture, the same self-contained-design discipline every other
    input here follows: `frozenset(aliases)` — the discovered alias dict's
    KEY SET is already the full candidate set regardless of collision for a
    SINGLE source string (`find_type_aliases` silently keeps the LAST
    right-hand side on a same-string redeclaration rather than dropping the
    name, unlike the real cross-file scan's `alias_candidates`, but the KEY
    is present either way — see
    `check_cross_file_alias_collision_still_denies` (BP56) for the dedicated
    cross-file collision check this single-string path cannot exercise) —
    unioned with `discover_local_detail_decoys` over the SAME
    fixture, exempting `root.detail_module_rel` so a control that sets
    `path_label=DETAIL_MODULE_REL` to test the legitimate declaration is
    not shadowed by its own fixture.
    """
    root = _ROOTS_BY_LABEL["bridge"]
    enums, aliases, declared_consts, shadows = discover_declarations(src)
    consts = resolve_consts(declared_consts, shadows)
    foreign = foreign_use_names(src)
    shadowed_type_names = frozenset(aliases) | discover_local_detail_decoys(
        [(path_label, src)], root.detail_module_rel
    )
    # Every rule below dispatches off the SAME `ScanRoot` flags `run_real_scan`
    # reads (#496) — see `_EXPECTED_ROOT_FLAGS`. Calling them unconditionally
    # is what let E3/E4 be switched off tree-wide with the self-test green.
    found = scan_source(
        path_label, src, enums, aliases, consts, foreign,
        bridge_mode=root.bridge_mode,
        gated_field_types=root.gated_field_types,
        shadowed_type_names=shadowed_type_names,
    )
    if root.bridge_mode:
        found += scan_bridge_plain_declarations(
            path_label, src, enums, aliases, foreign,
            gated_field_types=root.gated_field_types,
            shadowed_type_names=shadowed_type_names,
        )
    if root.construction_sites:
        found += scan_bridge_construction_sites(
            path_label,
            src,
            sanctioned_constructor_names(
                detail_src, owns_detail_type=root.owns_detail_type
            ),
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
    plus rules E2/E3, with rule E3's `allow_field_access` (shape 5) read off
    the roots rather than hardcoded — it is OFF everywhere since #497/#500 —
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
    module-level comment above `_ROOTS_BY_LABEL` for why. It is `False`
    today (#497/#500: shape 5's four DTO pass-through sites all moved to
    `detail::project(...)`, leaving the acceptance with no users); `WP7`
    proves the DTO pass-through now DENIES, and flipping either wrapper
    root's flag back to `True` in `roots.py` must make `WP7` STOP firing.
    Both the value and the direction of that mutation are the reverse of
    what this paragraph said before the flag was retired.

    Rule E5's `detail_module_rel` is read the same way, off ONE wrapper root
    (`_WRAPPER_DETAIL_MODULE_REL_FOR_SELFTEST`) — see that constant's
    comment for why one root suffices here.

    Rule E2's `gated_field_types` (#500) is read the same single-root way,
    off `_WRAPPER_GATED_FIELD_TYPES_FOR_SELFTEST` — today
    `frozenset({"String"})`, unchanged by the #500 migration (see that
    constant's comment for why the two wrapper roots' agreement is already
    enforced elsewhere).

    `shadowed_type_names` (#500 fix round 2) is derived from this control's
    own fixture, same as `scan_bridge_control` — see that function's
    docstring. A wrapper root's `gated_field_types` never contains `Detail`,
    so a decoy `Detail` declaration can shadow nothing THIS root's carve-out
    would have accepted anyway; computed uniformly regardless, both for
    symmetry with `scan_bridge_control` and because `String` collisions are
    representable here too even though no live wrapper control exercises one.
    """
    enums, aliases, declared_consts, shadows = discover_declarations(src)
    consts = resolve_consts(declared_consts, shadows)
    foreign = foreign_use_names(src)
    shadowed_type_names = frozenset(aliases) | discover_local_detail_decoys(
        [(path_label, src)], _WRAPPER_DETAIL_MODULE_REL_FOR_SELFTEST
    )
    # Same flag-driven dispatch as `scan_bridge_control` (#496), read off BOTH
    # wrapper roots via `_wrapper_flag`.
    found = scan_source(
        path_label, src, enums, aliases, consts, foreign,
        bridge_mode=_wrapper_flag("bridge_mode"),
        gated_field_types=_WRAPPER_GATED_FIELD_TYPES_FOR_SELFTEST,
        shadowed_type_names=shadowed_type_names,
    )
    if _wrapper_flag("bridge_mode"):
        found += scan_bridge_plain_declarations(
            path_label, src, enums, aliases, foreign,
            gated_field_types=_WRAPPER_GATED_FIELD_TYPES_FOR_SELFTEST,
            shadowed_type_names=shadowed_type_names,
        )
    if _wrapper_flag("construction_sites"):
        found += scan_bridge_construction_sites(
            path_label,
            src,
            sanctioned_constructor_names(
                detail_src, owns_detail_type=_wrapper_flag("owns_detail_type")
            ),
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


def check_cross_file_alias_collision_still_denies() -> list[str]:
    """`BP56` (#500 fix round 2, review finding "Important 1"): a gated
    field spelled `Detail` must still DENY when a `type Detail = String;`
    alias declared in ONE bridge file collides with a DIFFERENT, conflicting
    `type Detail = ...;` declared in ANOTHER bridge file.

    A dedicated check rather than a `BRIDGE_POSITIVE_CONTROLS` entry, for
    the same class of reason `check_bridge_key_distinctness` is one: this
    makes a claim about the CROSS-FILE aggregator (`_discover_tier_inputs`,
    `run_real_scan`'s Pass 1), not about a single self-contained fixture
    string. `scan_bridge_control` — every other bridge control in this
    file — calls `discover_declarations(src)` on ONE string, and within one
    string `find_type_aliases` cannot even represent a collision: a second
    `type Detail = ...;` in the SAME string just overwrites the first in its
    own local dict (last-write-wins), so the KEY `"Detail"` is present in
    `aliases` either way and `BP53` never actually exercises collision-drop.
    The bug this pins is specific to `_discover_tier_inputs`'s CROSS-FILE
    `alias_candidates` — the real, multi-file aggregation `run_real_scan`
    performs once per root — which DOES track collisions, and which is what
    dropped the shadow (see `is_bridge_field_safe`'s docstring, source 1).

    Verified by execution before this fix existed: FILE_A (BP53's own
    fixture) alone produced 2 findings; adding FILE_B — containing only
    `type Detail = Vec<u8>;`, no gated field of its own — took it to ZERO,
    because the collision emptied `aliases["Detail"]` from the RESOLVED
    dict `is_bridge_field_safe`'s fix-round-1 check consulted, and an empty
    dict has no member to deny on. The fix reads `alias_candidate_names`
    (the PRE-collision-drop set) instead, which still names `"Detail"`
    regardless of which value won the collision.

    NOT a clean isolation of Important 1 from Important 2, and this
    docstring used to claim otherwise until mutation-testing this control
    disproved it: `LOCAL_DETAIL_TYPE_RE`'s second alternative,
    `\\btype\\s+Detail\\s*[=<]`, matches FILE_B's `type Detail = Vec<u8>;`
    too, so `discover_local_detail_decoys` (Important 2's independent
    fix) ALSO denies this exact fixture — reverting `alias_candidate_names`
    to the post-collision-drop set here left this control GREEN, because
    the decoy check alone still supplied `"Detail"` to `shadowed_type_names`.
    This control still pins a real, useful regression (BOTH mechanisms
    denying a live exploit shape is not a bad thing), but the mutation
    proof that Important 1's mechanism specifically holds lives in
    `check_wrapper_alias_collision_isolated_from_decoy_check` (`WP9`)
    instead, which collides on `String` — a spelling `LOCAL_DETAIL_TYPE_RE`
    never matches — so nothing else can mask a regression there.
    """
    root = _ROOTS_BY_LABEL["bridge"]
    file_a = (
        "ffi/secretary-ffi-bridge/src/error/bp56_a.rs",
        '''
        type Detail = String;

        #[derive(thiserror::Error, Debug)]
        pub enum FooError {
            #[error("boom: {detail}")]
            Boom { detail: Detail },
        }
        ''',
    )
    file_b = (
        "ffi/secretary-ffi-bridge/src/error/bp56_b.rs",
        "type Detail = Vec<u8>;\n",
    )
    sources = [file_a, file_b]
    enums, aliases, consts, alias_candidate_names = _discover_tier_inputs(sources)
    shadow = alias_candidate_names | discover_local_detail_decoys(
        sources, root.detail_module_rel
    )
    label, raw = file_a
    found = scan_source(
        label, raw, enums, aliases, consts, foreign_use_names(raw),
        bridge_mode=root.bridge_mode,
        gated_field_types=root.gated_field_types,
        shadowed_type_names=shadow,
    )
    expect: ControlExpectation = {"rule": "E2", "field": "detail"}
    if not found:
        return ["POSITIVE control did not fire: BP56 (cross-file alias collision)"]
    if not any(_finding_matches(f, expect) for f in found):
        return [
            "POSITIVE control fired for the WRONG REASON: BP56 (cross-file "
            f"alias collision) -> expected {expect}, got "
            f"{[(f.variant, f.field, f.field_type) for f in found]}"
        ]
    return []


def check_wrapper_alias_collision_isolated_from_decoy_check() -> list[str]:
    r"""`WP9` (#500 fix round 2, review finding "Important 1", isolation
    proof): a WRAPPER-root gated field spelled `String` must still DENY
    when a `type String = usize;` alias in ONE wrapper file collides with a
    conflicting `type String = Vec<u8>;` in another — the SAME collision-
    drop bug `BP56` pins, but on a spelling `LOCAL_DETAIL_TYPE_RE` cannot
    reach.

    `BP56`'s fixture uses `Detail` because that is the bridge's real gated
    spelling, but `LOCAL_DETAIL_TYPE_RE`'s own pattern —
    `\b(?:struct|enum|union)\s+Detail\b|\btype\s+Detail\s*[=<]` — matches
    `type Detail = ...` too, so `discover_local_detail_decoys` (Important
    2's fix) ALSO denies `BP56`'s fixture independently of Important 1's
    `alias_candidate_names` mechanism. Reverting `_discover_tier_inputs`'s
    4th return value to the post-collision-drop set (mutation-tested during
    this fix's own review) left `BP56` GREEN — the decoy check alone was
    enough. `LOCAL_DETAIL_TYPE_RE` never mentions `String` in any of its
    three alternatives, so a collision on THAT spelling can only ever be
    caught by the raw-candidate mechanism: this is what makes a regression
    in `alias_candidate_names` specifically OBSERVABLE, independent of
    whichever other defence happens to also be watching. The wrapper root
    is used rather than the bridge because `gated_field_types` only
    contains `String` there — the bridge's is `{"Detail"}` alone, so a
    `String` collision would deny nothing bridge-side to observe.

    One root suffices (`ffi-py`, matching every other single-root wrapper
    constant here, e.g. `_WRAPPER_GATED_FIELD_TYPES_FOR_SELFTEST`) — this is
    a claim about the SHARED discovery/shadow machinery, not about either
    wrapper root's own `ScanRoot` data, which `_check_wrapper_roots_agree`
    already pins as identical.
    """
    root = _ROOTS_BY_LABEL["ffi-py"]
    file_a = (
        "ffi/secretary-ffi-py/src/wp9_a.rs",
        '''
        type String = usize;

        #[derive(thiserror::Error, Debug)]
        pub enum FooError {
            #[error("boom: {detail}")]
            Boom { detail: String },
        }
        ''',
    )
    file_b = ("ffi/secretary-ffi-py/src/wp9_b.rs", "type String = Vec<u8>;\n")
    sources = [file_a, file_b]
    enums, aliases, consts, alias_candidate_names = _discover_tier_inputs(sources)
    shadow = alias_candidate_names | discover_local_detail_decoys(
        sources, root.detail_module_rel
    )
    label, raw = file_a
    found = scan_source(
        label, raw, enums, aliases, consts, foreign_use_names(raw),
        bridge_mode=root.bridge_mode,
        gated_field_types=root.gated_field_types,
        shadowed_type_names=shadow,
    )
    expect: ControlExpectation = {"rule": "E2", "field": "detail"}
    if not found:
        return [
            "POSITIVE control did not fire: WP9 (wrapper cross-file alias "
            "collision, isolated from the decoy check)"
        ]
    if not any(_finding_matches(f, expect) for f in found):
        return [
            "POSITIVE control fired for the WRONG REASON: WP9 (wrapper "
            f"cross-file alias collision) -> expected {expect}, got "
            f"{[(f.variant, f.field, f.field_type) for f in found]}"
        ]
    return []


def check_detail_naming_param_types_are_all_withdrawn_under_decoy() -> list[str]:
    r"""#504 review R1: `_ctor_params_are_safe`'s wrapper-decoy withdrawal
    (`detail_param_ok=False`) must deny EVERY `SAFE_PARAM_TYPES` member
    whose spelling names the `Detail` newtype, not just the two spellings
    (`Detail`, `&Detail`) that happen to exist today.

    Independent of HOW the production withdrawal is implemented — this
    check computes its OWN `\bDetail\b`-naming subset of `SAFE_PARAM_TYPES`
    directly, rather than importing whatever set/logic
    `_ctor_params_are_safe` uses internally, so it is not tautological: a
    regression that reverts the withdrawal to a hand-maintained literal (the
    exact shape #504's own review caught — `allowed - {"Detail", "&Detail"}`
    silently missing a THIRD future `Detail`-naming spelling) is caught here
    even though the production code and this check independently agree
    today. Mutation-verified: temporarily reverting
    `_ctor_params_are_safe` to the pre-fix `allowed - {"Detail", "&Detail"}`
    literal, with `"&'static Detail"` added to `SAFE_PARAM_TYPES` as a
    stand-in for a plausible future member, reproduces a red result here
    (`_ctor_params_are_safe` sanctions the synthetic member under
    `detail_param_ok=False` when it should deny) — see the #504 review
    fix-round commit for the transcript.

    `\bDetail\b` deliberately does NOT match `&impl GatedDetail` (no word
    boundary between `Gated` and `Detail`), so that spelling is correctly
    excluded from this loop. `&impl GatedDetail`'s own wrapper-decoy
    exposure was the SAME class of hole one type over (#504 review R3) and
    is closed by a separate, independently-derived withdrawal
    (`gated_detail_param_ok` in `_ctor_params_are_safe`) rather than folded
    in here by a wider match — see
    `check_gated_detail_naming_param_types_are_all_withdrawn_under_decoy`
    below for its own coupling check, the `GatedDetail` analogue of this one.
    """
    failures: list[str] = []
    detail_naming = {t for t in SAFE_PARAM_TYPES if re.search(r"\bDetail\b", t)}
    if not detail_naming:
        return [
            "DETAIL WITHDRAWAL LIVENESS: no SAFE_PARAM_TYPES member matches "
            r"\bDetail\b — this check would pass vacuously"
        ]
    for ty in sorted(detail_naming):
        if _ctor_params_are_safe("x", f"(d: {ty})", detail_param_ok=False):
            failures.append(
                "DETAIL WITHDRAWAL INCOMPLETE: SAFE_PARAM_TYPES member "
                f"{ty!r} is NOT denied by _ctor_params_are_safe under "
                "detail_param_ok=False — a wrapper-root decoy `Detail` "
                "would leave this spelling sanctioned"
            )
    return failures


def check_gated_detail_naming_param_types_are_all_withdrawn_under_decoy() -> list[str]:
    r"""#504 review R3: the `GatedDetail` analogue of
    `check_detail_naming_param_types_are_all_withdrawn_under_decoy` directly
    above — same coupling risk, same independent-computation fix, one type
    over. `_ctor_params_are_safe`'s `gated_detail_param_ok=False` withdrawal
    must deny EVERY `SAFE_PARAM_TYPES` member whose spelling names
    `GatedDetail`, not just `&impl GatedDetail`, the one spelling that
    exists today.

    Computes its OWN `\bGatedDetail\b`-naming subset of `SAFE_PARAM_TYPES`
    directly rather than reading whatever the production withdrawal uses
    internally, for the same non-tautology reason the `Detail` check gives.
    Mutation-verified the same way: temporarily reverting the withdrawal to
    a hand-maintained `{"&impl GatedDetail"}` literal, with a synthetic
    `"&'static impl GatedDetail"` added to `SAFE_PARAM_TYPES`, reproduces a
    red result here.
    """
    failures: list[str] = []
    gated_detail_naming = {
        t for t in SAFE_PARAM_TYPES if re.search(r"\bGatedDetail\b", t)
    }
    if not gated_detail_naming:
        return [
            "GATED_DETAIL WITHDRAWAL LIVENESS: no SAFE_PARAM_TYPES member "
            r"matches \bGatedDetail\b — this check would pass vacuously"
        ]
    for ty in sorted(gated_detail_naming):
        if _ctor_params_are_safe("x", f"(d: {ty})", gated_detail_param_ok=False):
            failures.append(
                "GATED_DETAIL WITHDRAWAL INCOMPLETE: SAFE_PARAM_TYPES member "
                f"{ty!r} is NOT denied by _ctor_params_are_safe under "
                "gated_detail_param_ok=False — a wrapper-root decoy "
                "`trait GatedDetail` would leave this spelling sanctioned"
            )
    return failures


# `BP57`'s TWO planted-decoy targets (#500 fix round 2, review finding "the
# Important that matters more than either T4-I1/T4-I2"; the second added in
# the final whole-branch review). Deliberately unmistakable — no real PR
# would ever choose these names — and additionally listed in `.gitignore` as
# belt-and-suspenders; the PRIMARY guarantee that no residue survives is
# `check_real_scan_shadow_wiring_is_live`'s own `finally` block, not the
# gitignore entries.
#
# ONE PROBE PER TERM of the production expression, because each term is
# caught by a DIFFERENT decoy shape and neither substitutes for the other:
#
#   * `_SHADOW_WIRING_PROBE_REL` — a `struct Detail` decoy under the BRIDGE
#     root, caught by `discover_local_detail_decoys`, which returns a
#     hardcoded `frozenset({"Detail"})`.
#   * `_ALIAS_WIRING_PROBE_REL` — a `type String = ...;` alias decoy under a
#     WRAPPER root, caught by `alias_candidate_names` ONLY. The wrapper
#     roots' gated spelling is `String` (`ScanRoot.gated_field_types`), a
#     name `discover_local_detail_decoys` can never return.
_SHADOW_WIRING_PROBE_REL = (
    "ffi/secretary-ffi-bridge/src/error/__selftest_shadow_wiring_probe.rs"
)
_ALIAS_WIRING_PROBE_REL = (
    "ffi/secretary-ffi-uniffi/src/__selftest_alias_wiring_probe.rs"
)
# #515 I7: a BRIDGE file declaring a gated `detail: String`. Pins
# `run_real_scan`'s `gated_field_types` wiring in the WIDENING direction,
# which step 1's clean-tree check cannot see.
_GATED_STRING_WIRING_PROBE_REL = (
    "ffi/secretary-ffi-bridge/src/error/__selftest_gated_string_probe.rs"
)
# #515 I5: a bridge file OUTSIDE `detail.rs` writing `Detail(...)`.
# Pins rule E6's WIRING, which the direct-call check cannot see.
_E6_WIRING_PROBE_REL = (
    "ffi/secretary-ffi-bridge/src/error/__selftest_e6_wiring_probe.rs"
)


def check_real_scan_shadow_wiring_is_live() -> list[str]:
    r"""`BP57` (#500 fix round 2 review): `run_real_scan`'s OWN per-root
    computation of `shadowed_type_names` —

        shadowed_type_names = alias_candidate_names | discover_local_detail_decoys(
            sources[root.label], root.detail_module_rel
        )

    in `scan.py` — is pinned by NOTHING. Every self-test control
    (`BP54`/`BP55`/`BN29`/`BP56`/`WP9`, and `scan_bridge_control` /
    `scan_wrapper_control` generally) computes its OWN shadow set from its
    OWN fixture; not one of them reads that line. Severing it to
    `shadowed_type_names = frozenset()` was verified (by the reviewer, then
    re-verified here) to leave `--self-test` FULLY green — every count
    unchanged — and the real scan green too, because today's tree has no
    live decoy for an empty shadow set to fail to catch. `T4-I1`/`T4-I2`'s
    fixes can be switched off tree-wide, undetectably, right up until an
    attacker actually plants the decoy the protection exists to catch —
    at which point the protection has already failed.

    This is the same class #496 closed for `roots.py`'s rule-selecting
    booleans ("three of `roots.py`'s five rule flags were read by nothing,
    so `E3`/`E4`/`E5` could each be switched off tree-wide with
    `--self-test` green" — CLAUDE.md's guard section). That fix made
    `scan_bridge_control`/`scan_wrapper_control` DISPATCH off the SAME
    `ScanRoot` flags `run_real_scan` reads. The same move does NOT close
    THIS hole: `shadowed_type_names` is not `ScanRoot` DATA a control could
    dispatch off, it is an EXPRESSION inside `run_real_scan`'s own function
    body, and a control that independently RECOMPUTES that expression —
    which is exactly what `BP56`/`WP9` already do — provably does not
    observe a mutation to the call site itself: both stayed GREEN in
    review when this exact line was severed, because they call
    `discover_local_detail_decoys`/`_discover_tier_inputs` directly, never
    `run_real_scan`. The "shared helper" alternative considered and
    rejected for the same reason: routing `scan_bridge_control` through a
    shared helper would catch a bug IN the helper, but not a severed CALL
    to it at the one production site — the exact mutation demonstrated.

    The only way to observe a mutation INSIDE `run_real_scan`'s own body
    is to run `run_real_scan` — end to end, against the real filesystem
    tree, the SAME "plant / observe / revert" discipline this task's own
    Step 5 already used to demonstrate the `Detail` newtype's compile-time
    guarantee (`error/vault/mod.rs`, reverted by exact-text edit, `git
    diff` checked empty afterward).

    ONE PROBE PER TERM, because the expression has TWO and a single probe
    pins only one of them (final whole-branch review). The original version
    of this check planted the `struct Detail` decoy alone, which
    `discover_local_detail_decoys` — the SURVIVING term — catches on its
    own: replacing `alias_candidate_names` with `frozenset()` therefore
    left `--self-test` FULLY green and the real scan green, exactly the
    hole this control was written to close, one term over. That term is
    NOT redundant with the other: `discover_local_detail_decoys` returns a
    hardcoded `frozenset({"Detail"})`, while the WRAPPER roots' gated
    spelling is `String`, so only `alias_candidate_names` can ever shadow
    it. Measured on this tree: a planted `type String = SecretHolder;`
    under `ffi/secretary-ffi-uniffi/src/` takes the real scan from 46
    violations to `OK` (exit 0) the moment that term is severed. The
    denial is a #500 capability — merge-base `3775ef5` accepted the same
    fixture — so nothing else in the corpus would have missed it either.

    Four assertions, in order:

    1. The UNTOUCHED tree scans OK. This alone pins `gated_field_types`'s
       PRE-EXISTING, IDENTICAL wiring hole for free (mitigating context
       from review): severing `gated_field_types=root.gated_field_types`
       denies every one of the ~27 real `detail: Detail` fields
       immediately, no decoy needed — so a clean-tree baseline assertion
       catches it without a line of code written specifically for it.
    2. Planting a decoy `pub struct Detail(pub String);` — a throwaway
       `.rs` file under the BRIDGE root, needing NO gated field of its own
       (the ~27 EXISTING real ones are what a LIVE shadow set catches) —
       makes the scan FAIL. This pins the `discover_local_detail_decoys`
       TERM: an EMPTY (severed) shadow set has nothing to catch on today's
       clean tree, so only a POSITIVE probe like this observes it; step 1
       alone would not (a severed shadow set and a live one behave
       identically when there is no decoy to disagree about).
    3. Planting a decoy `type String = SecretHolder;` under a WRAPPER root
       makes the scan FAIL. This pins the `alias_candidate_names` TERM,
       and ONLY it — see the paragraph above for why step 2's probe cannot
       stand in for this one. A `type` alias rather than a `struct` on
       purpose: `alias_candidate_names` is the RAW `type X = Y;` LHS set
       (`_discover_tier_inputs`), so an alias is the only shape that
       reaches it.
    4. Removing both decoys (`finally` — runs even if 1-3 raise) restores
       a clean scan. Proves the probes leave no residue, and that the
       decoys specifically — not some unrelated cause — were what tripped
       steps 2 and 3.

    `run_real_scan`'s own stdout/stderr are captured and discarded: this
    check's OWN pass/fail reporting is what `--self-test` surfaces, not a
    second copy of the real scan's violation listing.
    """
    probes: tuple[tuple[str, str, str, str], ...] = (
        (
            "step 2",
            _SHADOW_WIRING_PROBE_REL,
            "pub struct Detail(pub String);\n",
            "run_real_scan's OWN shadowed_type_names computation (scan.py) "
            "may be severed, or its `discover_local_detail_decoys` TERM "
            "specifically may be — that term is what BP54/BP55/BN29/BP56/WP9 "
            "independently recompute without ever reading this call site",
        ),
        (
            "step 3",
            _ALIAS_WIRING_PROBE_REL,
            "type String = SecretHolder;\n",
            "run_real_scan's OWN shadowed_type_names computation (scan.py) "
            "may be severed, or its `alias_candidate_names` TERM "
            "specifically may be — no other control observes that term, and "
            "`discover_local_detail_decoys` cannot substitute for it "
            "(it returns only the spelling `Detail`, never `String`)",
        ),
        (
            "step 3b",
            _ALIAS_WIRING_PROBE_REL,
            "#[cfg(not(test))]\ntype String = SecretHolder;\n",
            "the deny-polarity alias pass (`_deny_polarity_alias_names`) may "
            "be severed. `alias_candidate_names` used to be harvested only "
            "from `discover_declarations`, whose PERMISSIVE `CFG_TEST_RE` "
            "skip also swallows `#[cfg(not(test))]` and every "
            "`#[cfg_attr(test, ..)]` — an over-matched skip on a DENY "
            "trigger is fail-OPEN, and this exact line scanned clean before "
            "#515 C4 (verified by execution). Step 3's un-gated probe cannot "
            "substitute: it passes whether or not the strict pass exists",
        ),
        (
            "step 3c",
            _GATED_STRING_WIRING_PROBE_REL,
            '#[derive(Debug, thiserror::Error)]\npub enum ZzProbe {\n'
            '    #[error("boom: {detail}")]\n    Boom { detail: String },\n}\n',
            "run_real_scan's `gated_field_types` wiring may be WIDENED — "
            "replaced by a hardcoded set that still contains `String`. "
            "BP51 recomputes the denial from `ScanRoot` data and never reads "
            "this call site, and step 1 only proves a CLEAN tree scans OK, "
            "which a widening preserves. The bridge must permit NO `String` "
            "under a gated name (#500's headline narrowing), so a bridge "
            "file declaring one has to red the real scan",
        ),
        (
            "step 3d",
            _E6_WIRING_PROBE_REL,
            "use super::Detail;\npub(crate) fn f(s: String) -> Detail "
            "{ Detail(s) }\n",
            "rule E6's call in `scan.py` may be severed. "
            "`check_e6_detail_construction_is_live` calls the rule FUNCTION "
            "directly, so it passes whether or not the scan ever invokes it "
            "— the same function-vs-wiring split BP57 exists to cover. E6 "
            "pins the `Detail` tuple-struct constructor to one file, which "
            "is what stops a DESCENDANT module (Rust privacy is subtree-, "
            "not file-scoped) relocating the minting capability out of the "
            "reviewed file",
        ),
    )

    existing = [rel for _, rel, _, _ in probes if (REPO_ROOT / rel).exists()]
    if existing:
        return [
            f"REAL SCAN WIRING PROBE: {rel} already exists — refusing to "
            "overwrite; remove it by hand and re-run"
            for rel in existing
        ]

    def _quiet_real_scan() -> int:
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            return run_real_scan()

    baseline = _quiet_real_scan()
    if baseline != 0:
        return [
            "REAL SCAN WIRING PROBE (BP57 step 1): the untouched tree does "
            f"not scan OK (exit {baseline}) — cannot run the decoy probes on "
            "top of an already-failing baseline. This also means "
            "gated_field_types' own real-scan wiring may be severed"
        ]

    failures: list[str] = []
    try:
        for step, rel, body, diagnosis in probes:
            decoy_path = REPO_ROOT / rel
            try:
                decoy_path.write_text(body, encoding="utf-8")
                planted = _quiet_real_scan()
                if planted == 0:
                    failures.append(
                        f"REAL SCAN WIRING (BP57 {step}): planting a decoy at "
                        f"{rel} did not fail the real scan — {diagnosis}"
                    )
            finally:
                decoy_path.unlink(missing_ok=True)
    finally:
        for _, rel, _, _ in probes:
            (REPO_ROOT / rel).unlink(missing_ok=True)

    if not failures:
        cleaned = _quiet_real_scan()
        if cleaned != 0:
            failures.append(
                "REAL SCAN WIRING PROBE (BP57 step 4): removing the decoys "
                f"did not restore a clean scan (exit {cleaned}) — a probe "
                "left residue, or the tree was already broken"
            )
    return failures


def _check_control_label_uniqueness() -> list[str]:
    """No two controls in any corpus may share a LABEL (#511, closed here).

    Every control is a `(label, src, ...)` tuple in a list, and the label is
    what a failure message names. A duplicate is not a crash and not a
    finding — it is two controls that report under one identity, so a
    regression in either prints a message pointing at the other, and a
    reviewer grepping the label finds the wrong fixture. #511 was filed
    after a `WP9` collision on this branch was caught by an implementer
    running `grep`, which is exactly the kind of catch that does not
    survive contact with a tired afternoon.

    Labels here are long prose strings, so the comparison is on the leading
    TOKEN (`BP52`, `WN3`, …) — the part that is actually used as an
    identity — rather than the whole sentence, which would let
    `BP52 <one wording>` and `BP52 <another>` both pass.
    """
    corpora = [
        ("CORE POSITIVE", POSITIVE_CONTROLS),
        ("CORE NEGATIVE", NEGATIVE_CONTROLS),
        ("BRIDGE POSITIVE", BRIDGE_POSITIVE_CONTROLS),
        ("BRIDGE NEGATIVE", BRIDGE_NEGATIVE_CONTROLS),
        ("WRAPPER POSITIVE", WRAPPER_POSITIVE_CONTROLS),
        ("WRAPPER NEGATIVE", WRAPPER_NEGATIVE_CONTROLS),
    ]
    seen: dict[str, str] = {}
    failures: list[str] = []
    for corpus_name, corpus in corpora:
        for entry in corpus:
            token = str(entry[0]).split()[0] if str(entry[0]).strip() else "<empty>"
            if token in seen:
                failures.append(
                    f"CONTROL LABEL COLLISION: {token!r} is used by both "
                    f"{seen[token]} and {corpus_name} — a duplicate label "
                    f"makes a regression in one control print a message "
                    f"naming the other (#511)"
                )
            else:
                seen[token] = corpus_name
    return failures


def check_e6_detail_construction_is_live() -> list[str]:
    """Rule E6 (#515 I5) fires on both arms and stays silent on the real file.

    E6 has no corpus control because it is a PLACEMENT rule keyed on the
    file path, which `scan_control`'s synthetic single-file fixtures cannot
    express — the same reason E4's file-placement arm is exercised directly.

    Three assertions, because two of them are the halves of one hole and the
    third is the false-positive guard that keeps the rule usable:

    1. `Detail(` in a bridge file OTHER than `detail.rs` must DENY.
    2. An unsanctioned `mod` INSIDE `detail.rs` must DENY. This is the arm
       that actually closes the descendant-module hole — Rust privacy is
       module-SUBTREE scoped, so `mod ext;` plus `#[path]` relocates the
       minting capability into an unreviewed file while arm 1 stays silent.
    3. `detail.rs` itself, with its real `Detail(...)` constructions and its
       two legitimate submodules, must stay CLEAN.
    """
    from payload_guard.rules.e6 import scan_bridge_detail_construction

    failures: list[str] = []
    foreign = scan_bridge_detail_construction(
        "ffi/secretary-ffi-bridge/src/error/zz_probe.rs",
        "use super::Detail;\npub(crate) fn f(s: String) -> Detail { Detail(s) }\n",
    )
    if not any(f.rule == "E6" for f in foreign):
        failures.append(
            "E6 ARM 1: `Detail(s)` written OUTSIDE "
            f"{DETAIL_MODULE_REL} did not produce an E6 finding — the "
            "newtype's minting capability is unpinned, and a descendant "
            "module can relocate it into an unreviewed file"
        )
    submod = scan_bridge_detail_construction(
        DETAIL_MODULE_REL, "pub struct Detail(String);\npub(crate) mod ext;\n"
    )
    if not any(f.rule == "E6" for f in submod):
        failures.append(
            f"E6 ARM 2: an unsanctioned `mod ext;` inside {DETAIL_MODULE_REL} "
            "did not produce an E6 finding — a child module inherits the "
            "private field's visibility, so declaring one hands the minting "
            "capability to whatever file `#[path]` points at"
        )
    # Read as a HARNESS FAILURE rather than a traceback: this file's own
    # standard (see `_check_wrapper_roots_agree`) is that a security gate
    # must not surface an IO problem as a raw stack trace, which reads as a
    # crashed tool rather than a failed check.
    try:
        real = (REPO_ROOT / DETAIL_MODULE_REL).read_text(encoding="utf-8")
    except OSError as exc:
        return failures + [
            f"E6 SELF-CHECK: cannot read {DETAIL_MODULE_REL} ({exc}) — the "
            "false-positive half of this check could not run, so a green "
            "self-test would not mean the rule is usable on the real tree"
        ]
    on_real = scan_bridge_detail_construction(DETAIL_MODULE_REL, real)
    if on_real:
        failures.append(
            f"E6 FALSE POSITIVE: the real {DETAIL_MODULE_REL} produced "
            f"{[f.source_line for f in on_real]!r} — its own constructions "
            "and its two sanctioned submodules must stay clean, or the rule "
            "is unusable and will be switched off rather than fixed"
        )
    return failures


def run_self_test() -> int:
    failures: list[str] = check_view_invariants()
    failures += _check_root_rule_flags()
    failures += check_e6_detail_construction_is_live()
    failures += _check_control_label_uniqueness()
    failures += _check_wrapper_roots_agree()
    failures += _check_wrapper_agreement_is_live()
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
    failures += check_cross_file_alias_collision_still_denies()
    failures += check_wrapper_alias_collision_isolated_from_decoy_check()
    failures += check_detail_naming_param_types_are_all_withdrawn_under_decoy()
    failures += check_gated_detail_naming_param_types_are_all_withdrawn_under_decoy()
    failures += check_real_scan_shadow_wiring_is_live()
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
