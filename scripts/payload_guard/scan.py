"""The real scan driver: `run_real_scan` walks every `ScanRoot` in
`payload_guard.roots.SCAN_ROOTS` and runs whichever rules that root's data
says apply (bridge_mode E1 plus E2/E3/E4 on the bridge root; E1/E2/E3 plus
E3 shape 5 on the two wrapper roots) against every `.rs` file, honouring the
allowlist. Moved out of the former single-file
`scripts/check-error-payload-hygiene.py` in #486 (task 4); rewritten in
#486 (task 9) to loop over `SCAN_ROOTS` instead of open-coding two hand-written
passes — see `payload_guard.roots` for why.
"""

from __future__ import annotations

import sys

from payload_guard.allowlist import load_allowlist
from payload_guard.config import ALLOWLIST_PATH, DETAIL_MODULE_REL, REPO_ROOT
from payload_guard.discovery import (
    _discover_tier_inputs, discover_scanned_error_type_names, foreign_use_names,
)
from payload_guard.roots import SCAN_ROOTS
from payload_guard.rules.e1 import scan_source
from payload_guard.rules.e2 import scan_bridge_plain_declarations
from payload_guard.rules.e3 import sanctioned_constructor_names, scan_bridge_construction_sites
from payload_guard.rules.e4 import is_detail_module, scan_bridge_gated_detail_impls
from payload_guard.rules.e5 import scan_wrapper_format_confinement
from payload_guard.types import Finding


def _check_roots_resolve() -> list[str]:
    """Every `ScanRoot.path` must exist and contain at least one `.rs` file
    (#496).

    `Path.rglob` on a NON-EXISTENT directory returns an empty generator, not
    an error. Without this check a root that moved — a crate rename, a
    refactor, a merge-conflict resolution in `roots.py` — silently
    contributed zero files, and the guard printed `error-payload hygiene: OK`
    with an entire crate unscanned under every rule that applied to it.
    Verified by execution: `mv ffi/secretary-ffi-py ffi/secretary-py` took a
    planted, otherwise-caught violation from exit 1 to exit 0.

    Only `core` failed closed before this, and only by ACCIDENT — rule E4's
    registry is built from core + bridge types, so an empty `core` made every
    `impl GatedDetail` target unscannable and E4 denied. The bridge and both
    wrapper roots, which between them hold every gated construction site,
    failed OPEN.

    A hard failure rather than a `Finding`: this is not a property of any
    scanned source, it is the guard being unable to do its job, and it must
    not be allowlistable.
    """
    problems: list[str] = []
    for r in SCAN_ROOTS:
        if not r.path.is_dir():
            problems.append(
                f"SCAN ROOT MISSING: {r.label} -> {r.path} is not a directory. "
                "If the tree moved, update payload_guard/roots.py; the guard "
                "will NOT scan a root it cannot find."
            )
            continue
        if not any(r.path.rglob("*.rs")):
            problems.append(
                f"SCAN ROOT EMPTY: {r.label} -> {r.path} contains no *.rs "
                "files. A root that contributes zero files silently exempts "
                "a whole crate."
            )
    return problems


def run_real_scan() -> int:
    root_problems = _check_roots_resolve()
    if root_problems:
        print("error-payload hygiene: FAIL\n", file=sys.stderr)
        for p in root_problems:
            print(f"  {p}", file=sys.stderr)
        return 1
    allowlist = load_allowlist(ALLOWLIST_PATH)
    sources: dict[str, list[tuple[str, str]]] = {
        r.label: [
            (str(rs.relative_to(REPO_ROOT)), rs.read_text(encoding="utf-8"))
            for rs in sorted(r.path.rglob("*.rs"))
        ]
        for r in SCAN_ROOTS
    }
    # Pass 1, ONCE PER ROOT — see `_discover_tier_inputs`. Cross-root vouching
    # is exactly what this separation exists to prevent: a wrapper-local
    # alias/const/enum must not vouch for a bridge or core field, or vice
    # versa.
    tiers = {label: _discover_tier_inputs(srcs) for label, srcs in sources.items()}

    # Rule E4's registry stays CORE + BRIDGE: the impls in error/detail.rs name
    # core types far more often than bridge-local ones, and no wrapper crate
    # can implement the `pub(crate)` trait at all.
    core_enums = tiers["core"][0]
    bridge_enums = tiers["bridge"][0]
    scanned_error_type_names = discover_scanned_error_type_names(
        sources["core"], sources["bridge"], core_enums, bridge_enums
    )

    # Pass 2: the actual scan, now with tiers 2, 3, and 4 available — each
    # file's own foreign `use` bindings withdrawing the bare-name credits
    # that file's namespace contradicts.
    violations: list[Finding] = []
    for root in SCAN_ROOTS:
        enums, aliases, consts = tiers[root.label]
        detail_src = (
            next(
                (
                    raw
                    for label, raw in sources[root.label]
                    if label.replace("\\", "/") == root.detail_module_rel
                ),
                None,
            )
            if root.detail_module_rel
            else None
        )
        sanctioned = sanctioned_constructor_names(detail_src)
        for label, raw in sources[root.label]:
            foreign = foreign_use_names(raw)
            findings = scan_source(
                label, raw, enums, aliases, consts, foreign,
                bridge_mode=root.bridge_mode,
                gated_field_types=root.gated_field_types,
            )
            if root.bridge_mode:
                findings += scan_bridge_plain_declarations(
                    label, raw, enums, aliases, foreign,
                    gated_field_types=root.gated_field_types,
                )
            if root.construction_sites:
                findings += scan_bridge_construction_sites(
                    label, raw, sanctioned,
                    allow_field_access=root.allow_field_access,
                )
            if root.gated_detail_impls:
                findings += scan_bridge_gated_detail_impls(
                    label, raw, scanned_error_type_names
                )
            if root.format_confinement:
                findings += scan_wrapper_format_confinement(
                    label, raw, root.detail_module_rel
                )
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
            elif v.rule == "E3":
                detail = (
                    f"gated field `{v.field}` is built from an unsanctioned "
                    f"expression: {v.field_type}"
                )
            elif v.rule == "E4":
                detail = f"impl GatedDetail for `{v.field}`: {v.field_type}"
            elif v.rule == "E5":
                detail = (
                    f"`format!` outside the sanctioned detail module — "
                    f"{v.field_type}"
                )
            else:
                detail = f"variant {v.variant} interpolates `{v.field}: {v.field_type}`"
            print(
                f"  {v.path}:{v.line}\n"
                f"    {detail}\n"
                f"    {v.source_line}",
                file=sys.stderr,
            )
        print(
            f"\n{len(violations)} violation(s). A `core` or bridge/wrapper "
            "error payload must not carry an ungated runtime String — it "
            "reaches both platform UIs and their logs (#474/#480/#486). "
            "Carry a &'static str hint plus an ordinal (E1/E2), build the "
            "value through a `detail::*` constructor (E3), move the impl "
            f"into {DETAIL_MODULE_REL} (E4), confine a wrapper crate's "
            "format! to its own detail.rs (E5), or record a reviewed "
            "exception in"
            "\n  "
            f"{ALLOWLIST_PATH.relative_to(REPO_ROOT)}",
            file=sys.stderr,
        )
        return 1
    print("error-payload hygiene: OK")
    return 0
