"""The real scan driver: `run_real_scan` walks both scan roots and runs
rules E1-E4 (bridge_mode E1 plus E2/E3/E4 on the bridge root) against every
`.rs` file, honouring the allowlist. Moved out of the former single-file
`scripts/check-error-payload-hygiene.py` in #486 (task 4).
"""

from __future__ import annotations

import sys

from payload_guard.allowlist import load_allowlist
from payload_guard.config import (
    ALLOWLIST_PATH, BRIDGE_SCAN_ROOT, DETAIL_MODULE_REL, REPO_ROOT, SCAN_ROOT,
)
from payload_guard.discovery import (
    _discover_tier_inputs, discover_scanned_error_type_names, foreign_use_names,
)
from payload_guard.rules.e1 import scan_source
from payload_guard.rules.e2 import scan_bridge_plain_declarations
from payload_guard.rules.e3 import sanctioned_constructor_names, scan_bridge_construction_sites
from payload_guard.rules.e4 import is_detail_module, scan_bridge_gated_detail_impls
from payload_guard.types import Finding


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

    # Rule E4's registry (#480): every `#[error]`-bearing enum/struct name
    # this guard scans under EITHER root. Cross-root on purpose — the impls
    # in `error/detail.rs` name core types (`secretary_core::vault::VaultError`)
    # far more often than bridge-local ones.
    scanned_error_type_names = discover_scanned_error_type_names(
        core_sources, bridge_sources, core_enums, bridge_enums
    )

    # Rule E3's sanctioned-constructor set, read from the ONE detail module.
    # If that file is missing from the scanned sources the set is EMPTY and
    # every `detail::*` call denies — see `sanctioned_constructor_names`.
    detail_src = next(
        (raw for label, raw in bridge_sources if is_detail_module(label)), None
    )
    sanctioned = sanctioned_constructor_names(detail_src)

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
    # declarations) and `scan_bridge_plain_declarations` (sweep 2, plain-derive
    # `*Error`/`*Warning` enums with no `#[error(...)]` attribute at all) —
    # PLUS rule E3 (the construction sites E2's gated-name carve-out defers
    # to) and rule E4 (the `impl GatedDetail` allowlist itself).
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
        findings += scan_bridge_plain_declarations(
            label, raw, bridge_enums, bridge_aliases, foreign
        )
        findings += scan_bridge_construction_sites(label, raw, sanctioned)
        findings += scan_bridge_gated_detail_impls(
            label, raw, scanned_error_type_names
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
            "payload must not carry an ungated runtime String — it reaches "
            "both platform UIs and their logs (#474/#480). Carry a "
            "&'static str hint plus an ordinal (E1/E2), build the value "
            "through a `detail::*` constructor (E3), move the impl into "
            f"{DETAIL_MODULE_REL} (E4), or record a reviewed exception in"
            "\n  "
            f"{ALLOWLIST_PATH.relative_to(REPO_ROOT)}",
            file=sys.stderr,
        )
        return 1
    print("error-payload hygiene: OK")
    return 0
