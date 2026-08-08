"""Which rules run over which source tree, and with what settings (#486).

Before #486 the roots were two module-level constants and `run_real_scan`
open-coded which rules applied to each. Adding the two binding wrapper crates
made that untenable — they take E1/E2/E3 and the NEW rule E5, but NOT E4, and
they take an E3 acceptance (shape 5) the bridge deliberately does not get.
Spelling each root's rule set out as data keeps "which rules apply here" a
thing a reviewer reads rather than infers.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .config import REPO_ROOT


@dataclass(frozen=True)
class ScanRoot:
    """One scanned source tree and the rules that apply to it."""

    label: str
    """Human-readable name, used in self-test failure messages only."""

    path: Path
    """Tree to walk for `*.rs`."""

    detail_module_rel: str | None
    """Repo-relative path of this root's sanctioned-constructor module, or
    `None` when the root has none (core). A root whose module is MISSING
    yields an EMPTY sanctioned set and therefore denies every `detail::*`
    call — `sanctioned_constructor_names`' fail-closed hinge, preserved
    per-root."""

    bridge_mode: bool
    """Rule E1's carve-out plus rule E2's two declaration sweeps."""

    construction_sites: bool
    """Rule E3."""

    gated_detail_impls: bool
    """Rule E4. Bridge only: `GatedDetail` is `pub(crate)` in the bridge, so
    no other crate can implement it even if a future author tried, and E4's
    premise — the set of types a detail string can be built from is exactly
    the set of impls in one reviewed file — is unaffected by the new roots."""

    format_confinement: bool
    """Rule E5 (#486). Wrapper crates only — see `rules/e5.py` for why the
    bridge is excluded (its `format!` mostly builds filenames)."""

    allow_field_access: bool
    """Rule E3 shape 5: accept a SINGLE-HOP `a.uuid_hex` for field
    `uuid_hex` (not a multi-hop `a.b.uuid_hex`). Wrapper roots only. It is a
    new ACCEPTANCE, so granting it where nothing needs it would open a
    laundering door for free — all four DTO pass-through sites are in the
    wrapper crates, and all four are single-hop."""


SCAN_ROOTS: tuple[ScanRoot, ...] = (
    ScanRoot(
        label="core",
        path=REPO_ROOT / "core" / "src",
        detail_module_rel=None,
        bridge_mode=False,
        construction_sites=False,
        gated_detail_impls=False,
        format_confinement=False,
        allow_field_access=False,
    ),
    ScanRoot(
        label="bridge",
        path=REPO_ROOT / "ffi" / "secretary-ffi-bridge" / "src",
        detail_module_rel="ffi/secretary-ffi-bridge/src/error/detail.rs",
        bridge_mode=True,
        construction_sites=True,
        gated_detail_impls=True,
        format_confinement=False,
        allow_field_access=False,
    ),
    ScanRoot(
        label="ffi-py",
        path=REPO_ROOT / "ffi" / "secretary-ffi-py" / "src",
        detail_module_rel="ffi/secretary-ffi-py/src/detail.rs",
        bridge_mode=True,
        construction_sites=True,
        gated_detail_impls=False,
        format_confinement=True,
        allow_field_access=True,
    ),
    ScanRoot(
        label="ffi-uniffi",
        path=REPO_ROOT / "ffi" / "secretary-ffi-uniffi" / "src",
        detail_module_rel="ffi/secretary-ffi-uniffi/src/detail.rs",
        bridge_mode=True,
        construction_sites=True,
        gated_detail_impls=False,
        format_confinement=True,
        allow_field_access=True,
    ),
)
