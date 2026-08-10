"""Which rules run over which source tree, and with what settings (#486).

Before #486 the roots were two module-level constants and `run_real_scan`
open-coded which rules applied to each. Adding the two binding wrapper crates
made that untenable — they take E1/E2/E3 and the NEW rule E5, but NOT E4.
They also took an E3 acceptance (shape 5) the bridge was deliberately denied;
that one was RETIRED in #497/#500 once all four of its sites moved onto a
sanctioned constructor, so `allow_field_access` is now False everywhere — see
the field's own doc below, which this paragraph used to contradict.
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

    gated_field_types: frozenset[str]
    """Type spellings accepted under a `GATED_FIELD_NAMES` field name on this
    root (#500). The BRIDGE moved all 27 of its gated fields to the `Detail`
    newtype, whose private inner field makes a runtime `String` unrepresentable
    in the position; the two WRAPPER crates keep `String` because uniffi's UDL
    must project a `string` and PyO3 exceptions take a message, so their
    posture is unchanged and rules E2/E3/E5 remain their only enforcement.

    QUALIFIED, and the qualifier is load-bearing: this is a set of SPELLINGS,
    matched textually. The unrepresentability claim above holds only while a
    field written `Detail` RESOLVES to `secretary_ffi_bridge::Detail`. Two
    things stand between the spelling and that resolution, and neither is name
    resolution:

    * A same-spelled DECLARATION elsewhere in the root is caught —
      `discover_local_detail_decoys` (`discovery.py`) withdraws `Detail` from
      this set on any root where a second `struct`/`enum`/`union`/`type
      Detail` is declared outside the root's own `detail_module_rel`
      (`BP54`/`BP55` pin it, `BN29` pins that the real declaration does not
      shadow itself).
    * An IMPORT is NOT caught, in either spelling. `use std::string::String
      as Detail;` in a bridge file, plus a new gated field declared `Detail`
      and an E3 arm-4 parameter re-wrap, scans with ZERO findings — verified
      by execution, and tracked by #512. See
      `discover_local_detail_decoys`' residual 5 and the entry point's
      "THE #500 NEWTYPE" boundary 2: the compiler guarantee is
      per DECLARATION, over the 27 fields that hold the real type, not a
      root-wide property this flag can assert on its own.

    Empty for `core`, which has no gated-name carve-out at all — every field
    there must clear `is_data_free` on its own."""

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

    owns_detail_type: bool
    """This root DECLARES the authentic `Detail` newtype (#500 fix round 1).

    True for the BRIDGE alone, whose `error/detail.rs` holds
    `pub struct Detail(String)`. `SAFE_PARAM_TYPES` matches the SPELLING
    `Detail` and does not resolve the name, so on every other root a locally
    declared `struct Detail` in the sanctioned module is a decoy that would
    pass the signature gate and launder an arbitrary `String`. Where this is
    False, such a declaration withdraws the `Detail` parameter type — see
    `rules/e3.py`'s `LOCAL_DETAIL_TYPE_RE`.

    THIS ONE FLAG NOW SUPPRESSES **TWO** DECOY WITHDRAWALS, not one (#504
    review R3), and that is stated at the DECLARATION because this is the
    line a future author reads when deciding to flip it. `rules/e3.py`'s
    `sanctioned_constructor_names` consults it twice:

        detail_param_ok       = owns_detail_type or not LOCAL_DETAIL_TYPE_RE...
        gated_detail_param_ok = owns_detail_type or not LOCAL_GATED_DETAIL_TRAIT_RE...

    So setting it `True` on a wrapper root silently re-opens BOTH the decoy
    `struct/enum/union/type Detail` hole (`WP8`/`WP10`) AND the decoy
    `trait GatedDetail` hole (`WP11`) — two independent laundering classes,
    one flag. The reuse is deliberate (both ask the same question: does this
    root own the real types?) and is argued in
    `sanctioned_constructor_names`' docstring; it was documented ONLY there
    until #500 Task 8, which is the wrong place for a warning about a flag's
    blast radius."""

    allow_field_access: bool
    """Rule E3 shape 5: accept a SINGLE-HOP `a.uuid_hex` for field
    `uuid_hex` (not a multi-hop `a.b.uuid_hex`).

    **OFF on every root as of #497/#500.** It was granted for exactly four
    wrapper DTO pass-through sites; #500 moved all four onto
    `detail::project(...)`, a sanctioned-constructor call (E3 shape 2), so the
    acceptance had ZERO live sites. Its own rule for itself then applied: "it
    is a new ACCEPTANCE, so granting it where nothing needs it would open a
    laundering door for free." The shape it accepts is an ARBITRARY single-hop
    receiver — `<anything>.detail`, a local of any type, including one
    declared outside every scan root — which is wider than the four sites that
    justified it and was disclosed as such in the guard's LIMITS (#497).
    Switched off rather than left dormant; `WP7` pins the denial, and turning
    it back on for a future DTO must come with live sites and a fresh review."""


SCAN_ROOTS: tuple[ScanRoot, ...] = (
    ScanRoot(
        label="core",
        path=REPO_ROOT / "core" / "src",
        detail_module_rel=None,
        bridge_mode=False,
        gated_field_types=frozenset(),
        construction_sites=False,
        gated_detail_impls=False,
        format_confinement=False,
        owns_detail_type=False,
        allow_field_access=False,
    ),
    ScanRoot(
        label="bridge",
        path=REPO_ROOT / "ffi" / "secretary-ffi-bridge" / "src",
        detail_module_rel="ffi/secretary-ffi-bridge/src/error/detail.rs",
        bridge_mode=True,
        # #500: the bridge's 27 gated fields are the `Detail` newtype, whose
        # private inner field makes a runtime `String` UNREPRESENTABLE in the
        # position. `String` is no longer accepted here — a new bridge error
        # type cannot opt out of the newtype by declaring the old spelling.
        # The wrapper roots still take `String`; see the spec's §4 for why
        # that boundary is real and not an oversight.
        #
        # CONDITIONAL, per `gated_field_types`' own docstring above: this is a
        # SPELLING, and "unrepresentable" holds only while a field written
        # `Detail` resolves to `secretary_ffi_bridge::Detail`. A same-spelled
        # DECLARATION elsewhere in this root withdraws the acceptance
        # (`discover_local_detail_decoys`); an IMPORT — `use
        # std::string::String as Detail;` — does not, and scans clean (#512).
        # Do not read this line as a root-wide guarantee.
        gated_field_types=frozenset({"Detail"}),
        construction_sites=True,
        gated_detail_impls=True,
        format_confinement=False,
        owns_detail_type=True,
        allow_field_access=False,
    ),
    ScanRoot(
        label="ffi-py",
        path=REPO_ROOT / "ffi" / "secretary-ffi-py" / "src",
        detail_module_rel="ffi/secretary-ffi-py/src/detail.rs",
        bridge_mode=True,
        gated_field_types=frozenset({"String"}),
        construction_sites=True,
        gated_detail_impls=False,
        format_confinement=True,
        owns_detail_type=False,
        allow_field_access=False,
    ),
    ScanRoot(
        label="ffi-uniffi",
        path=REPO_ROOT / "ffi" / "secretary-ffi-uniffi" / "src",
        detail_module_rel="ffi/secretary-ffi-uniffi/src/detail.rs",
        bridge_mode=True,
        gated_field_types=frozenset({"String"}),
        construction_sites=True,
        gated_detail_impls=False,
        format_confinement=True,
        owns_detail_type=False,
        allow_field_access=False,
    ),
)
