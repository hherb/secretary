from __future__ import annotations

from pathlib import Path

# `scripts/payload_guard/config.py` -> repo root is three parents up.
# (It was two in the pre-#486 single-file entry point at `scripts/`.)
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCAN_ROOT = REPO_ROOT / "core" / "src"
# #480: the FFI bridge builds its own detail strings with `format!` and was,
# until rules E2/E3/E4, entirely unscanned. Bridge files get their OWN
# discovery pass (`bridge_mode`) rather than being folded into `SCAN_ROOT`'s:
# a bridge-local alias/const/enum must not vouch for a core field, or vice
# versa.
BRIDGE_SCAN_ROOT = REPO_ROOT / "ffi" / "secretary-ffi-bridge" / "src"
# #480 rule E4: the ONE file permitted to declare `impl GatedDetail for X`.
# Repo-relative and POSIX-spelled, matching `run_real_scan`'s `path_label`
# (`str(path.relative_to(REPO_ROOT))`); compared via `is_detail_module`.
DETAIL_MODULE_REL = "ffi/secretary-ffi-bridge/src/error/detail.rs"
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

# #480/rule E2: field NAMES whose construction site rule E3 gates. A bridge
# field under one of these names, declared EXACTLY `String`,
# is not a structural finding — its VALUE is checked at the construction
# site instead of being denied outright by TYPE. Pinned to this exact set
# (spec §3.2): `record_uuid_hex` / `device_uuid_hex` are deliberately NOT
# members — those are DTO-carrying fields (sync/dto.rs, sync/status.rs), not
# diagnostic text, and gating them here would launder real payload data
# through a name that merely LOOKS like the diagnostic-hex convention.
GATED_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "detail",
        "uuid_hex",
        "block_uuid_hex",
        "recipient_fingerprint_hex",
        "expected_fingerprint_hex",
        "got_fingerprint_hex",
    }
)

# `use ...;` — the per-file name bindings that make a BARE spelling mean
# something other than what tree-global discovery assumed. Roots that stay
# inside this crate; anything else (`std`, `core`, a third-party crate) binds
# a name this guard does not scan and therefore cannot vouch for.
LOCAL_USE_ROOTS: frozenset[str] = frozenset({"crate", "super", "self"})
