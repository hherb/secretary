"""Rule E4: every `impl GatedDetail for X` is a security decision and must
sit in the one reviewed file (`DETAIL_MODULE_REL`), naming a plain type this
guard actually scans. This is the allowlist rule E3's `detail::*`
constructors rest on: because the trait is `pub(crate)` and its constructors
take `&impl GatedDetail`, pinning the impls to one file pins the whole set of
types a detail string can be built from to one review. Moved out of the
former single-file `scripts/check-error-payload-hygiene.py` in #486
(task 4). Read the entry point's module docstring first for the WHY and THE
BRIDGE RULES.
"""

from __future__ import annotations

import re

from payload_guard.config import DETAIL_MODULE_REL
from payload_guard.lexer import strip_comments
from payload_guard.types import Finding

# Rule E4's anchor: the TRAIT NAME plus `for`, and nothing else.
#
# FOR A VIOLATION-FINDING REGEX, MATCHING LESS IS FAIL-OPEN. The first version
# of this rule spelled it `impl\s+GatedDetail\s+for\s+([A-Za-z0-9_:<>]+)` and
# called matching more text "the fail-closed direction" — the claim was right
# and the regex did the opposite of it. `impl\s+` REQUIRES whitespace after
# `impl`, so `impl<T: Display> GatedDetail for T {}` — a one-line blanket impl
# that hands the trait to EVERY `Display` type and collapses the premise both
# E3 and E4 rest on — never matched, in `detail.rs` or anywhere else. Neither
# did `impl crate::error::detail::GatedDetail for X {}`, and the target class
# excluded `&`, `(`, `[` and `'`, so `impl<'a> GatedDetail for &'a str {}` and
# `impl GatedDetail for &Plain {}` were invisible too. All six shapes were
# rustc-compiled and confirmed to produce ZERO findings, with E3 then happily
# accepting `detail: detail::gated(&Wrap(decrypted_key))`.
#
# Anchoring on `GatedDetail for` alone removes every one of those degrees of
# freedom: whatever precedes the trait name (generic parameters, a qualified
# trait path, line breaks) cannot hide the anchor, because the anchor does not
# look at it. The `impl` header is then recovered BACKWARDS, and failing to
# recover it is an `UNPARSED` finding rather than a skip.
IMPL_GATED_ANCHOR_RE = re.compile(r"\bGatedDetail\s+for\b")
IMPL_KW_RE = re.compile(r"\bimpl\b")
# How far back to look for the `impl` keyword introducing an anchor. Generic
# parameter lists in this codebase are a few dozen characters; 512 is slack.
# Coming up empty is a FINDING (`UNPARSED`), not a skip, so the bound cannot
# hide an impl — only mislabel one.
IMPL_HEADER_WINDOW = 512
# A plain type PATH: `::`-separated plain identifiers, nothing else. Rule E4
# accepts no other target shape. A reference (`&Plain`), a lifetime-bearing
# type (`&'a str`), a tuple, an array, `dyn Trait`, a generic application
# (`Wrap<T>`) and `()` all fail this and DENY, because each is a claim about
# something other than one named type this guard can look up.
PLAIN_TYPE_PATH_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*$")
# The path roots that name a crate THIS GUARD SCANS. `crate` / `self` /
# `super` resolve inside `secretary-ffi-bridge` itself (the bridge `ScanRoot`
# in `payload_guard.roots`, the only one this rule ever runs over — see
# `ScanRoot.gated_detail_impls`), `secretary_core` is the core `ScanRoot`'s
# crate, and `secretary_ffi_bridge` is the bridge spelled by its own crate
# name. Anything else — `std`, `secretary_cli`, any third-party crate, or
# either WRAPPER crate's own name — names a type no registry here has
# scanned.
SCANNED_IMPL_ROOTS: frozenset[str] = frozenset(
    {"crate", "self", "super", "secretary_core", "secretary_ffi_bridge"}
)
# Short, stable REASON CODES prefixing each of rule E4's six denial arms.
# Their purpose is mutation-verifiability, not display: the arms OVERLAP —
# a bare target also fails the root check, a blanket `impl<T> ... for T` also
# has a bare target, an impl outside detail.rs would also fail several of the
# in-file checks — so a control asserting only "a finding fired" cannot tell
# an arm's removal from its presence. Controls assert `field_type_prefix`
# against these codes, which makes each arm independently mutatable; three
# mutation checks came back GREEN before they existed.
E4_OUTSIDE = "outside-detail-module: "
E4_GENERIC = "generic-impl: "
E4_NONPATH = "non-path-target: "
E4_BARE = "bare-target: "
E4_ROOT = "foreign-crate-root: "
E4_UNSCANNED = "unscanned-type: "


def is_detail_module(path_label: str) -> bool:
    """Whether `path_label` names the one file permitted to declare an
    `impl GatedDetail` (`DETAIL_MODULE_REL`). Separator-normalized so a
    Windows-spelled `path_label` compares equal."""
    return path_label.replace("\\", "/") == DETAIL_MODULE_REL


def impl_header_before(src: str, anchor_start: int) -> tuple[int, str] | None:
    """`(impl_keyword_start, text between `impl` and the anchor)` for the
    nearest `impl` keyword preceding a `GatedDetail for` anchor, or `None`.

    The between-text is what tells a GENERIC impl from a plain one: it holds
    the generic parameter list (`<T: Display>`) and/or a qualified trait path
    prefix (`crate::error::detail::`). Searching BACKWARDS from the anchor —
    rather than matching the header forwards — is the whole point: a forward
    match has to model everything that may sit between `impl` and the trait
    name, and every one of those things was a bypass (see
    `IMPL_GATED_ANCHOR_RE`).
    """
    matches = list(
        IMPL_KW_RE.finditer(src, max(0, anchor_start - IMPL_HEADER_WINDOW), anchor_start)
    )
    if not matches:
        return None
    m = matches[-1]
    return m.start(), src[m.end() : anchor_start]


def impl_target_text(src: str, start: int) -> tuple[str, int]:
    """`(whitespace-collapsed self type, end offset)` for the impl target
    beginning at `start` (just past a `GatedDetail for` anchor).

    Ends at the first `{` or `;` outside `()`/`<>`/`[]` nesting, or at a
    `where` clause, whichever comes first. Nesting is tracked so
    `Wrap<Vec<u8>>` and `(u8, u8)` come out whole — this function does not
    judge the shape, it only delimits it; `PLAIN_TYPE_PATH_RE` judges.
    """
    depth = 0
    i, n = start, len(src)
    while i < n:
        ch = src[i]
        if ch in "(<[":
            depth += 1
        elif ch in ")>]":
            if depth > 0:
                depth -= 1
        elif depth == 0 and ch in "{;":
            break
        i += 1
    text = src[start:i]
    wm = re.search(r"\bwhere\b", text)
    if wm:
        i = start + wm.start()
        text = text[: wm.start()]
    return " ".join(text.split()), i


def scan_bridge_gated_detail_impls(
    path_label: str, raw: str, scanned_error_type_names: frozenset[str]
) -> list[Finding]:
    """Rule E4 (#480): `impl GatedDetail for X` is a SECURITY DECISION — a
    claim that `X`'s `Display` output carries no vault plaintext, password,
    mnemonic or key bytes — so every one of them must sit in the single
    reviewed file `error/detail.rs`, and each must name a type whose payloads
    something has actually checked.

    This is the Rust analogue of iOS's `SecretFreeError` conformance and
    Android's `SecretFreeThrowable` declaration (#467/#472), with one
    difference the two platforms could not have: because the trait is
    `pub(crate)` and its constructors take `&impl GatedDetail`, the set of
    types a detail string can be built from is exactly the set of impls —
    so PINNING THE IMPLS TO ONE FILE pins the whole allowlist to one review.

    SIX checks, in order — each with its own reason code so a control can
    pin WHICH one fired (they overlap heavily; see the reason-code comment):

    1. Any impl in a file OTHER than `DETAIL_MODULE_REL` is a finding. There
       is no allowlist story for this arm — move the impl.
    2. A GENERIC impl (`impl<...>`) is a finding. Generic parameters are how
       a claim gets made about types the author has not enumerated, and
       enumerability is the entire premise: `impl<T: Display> GatedDetail
       for T {}` would hand the trait to every `Display` type in one line.
       This arm has no allowlist story either.
    3. A target that is not a plain `::`-separated type path is a finding
       (`&Plain`, `&'a str`, `(u8, u8)`, `[u8; 4]`, `dyn Foo`, `Wrap<T>`,
       `()`): each is a claim about something other than one named type this
       guard can look up.
    4. A BARE (single-segment) target is a finding: a bare name states no
       crate, so it cannot be told apart from a `use`-imported foreign type
       of the same name — write the path.
    5. The path must be ROOTED IN A SCANNED CRATE (`SCANNED_IMPL_ROOTS`).
    6. Its LAST SEGMENT must be a type this guard itself scans
       (`scanned_error_type_names`) — the same "safe by recursion" argument
       tier 2 of `is_data_free` makes for a field referencing a local error
       enum: this guard already fails at that type's own definition if one
       of its payloads is not data-free.

    Arms 5 and 6 are allowlistable after human review (`std::io::Error`'s
    path + errno is already-disclosed under the threat model, and so on).

    THE ROOT CHECK IS LOAD-BEARING AND IS NOT REDUNDANT WITH THE REGISTRY
    CHECK. `scanned_error_type_names` holds BARE names, and `core/src/error.rs`
    declares a `thiserror` enum literally called `Error` — so a last-segment-
    only test accepts `impl GatedDetail for std::io::Error {}`, crediting a
    FOREIGN type for a same-named local one. That is the exact collision
    `foreign_use_names` exists to withdraw for field references, arriving
    here by a different door; it is live in the tree today, and `BP20` pins
    it.

    LIMIT, same class as E1's: this reads TEXT, not expanded macros. An
    `impl GatedDetail for ...` produced by a `macro_rules!` expansion is
    invisible here, exactly as a macro-generated `#[error(...)]` is invisible
    to `scan_source` — the module docstring's LIMITS records the general
    form. "Any impl outside detail.rs is a finding" is therefore a claim
    about impls this guard can SEE, and the honest scope of arm 1.
    """
    src = strip_comments(raw)
    in_detail = is_detail_module(path_label)
    findings: list[Finding] = []
    for m in IMPL_GATED_ANCHOR_RE.finditer(src):
        header = impl_header_before(src, m.start())
        target, target_end = impl_target_text(src, m.end())
        if header is None:
            # A `GatedDetail for` anchor with no `impl` keyword in front of
            # it is a construct this guard does not model. Fail closed on
            # STRUCTURE, exactly as `scan_source` does for an attribute whose
            # variant it cannot locate.
            findings.append(
                Finding(
                    path=path_label,
                    line=src.count("\n", 0, m.start()) + 1,
                    source_line=" ".join(src[m.start() : target_end].split()),
                    variant="<impl GatedDetail>",
                    field=target or "<unparsed>",
                    field_type=(
                        "UNPARSED: found a `GatedDetail for` anchor with no "
                        "`impl` keyword in front of it — this guard cannot "
                        "tell what declares it"
                    ),
                    rule="E4",
                )
            )
            continue
        impl_start, between = header
        has_generics = between.lstrip().startswith("<")
        segments = [seg for seg in target.split("::") if seg]
        reason: str | None = None
        if not in_detail:
            reason = (
                f"{E4_OUTSIDE}declared outside {DETAIL_MODULE_REL} — every "
                "impl of this trait is a secret-freedom claim and must sit "
                "in that one reviewed file"
            )
        elif has_generics:
            reason = (
                f"{E4_GENERIC}the impl declares generic parameters, so it "
                "claims secret-freedom for a FAMILY of types rather than one "
                "named type — the set of impls would stop being enumerable, "
                "which is the premise rules E3 and E4 rest on"
            )
        elif not PLAIN_TYPE_PATH_RE.match(target):
            reason = (
                f"{E4_NONPATH}target `{target or '<empty>'}` is not a plain "
                "type path (reference, lifetime, tuple, array, `dyn`, "
                "generic application or unit), so there is no single named "
                "type to look up"
            )
        elif len(segments) < 2:
            reason = (
                f"{E4_BARE}target is a BARE name, which states no crate and "
                "so cannot be distinguished from a use-imported foreign type "
                "of the same name — write the full path"
            )
        elif segments[0] not in SCANNED_IMPL_ROOTS:
            reason = (
                f"{E4_ROOT}target is rooted at `{segments[0]}`, a crate this "
                "guard does not scan, so its payloads are not checked "
                "anywhere — allowlist after review"
            )
        elif segments[-1] not in scanned_error_type_names:
            reason = (
                f"{E4_UNSCANNED}target's last path segment `{segments[-1]}` "
                "is not an error type this guard scans, so the "
                "safe-by-recursion argument does not cover it — allowlist "
                "after review"
            )
        if reason is None:
            continue
        findings.append(
            Finding(
                path=path_label,
                line=src.count("\n", 0, impl_start) + 1,
                source_line=" ".join(src[impl_start:target_end].split()),
                variant="<impl GatedDetail>",
                field=target,
                field_type=reason,
                rule="E4",
            )
        )
    return findings
